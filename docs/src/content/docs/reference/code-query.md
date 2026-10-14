---
title: CodeQuery and RQL Vocabulary Reference
description: Every source, pattern field, kind, role, step, option, value label, result type, diagnostic code, and limit that query_code accepts, in RQL and JSON spellings.
---

This page lists the complete query vocabulary of the `query_code` engine. Each table is
enumerated from the registries that the parser and validator use. RQL and JSON
`CodeQuery` are two spellings of one model, so every row gives both spellings where
they differ.

For explanations and worked examples, read [Code Querying](/code-querying/),
[Rune Query Language](/rune-query-language/), and [JSON CodeQuery](/code-query-json/).

## Print the live vocabulary

The binary can print parts of this vocabulary for the build you are running:

| Command | What it prints |
| --- | --- |
| `bifrost --help query_code` | Every `query_code` parameter, and every step as `name (input -> output): meaning`. The parameter list does not show the seed sources `generation_sites`, `exports`, and `configuration_facts`, but `query_code` accepts them. |
| `bifrost --list-row-schemas` | The `bifrost_relation_schema/v1` catalog: every result row domain, each field's scalar type, nullability, join-key status, and enum labels. |
| REPL `:kinds`, `:roles`, `:languages` | The normalized kinds, roles, and language labels. `:languages` also prints the dialect labels `tsx`, `jsx`, and `cpp-c`, which `:ir` accepts. A query accepts `tsx` and `jsx` as file extensions, but rejects `cpp-c`. |
| REPL `:doc NAME` | Help for one form, kind, role, language, command, example, or row domain. |

Start the REPL with `bifrost --root DIR --repl`.

## Schema version

There is one schema version: `1`.

- JSON: `schema_version` is optional. The value is the string `"1"`. The number `1` is
  also accepted and is rewritten to `"1"`. Any other value is rejected with
  `unsupported schema version`.
- RQL: a standalone query has no schema-version option. It always uses version 1.
  Policy selectors pin it with `(rql :schema-version 1 QUERY)`; see
  [static-analysis policies](/static-analysis-policies/).

## Query plan fields

A query plan node has exactly one of these 11 sources:

- `match`, a structural pattern;
- a set operator: `union`, `intersect`, or `except`;
- a seed source: `occurrences`, `scopes`, `bindings`, `paths`,
  `generation_sites`, `exports`, or `configuration_facts`.

A second source is rejected. Unknown fields are rejected.

| JSON field | RQL form | Value | Default | Meaning |
| --- | --- | --- | --- | --- |
| `match` | a kind head, such as `(call ...)` | pattern | none | Root structural pattern. It must constrain `kind`, `name`, or `text`. |
| `union` | `(union Q Q ...)` | 2 to 16 plans | none | Typed endpoints reached by any branch, in first-appearance order. |
| `intersect` | `(intersect Q Q ...)` | 2 to 16 plans | none | Typed endpoints reached by every branch, in first-branch order. |
| `except` | `(except Q Q ...)` | 2 to 16 plans | none | First-branch endpoints that no later branch reaches. |
| `occurrences` | `(occurrences ...)`, `(occurrence ...)` | occurrence filter | every occurrence | Seed classified identifier occurrences. |
| `scopes` | `(scopes ...)`, `(scope ...)` | scope filter | every scope | Seed lexical scope rows. |
| `bindings` | `(bindings ...)`, `(binding ...)` | binding filter | every binding | Seed lexical binding rows. |
| `paths` | `(paths ...)`, `(path ...)` | path filter | every path | Seed qualified-path rows. |
| `generation_sites` | `(generation-sites ...)`, `(generation_sites ...)` | generation-site filter | every site | Seed generation-site rows from recorded materialization provenance. |
| `exports` | `(exports ...)`, `(export ...)` | export filter | every export | Seed export rows from recorded materialization provenance and Python module-level `__all__` literals. |
| `dependency_evidence` | `(dependency-evidence ...)`, `(dependency_evidence ...)` | dependency filter | every stored fact | Revision-selected declared and exact locked Cargo and JS/TS evidence; no query-time dependency discovery. |
| `configuration_facts` | `(configuration-facts ...)`, `(configuration_facts ...)` | configuration filter | every fact | Seed facts from YAML, TOML, JSON, XML, and properties documents. |
| `where` | `(where "glob" ... Q)` | array of globs, or array of glob arrays | whole workspace | Workspace-relative path globs. A flat list means any glob. Nested lists mean every group, with any glob inside a group. Repeated RQL `where` forms combine like nested lists. |
| `languages` | `(language label ... Q)`, `(languages label ... Q)` | array of language labels | every language | Restrict to these languages. Repeated RQL forms intersect. Disjoint sets are rejected. `configuration_facts` rejects this field. |
| `inside` | `(inside P Q)` | pattern | none | The root match must be lexically inside a node that matches `P`. Only with `match`. |
| `inside_decl` | `(inside-decl P Q)`, `(inside_decl P Q)` | pattern | none | Like `inside`, but the search stops at a nested callable declaration. A Rust `impl` member can also match the type that owns the `impl`. Only with `match`. |
| `not_inside` | `(not-inside P Q)` | pattern | none | Reject the root match when a matching ancestor exists. Only with `match`. |
| `steps` | wrapper forms such as `(file-of Q)` | array of step objects | no steps | Ordered typed steps. At most 16 per plan node. |
| `limit` | `(limit N Q)` | integer 1 to 1000 | `100` | Maximum terminal results. Root only. |
| `result_detail` | `(result-detail compact Q)`, `(result_detail full Q)` | `compact` or `full` | `compact` | `full` adds stable IDs, byte and column ranges, and capture ranges. Root only. |
| `execution_mode` | `(explain Q)` or `(profile Q)` | `results`, `explain`, or `profile` | `results` | `explain` plans without running. `profile` runs and adds measurements. Root only. |
| `schema_version` | none | `"1"` | `"1"` | Pin the schema version. Root only. |

Root-only fields cannot appear inside a set operand. `inside`, `inside_decl`, and
`not_inside` belong in the branch that holds `match`.

### Seed source filters

All filter axes are optional. Axes combine with AND. Values inside one axis combine
with OR. Each axis takes at most 32 entries.

| Source | JSON field | RQL keyword | Values |
| --- | --- | --- | --- |
| `occurrences` | `class` | `:class`, `:classes` | [occurrence classes](#occurrences) |
| `occurrences` | `role` | `:role`, `:roles` | [occurrence roles](#occurrences) |
| `occurrences` | `namespace` | `:namespace`, `:namespaces` | [namespaces](#occurrences) |
| `scopes` | `kind` | `:kind`, `:kinds` | [normalized kinds](#normalized-kinds) of the scope's anchor node |
| `bindings` | `kind` | `:kind`, `:kinds` | [binding kinds](#lexical-environment) |
| `bindings` | `name` | `:name`, `:names` | exact names, each at most 256 bytes |
| `bindings` | `hoisting` | `:hoisting` | [hoisting classes](#lexical-environment) |
| `paths` | `min_segments` | `:min-segments`, `:min_segments` | positive integer |
| `generation_sites` | `kind` | `:kind`, `:kinds` | `accessor_macro`, `alias_macro`, `preprocessor_definition` |
| `generation_sites` | `input` | `:input`, `:inputs` | `literal`, `dynamic` |
| `exports` | `form` | `:form`, `:forms` | `named`, `default_named`, `default_anonymous`, `common_js_root`, `common_js_member`, `python_all` |
| `exports` | `name` | `:name`, `:names` | exact exported names |
| `configuration_facts` | `formats` | `:format`, `:formats` | [configuration formats](#configuration-facts) |
| `configuration_facts` | `node_kinds` | `:node-kind`, `:node_kind`, `:node-kinds`, `:node_kinds` | [node kinds](#configuration-facts) |
| `configuration_facts` | `roles` | `:role`, `:roles` | [member roles](#configuration-facts) |
| `configuration_facts` | `scalar_kinds` | `:scalar-kind`, `:scalar_kind`, `:scalar-kinds`, `:scalar_kinds` | [scalar kinds](#configuration-facts) |
| `configuration_facts` | `keys` | `:key`, `:keys` | exact keys, each at most 4096 bytes |
| `configuration_facts` | `routes` | `:route`, `:routes` | route alternatives; see [routes](#configuration-facts) |
| `configuration_facts` | `fact_ordinals` | `:fact-ordinal`, `:fact_ordinal`, `:fact-ordinals`, `:fact_ordinals` | zero-based fact occurrence numbers |
| `configuration_facts` | `provenances` | `:provenance`, `:provenances` | `authored` |
| `configuration_facts` | `completenesses` | `:completeness`, `:completenesses` | `complete`, `incomplete` |

## Patterns

A pattern combines all its constraints with AND. In RQL a pattern is a kind head
followed by keyword options and predicate forms:

```text
(KIND [:ROLE VALUE | :PROPERTY VALUE | (PREDICATE ...)]*)
```

- `KIND` is one [normalized kind](#normalized-kinds), spelled exactly as listed, with
  underscores (`field_access`, not `field-access`). A head with no arguments, such as
  `(loop)`, is valid.
- `:ROLE VALUE` constrains a [role](#roles). A single-target role takes a pattern or a
  string. The string is shorthand for `(name "...")`, so `:callee "run"` equals
  `:callee (name "run")`. A list role takes `[PATTERN ...]`. `:kwargs` takes
  `[(ARGNAME PATTERN) ...]`, for example `:kwargs [(shell (boolean_literal))]`.
- `:PROPERTY VALUE` and `(PREDICATE ...)` are two spellings of the same constraint.
  `(function :name "run")` equals `(function (name "run"))`.
- A bare string inside a kind head is an error. Write `(function :name "register")`,
  not `(function "register")`.
- Nested role patterns may be unconstrained or capture-only. The root pattern may not.

| JSON field | RQL keyword | RQL predicate form | Value | Meaning |
| --- | --- | --- | --- | --- |
| `kind` | kind head | kind head | kind, or array of kinds (at most 32) | Match these kinds and their subtypes. |
| `not_kind` | `:not-kind`, `:not_kind` | `(not-kind K)`, `(not_kind [K ...])` | kind, or array of kinds | Exclude these kinds and their subtypes. Never used for file pruning. |
| `async` | `:async true`, `:async false` | `(async true)`, `(async false)` | boolean | Match AST-backed callable asyncness. Valid on callable kinds; an adapter without this fact reports incomplete. |
| `name` | `:name "x"` | `(name "x")` | exact string, or `{ "regex": "..." }` | Match the normalized name. At most 4096 bytes. |
| `name` with regex | `:name/regex "re"` | `(name/regex "re")` | regular expression | Match the normalized name with a Rust regular expression. |
| `text` | `:text/regex "re"` | `(text/regex "re")` | `{ "regex": "..." }` only | Match parser-backed source text. There is no exact-text form. |
| `boolean_value` | `:boolean-value`, `:boolean_value` | `(boolean-value true)`, `(boolean_value false)` | `true` or `false` | Match a boolean literal by its language-neutral value. |
| `string_value` | `:string-value`, `:string_value` | `(value "https://example.com")` | exact string, or `{ "regex": "..." }` | Match a string literal by its decoded value, with quotes and language escapes resolved. |
| `string_value` with regex | `:string-value/regex`, `:string_value/regex` | `(value/regex "^https?://")` | regular expression | Match the decoded value of a string literal with a Rust regular expression. |
| `not`, `all`, `any` | none | `(not P)`, `(and P Q ...)`, `(or P Q ...)` | pattern, or two or more patterns | Negate or combine constraints on the same node. |
| `capture` | `:capture "label"` | `(capture "label")` | string, 1 to 128 bytes | Return this node under the label. A repeated label must bind the same text. Use the `anchor` step to report a captured node's exact source range as the result location. |
| `arity` | `:arity N` (exact count only) | `(arity N)`, `(arity :min N :max M)` | integer, or `{ "min": N, "max": M }`; bounds 0 to 1024 | Positional argument count of a call, or element count of a collection literal. Bounds are inclusive and either may be omitted, but not both. |
| `visibility` | `:visibility` | `(visibility public)`, `(visibility [public protected])` | [visibility labels](#patterns-and-calls) | Match a callable by the visibility its adapter recorded. Callable kinds only. |
| `parameter_type` | `:parameter-type`, `:parameter_type` | `(parameter-type "String")`, `(parameter_type "String")` | exact string, or `{ "regex": "..." }` | Match a callable with a parameter whose recorded type spelling equals the string. Callable kinds only. |
| `parameter_type` with regex | `:parameter-type/regex`, `:parameter_type/regex` | `(parameter-type/regex "re")`, `(parameter_type/regex "re")` | regular expression | Match the recorded parameter type spelling with a regular expression. |
| `has` | `:has P` | `(has P)` | pattern | Require a matching descendant. |
| `not_has` | `:not-has P`, `:not_has P` | `(not-has P)`, `(not_has P)` | pattern | Reject nodes with a matching descendant. Never used for file pruning. |

Role fields (`callee`, `args`, and the others) are listed under [Roles](#roles).

## Normalized kinds

Kind matching includes subtypes. `literal` matches every literal subtype. There is no
exact-kind operator; use a leaf kind or subtract subtypes with `not_kind`.

| Kind | Parent | Meaning |
| --- | --- | --- |
| `declaration` | none | Any declaration, including callable, class, and import declarations. |
| `callable` | `declaration` | Any callable declaration: function, method, constructor, or lambda. |
| `function` | `callable` | A named free-standing function declaration. |
| `method` | `callable` | A method declared on a class or similar container. |
| `constructor` | `callable` | A constructor declaration. |
| `lambda` | `callable` | An anonymous function or lambda expression. |
| `class` | `declaration` | A class-like declaration. |
| `import` | `declaration` | An import declaration. |
| `parameter` | `declaration` | A formal parameter declaration. |
| `module` | `declaration` | A module or namespace declaration that contains other declarations. |
| `call` | none | A call of a function, method, or constructor. |
| `concurrent_spawn` | none | A structured operation that starts a callable in a separate concurrent task. |
| `resource_release` | none | A construct that releases a resource when it exits, such as Java try-with-resources or a Python `with` statement. |
| `assignment` | none | An assignment expression or statement. |
| `await` | none | An await expression. |
| `field_access` | none | A member or field access. |
| `identifier` | none | An identifier reference. |
| `literal` | none | Any literal value. |
| `string_literal` | `literal` | A string literal. |
| `numeric_literal` | `literal` | A numeric literal. |
| `boolean_literal` | `literal` | A boolean literal. |
| `null_literal` | `literal` | A null-like literal. |
| `collection_literal` | `literal` | An array, list, set, dictionary, or tuple literal. |
| `jsx_element` | none | A JSX element, including a self-closing element. |
| `jsx_attribute` | none | A named JSX attribute. |
| `jsx_spread_attribute` | none | A JSX spread attribute expression. |
| `object_property` | none | A named property pair in an object literal. |
| `computed_property` | none | A computed object-property key. |
| `spread_element` | none | A spread expression in an object, array, or argument list. |
| `return` | none | A return statement. |
| `throw` | none | A throw or raise statement. |
| `catch` | none | A catch or exception-handler clause. |
| `if` | none | A conditional statement or expression. |
| `loop` | none | Any loop construct. |
| `for_loop` | `loop` | A loop over a collection, iterator, or range (the for-each family). |
| `while_loop` | `loop` | A condition-controlled loop: while, do-while, or until. |
| `decorator` | none | A decorator, annotation, or attribute. |
| `block` | none | A statement list that opens its own lexical scope, such as a method body or a bare block. |
| `switch` | none | A switch statement. |
| `case` | none | A switch case or default label. |
| `label` | none | A labeled statement target. |
| `goto` | none | A goto statement. |
| `break` | none | A break statement. |
| `continue` | none | A continue statement. |

Each language adapter supports a subset of kinds. A query that names an unsupported
kind for a language returns an `incomplete` diagnostic for that language. See
[language support](/reference/languages/) for the kinds each language supports,
and [Rune IR](/rune-ir/) for the per-language mappings.

A semantic-pack rule with a `language_construct` trigger also accepts these 43
kind labels as its `construct` value. The trigger compares the node's recorded
kind for equality and does not include subtypes: `callable` does not match a
`function` node, and `literal` does not match a `string_literal` node. See
[semantic-pack reference](/reference/semantic-packs/) for the trigger and its
other construct labels.

## Roles

A role is a named edge from a matched node to a sub-node. The pattern's kind must be
one of the role's valid parent kinds. A broad kind such as `declaration` accepts the
roles of its subtypes only where listed.

| Role | Value | RQL value | Valid parent kinds | Meaning |
| --- | --- | --- | --- | --- |
| `callee` | one pattern | pattern or `"name"` | `call`, `concurrent_spawn` | The call target name or expression. |
| `receiver` | one pattern | pattern or `"name"` | `call`, `concurrent_spawn` | The receiver or qualifying scope of a call. |
| `args` | ordered list | `[pattern ...]` | `call`, `concurrent_spawn` | Positional arguments, in order. |
| `kwargs` | name-to-pattern map | `[(name pattern) ...]` | `call`, `concurrent_spawn` | Named arguments, by argument name. At most 64 names, each at most 128 bytes. |
| `left` | one pattern | pattern or `"name"` | `assignment` | The assignment target. |
| `right` | one pattern | pattern or `"name"` | `assignment` | The assigned value. |
| `operator` | one pattern | pattern or `"name"` | `assignment` | The assignment operator token, as the grammar records it. |
| `module` | one pattern | pattern or `"name"` | `import`, `declaration` | The module an import names. |
| `decorators` | ordered list | `[pattern ...]` | `function`, `method`, `constructor`, `lambda`, `callable`, `class`, `parameter`, `declaration` | Decorators, annotations, or attributes, in order. |
| `object` | one pattern | pattern or `"name"` | `field_access` | The object side of a member access. |
| `field` | one pattern | pattern or `"name"` | `field_access` | The member name side of a member access. |
| `iterable` | one pattern | pattern or `"name"` | `for_loop` | The expression a for-each loop iterates. |
| `elements` | ordered list | `[pattern ...]` | `collection_literal` | The elements of a collection literal, in order. |
| `tag` | one pattern | pattern or `"name"` | `jsx_element` | The tag expression of a JSX element. |
| `attributes` | ordered list | `[pattern ...]` | `jsx_element` | The attributes of a JSX element, in source order. |
| `children` | ordered list | `[pattern ...]` | `jsx_element` | The children of a JSX element, in source order. |
| `value` | one pattern | pattern or `"name"` | `jsx_attribute`, `jsx_spread_attribute`, `object_property`, `computed_property`, `spread_element` | The value expression of an attribute, property, or spread. |
| `key` | one pattern | pattern or `"name"` | `object_property` | The static key of an object property. |

An ordered-list role needs each listed pattern to match a different edge, in source
order. The matches need not be adjacent, and the list does not fix the total count.
Use `arity` for an exact count. Each list holds at most 64 patterns.

## Steps

Each step consumes one row domain and produces another. A pipeline is valid when each
step accepts the domain the previous step produced. In RQL, a step is a wrapper form
around the query it consumes, and inner forms run first. In JSON, a step is an object
in `steps` with `op` set to the step name and its options as sibling fields.

The tables below list every step. "Options" gives JSON field names; the RQL keywords
are in [Step options](#step-options).

### Row operations

| JSON `op` | RQL form | Input -> output | Options | Meaning |
| --- | --- | --- | --- | --- |
| `filter` | `filter` | any row -> same row | `where` (required) | Keep rows for which every typed predicate holds. |
| `project` | `project` | any row -> projected row | `columns` (required) | Publish selected fields, optionally renamed, to later `filter` and `project` steps and to relational policy bindings. |
| `anchor` | `anchor` | `structural_match` -> `structural_match` | `capture` (required) | Emit one row for each distinct node bound to the named positive capture, using that node's source range as the reported location while retaining the structural root for matching and later steps. |
| `statement_facts` | `statement-facts`, `statement_facts` | `structural_match` -> `structural_match` | `statement_fact_kind` (required) | Retain structural matches for one registered CodeQL statement fact. C/C++-only kinds return no matches for other languages; `nested-loops-with-same-variable` is supplied by both C++ and C#. Supported kinds are `alloca-in-loop`, `complex-block`, `complex-condition`, `empty-block`, `long-switch`, `missing-case-in-switch`, `nested-loops-with-same-variable`, and `use-of-goto`. |
| `cpp_facts` | `cpp-facts`, `cpp_facts` | `structural_match` -> `structural_match` | `kind` (required) | Retain C++ class, special-member, catch, throw, or inheritance matches for one registered CodeQL parity fact. Supported kinds are `assignment-does-not-return-this`, `catch-by-value`, `constructor-delegation`, `constructor-used-as-copy-constructor`, `rule-of-three`, `rule-of-two`, `throwing-pointer`, and `undisciplined-multiple-inheritance`. |

After `project`, only `filter` and `project` may follow. In `query_code` output, a
projected row still renders as its source row. See
[Row predicates and projections](#row-predicates-and-projections).

### Declarations, files, and imports

| JSON `op` | RQL form | Input -> output | Options | Meaning |
| --- | --- | --- | --- | --- |
| `enclosing_decl` | `enclosing-decl` | `structural_match` or `dispatch_target` -> `declaration` | none | The smallest real indexed declaration that contains the match or dispatch call site. |
| `file_of` | `file-of` | most row domains -> `file` | none | The workspace file that holds the row. Accepted inputs are listed below this table. |
| `imports_of` | `imports-of` | `file` -> `file` | none | Project files that the input file's resolved imports point to. For Rust, this includes the file that defines an item reached through `pub use` re-exports. |
| `importers_of` | `importers-of` | `file` -> `file` | none | Project files whose resolved imports point to the input file. For Rust, a file that reaches an item in the input file through `pub use` re-exports is an importer. |
| `python_import_site` | `python-import-site` | `structural_match` -> `structural_match` | none | Add parser-derived Python import leaves, local target resolution, scope, duplicate, exact `except ImportError` handler context, self-import, and `__all__` facts. |
| `python_import_cycles` | `python-import-cycles` | `structural_match` -> `structural_match` | none | Mark Python import sites with a confirmed cycle in the persisted workspace file graph; unresolved targets and absent paths remain incomplete. |
| `python_commented_out_code` | `python-commented-out-code` | `structural_match` -> `python_rule_fact` | none | Return one source-spanned row for each Python commented-out-code block recognized from tree-sitter comment nodes. Rows retain exact comment lines and text; CodeQL-style example-heavy, documentation-like, filler, path, URL, doctest, and end-of-line exclusions apply. |

`python_import_cycles` also adds the typed row field `python_import_cycle_state`
with values `cyclic` and `incomplete`. A missing path is incomplete because the
workspace graph does not prove the absence of external or dynamic imports, and
path-derived package identity may be unresolved.

`python_import_site` also adds the optional Boolean field
`python_import_duplicate`. It is true for a later namespace `import`
that repeats the same parsed module and local binding in this file. It is
absent when the import does not meet that selector. The existing
`python_import_repeated` field remains broader: it marks each member of a
same-module group, including the first import and `from` imports.

`python_import_site` also adds the optional Boolean field
`python_import_in_import_error_handler`. It is true when the import is in a
handler whose exception type resolves to the builtin `ImportError`, false when
the parsed context proves it is outside such a handler, and absent when parser
or exception identity information is incomplete. The import-site `complete`
field is false when this context cannot be established, so policies that
exclude compatibility imports should require `python_import_in_import_error_handler`
to equal false.

`python_import_site` also adds the optional Boolean field
`python_import_in_main_guard`. It is true when the import is contained by an
AST `if __name__ == "__main__"` (including the reversed comparison), false
when the parsed import is outside such a guard, and absent when import-site
context could not be read. Cycle policies can exclude main-guard imports by
requiring this field to equal false.

`python_commented_out_code` emits only classified blocks. Its
`python_rule_fact.range` spans the block, `comment_block_text` stores the exact
source slice, and `comment_block_lines` stores each physical line within that
slice, including blank lines between comments.

`file_of` accepts: `structural_match`, `declaration`, `procedure`, `program_point`,
`control_edge`, `typestate_finding`, `typestate_witness`,
`flow_endpoint`, `flow_witness`, `class_set_row`, `absent_member_finding`,
`absent_member_witness`, `taint_finding`, `reference_site`, `call_site`,
`expression_site`, `jsx_attribute_value`, `receiver_analysis`,
`member_target_analysis`, `keyed_read_value`, `receiver_outcome`, `receiver_evidence`,
`field_write_value`, `call_shape`, `call_result`, `result_subject_use`,
`call_argument_group`, `call_argument`, `call_binding`, `call_effect`,
`call_result_contract`, `call_result_obligation`, `result_contract_use`,
`result_contract_failure_use`, `procedure_effect`, `callable_signature`,
`signature_parameter`, `decorated_parameter`, `callable_applicability`,
`overload_selection`, `member_selection`, `dispatch_outcome`, `dispatch_target`,
`member_family`, `member_family_edge`, `python_hierarchy_fact`, `occurrence`, `lexical_scope`, `binding`,
`qualified_path`, `path_segment`, `state_event`, `branch_relation`, `cpp_expression`, `loop_relation`,
`failure_handler_state`, and `statement_reachability`.

### Type hierarchy and members

| JSON `op` | RQL form | Input -> output | Options | Meaning |
| --- | --- | --- | --- | --- |
| `supertypes` | `supertypes` | `declaration` -> `declaration` | `depth` or `transitive` | Indexed supertypes: direct by default, up to `depth` hops, or the full closure. |
| `subtypes` | `subtypes` | `declaration` -> `declaration` | `depth` or `transitive` | Indexed subtypes: direct by default, up to `depth` hops, or the full closure. |
| `members` | `members` | `declaration` -> `declaration` | none | Direct indexed members of a type. |
| `owner` | `owner` | `declaration` -> `declaration` | none | The exact indexed type that declares a member. |
| `member_family` | `member-family`, `member_family` | `declaration` -> `member_family` | none | One method-family outcome row per member: the family ID when proven, otherwise a typed reason. |
| `family_edges` | `family-edges`, `family_edges` | `declaration` -> `member_family_edge` | none | Proven `overrides` and `implements` edges of a member, plus their inverses `overridden_by` and `implemented_by`. |
| `python_override_signatures` | `python-override-signatures`, `python_override_signatures` | `declaration` -> `python_hierarchy_fact` | none | C3-selected Python override paired with each source and target callable-signature entry, including stable signature IDs, arity, and coverage. |

### References and calls

| JSON `op` | RQL form | Input -> output | Options | Meaning |
| --- | --- | --- | --- | --- |
| `references_of` | `references-of` | `declaration` -> `reference_site` | `reference_kinds`, `proof`, `surface` | Resolved source sites that refer to the declaration. |
| `used_by` | `used-by` | `declaration` -> `declaration` | `reference_kinds`, `proof`, `surface` | Declarations that contain references to the input. |
| `uses` | `uses` | `declaration` -> `declaration` | `reference_kinds`, `proof`, `surface` | Declarations that the input refers to. |
| `callers` | `callers` | `declaration` -> `declaration` | `depth`, `proof`, `completeness` | Callers through resolved incoming call edges, direct or up to `depth` hops. |
| `callees` | `callees` | `declaration` -> `declaration` | `depth`, `proof`, `completeness` (only `exhaustive`) | Callees through resolved outgoing call edges, direct or up to `depth` hops. |
| `call_sites_to` | `call-sites-to`, `call_sites_to` | `declaration` -> `call_site` | `proof` | Call sites whose resolved callee is the declaration. |
| `call_sites_from` | `call-sites-from`, `call_sites_from` | `declaration` -> `call_site` | `proof` | Call sites written inside the declaration. |
| `call_input` | `call-input`, `call_input` | `call_site` -> `expression_site` | exactly one of `receiver`, `parameter_index`, `parameter_name` | The receiver expression, or the argument bound to one formal parameter. |

### Reference edges

| JSON `op` | RQL form | Input -> output | Options | Meaning |
| --- | --- | --- | --- | --- |
| `edges_of` | `edges-of`, `edges_of` | `declaration` -> `reference_edge` | `reference_kinds`, `proof`, `surface`, `usage`, `relation`, `site_class` | Inverse edges: every usage site the usage index lists for the declaration. |
| `edges_from` | `edges-from`, `edges_from` | `occurrence` -> `reference_edge` | same six options | Forward edges: the targets the resolver chose for that exact token. |
| `edge_target` | `edge-target`, `edge_target` | `reference_edge` -> `declaration` | none | The exact indexed target declaration of an edge. |

### Occurrences, scopes, bindings, and resolution

| JSON `op` | RQL form | Input -> output | Options | Meaning |
| --- | --- | --- | --- | --- |
| `occurrences_of` | `occurrences-of`, `occurrences_of` | `declaration` -> `occurrence` | `class`, `role`, `namespace` | The declaration's name occurrence plus every reference occurrence that resolves to it. |
| `occurrences_in` | `occurrences-in`, `occurrences_in` | `structural_match`, `lexical_scope`, or `file` -> `occurrence` | `class`, `role`, `namespace` | Classified identifier occurrences inside the match or file, or whose exact innermost scope is the supplied lexical scope. |
| `occurrence_target` | `occurrence-target`, `occurrence_target` | `occurrence` -> `declaration` | none | The declarations that a reference occurrence resolved to. |
| `scope_of` | `scope-of`, `scope_of` | `binding`, `occurrence`, or `structural_match` -> `lexical_scope` | none | The innermost lexical scope that owns the input. |
| `scope_ancestors` | `scope-ancestors`, `scope_ancestors` | `lexical_scope` -> `lexical_scope` | none | The enclosing scopes, innermost first, without the scope itself. |
| `bindings_in` | `bindings-in`, `bindings_in` | `lexical_scope` or `structural_match` -> `binding` | `kind`, `name`, `hoisting` | Bindings declared in the scope, or in the scopes inside the match. |
| `binding_of` | `binding-of`, `binding_of` | `occurrence` -> `binding` | `include_shadowed` | The binding of the occurrence's name that is in effect at its exact position. |
| `binding_occurrence` | `binding-occurrence`, `binding_occurrence` | `binding` -> `occurrence` | none | The binder occurrence of the binding's declaring token. |
| `binding_uses` | `binding-uses`, `binding_uses` | `binding` -> `occurrence` | none | Reference occurrences whose exact lexical `binding_of` result is the input binding, joined from per-file occurrence and binding facts at query time. |
| `python_variable_of` | `python-variable-of`, `python_variable_of` | `binding` or `occurrence` -> `python_rule_fact` | none | Map one Python binder or identifier to the query-local variable grouped by its resolved lexical scope and name; `global` and `nonlocal` declarations redirect to their owning scope. |
| `python_variable_definitions` | `python-variable-definitions`, `python_variable_definitions` | `python_rule_fact` -> `python_rule_fact` | none | Return the source-ordered definitions of a lexical-variable row, with kind, first-definition status, and reachability. |
| `python_variable_uses` | `python-variable-uses`, `python_variable_uses` | `python_rule_fact` -> `python_rule_fact` | none | Return the reads and writes of a lexical-variable row, including closure reads from nested scopes. |
| `python_variable_peers` | `python-variable-peers`, `python_variable_peers` | `python_rule_fact` -> `python_rule_fact` | none | Return same-name lexical variables from other scopes in the same file, with module-definition exclusion facts. |
| `python_variable_nested_loops` | `python-variable-nested-loops`, `python_variable_nested_loops` | `python_rule_fact` -> `python_rule_fact` | none | Return nested `for` loops targeting one lexical variable, with outer-use and post-inner-loop reuse facts. Reuse requires a later read in the same statement block with no intervening definition; an unconditional write in the inner loop body prevents the reuse fact. |
| `identical_operands` | `identical-operands`, `identical_operands` | `structural_match` -> `structural_match` | none | Python pairwise comparisons whose bare names share an exact binding, or whose static attribute paths share member names and root binding; unresolved supported bindings make the query incomplete. |
| `python_missing_self` | `python-missing-self`, `python_missing_self` | `structural_match` -> `structural_match` | none | Python method comparisons of the same bare name without a local binding or explicit scope directive, when a same-class `self.<name>` access resolves `self` to a method parameter. |
| `candidates_of` | `candidates-of`, `candidates_of` | `occurrence` -> `resolution_candidate` | `tier`, `outcome`, `boundary` | Every candidate the resolver considered for a reference occurrence. |
| `candidate_hierarchy` | `candidate-hierarchy`, `candidate_hierarchy` | `occurrence` -> `candidate_hop` | none | The hierarchy hops through which each traced member candidate was found. |
| `candidate_target` | `candidate-target`, `candidate_target` | `resolution_candidate` -> `declaration` | none | The workspace declaration of a unit-backed candidate. Other candidates produce no row. |
| `member_selection` | `member-selection`, `member_selection` | `occurrence` -> `member_selection` | none | One member-selection summary row per reference occurrence, from the resolver's candidate trace. |
| `callable_applicability` | `callable-applicability`, `callable_applicability` | `occurrence` -> `callable_applicability` | none | One row per candidate callable the resolver considered, with its applicability verdict and rejection reason. |
| `overload_selection` | `overload-selection`, `overload_selection` | `occurrence` -> `overload_selection` | none | One overload-selection summary per reference occurrence: `resolved_unique`, `ambiguous`, `unresolved`, or `unknown_shape`. |

### Qualified paths

| JSON `op` | RQL form | Input -> output | Options | Meaning |
| --- | --- | --- | --- | --- |
| `segments_of` | `segments-of`, `segments_of` | `qualified_path` -> `path_segment` | `resolved` | The ordered segments of a path, with decoded text and spelled generic arity. With `resolved`, each segment also carries its own resolution. |
| `segment_target` | `segment-target`, `segment_target` | `path_segment` -> `declaration` | none | The workspace declarations that one segment resolves to. |

### Receivers and dispatch

| JSON `op` | RQL form | Input -> output | Options | Meaning |
| --- | --- | --- | --- | --- |
| `receiver_targets` | `receiver-targets`, `receiver_targets` | `structural_match`, `reference_site`, `call_site`, `expression_site`, or `occurrence` -> `receiver_analysis` | `capture` | Analyze the receiver value of a call or member site, within bounds. |
| `points_to` | `points-to`, `points_to` | `structural_match`, `reference_site`, `expression_site`, or `occurrence` -> `receiver_analysis` | `capture` | Analyze where an expression's value comes from, within bounds. |
| `member_targets` | `member-targets`, `member_targets` | `structural_match`, `reference_site`, or `occurrence` -> `member_target_analysis` | `capture` | Resolve the exact static member, with the receiver owner and model provenance. |
| `receiver_outcome` | `receiver-outcome`, `receiver_outcome` | `structural_match`, `reference_site`, `call_site`, `expression_site`, `occurrence`, `receiver_analysis`, or `member_target_analysis` -> `receiver_outcome` | none | Exactly one terminal outcome row per analyzed site. |
| `receiver_evidence` | `receiver-evidence`, `receiver_evidence` | `structural_match`, `reference_site`, `call_site`, `expression_site`, `occurrence`, or `receiver_analysis` -> `receiver_evidence` | none | Zero or more parent-linked evidence rows per analyzed site. |
| `dispatch_outcome` | `dispatch-outcome`, `dispatch_outcome` | `structural_match`, `call_site`, `reference_site`, or `occurrence` -> `dispatch_outcome` | none | Exactly one bounded-dispatch outcome row per site, with coverage and target count. |
| `dispatch_targets` | `dispatch-targets`, `dispatch_targets` | `structural_match`, `call_site`, `reference_site`, or `occurrence` -> `dispatch_target` | none | One row per retained dispatch candidate, and per boundary arm that names a target. |

`receiver_evidence` does not accept `member_target_analysis` rows.

### Call shape, bindings, and signatures

| JSON `op` | RQL form | Input -> output | Options | Meaning |
| --- | --- | --- | --- | --- |
| `call_shape` | `call-shape`, `call_shape` | `structural_match`, `call_site`, or `occurrence` -> `call_shape` | none | Exactly one structured call-shape row per call site, with the decoded callee token and written argument count. |
| `call_results` | `call-results`, `call_results` | `call_shape` -> `call_result` | none | The ordered normal result values of the semantic call. |
| `call_argument_groups` | `call-argument-groups`, `call_argument_groups` | `call_shape` -> `call_argument_group` | none | The ordered argument-list groups of a call. |
| `call_arguments` | `call-arguments`, `call_arguments` | `call_argument_group` -> `call_argument` | none | The ordered arguments of one argument-list group. |
| `call_bindings` | `call-bindings`, `call_bindings` | `call_shape` -> `call_binding` | none | Actual-to-formal binding rows, plus rows for the receiver, implicit arguments, defaulted formals, and Python required formals definitely left unbound. Unknown Python keywords have a distinct reason. At least one row per call. |
| `resolved_call` | `resolved-call`, `resolved_call` | `call_binding` -> `call_binding` | `resolves_to` and `call_proof` (both required), `receiver_type` | Keep binding rows whose call resolves to one callable identity with `exact` or `declared` proof. |
| `resolved_value` | `resolved-value`, `resolved_value` | `call_binding` or Python `structural_match` -> same row | `resolves_to` and exact `call_proof` (both required) | Keep a bound call actual or Python decorator expression only when the bounded resolver proves the requested exact declaration identity. Unresolved, ambiguous, shadowed, unsupported, or budget-limited values make the query incomplete. |
| `call_argument` | `call-argument`, `call_argument` | `call_binding` -> `call_binding` | exactly one of `formal_name`, `formal_index` | Keep the source argument bound to one formal parameter, with exact mapping and exhaustive coverage. |
| `cpp_bad_strncpy_size` | `cpp-bad-strncpy-size`, `cpp_bad_strncpy_size` | `call_binding` -> `call_binding` | none | Keep a call-binding row when structured fixed-array extents prove that a `strncpy` source is larger than its destination and the policy has already selected the exact declared library identity. |
| `cpp_network_to_host_function_as_array_bound` | `cpp-network-to-host-function-as-array-bound`, `cpp_network_to_host_function_as_array_bound` | `call_binding` -> `call_binding` | none | Keep a call-binding row when structured syntax proves a direct `ntohl` result is passed as the `memcpy` bound after exact declared call selection. |
| `callable_signature` | `callable-signature`, `callable_signature` | `declaration` -> `callable_signature` | none | One row per persisted signature of a declaration; an overload set gives one row per overload. Python special methods additionally carry their query-time protocol arity verdict and placeholder status. |
| `signature_parameters` | `signature-parameters`, `signature_parameters` | `callable_signature` -> `signature_parameter` | none | The ordered declared parameters of a signature. |
| `decorator_bindings` | `decorator-bindings`, `decorator_bindings` | `structural_match` -> `decorated_parameter` | `module`, `imported_name` | One row for each decorator applied to a matched parameter. |

### C++ typed expression facts

| JSON `op` | RQL form | Input -> output | Options | Meaning |
| --- | --- | --- | --- | --- |
| `cpp_expressions` | `cpp-expressions`, `cpp_expressions` | `structural_match` -> `cpp_expression` | none | Project occurrence-keyed C++ literal, array-parameter, function-parameter, bit-field, enum, function-signature, loop-variable, and `sizeof` facts from the selected AST range. Scalar values that the source does not prove remain null, and `completeness` is `open` with a reason when the row is partial. |

The relation is intentionally source-backed and query-lifetime. It does not claim
ABI layout, overload resolution, conversion range, or cross-file constant identity.
For example, `signedness: ambiguous` means the declaration uses a plain integral
spelling whose signedness is implementation-defined; it is not a claim that the
field is signed. The stable row fields include `kind`, `type_form`, `signedness`,
`width_bits`, `literal_text`, `integer_value`, array and bit-field properties,
enum initializer properties, top-level return/member `const` properties, and
`sizeof_operand_kind`/`sizeof_operand_is_parameter`/`sizeof_has_side_effect`,
member classification, exact source-derived parameter size when available, enum
implicit-initializer context, and nested short-loop context.

### Effects and result contracts

| JSON `op` | RQL form | Input -> output | Options | Meaning |
| --- | --- | --- | --- | --- |
| `call_effects` | `call-effects`, `call_effects` | `call_shape` -> `call_effect` | none | One row per dispatch arm and declared effect from an active semantic pack. At least one row per call. |
| `procedure_effects` | `procedure-effects`, `procedure_effects` | `declaration` -> `procedure_effect` | none | One row per procedure and effect over its reachable call graph, direct or transitive, with coverage. |
| `result_contract_calls` | `result-contract-calls`, `result_contract_calls` | `call_shape` -> `call_shape` | none | Keep calls whose every dispatch arm selects a reviewed result contract. |
| `call_result_contracts` | `call-result-contracts`, `call_result_contracts` | `call_shape` -> `call_result_contract` | none | Reviewed validity contracts for a call's normal results. At least one row per call. |
| `call_result_obligations` | `call-result-obligations`, `call_result_obligations` | `call_shape` -> `call_result_obligation` | none | Java result-use and return-use obligations from the selected JDK model. |
| `result_contract_uses` | `result-contract-uses`, `result_contract_uses` | `call_result_contract` -> `call_result_contract` | none | Add aggregate counts of operations on the protected result to each contract row. |
| `result_subject_uses` | `result-subject-uses`, `result_subject_uses` | `call_result` -> `result_subject_use` | none | Procedure-local uses of a call result as a receiver. |
| `result_contract_operation_uses` | `result-contract-operation-uses`, `result_contract_operation_uses` | `call_result_contract` -> `result_contract_use` | none | One row per structured operation on a protected result, with a guard verdict. |
| `result_contract_failure_uses` | `result-contract-failure-uses`, `result_contract_failure_uses` | `call_result_contract` -> `result_contract_failure_use` | `provenance`, `consumer` | Values returned or passed to calls inside the failure arm of a conditional result contract. |

### Procedures, control flow, and branch and loop relations

| JSON `op` | RQL form | Input -> output | Options | Meaning |
| --- | --- | --- | --- | --- |
| `procedure_of` | `procedure-of`, `procedure_of` | `structural_match` or `declaration` -> `procedure` | none | The smallest source-backed executable procedure that contains the input. |
| `program_point_of` | `program-point-of`, `program_point_of` | `structural_match` -> `program_point` | none | The unique source-mapped point for a structural match. For `await`, this is its `AsyncSuspend`; no unique point reports incomplete. |
| `cfg_entry` | `cfg-entry`, `cfg_entry` | `procedure` -> `program_point` | none | The entry point of the procedure's control-flow graph. |
| `cfg_exits` | `cfg-exits`, `cfg_exits` | `procedure` -> `program_point` | none | The normal and exceptional exit points of the procedure. |
| `cfg_successor_edges` | `cfg-successor-edges`, `cfg_successor_edges` | `program_point` -> `control_edge` | none | Outgoing control edges, one hop. |
| `cfg_predecessor_edges` | `cfg-predecessor-edges`, `cfg_predecessor_edges` | `program_point` -> `control_edge` | none | Incoming control edges, one hop. |
| `cfg_edge_source` | `cfg-edge-source`, `cfg_edge_source` | `control_edge` -> `program_point` | none | The source point of an edge. |
| `cfg_edge_target` | `cfg-edge-target`, `cfg_edge_target` | `control_edge` -> `program_point` | none | The target point of an edge. |
| `control_relations` | `control-relations`, `control_relations` | `procedure` -> `control_relation` | `control_relation`, `exit_partition` | Dominance, postdominance, control dependence, entry reachability, and loop membership between program points. |
| `guards_of` | `guards-of`, `guards_of` | `procedure` -> `guard` | none | The normalized branch conditions the adapter recorded, with their true and false successor edges. |
| `branch_relations` | `branch-relations`, `branch_relations` | `structural_match` -> `branch_relation` | `branch_relation` | Compare the ordered arms of one `if` match: identical bodies, repeated or contradictory conditions, and similar relations. |
| `cpp_expressions` | `cpp-expressions`, `cpp_expressions` | `structural_match` -> `cpp_expression` | none | Project typed, occurrence-keyed C++ expression facts from the selected source range. |
| `cpp_inconsistent_loop_direction` | `cpp-inconsistent-loop-direction`, `cpp_inconsistent_loop_direction` | `structural_match` -> `structural_match` | none | Keep a C/C++ `for` match when its structured condition direction and update direction disagree for the same loop variable. |
| `cpp_unsafe_array_for_days_of_the_year` | `cpp-leap-year-unsafe-array-for-days-of-the-year`, `cpp_unsafe_array_for_days_of_the_year` | `structural_match` -> `structural_match` | none | Keep a C/C++ numeric-literal match when the structured literal `365` is a fixed array or vector-constructor extent. |
| `cpp_provenance` | `cpp-provenance`, `cpp_provenance` | `structural_match` -> `structural_match` | `cpp_provenance_rule` | Filter a C/C++ return, assignment, or call anchor through one direct procedure-local provenance rule. The source-backed terminal anchor is preserved; unresolved aliases and call identities remain incomplete. |
| `loop_relations` | `loop-relations`, `loop_relations` | `procedure` -> `loop_relation` | none | For a Java loop, prove whether its body can reach its own repeat edge before it exits. |
| `statement_reachability` | `statement-reachability`, `statement_reachability` | `procedure` -> `statement_reachability` | none | For Java statements, report whether bounded entry reachability reaches any of the statement's control-flow entries. |
| `switch_coverage` | `switch-coverage`, `switch_coverage` | `procedure` -> `switch_coverage` | none | One coverage verdict per switch: exhaustive, non-exhaustive, or unknown. |
| `failure_handler_state` | `failure-handler-state`, `failure_handler_state` | `structural_match` -> `failure_handler_state` | none | Classify a catch, except, or rescue body as empty, nonempty, or unknown. |

### Flow, state, taint, and typestate

| JSON `op` | RQL form | Input -> output | Options | Meaning |
| --- | --- | --- | --- | --- |
| `state_events_of` | `state-events-of`, `state_events_of` | `procedure` or `declaration` -> `state_event` | `event_class`, `subject` | Establish, kill, and read events of bindings and properties, placed on the control-flow graph. |
| `flow_relations_of` | `flow-relations-of`, `flow_relations_of` | `state_event` or `procedure` -> `flow_relation` | `flow_relation`, `certainty` | Reaching, dominance, and same-evaluation relations between state events. |
| `flow_source` | `flow-source`, `flow_source` | `flow_relation` -> `state_event` | none | The establish or kill end of a relation. |
| `flow_target` | `flow-target`, `flow_target` | `flow_relation` -> `state_event` | none | The read end of a relation. |
| `value_flow` | `value-flow`, `value_flow` | `procedure` -> `flow_endpoint` | `plan_ref` (required) | Run one host-registered value-flow plan for the exact procedure. |
| `taint` | `taint` | `procedure` -> `taint_finding` | `taint_ref` (required) | Project the findings of one host-registered production taint result for the exact procedure. |
| `typestate` | `typestate` | `procedure` -> `typestate_finding` | `protocol_ref` (required) | Run one host-registered typestate protocol for the exact procedure. |
| `witness` | `witness` | `typestate_finding`, `flow_endpoint`, or `absent_member_finding` -> `typestate_witness`, `flow_witness`, or `absent_member_witness` | `max_steps`, `max_bytes` | Project the retained evidence of each finding without running the analysis again. |
| `class_set` | `class-set`, `class_set` | `procedure` -> `class_set_row` | none | For each member access reachable from the procedure, the classes its receiver may hold. |
| `python_iterator_return_protocol` | `python-iterator-return-protocol`, `python_iterator_return_protocol` | `procedure` -> `python_rule_fact` | none | For each value returned by a Python `__iter__`, classify its bounded runtime classes by whether they declare inherited `__iter__` and `__next__`; expose exact direct receiver returns as `returns_receiver`; unresolved or incomplete class sets stay open. |
| `absent_member` | `absent-member`, `absent_member` | `procedure` -> `absent_member_finding` | `finding_proof` | Member accesses where a class reaches the site and lacks the member; Proven requires a fully known receiver set, while Conditional admits only the documented receiver, value-flow, and write remainders. |
| `nilness_operations` | `nilness-operations`, `nilness_operations` | `procedure` -> `nilness_operation` | none | Pointer operations with their procedure-local nilness fact. Go only; other languages yield no rows and an incomplete `unsupported_structural_feature` diagnostic. |
| `assignment_relations` | `assignment-relations`, `assignment_relations` | `procedure` -> `assignment_relation` | `assignment_relation` | Self-assignments, local self-initializers, failed swaps, and overwritten-unread assignments. The bounded `self_initializer` slice currently supports C/C++ local declarations; other relation coverage is language-specific and reports `effect_derivation_incomplete` when unsupported. |
| `detached_task_transfers` | `detached-task-transfers`, `detached_task_transfers` | `procedure` -> `detached_task_transfer` | none | Values copied into calls that run detached in a different task. |

### Values

| JSON `op` | RQL form | Input -> output | Options | Meaning |
| --- | --- | --- | --- | --- |
| `python_builtin_identity` | `python-builtin-identity`, `python_builtin_identity` | `occurrence` -> `python_rule_fact` | none | Resolve an unqualified Python builtin reference using its exact lexical binding. A local or module shadow is partial; missing or wildcard-import evidence stays open. For a proven direct call callee, the result also has `call_callee=true`. |
| `python_uninitialized_variable` | `python-uninitialized-variable`, `python_uninitialized_variable` | `occurrence` -> `python_rule_fact` | none | Join an exact Python value reference to its lexical binding and procedure-local CFG read. Emit a finding only for a complete may-be-uninitialized answer; globals, class scopes, builtins, closures and open flow identities stay incomplete. |
| `python_assertion_context` | `python-assertion-context`, `python_assertion_context` | `structural_match` -> `python_rule_fact` | none | Add tri-state `test_scope` and `terminal_elif_else` fields to the shared Python rule-fact row for one assertion. Unresolved unittest inheritance remains `unknown`. |
| `tuple_return_assignment` | `tuple-return-assignment`, `tuple_return_assignment` | `structural_match` -> `python_rule_fact` | none | Resolve a direct local call assigned to a tuple or list and compare its exact distinct return arities with the direct assignment target count. |
| `python_implicit_string_concatenation` | `python-implicit-string-concatenation`, `python_implicit_string_concatenation` | `structural_match` -> `python_rule_fact` | none | Emit one anchored row for every literal part implicitly concatenated inside a list element. |
| `python_format_issues` | `python-format-issues`, `python_format_issues` | `structural_match` -> `python_rule_fact` | none | Inspect exact Python `str.format` calls and `%` binary expressions for five brace-format and three percent-format issues. Format values and supported single-initializer aliases are resolved structurally; unsupported or ambiguous shapes remain partial. |
| `python_url_construction` | `python-url-construction`, `python_url_construction` | `structural_match` -> `python_rule_fact` | none | Project typed per-slot full or partial URL-control facts for Python `+`, f-strings, `%` formatting, and literal `str.format` construction. Unknown format strings and operands remain incomplete. |
| `python_raise_not_implemented` | `python-raise-not-implemented`, `python_raise_not_implemented` | `structural_match` -> `python_rule_fact` | none | Identify direct, call-form, or one-step aliased raises of the builtin `NotImplemented` singleton. A shadow is partial, unresolved identity is open, and `NotImplementedError` is distinct and excluded. |
| `jsx_attribute_value` | `jsx-attribute-value`, `jsx_attribute_value` | `structural_match` -> `jsx_attribute_value` | `identity`, `element_name`, `property_name` | The exact expression of a JSX attribute value, with the element's intrinsic, component, or unknown identity. |
| `keyed_read_value` | `keyed-read-value`, `keyed_read_value` | `structural_match` -> `keyed_read_value` | `runtime`, `global`, `container` (all required); one of `property`, `index`, `key_kind`; `index_min`, `index_max`, `source_origin` | A keyed read of a runtime input container, such as `process.env.HOME` or `sys.argv[1]`, resolved to its value. |
| `field_write_value` | `field-write-value`, `field_write_value` | `member_target_analysis` -> `field_write_value` | `receiver_identity_id`, `member_target_id` | The right-hand expression of a simple field assignment whose member and receiver `member_targets` proved. |

Configuration facts are a seed source, not a step. See
[Seed source filters](#seed-source-filters).

### Build topology

| JSON `op` | RQL form | Input -> output | Options | Meaning |
| --- | --- | --- | --- | --- |
| `target_of` | `target-of`, `target_of` | `file` -> `build_target` | none | The build target that the workspace's build files assign the file to. |
| `source_set_of` | `source-set-of`, `source_set_of` | `file` -> `source_set` | none | The declared source set that contains the file, with the build file that defines it. |
| `topology_edges_of` | `topology-edges-of`, `topology_edges_of` | `build_target` -> `topology_edge` | none | Dependencies that a build target declares on other targets in the workspace. |

These steps read Maven `pom.xml` files only. Each `pom.xml` declares one build
target with the source sets `main` (`src/main`) and `test` (`src/test`) in its
directory. A dependency edge links two targets of the same workspace and
carries the Maven scope.

- A workspace without a readable Maven build, including a Gradle-only
  workspace, returns `topology_derivation_incomplete`. So does a reactor that
  lists a module whose `pom.xml` is missing.
- A file that two source sets claim returns no row and a
  `topology_ownership_ambiguous` diagnostic.
- A file that no build file claims, in a fully read build, returns no row and
  no diagnostic.

### Materialization

| JSON `op` | RQL form | Input -> output | Options | Meaning |
| --- | --- | --- | --- | --- |
| `generates` | `generates` | `generation_site` -> `declaration_state` | none | The state rows of the declarations a generation site creates. |
| `generated_by` | `generated-by`, `generated_by` | `declaration` or `declaration_state` -> `generation_site` | none | The generation site that created a generated declaration. |
| `declaration_state_of` | `declaration-state-of`, `declaration_state_of` | `declaration` -> `declaration_state` | `origin`, `declaration_only`, `config_gated` | The state row of a declaration: origin, declaration-only flag, and configuration gate. |
| `implementation_of` | `implementation-of`, `implementation_of` | `declaration_state` or `declaration` -> `declaration` | none | The runnable implementation that a declaration-only signature links to. |
| `stubs_of` | `stubs-of`, `stubs_of` | `declaration` -> `declaration_state` | none | The declaration-only stubs whose implementation link resolves to the declaration. |
| `export_target` | `export-target`, `export_target` | `export` -> `declaration` | none | The declaration an export row created, where the analyzer models one. |

### Rewrite paths

| JSON `op` | RQL form | Input -> output | Options | Meaning |
| --- | --- | --- | --- | --- |
| `rewrite_paths_of` | `rewrite-paths-of`, `rewrite_paths_of` | `file` -> `rewrite_path` | `domain`, `rewrite_outcome` | The bounded rewrite chases the file takes part in, with ordered steps, the declared bound, and the outcome. |

## Step options

Options are written before the nested query in RQL, for example
`(callers :depth 2 :proof proven QUERY)`.

| JSON field | RQL keyword | Steps | Required | Value | Default |
| --- | --- | --- | --- | --- | --- |
| `where` | `:where` | `filter` | yes | 1 to 16 row predicates | none |
| `columns` | `:columns` | `project` | yes | 1 to 32 columns | none |
| `depth` | `:depth` | `supertypes`, `subtypes`, `callers`, `callees` | no | positive integer | direct (one hop) |
| `transitive` | `:transitive` | `supertypes`, `subtypes` | no | `true` only; not with `depth` | direct |
| `reference_kinds` | `:reference-kinds` | `references_of`, `used_by`, `uses`, `edges_of`, `edges_from` | no | non-empty list of [reference kinds](#references-and-edges) | every kind, including unclassified hits |
| `proof` | `:proof` | `references_of`, `used_by`, `uses`, `edges_of`, `edges_from`, `callers`, `callees`, `call_sites_to`, `call_sites_from` | no | `proven` or `unproven` | both |
| `surface` | `:surface` | `references_of`, `used_by`, `uses`, `edges_of`, `edges_from` | no | `external_usages` or `lsp_references` | `external_usages` for the reference steps; no default for the edge steps |
| `completeness` | `:completeness` | `callers`, `callees` | no | `exhaustive` or `proven_subset`; `proven_subset` only on `callers` with `proof` `proven` | `exhaustive` |
| `receiver` | `:receiver` | `call_input` | one selector | `true` | none |
| `parameter_index` | `:parameter-index` | `call_input` | one selector | zero-based index, excluding receiver-bound parameters | none |
| `parameter_name` | `:parameter-name` | `call_input` | one selector | declared parameter name, 1 to 128 bytes | none |
| `capture` | `:capture` | `anchor` (required); `receiver_targets`, `points_to`, `member_targets` (optional) | depends on the step | a declared positive capture name, 1 to 128 bytes; only after a structural match | each distinct captured node's source range for `anchor`; the receiver, member, or value derived from the match for the receiver steps |
| `protocol_ref` | `:protocol-ref` | `typestate` | yes | `namespace:name` | none |
| `plan_ref` | `:plan-ref`, `:plan_ref` | `value_flow` | yes | `namespace:name` | none |
| `taint_ref` | `:taint-ref`, `:taint_ref` | `taint` | yes | `namespace:name` | none |
| `max_steps` | `:max-steps` | `witness` | no | non-negative integer; only lowers host limits | host limit |
| `max_bytes` | `:max-bytes` | `witness` | no | non-negative integer; only lowers host limits | host limit |
| `finding_proof` | `:proof` | `absent_member` | no | `proven`, `conditional`, or `any` | `proven` |
| `class` | `:class`, `:classes` | `occurrences_of`, `occurrences_in` | no | [occurrence classes](#occurrences) | every class |
| `role` | `:role`, `:roles` | `occurrences_of`, `occurrences_in` | no | [occurrence roles](#occurrences) | every role |
| `namespace` | `:namespace`, `:namespaces` | `occurrences_of`, `occurrences_in` | no | [namespaces](#occurrences) | every namespace |
| `kind` | `:kind`, `:kinds` | `bindings_in` | no | [binding kinds](#lexical-environment) | every kind |
| `name` | `:name`, `:names` | `bindings_in` | no | exact names, at most 256 bytes each | every name |
| `hoisting` | `:hoisting` | `bindings_in` | no | [hoisting classes](#lexical-environment) | every class |
| `include_shadowed` | `:include-shadowed`, `:include_shadowed` | `binding_of` | no | `true` | only the winning binding |
| `tier` | `:tier`, `:tiers` | `candidates_of` | no | [precedence tiers](#lexical-environment) or `unattributed` | every tier |
| `outcome` | `:outcome`, `:outcomes` | `candidates_of` | no | `selected`, `rejected`, or a [rejection reason](#lexical-environment) | every outcome |
| `boundary` | `:boundary`, `:boundaries` | `candidates_of` | no | [boundary statuses](#lexical-environment) | every status |
| `usage` | `:usage` | `edges_of`, `edges_from` | no | [usage kinds](#references-and-edges) | every usage kind |
| `relation` | `:relation` | `edges_of`, `edges_from` | no | [owner relations](#references-and-edges) | every relation |
| `site_class` | `:site-class` | `edges_of`, `edges_from` | no | `use_site` or `declaration_site` | both |
| `resolved` | `:resolved` | `segments_of` | no | `true` | no segment resolution |
| `event_class` | `:class`, `:classes` | `state_events_of` | no | `establish`, `kill`, `read` | every class |
| `subject` | `:subject`, `:subjects` | `state_events_of` | no | `binding`, `property` | both |
| `flow_relation` | `:relation`, `:relations` | `flow_relations_of` | no | `reaching`, `dominates`, `same_evaluation` | every relation |
| `certainty` | `:certainty`, `:certainties` | `flow_relations_of` | no | `exact`, `may` | both |
| `control_relation` | `:relation`, `:relations` | `control_relations` | no | [control relations](#control-and-branch-relations) | every relation |
| `exit_partition` | `:exit-partition`, `:exit_partition`, `:exit-partitions` | `control_relations` | no | [exit partitions](#control-and-branch-relations) | every partition |
| `branch_relation` | `:relation`, `:relations` | `branch_relations` | no | [branch relations](#control-and-branch-relations) | every relation |
| `assignment_relation` | `:relation`, `:relations` | `assignment_relations` | no | `self_assignment`, `self_initializer`, `failed_swap`, `overwritten_unread` | `self_assignment` only |
| `cpp_provenance_rule` | `:rule`, `:rules` | `cpp_provenance` | no | `incorrect_pointer_scaling_char`, `return_stack_allocated_memory`, `stack_address_escape`, `suspicious_pointer_scaling`, `suspicious_pointer_scaling_void`, `improper_null_termination` | every rule |
| `provenance` | `:provenance`, `:provenances` | `result_contract_failure_uses` | no | [failure-use provenance](#effects-and-contracts) | every class |
| `consumer` | `:consumer`, `:consumers` | `result_contract_failure_uses` | no | [failure-use consumers](#effects-and-contracts) | every class |
| `domain` | `:domain`, `:domains` | `rewrite_paths_of` | no | `rust_import_alias` | every domain |
| `rewrite_outcome` | `:outcome`, `:outcomes` | `rewrite_paths_of` | no | `converged`, `cycle`, `exceeded_budget` | every outcome |
| `origin` | `:origin`, `:origins` | `declaration_state_of` | no | `parsed`, `generated`, `recovered` | every origin |
| `declaration_only` | `:declaration-only`, `:declaration_only` | `declaration_state_of` | no | `true` or `false` | both |
| `config_gated` | `:config-gated`, `:config_gated` | `declaration_state_of` | no | `true` or `false` | both |
| `identity` | `:identity` | `jsx_attribute_value` | no | `intrinsic`, `component`, `unknown` | every identity |
| `element_name` | `:element-name`, `:element_name` | `jsx_attribute_value` | no | exact unqualified tag name | every element |
| `property_name` | `:property-name`, `:property_name` | `jsx_attribute_value` | no | exact attribute or property name | every property |
| `runtime` | `:runtime` | `keyed_read_value` | yes | [runtime roots](#runtime-keyed-reads) | none |
| `global` | `:global` | `keyed_read_value` | yes | [runtime roots](#runtime-keyed-reads) | none |
| `container` | `:container` | `keyed_read_value` | yes | [runtime roots](#runtime-keyed-reads) | none |
| `property` | `:property` | `keyed_read_value` | one selector | exact static property key; containers `env`, `environ` | none |
| `index` | `:index` | `keyed_read_value` | one selector | exact non-negative index; container `argv` | none |
| `key_kind` | `:key-kind`, `:key_kind` | `keyed_read_value` | one selector | `static-property` or `static-index` | none |
| `index_min` | `:index-min`, `:index_min` | `keyed_read_value` | no | non-negative integer; with `key_kind` `static-index` | open |
| `index_max` | `:index-max`, `:index_max` | `keyed_read_value` | no | non-negative integer; with `key_kind` `static-index` | open |
| `source_origin` | `:source-origin`, `:source_origin` | `keyed_read_value` | no | `pristine_input` | no origin constraint |
| `receiver_identity_id` | `:receiver-identity-id`, `:receiver_identity_id` | `field_write_value` | no | exact stable ID | every receiver |
| `member_target_id` | `:member-target-id`, `:member_target_id` | `field_write_value` | no | exact stable ID | every member |
| `module` | `:module` | `decorator_bindings` | no | exact imported module, at most 4096 bytes | every module |
| `imported_name` | `:imported-name`, `:imported_name` | `decorator_bindings` | no | exact imported symbol name, at most 4096 bytes | every name |
| `resolves_to` | `:resolves-to`, `:resolves_to` | `resolved_call`, `resolved_value` | yes | [call identity](#patterns-and-calls) | none |
| `call_proof` | `:proof` | `resolved_call`, `resolved_value` | yes | `exact` or `declared` for calls; `resolved_value` requires `exact` | none |
| `receiver_type` | `:receiver-type`, `:receiver_type` | `resolved_call` | no | a call identity, or `(assignable-to IDENTITY)` | every receiver |
| `formal_name` | `:formal-name`, `:formal_name` | `call_argument` | one selector | declared formal name, 1 to 128 bytes | none |
| `formal_index` | `:formal-index`, `:formal_index` | `call_argument` | one selector | zero-based formal index | none |

### How RQL spells option values

Two rules decide how an RQL option value is written:

- These options take a vector `[...]`, even for one value, and accept `-` in place of
  `_` in each label: `:reference-kinds`, `:usage`, `:relation` (on every step that has
  it), `:site-class`, `:class` and `:subject` on `state-events-of`, `:certainty`,
  `:exit-partition`, `:provenance`, `:consumer`, `:domain`, and `:outcome` on
  `rewrite-paths-of`. The single-value options `:proof`, `:surface`, and `:completeness` also
  accept `-` for `_`. `:key-kind` (JSON `key_kind`) accepts both `static-property` and
  `static_property`, and both `static-index` and `static_index`.
- All other filter options take one bare label or a vector, and the label must be
  spelled exactly as listed, with underscores. This covers the occurrence, scope,
  binding, candidate, declaration-state, generation-site, export, and configuration
  filters. Configuration `:format` and `:role` are exceptions: `:format` accepts the
  format aliases, and `:role` accepts `-` for `_`.

## Row predicates and projections

`filter` and `project` read the public row schema of their input domain. Print the
schemas with `bifrost --list-row-schemas`.

| Item | JSON | RQL |
| --- | --- | --- |
| Predicate | `{ "field": F, "op": OP, "value": V }` | `(F OP V)` |
| Set predicate | `{ "field": F, "op": "in", "values": [V, ...] }` | `(F in [V ...])` |
| Null test | `{ "field": F, "op": "is_null" }` | `(F is-null)` |
| Comparison operators | `eq`, `ne`, `lt`, `le`, `gt`, `ge` | same |
| String regex | `regex` | same |
| Null operators | `is_null`, `is_not_null` | `is-null`, `is-not-null` |
| String literal | `{ "string": "x" }` | `"x"` |
| Integer-list literal | `{ "integer_list": [2, 3] }` | `(2 3)` |
| Integer literal | `{ "integer": 3 }` | `3` |
| Boolean literal | `{ "boolean": true }` | `true` or `false` |
| Enum literal | `{ "enum": "reference" }` | a bare label such as `reference`, or `(enum true)` when the label would otherwise read as a boolean |
| Second field | `{ "field": "OTHER" }` | `(field OTHER)` |
| Column | `{ "source": F, "name": NEW }` | `F` or `(F NEW)` |

Rules:

- A filter has 1 to 16 predicates. An `in` set has 1 to 64 literals.
- Ordered comparison (`lt`, `le`, `gt`, `ge`) is defined only for integer fields.
- `regex` is defined only for string-valued fields and uses the bounded Rust regular-expression syntax.
- A comparison with a second field needs both fields to have the same scalar type.
- A comparison with an absent nullable field is false, including `ne`. Use `is_null`
  to select absence. A null test on a field that is not nullable is rejected.
- Bare RQL labels are checked against the field's published enum labels.
- A projection has 1 to 32 columns with unique output names. Field names are at most
  256 bytes. Later steps see only the projected names.

## Constrained value labels

### Languages

`languages` and RQL `language` accept these labels:

| Label | Language | Other accepted spellings |
| --- | --- | --- |
| `java` | Java | none |
| `go` | Go | none |
| `cpp` | C and C++ | `c++`, `c`, `cc`, `cxx`, `h`, `hin`, `hpp`, `hh`, `hxx` |
| `javascript` | JavaScript, including JSX | `js`, `mjs`, `cjs`, `jsx` |
| `typescript` | TypeScript, including TSX | `ts`, `tsx` |
| `python` | Python | `py` |
| `rust` | Rust | `rs` |
| `php` | PHP | none |
| `scala` | Scala | none |
| `csharp` | C# | `c#`, `cs` |
| `ruby` | Ruby | `rb` |
| `kotlin` | Kotlin | `kt`, `kts` |
| `jvm` | family: `java`, `kotlin`, `scala` | none |
| `js-ts` | family: `javascript`, `typescript` | none |

Concrete labels ignore case, surrounding spaces, a leading `.`, and the
characters `-` and `_`. Family names must be written exactly as `jvm` or
`js-ts`. A family expands to its members, and duplicates are removed. A list
holds at most 32 entries, and an unknown label is an error.

An extension selects its whole language. `c` and `h` select every `cpp` file,
both C and C++, and `tsx` selects every `typescript` file. To restrict a query
to C files, add a `where` glob such as `**/*.c`. No query infers a language
from the workspace. See [language support](/reference/languages/)
for what each language supports.

### Patterns and calls

| Axis | Labels |
| --- | --- |
| `visibility` | `public`, `protected`, `internal`, `package_private`, `private`, `crate_or_module`, `unknown`. `unknown` means the adapter looked and could not classify; it never equals `public`. |
| `result_detail` | `compact`, `full` |
| `execution_mode` | `results`, `explain`, `profile` |
| call identity (`resolves_to`, `receiver_type`) | JSON object with exactly one key: `stable`, `qualified`, `workspace_declaration`, or `active_semantic_model`. In RQL, an unquoted value is a `stable` ID and a quoted value is a `qualified` locator. Qualified locators resolve only when a policy is loaded; a standalone query with one is invalid. |
| `receiver_type` family | JSON `{ "assignable_to": IDENTITY, "resolved_identities": [...] }`; RQL `(assignable-to IDENTITY)`. Matches the named workspace type and every subtype in its complete typed hierarchy. |

### Occurrences

Occurrence classes: `declaration`, `reference`, `binding`, `non_reference`. The class
follows from the role:

| Role | Class | Meaning |
| --- | --- | --- |
| `declaration_name` | `declaration` | The name token of a declaration head. |
| `binder` | `binding` | A binding introduction: parameter, local, pattern binder, loop variable, or catch variable. |
| `label_or_key` | `non_reference` | A label, keyword-argument name, or map-key position. |
| `type_operand` | `reference` | An identifier used as a type: annotation, generic argument, or extends or implements operand. |
| `path_segment` | `reference` | A non-final segment of a qualified path or scoped name. |
| `import_alias` | `non_reference` | The local alias that an import or export introduces. |
| `import_target` | `reference` | The imported or exported source name. |
| `receiver_position` | `reference` | The receiver of a member access or call. |
| `member_position` | `reference` | The member name in a member access or call. |
| `pattern_position` | `reference` | A non-binding identifier inside a pattern, such as a matched constant. |
| `generated_source` | `non_reference` | A token that generates declarations elsewhere, such as an accessor macro argument. |
| `value_reference` | `reference` | A plain read or write of a value in expression position. |
| `global_directive` | `non_reference` | A name declared by a Python `global` statement. |
| `nonlocal_directive` | `non_reference` | A name declared by a Python `nonlocal` statement. |

Namespaces: `type`, `value`, `module`, `macro`, `label`, `path_prefix`. `path_prefix`
is the namespace of a qualifier that may name a module or a type, which lookup
decides.

### Lexical environment

Python's `python-variable-of` relation adds a query-local variable identity over
the existing per-token binding rows. A `lexical_variable` row groups all
definitions and uses with the same name in its resolved module, function, class,
or comprehension scope. Explicit `global` and `nonlocal` declarations redirect
the group to the module or enclosing function that owns the name. Its
`variable_id` is stable for the file content and resolved scope; `scope_kind`,
`is_global`, and `is_nonlocal` describe the owning scope and redirection.

Use `python-variable-definitions` and `python-variable-uses` on a
`lexical_variable` row to inspect it. Definition rows are ordered by
`definition_order`; `first_definition` marks the earliest one. `definition_kind`
distinguishes assignments, parameters, loop targets, imports, augmented writes,
deletions, `with` and `except` targets, function/class declarations, and pattern
targets. `reachability` is `reachable`, `unreachable`, or `open`. Use rows have
`access_kind` (`read` or `write`) and `nested_scope`, which marks an access to
the variable from a nested scope such as a closure. These facts are derived
from the selected file's AST for the query and do not change persisted binding
rows. Variable rows also expose `is_builtin` and `has_read`; definition rows
expose `definition_is_unused`, `annotation_only`, `annotated_assignment`,
`is_decorated`, `is_abstract`, `is_overriding_method`, and
`is_overridden_method` for scoped policy queries. `annotated_assignment` marks
an assignment target with a type annotation, including assignments that also
provide a value.

The Python tutorial's [lexical variable example](/code-query-tutorials/python/#lexical-variables)
shows the variable, definition, use, and same-name peer steps together.

| Axis | Labels |
| --- | --- |
| binding `kind` | `local`, `parameter`, `pattern_binder`, `loop_variable`, `catch_or_resource`, `import_binder`, `type_parameter` |
| `hoisting` | `source_order` (in effect from its activation point to the end of the scope), `scope_wide` (in effect for the whole scope), `declared_head` (in effect only within a range the adapter states, such as a match arm) |
| `python_rule_fact.relation` for variables | `lexical_variable`, `lexical_variable_definition`, `lexical_variable_use`, `lexical_variable_peer`, `nested_loop_same_variable` |
| Python variable `scope_kind` | `module`, `function`, `class`, `comprehension` |
| Python variable `definition_kind` | `assignment`, `parameter`, `loop_target`, `import`, `augmented`, `del`, `with_target`, `except_target`, `function_declaration`, `class_declaration`, `pattern_target` |
| Python variable `reachability` | `reachable`, `unreachable`, `open` |
| Python variable `access_kind` | `read`, `write` |
| Python variable peer `related_scope_kind` | `module`, `function`, `class`, `comprehension` |
| Python variable definition facts | `definition_is_unused`, `annotation_only`, `annotated_assignment`, `is_decorated`, `is_abstract`, `is_overriding_method`, `is_overridden_method` |
| Python variable identity facts | `is_builtin`, `has_read`, `is_global`, `is_nonlocal` |
| Python variable definition exclusion fields | `in_main_guard`, `optimizing_parameter`, `self_assignment` |
| Python variable peer exclusion fields | `related_has_definition_outside_main`, `related_has_deletion`, `related_has_import`, `related_is_pytest_fixture` |
| Python nested-loop fields | `nested_loop_has_outer_use`, `nested_loop_reused` |
| candidate `tier`, strongest first | `lexical_binding`, `own_member`, `inherited_member`, `explicit_import`, `package_or_module`, `wildcard_import`, `external_root`, `name_only_fallback`; the filter also accepts `unattributed` for rows with no tier |
| candidate `outcome` | `selected`, `rejected`, and the rejection reasons `shadowed_by_nearer`, `not_in_scope_at_position`, `wrong_namespace`, `not_visible`, `wrong_declaration_space`, `ambiguous_peer`, `boundary_blocked`, `hidden_by_closer_member`, `callable_applicability_deferred` |
| candidate `boundary` | `workspace_local`, `external_indexed`, `external_declared_unindexed` (the build declares the dependency but nothing indexed it), `external_unknown` |

### References and edges

| Axis | Labels |
| --- | --- |
| `reference_kinds` | `method_call`, `constructor_call`, `field_read`, `field_write`, `type_reference`, `self_type_alias` (a reference through a `Self`-style type alias), `static_reference`, `super_call`, `inheritance` |
| `proof` | `proven`, `unproven` |
| `surface` | `external_usages`, `lsp_references` |
| `completeness` | `exhaustive`, `proven_subset` |
| edge `usage` | `reference`, `import`, `reexport`, `self_receiver`, `definition`, `override_declaration`. Edge rows can also carry `declared_reference`, which the filter does not accept. |
| edge `relation` (owner relation) | `same_owner`, `inherited_owner`, `self_reference`, `external`, `unknown`. `unknown` never equals `external`. |
| edge `site_class` | `use_site`, `declaration_site` |

### Control and branch relations

| Axis | Labels |
| --- | --- |
| `control_relation` | `dominates`, `postdominates`, `control_depends_on`, `reachable`, `in_loop` |
| `exit_partition` | `normal_and_exceptional`, `normal_only`, `exceptional_only`, `with_cancellation`, `with_suspension` |
| `branch_relation` | `identical_bodies`, `repeated_condition`, `contradictory_condition`, `subsumed_condition`, `redundant_boolean_return` |
| `cpp_expression.kind` | `array_parameter`, `bit_field`, `enum_definition`, `enumerator`, `function_signature`, `integer_literal`, `string_literal`, `loop_variable`, `sizeof_expression` |
| `cpp_expression.type_form` | `builtin`, `named`, `pointer`, `reference`, `array`, `function`, `unknown` |
| `cpp_expression.signedness` | `signed`, `unsigned`, `ambiguous`, `unknown` |
| `cpp_expression.completeness` | `complete`, `open` |
| `assignment_relation` | `self_assignment`, `failed_swap`, `overwritten_unread` |
| `event_class` | `establish`, `kill`, `read` |
| `subject` | `binding`, `property` |
| `flow_relation` | `reaching`, `dominates`, `same_evaluation` |
| `certainty` | `exact`, `may` |
| rewrite `domain` | `rust_import_alias` |
| `rewrite_outcome` | `converged`, `cycle`, `exceeded_budget` |

### Effects and contracts

| Axis | Labels |
| --- | --- |
| failure-use `provenance` | `condition_result`, `distinct_zero_binding`, `distinct_binding`, `independent`, `unknown` |
| failure-use `consumer` | `return`, `returned_call_argument`, `call_argument` |
| `finding_proof` | `proven` (receiver set fully known), `conditional` (other receiver values may remain unknown; a listed global write is allowed only with no receiver bound and an Any name set; a declared parameter is allowed only for one annotated workspace class with no workspace subclass, unresolved or unmodeled external base, or dynamic-attribute hook), `any` |
| `call_proof` | `exact` (exact selector proof), `declared` (a complete declared semantic-model callable) |

### Materialization

| Axis | Labels |
| --- | --- |
| declaration `origin` | `parsed`, `generated` (created by a macro-like construct), `recovered` (rebuilt from a broken parse) |
| generation `kind` | `accessor_macro` (such as `attr_accessor`), `alias_macro` (such as `alias_method`), `preprocessor_definition` (a `#define`) |
| generation `input` | `literal`, `dynamic` (the generated names are unknown) |
| export `form` | `named`, `default_named`, `default_anonymous`, `common_js_root` (`module.exports = ...`), `common_js_member` (one property of a `module.exports` object), `python_all` (a literal member of module-level `__all__`) |

### Configuration facts

| Axis | Labels |
| --- | --- |
| `formats` | `yaml` (alias `yml`), `toml`, `json`, `xml`, `properties` (aliases `props`, `property`) |
| `node_kinds` | `document`, `object`, `section`, `sequence`, `member`, `scalar` |
| `roles` | `object_member`, `table_entry`, `property`, `xml_attribute`, `xml_element`. Result rows spell these with `-`, such as `object-member`. |
| `scalar_kinds` | `string`, `boolean`, `integer`, `decimal`, `null`, `url`, `duration`, `opaque` |
| `provenances` | `authored` |
| `completenesses` | `complete`, `incomplete` (from a partly recovered document) |

A route is an ordered list of segments. It has at most 64 segments. An empty route
selects the document fact.

| Segment | JSON | RQL |
| --- | --- | --- |
| key | `{ "kind": "key", "key": "server" }` | `(key "server")` |
| index | `{ "kind": "index", "ordinal": 0 }` | `(index 0)` |
| any one segment | `{ "kind": "any" }` | `(any)` |

`routes` holds route alternatives: JSON `[[segment, ...], ...]`, RQL
`:route [[(key "server") (index 0)]]`.

### Runtime keyed reads

`keyed_read_value` accepts exactly these `runtime`, `global`, and `container`
combinations. The container decides how its elements are addressed.

| `runtime` | `global` | `container` | Selector |
| --- | --- | --- | --- |
| `node` | `process` | `env` | `property`, or `key_kind` `static-property` |
| `node` | `process` | `argv` | `index`, or `key_kind` `static-index` with optional `index_min` and `index_max` |
| `python` | `os` | `environ` | `property`, or `key_kind` `static-property` |
| `python` | `sys` | `argv` | `index`, or `key_kind` `static-index` with optional `index_min` and `index_max` |

## Result types

Every result item has a `result_type`. It names the output domain of the last
step, or the source domain when there are no steps. There are 81 result types.

Every item can also carry two fields that are not listed in the table:

- `provenance`: the paths from the seed row through each step to this row.
- `provenance_truncated`: `true` when the row had more than 16 paths and some
  were left out.

The table lists the other top-level JSON fields of each result type. A field
in the last column is left out of the JSON when it has no value. With
`result_detail` `compact`, some identity and range fields are left out, such as
`id`, `ast_id`, and `node_range` on `structural_match` rows. Use
`result_detail` `full` to get them.

| `result_type` | Fields always present | Fields that can be absent or null |
| --- | --- | --- |
| `structural_match` | `end_line`, `kind`, `language`, `path`, `start_line`, `text` | `ast_id`, `captures`, `decorated_range`, `decorator_ranges`, `enclosing_symbol`, `id`, `node_range` |
| `declaration` | `end_line`, `fq_name`, `kind`, `language`, `path`, `start_line` | `id`, `node_range`, `semantic_model`, `signature`, `site_id` |
| `procedure` | `artifact_id`, `dialect`, `evidence`, `id`, `language`, `path`, `procedure_kind`, `range` | none |
| `program_point` | `event_count`, `evidence`, `id`, `language`, `path`, `procedure_id`, `range` | `boundary` |
| `control_edge` | `edge_kind`, `evidence`, `id`, `language`, `path`, `procedure_id`, `range`, `source`, `target` | none |
| `typestate_finding` | `analysis_complete`, `binding_plan_hash`, `certainty`, `finding_kind`, `id`, `language`, `omitted_witnesses`, `path`, `path_complete`, `path_proven`, `protocol_hash`, `protocol_ref`, `range`, `retained_witnesses`, `subject` | `abstained`, `uncertainty` |
| `typestate_witness` | `binding_plan_hash`, `evidence`, `finding_id`, `id`, `language`, `omitted_steps_lower_bound`, `path`, `protocol_hash`, `protocol_ref`, `range`, `retained_bytes`, `steps`, `subject`, `witness_index` | `abstained`, `alternatives_truncated`, `observed_state`, `retention_truncated`, `truncated`, `uncertainty` |
| `flow_endpoint` | `id`, `language`, `omitted_witnesses`, `path`, `plan_ref`, `range`, `reachability`, `retained_witnesses`, `sink`, `status` | `ambiguous`, `certainty`, `path_qualities`, `reason`, `source` |
| `flow_witness` | `endpoint_id`, `evidence`, `id`, `language`, `omitted_steps_lower_bound`, `path`, `plan_ref`, `range`, `retained_bytes`, `steps`, `witness_index` | `alternatives_truncated`, `retention_truncated`, `truncated` |
| `class_set_row` | `file`, `id`, `member`, `origin`, `range`, `status` | `class`, `guard_only` |
| `absent_member_finding` | `also_fails_at`, `caller`, `class`, `file`, `id`, `member`, `origin_file`, `origin_range`, `proof`, `range`, `remainders`, `witness_steps` | `condition` |
| `absent_member_witness` | `evidence`, `finding_id`, `id`, `language`, `omitted_steps_lower_bound`, `path`, `range`, `retained_bytes`, `steps`, `witness_index`, `witness_status` | `alternatives_truncated`, `retention_truncated`, `truncated`, `unavailable_reason` |
| `taint_finding` | `evidence`, `id`, `language`, `origins`, `path`, `range`, `reached_labels`, `sink`, `sink_event_id`, `witnesses` | `ambiguous`, `origins_truncated`, `witnesses_truncated` |
| `file` | `language`, `path` | `package_fq`, `package_syntactic` |
| `dependency_evidence` | `complete`, `conditions`, `ecosystem`, `end_byte`, `evidence_kind`, `id`, `package`, `path`, `scope`, `source_digest`, `start_byte` | `declared_by`, `exact_version`, `locator`, `range`, `source`, `version_requirement` |
| `configuration_fact` | `completeness`, `end_byte`, `fact_id`, `fact_provenance`, `format`, `id`, `node_kind`, `ordinal`, `path`, `range`, `route`, `start_byte` | `index`, `key`, `occurrence`, `parent_id`, `role`, `scalar_kind`, `value_id` |
| `reference_site` | `language`, `path`, `proof`, `range`, `target`, `usage_kind` | `enclosing_declaration`, `reference_kind` |
| `call_site` | `call_kind`, `callee`, `callee_range`, `caller`, `language`, `path`, `proof`, `range` | `arguments`, `receiver` |
| `expression_site` | `call_range`, `callee_fq_name`, `caller_fq_name`, `input_kind`, `language`, `path`, `range`, `text` | `parameter_index`, `parameter_name` |
| `jsx_attribute_value` | `ast_id`, `attribute_kind`, `coverage`, `element_identity`, `id`, `language`, `path`, `range`, `text` | `attribute_name`, `attribute_target`, `component`, `element_name`, `property_name`, `reason` |
| `receiver_analysis` | `analysis_kind`, `input_kind`, `language`, `outcome`, `path`, `range`, `site_id`, `text` | `capture`, `limit`, `member_targets`, `reason`, `site_ast_id`, `values` |
| `member_target_analysis` | `coverage`, `input_kind`, `language`, `outcome`, `path`, `range`, `site_id`, `text` | `capture`, `limit`, `member_range`, `member_targets`, `reason`, `site_ast_id` |
| `receiver_outcome` | `analysis_kind`, `candidate_count`, `candidates_truncated`, `coverage`, `id`, `language`, `outcome`, `path`, `range`, `scope_nodes`, `setup_nodes`, `site_id`, `summary_expansions` | `limit`, `reason`, `semantic_unsupported`, `site_ast_id` |
| `receiver_evidence` | `chain_hop`, `completeness`, `evidence_kind`, `id`, `ordinal`, `path`, `proof`, `range`, `site_id` | `declaration_fq_name`, `declaration_id`, `declaration_kind`, `factory_id`, `model_id`, `pack_id`, `parent_evidence_id`, `site_ast_id` |
| `points_to_candidate` | `candidate_index`, `completeness`, `coverage`, `id`, `language`, `path`, `proof`, `range`, `site_id` | `object_cardinality`, `object_id`, `program_point_id` |
| `field_write_value` | `assignment_ast_id`, `assignment_range`, `completeness`, `coverage`, `id`, `language`, `left_ast_id`, `member_ast_id`, `member_range`, `member_target`, `member_target_id`, `path`, `proof`, `range`, `receiver_ast_id`, `receiver_identity_id`, `receiver_range`, `rhs_ast_id`, `text`, `write_site_id` | none |
| `keyed_read_value` | `completeness`, `conclusive_exclusion`, `container`, `global`, `id`, `key_kind`, `language`, `outcome`, `path`, `proof`, `range`, `runtime`, `source_origin`, `terminal`, `text` | `active_model_set_hash`, `behavior_id`, `exposure_id`, `index`, `limitations`, `property`, `refinement_identity` |
| `call_shape` | `argument_count`, `call_kind`, `coverage`, `group_count`, `id`, `language`, `path`, `range`, `site_ast_id`, `site_id` | `callee_name`, `callee_range` |
| `call_result` | `call_id`, `completeness`, `id`, `language`, `ordinal`, `path`, `point_id`, `procedure_id`, `proof`, `range`, `site_ast_id`, `site_id`, `value_id` | none |
| `call_argument_group` | `argument_count`, `group_index`, `id`, `kind`, `path`, `range`, `site_id` | none |
| `call_argument` | `argument_index`, `group_id`, `id`, `path`, `range`, `site_id`, `spread` | `name` |
| `call_binding` | `actual_count`, `bound_count`, `conversion_status`, `coverage`, `dispatch_coverage`, `dispatch_outcome`, `dispatch_target_count`, `dispatch_targets_truncated`, `id`, `language`, `mapping`, `path`, `range`, `selector_exact`, `site_ast_id`, `site_id`, `terminal` | `actual_index`, `actual_name`, `argument_id`, `binding_kind`, `conversion`, `conversion_reason`, `declared_target_id`, `dispatch_completeness`, `dispatch_proof`, `formal_index`, `formal_layout_id`, `formal_name`, `group_id`, `model_activation_reason`, `model_activation_source_id`, `model_activation_source_kind`, `model_activation_status`, `model_active_set_hash`, `model_ambiguous`, `model_callable_id`, `model_completeness`, `model_id`, `model_origin`, `model_pack_digest`, `model_pack_version`, `model_producer`, `model_producer_version`, `model_proof`, `model_record_id`, `pack_id`, `reason`, `receiver_type_id`, `selector_proof`, `selector_summary_active_set_hash`, `selector_summary_completeness`, `selector_summary_id`, `selector_summary_model_id`, `selector_summary_model_proof`, `selector_summary_origin`, `selector_summary_pack_digest`, `selector_summary_pack_id`, `selector_summary_pack_version`, `selector_summary_producer`, `selector_summary_producer_version`, `selector_summary_record_id`, `semantic_target_id`, `signature_id`, `target`, `target_origin` |
| `call_effect` | `arm_count`, `classification`, `coverage`, `derivation`, `id`, `language`, `modeled_arm_count`, `path`, `range`, `site_ast_id`, `site_id`, `terminal` | `callee`, `callee_symbol`, `certainty`, `effect_id`, `execution_timing`, `model_id`, `pack_id`, `proof`, `reason`, `summary_id`, `target_id`, `timing` |
| `call_result_contract` | `arm_count`, `coverage`, `fresh_allocation`, `id`, `language`, `member_contract_count`, `modeled_arm_count`, `path`, `range`, `site_ast_id`, `site_id`, `success_guard_count`, `terminal` | `callee`, `callee_symbol`, `condition_result_ordinal`, `model_id`, `pack_id`, `predicate`, `proof`, `reason`, `result_ordinal`, `result_success_predicate`, `result_use_count`, `summary_id`, `target_id`, `unguarded_result_use_count`, `use_validation`, `use_validation_coverage` |
| `call_result_obligation` | `arm_count`, `coverage`, `id`, `language`, `modeled_arm_count`, `path`, `range`, `result_use`, `site_ast_id`, `site_id`, `terminal` | `failure_predicate`, `model_id`, `obligation_basis`, `obligation_kind`, `obligation_provenance`, `pack_id`, `reason`, `result_ordinal`, `result_use_detail`, `summary_id` |
| `result_subject_use` | `completeness`, `id`, `language`, `outcome`, `path`, `proof` | `artifact_id`, `conversion_witnesses`, `origin`, `procedure_id`, `reason`, `receiver_call_id`, `receiver_point_id`, `receiver_range`, `receiver_site_ast_id`, `receiver_site_id`, `subject_id`, `witness_event_ids` |
| `result_contract_use` | `acquisition_id`, `acquisition_site_ast_id`, `acquisition_site_id`, `applicability`, `coverage`, `guard`, `id`, `language`, `operation_point_id`, `path`, `range`, `result_ordinal`, `timing`, `use_kind` | `acquisition_predicate`, `ast_id`, `condition_result_ordinal`, `member`, `model_id`, `operation_site_ast_id`, `operation_site_id`, `pack_id`, `parameter_count`, `parameter_ordinal`, `required_predicate`, `result_success_predicate`, `summary_id` |
| `result_contract_failure_use` | `acquisition_id`, `acquisition_site_ast_id`, `acquisition_site_id`, `condition_result_ordinal`, `consumer`, `consumer_point_id`, `coverage`, `failure_provenance`, `id`, `language`, `operand_value_id`, `path`, `procedure_id`, `proof`, `range` | `argument_ordinal`, `ast_id`, `binding_value_id`, `condition_value_id`, `consumer_call_id`, `consumer_site_ast_id`, `consumer_site_id`, `establishment_point_id`, `establishment_value_id`, `failure_edge_id`, `model_id`, `pack_id`, `summary_id` |
| `nilness_operation` | `coverage`, `fact`, `id`, `language`, `operation_point_id`, `origin`, `path`, `procedure_id`, `proof`, `range`, `subject_value_id`, `use_kind` | `ast_id`, `reason` |
| `switch_coverage` | `case_count`, `default_present`, `has_false_case`, `has_true_case`, `id`, `kind`, `language`, `path`, `procedure_id`, `proof`, `range`, `selector_domain`, `switch_fact_id`, `verdict` | `ast_id`, `reason`, `selector_value_id` |
| `assignment_relation` | `coverage`, `id`, `language`, `path`, `procedure_id`, `proof`, `range`, `relation_kind`, `storage_kind`, `verdict` | `assignment_point_id`, `ast_id`, `reason`, `replacement_events`, `rhs_value_id`, `target_value_id` |
| `detached_task_transfer` | `call_id`, `call_point_id`, `coverage`, `id`, `language`, `path`, `procedure_id`, `proof`, `range`, `role`, `timing`, `value_id` | `ast_id`, `object_cardinality`, `object_id`, `ordinal`, `reason` |
| `procedure_effect` | `coverage`, `derivation`, `id`, `language`, `path`, `procedure_id`, `procedure_name`, `range`, `site_id`, `terminal`, `witness_available`, `witness_steps`, `witness_truncated` | `certainty`, `classification`, `depth`, `effect_id`, `execution_timing`, `model_id`, `pack_id`, `reason`, `summary_id`, `timing`, `witness_chain`, `witness_effect_site_id`, `witness_site_id` |
| `callable_signature` | `coverage`, `declaration`, `declaration_only`, `generic_arity`, `id`, `language`, `ordinal`, `parameter_count`, `path`, `range`, `repeated`, `role`, `site_id` | `label`, `receiver_contract`, `required_arity`, `return_type`, `special_method_expected_maximum`, `special_method_expected_minimum`, `special_method_reason`, `special_method_status`, `total_arity` |
| `signature_parameter` | `id`, `label`, `label_end_byte`, `label_start_byte`, `parameter_index`, `path`, `range`, `signature_id` | `declared_type`, `optional`, `repeated` |
| `decorated_parameter` | `binding_status`, `boundary`, `completion`, `coverage`, `decorator_name`, `decorator_range`, `id`, `language`, `parameter_id`, `path`, `range`, `terminal` | `annotation_status`, `annotation_type`, `decorator_id`, `imported_name`, `local_name`, `module`, `owner_id`, `parameter_ordinal`, `port_id`, `procedure_id`, `reason`, `value_id` |
| `callable_applicability` | `candidate`, `id`, `language`, `ordinal`, `path`, `range`, `selected`, `site_ast_id`, `verdict` | `reason`, `tier` |
| `overload_selection` | `applicable_count`, `considered_count`, `id`, `inapplicable_count`, `language`, `path`, `range`, `resolution`, `site_ast_id`, `supported`, `unknown_count` | none |
| `member_selection` | `candidate_count`, `coverage`, `id`, `language`, `member`, `outcome`, `path`, `range`, `role`, `selected_count`, `site_ast_id`, `trace_completeness` | none |
| `dispatch_outcome` | `call_site_count`, `coverage`, `id`, `language`, `outcome`, `path`, `range`, `site_id`, `target_count`, `targets_truncated` | `exceeded_limit`, `semantic_unsupported`, `site_ast_id` |
| `dispatch_target` | `completeness`, `coverage`, `dispatch`, `id`, `ordinal`, `path`, `proof`, `site_id`, `target_id`, `target_path` | `boundary_kind`, `site_ast_id`, `target_declaration`, `target_fq_name` |
| `member_family` | `capability`, `coverage`, `edge_count`, `id`, `implemented_by_count`, `implements_count`, `language`, `member_id`, `outcome`, `overridden_by_count`, `overrides_count`, `path`, `range`, `root_count` | `family_id`, `member`, `reason` |
| `member_family_edge` | `completeness`, `coverage`, `hierarchy_depth`, `id`, `member_id`, `ordinal`, `path`, `proof`, `range`, `relation`, `target_id` | `family_id`, `source`, `target` |
| `python_hierarchy_fact` | `coverage`, `fact_kind`, `id`, `language`, `outcome`, `path`, `range`, `root_id` | `base_branch_definition_count`, `base_resolution`, `base_spelling`, `declaration`, `declaration_id`, `has_non_strict_ordering`, `has_strict_ordering`, `inherited_ne_delegates`, `inherited_ne_present`, `member_name`, `mro_rank`, `ordinal`, `owner`, `owner_id`, `reason`, `root`, `root_declaration_id`, `source_repeated_arity`, `source_required_arity`, `source_signature_coverage`, `source_signature_id`, `source_signature_ordinal`, `source_total_arity`, `target`, `target_id`, `target_non_trivial`, `target_owner`, `target_owner_id`, `target_reads_self`, `target_repeated_arity`, `target_required_arity`, `target_signature_coverage`, `target_signature_id`, `target_signature_ordinal`, `target_total_arity`, `total_ordering_decorator` |
| `occurrence` | `ast_id`, `class`, `end_byte`, `id`, `language`, `namespace`, `path`, `range`, `raw_spelling`, `role`, `start_byte`, `target` | `decoded_spelling`, `enclosing_symbol` |
| `lexical_scope` | `end_byte`, `id`, `index`, `language`, `path`, `range`, `start_byte` | `ast_id`, `kind`, `parent_index` |
| `binding` | `activation_end_byte`, `activation_start_byte`, `declaring_scope_index`, `end_byte`, `hoisting`, `id`, `kind`, `language`, `name`, `namespace`, `path`, `range`, `source_order`, `start_byte`, `visibility` | `ast_id`, `import`, `reached_from_ast_id`, `shadowed` |
| `resolution_candidate` | `ast_id`, `boundary`, `candidate`, `end_byte`, `id`, `language`, `ordinal`, `outcome`, `path`, `range`, `start_byte`, `trace_completeness`, `visibility` | `applicability`, `canonical_member_id`, `dispatch_tier`, `external_target`, `hierarchy_depth`, `owner`, `rejection_reason`, `tier` |
| `candidate_hop` | `ast_id`, `candidate_id`, `end_byte`, `hop`, `id`, `language`, `path`, `range`, `relation`, `start_byte` | `from`, `to` |
| `generation_site` | `end_byte`, `generated`, `generated_count`, `id`, `input`, `kind`, `language`, `path`, `range`, `start_byte` | `ast_id` |
| `export` | `end_byte`, `exported_name`, `form`, `id`, `language`, `path`, `range`, `start_byte` | `ast_id`, `target_fq_name` |
| `declaration_state` | `config_gated`, `declaration_only`, `fq_name`, `id`, `language`, `origin`, `path`, `unit_kind` | `ast_id`, `end_byte`, `range`, `start_byte` |
| `reference_edge` | `edge_provenance`, `end_byte`, `generation`, `id`, `language`, `owner_relation`, `path`, `proof`, `range`, `site_class`, `start_byte`, `target`, `usage_kind` | `ast_id`, `enclosing_declaration`, `reference_kind` |
| `state_event` | `completeness`, `end_byte`, `event_class`, `generation`, `id`, `language`, `path`, `procedure_id`, `program_point`, `program_point_id`, `range`, `start_byte`, `subject`, `subject_value`, `value` | `ast_id`, `member`, `uncovered_axes` |
| `binding_initializer_call` | `end_byte`, `establishment_event_id`, `id`, `initializer_role`, `language`, `path`, `range`, `site_ast_id`, `start_byte` | none |
| `flow_relation` | `certainty`, `completeness`, `generation`, `id`, `language`, `path`, `procedure_id`, `range`, `relation`, `source`, `target` | `uncovered_axes` |
| `control_relation` | `certainty`, `completeness`, `exit_partition`, `generation`, `id`, `language`, `path`, `procedure_id`, `range`, `relation`, `source`, `target` | `controlling_edge_id`, `uncovered_relations` |
| `branch_relation` | `earlier_ordinal`, `earlier_range`, `id`, `language`, `later_ordinal`, `later_range`, `owner_id`, `owner_range`, `path`, `range`, `relation`, `verdict` | `orientation`, `reason` |
| `cpp_expression` | `completeness`, `id`, `kind`, `language`, `path`, `range`, `signedness`, `type_form` | `array_extent`, `array_is_reference`, `bit_field_anonymous`, `bit_field_width`, `completeness_reason`, `enum_has_implicit_before_nonreference`, `enum_ordinal`, `enum_scoped`, `enum_value`, `has_initializer`, `integer_value`, `literal_text`, `loop_has_short_ancestor`, `member_function`, `member_function_const`, `name`, `parameter_by_value`, `return_top_level_const`, `sizeof_has_side_effect`, `sizeof_operand_is_parameter`, `sizeof_operand_kind`, `type_size_bytes`, `type_size_exact`, `type_text`, `width_bits` |
| `loop_relation` | `id`, `language`, `loop_kind`, `path`, `procedure_id`, `range`, `verdict` | `body_range`, `reasons`, `repeat_edge_id` |
| `failure_handler_state` | `catch_ast_id`, `coverage`, `id`, `language`, `path`, `proof`, `range`, `verdict` | `body_range`, `reason` |
| `statement_reachability` | `id`, `language`, `path`, `procedure_id`, `range`, `statement_kind`, `verdict` | `reason` |
| `python_rule_fact` | `completeness`, `id`, `language`, `outcome`, `owner_id`, `path`, `proof`, `range`, `relation` | `access_kind`, `annotated`, `annotated_assignment`, `annotation_only`, `assignment_arity_match`, `assignment_target_count`, `callable_evaluation_time`, `comment_block_lines`, `comment_block_text`, `default_equivalent`, `definition_is_unused`, `definition_kind`, `definition_order`, `distinct_tuple_arities`, `exception_class`, `expected_exception`, `explicit_return_statements`, `explicit_value_returns`, `fallthrough_none_returns`, `first_definition`, `forwarded`, `has_read`, `in_main_guard`, `is_abstract`, `is_async`, `is_builtin`, `is_decorated`, `is_generator`, `is_global`, `is_nonlocal`, `is_overridden_method`, `is_overriding_method`, `loop_has_body_read`, `loop_policy_excluded`, `mixed_returns`, `mixed_tuple_arities`, `name`, `nested_loop_has_outer_use`, `nested_loop_reused`, `nested_scope`, `none_returns`, `operand_kind`, `optimizing_parameter`, `parameter_count`, `raised_expression`, `reachability`, `reason`, `related_has_definition_outside_main`, `related_has_deletion`, `related_has_import`, `related_is_pytest_fixture`, `related_scope_kind`, `result_use`, `return_contract`, `returns_receiver`, `scope_kind`, `self_assignment`, `target_id`, `terminal_elif_else`, `test_scope`, `tuple_return_arities`, `tuple_return_count`, `url_prefix`, `variable_id` |
| `guard` | `completeness`, `id`, `language`, `path`, `point`, `predicate`, `procedure_id`, `proof`, `range` | `classes_value`, `constant`, `constant_value`, `equality_negated`, `false_edge_id`, `false_target_id`, `guarded_value`, `integer_relation`, `member_value`, `null_on_true`, `null_target_id`, `opaque_digest`, `subject_value`, `true_edge_id`, `true_target_id` |
| `rewrite_path` | `completeness`, `declared_bound`, `domain`, `end_byte`, `generation`, `id`, `language`, `origin_specifier`, `outcome`, `path`, `range`, `start_byte`, `step_count`, `steps` | `explored`, `fixed_point`, `uncovered_domains`, `witness` |
| `qualified_path` | `ast_id`, `end_byte`, `id`, `language`, `path`, `range`, `segment_count`, `start_byte` | none |
| `path_segment` | `end_byte`, `id`, `language`, `ordinal`, `path`, `path_ast_id`, `range`, `start_byte`, `text` | `ast_id`, `generic_arity`, `namespace`, `resolution_status`, `target_count` |
| `source_set` | `build_file`, `completeness`, `id`, `name` | `target_id` |
| `build_target` | `build_file`, `completeness`, `id`, `name` | `build_project_id` |
| `topology_edge` | `build_file`, `completeness`, `from_id`, `from_name`, `id`, `scope`, `to_name` | `to_id` |
| `cross_domain` | `domain`, `id`, `operator`, `path` | `binding`, `code`, `code_id`, `code_path`, `configuration`, `configuration_contributors`, `configuration_id`, `configuration_path`, `dependency_id`, `effective_configuration`, `key`, `mapping_id`, `mitigated`, `owner`, `range`, `relation` |

On `call_result_obligation` items, `obligation_provenance` carries the native or
model origin. The typed row field selector `provenance` selects that origin;
the result item's `provenance` array carries query traversal evidence.

For Python special methods, `special_method_status` is `compatible`, `too_few`,
`too_many`, `required_optional_second`, `required_optional_third`,
`placeholder`, or `incomplete`. Expected positional bounds are adjusted for an
explicit `@staticmethod`; `special_method_reason` explains incomplete syntax
or signature evidence. A missing status means the declaration is not a
recognized Python special method. The field is filterable in RQL.

Python lifecycle rows expose `target_non_trivial` when the target body and its
control flow are complete: the target must have a normal exit and contain a
statement other than `pass`, its first docstring, or a same-name superclass
delegation. `target_reads_self` records whether an override directly reads its
receiver as an attribute object or call argument; unavailable binding or source
evidence leaves the field empty. Python MRO member rows expose
`base_branch_definition_count`, the number of distinct effective declarations
of that name across resolved direct-base branches; a shared declaration
reached through a diamond counts once. They also expose class-level
`has_strict_ordering` and `has_non_strict_ordering` booleans over the effective
C3 member set, plus `total_ordering_decorator`, which is true only for a
recognized `functools.total_ordering` import and absent when decorator identity
is uncertain. `inherited_ne_present` distinguishes inherited `__ne__`
declarations from Python's implicit equality delegation, while
`inherited_ne_delegates` is true only when every inherited declaration has a
recognized direct `not self.__eq__(other)` or equivalent comparison form. It
is false when any inherited declaration is known not to delegate and absent
when the declarations cannot be classified completely.
An explicit bare `object` base with no local or imported binding is a resolved
base fact without a `target` declaration; `class_mro` treats it as a leaf and
omits it, matching the implicit root case.
Iterator return rows expose `returns_receiver` as `true` for a direct return of
the first receiver parameter, `false` for another exact selected return
expression, and omit it when receiver identity is unresolved.

For C# `call_binding` rows, `conversion: "csharp_implicit_numeric"` currently
means only a proven `char` actual converted to an `int` formal. Other C# numeric
pairs require distinct conversion kinds and wire labels. When the adapter cannot
prove a pair, the row keeps `conversion_status: "unknown"` and its typed reason.

Two other sources describe result rows:

- `bifrost --list-row-schemas` prints the typed fields that `filter`,
  `project`, and relational policies read, with each field's scalar type,
  nullability, and enum labels. REPL `:doc DOMAIN` prints one domain. These
  row-schema fields are not the same as the JSON fields above. For example,
  the `structural_match` row schema has `id`, `ast_id`, `language`, and
  `kind`.
- The [Python client reference](/reference/python-client/) maps each
  `result_type` to its Python class.

## Diagnostics

A result carries a `diagnostics` array. Each diagnostic has a `code`, an `impact`, a
`language` (a language label, `workspace`, or `all`), a `message`, an optional
`branch` path inside a set operation, and, for exhausted work, an `exhausted_roots`
list that names each file, procedure, and budget lane that stopped.

### Impact

| Impact | Meaning for your conclusion |
| --- | --- |
| `invalid` | The query could not run as written. Treat the result as an error. |
| `incomplete` | Some work was skipped, unsupported, cut short, or cancelled. Positive rows remain valid, but an empty or short answer does not prove absence. |
| `declared_non_exhaustive` | The query asked for a proven subset (`callers` with `completeness` `proven_subset`). The rows are proven, but they are not all the answers. |
| `advisory` | Guidance only. It does not affect completeness. |

`truncated: true` also means the answer is not complete. Cancellation is reported as
the `cancelled` code with `incomplete` impact. See
[Agent Result Safety](/agent-result-safety/) for the full decision rule.

### Diagnostic codes

The impact column gives the impact that `query_code` uses for each code.

| Code | Impact | Meaning |
| --- | --- | --- |
| `invalid_plan` | `invalid` | The plan cannot run, for example a `resolved_call` with an unresolved qualified locator. |
| `cancelled` | `incomplete` | The query was cancelled; rows already produced are partial. |
| `unsupported_structural_feature` | `incomplete` | An adapter does not support a kind, role, or predicate the query uses, or did not record it. |
| `missing_structural_adapter` | `incomplete` | No structural or configuration adapter exists for some files. |
| `unsupported_import_analysis` | `incomplete` | A language has no structured import analysis; its files were left out of import steps. |
| `dynamic_import_target` | `incomplete` | An include/require target depends on runtime state, so its workspace file was left out of import traversal. |
| `semantic_results_omitted` | `incomplete` | Some inputs or rows were left out, for example because a provider returned no data or the workspace changed while the query ran. |
| `semantic_workspace_required` | `incomplete` | The step needs workspace-backed semantic services that this host does not provide. |
| `no_enclosing_procedure` | `advisory` | No source-backed procedure contains the input. |
| `semantic_capability_unsupported` | `incomplete` | A semantic capability the step needs is unsupported for the language. |
| `semantic_analysis_partial` | `incomplete` | Semantic analysis or document ingestion finished with partial evidence. |
| `call_binding_dispatch_partial` | `incomplete` | A call binding has an exact target and mapping, but no exact selector proof. |
| `call_binding_selector_rejected` | `incomplete` | `resolved_call` rejected every call-binding candidate it saw. |
| `semantic_budget_exhausted` | `incomplete` | A semantic budget lane ran out. |
| `semantic_provider_failed` | `incomplete` | The semantic provider failed. |
| `semantic_pack_acquisition_pending` | `incomplete` | A needed semantic pack is not available yet. |
| `unresolved_protocol_reference` | `incomplete` | No typestate protocol is registered under `protocol_ref`. |
| `typestate_registration_stale` | `incomplete` | The typestate registration belongs to another workspace generation. |
| `typestate_handle_stale` | `incomplete` | The typestate handle no longer matches the workspace. |
| `typestate_root_mismatch` | `incomplete` | The registration does not match this procedure root. |
| `typestate_capability_unsupported` | `incomplete` | Typestate analysis is unsupported here. |
| `typestate_analysis_partial` | `incomplete` | The typestate analysis abstained or finished with partial evidence. |
| `typestate_provider_failed` | `incomplete` | The typestate provider failed. |
| `typestate_solver_budget_exhausted` | `incomplete` | The typestate solver ran out of work budget. |
| `typestate_finding_budget_exhausted` | `incomplete` | The typestate finding budget ran out. |
| `typestate_witness_truncated` | `incomplete` | Typestate witness evidence was cut at a limit. |
| `unresolved_value_flow_plan_reference` | `incomplete` | No value-flow plan is registered under `plan_ref`. |
| `value_flow_registration_stale` | `incomplete` | The value-flow registration belongs to another workspace generation. |
| `value_flow_handle_stale` | `incomplete` | The value-flow handle no longer matches the workspace. |
| `value_flow_root_mismatch` | `incomplete` | The registration does not match this procedure root. |
| `value_flow_capability_unsupported` | `incomplete` | Value-flow analysis is unsupported here. |
| `value_flow_analysis_partial` | `incomplete` | Value-flow analysis finished with partial evidence. |
| `value_flow_provider_failed` | `incomplete` | The value-flow provider failed. |
| `value_flow_solver_budget_exhausted` | `incomplete` | The value-flow solver ran out of work budget. |
| `value_flow_witness_truncated` | `incomplete` | Value-flow witness evidence was cut at a limit. |
| `type_flow_witness_truncated` | `incomplete` | An absent-member witness was cut at a limit. |
| `type_flow_witness_unavailable` | `incomplete` | An absent-member witness could not be retained. |
| `unresolved_taint_result_reference` | `incomplete` | No taint result is registered under `taint_ref`. |
| `taint_registration_stale` | `incomplete` | The taint registration belongs to another workspace generation. |
| `taint_handle_stale` | `incomplete` | The taint handle no longer matches the workspace. |
| `taint_root_mismatch` | `incomplete` | The registration does not match this procedure root. |
| `taint_plan_report_mismatch` | `incomplete` | The registered taint plan and report do not match. |
| `taint_projection_failed` | `incomplete` | Projecting the registered taint result failed. |
| `taint_finding_truncated` | `incomplete` | Taint findings, origins, or witnesses were cut at a limit. |
| `receiver_analysis_partial` | `incomplete` | Receiver analysis returned rows with unsupported shapes or providers. |
| `receiver_analysis_failed` | `incomplete` | Receiver analysis failed. |
| `call_relation_budget_exhausted` | `incomplete` | Call traversal ran out of budget. |
| `call_relation_parse_failed` | `incomplete` | A file could not be parsed for call traversal. |
| `call_relation_candidates_omitted` | `incomplete`, or `declared_non_exhaustive` under `proven_subset` | Call candidates were left out, for example because a related declaration has no exact indexed range. |
| `call_relation_targets_ambiguous` | `advisory` | A call has more than one possible target. |
| `call_relation_candidate_limit` | `incomplete` | Call traversal reached its candidate limit. |
| `call_relation_analysis_failed` | `incomplete` | Call analysis failed. |
| `reference_source_bytes_truncated` | `incomplete` | Reference search reached its source-byte limit. |
| `reference_candidate_files_truncated` | `incomplete` | Reference search reached its candidate-file limit. |
| `reference_candidates_omitted` | `incomplete` | Reference candidates were left out. |
| `reference_targets_ambiguous` | `advisory` | A reference has more than one possible target. |
| `reference_callsite_limit` | `incomplete` | Reference search reached its call-site limit. |
| `reference_analysis_failed` | `incomplete` | Reference analysis failed. |
| `uses_parser_unsupported` | `incomplete` | `uses` cannot parse this language. |
| `uses_candidate_limit` | `incomplete` | `uses` reached its candidate limit. |
| `uses_targets_ambiguous` | `advisory` | A use has more than one possible target. |
| `uses_candidates_omitted` | `incomplete` | `uses` candidates were left out. |
| `execution_budget_exhausted` | `incomplete` | The query scan budget ran out (files, source bytes, or fact nodes). |
| `pipeline_budget_exhausted` | `incomplete` | The seed and edge row budget ran out. |
| `import_graph_budget_exhausted` | `incomplete` | The import graph budget ran out; import results are partial. |
| `occurrence_role_unsupported` | `incomplete` | An adapter does not classify an occurrence role or namespace the query names. |
| `occurrence_resolution_incomplete` | `incomplete` | Occurrence resolution did not finish. |
| `occurrence_row_budget_exhausted` | `incomplete` | The occurrence row budget ran out. |
| `environment_axis_unsupported` | `incomplete` | An adapter does not support a lexical-environment axis. |
| `materialization_axis_unsupported` | `incomplete` | An adapter does not support a materialization axis, such as `generation_sites` or `exports`. |
| `materialization_derivation_incomplete` | `incomplete` | Materialization rows could not be fully derived. |
| `materialization_row_budget_exhausted` | `incomplete` | The materialization row budget ran out. |
| `environment_derivation_incomplete` | `incomplete` | Scopes, bindings, or intervals could not be fully derived. |
| `environment_row_budget_exhausted` | `incomplete` | The lexical-environment or configuration row budget ran out. |
| `resolution_trace_incomplete` | `incomplete` | The resolver records only selected candidates, so a missing rejection row proves nothing. |
| `edge_axis_unsupported` | `incomplete` | An adapter does not support an edge projection, such as forward edges. |
| `edge_derivation_incomplete` | `incomplete` | Edge derivation was truncated, cancelled, or failed. |
| `flow_state_axis_unsupported` | `incomplete` | An adapter does not support a flow-state axis. |
| `flow_state_derivation_incomplete` | `incomplete` | State events or flow relations could not be fully derived. |
| `rewrite_domain_unsupported` | `incomplete` | A rewrite domain is unsupported here. |
| `rewrite_path_derivation_incomplete` | `incomplete` | Rewrite paths could not be fully derived. |
| `control_relation_derivation_incomplete` | `incomplete` | Control relations could not be fully derived. |
| `branch_relation_derivation_incomplete` | `incomplete` | Branch relations could not be fully derived. |
| `loop_relation_derivation_incomplete` | `incomplete` | Loop relations could not be fully derived. |
| `failure_handler_derivation_incomplete` | `incomplete` | A failure-handler body could not be classified. |
| `statement_reachability_derivation_incomplete` | `incomplete` | Statement reachability could not be fully derived. |
| `control_relation_exit_partition_partial` | `incomplete` | A control relation could not be computed for every exit partition. |
| `topology_derivation_incomplete` | `incomplete` | The build topology could not be fully read. |
| `topology_ownership_ambiguous` | `incomplete` | More than one declared source set claims a file. |
| `identity_axis_unsupported` | `incomplete` | An adapter does not support qualified-path identity axes. |
| `path_derivation_incomplete` | `incomplete` | Qualified paths, segments, or configuration routes could not be fully derived. |
| `effect_derivation_incomplete` | `incomplete` | Effect or assignment-relation rows could not be fully derived. |
| `result_contract_derivation_incomplete` | `incomplete` | Result-contract rows could not be fully derived. |
| `result_obligation_derivation_incomplete` | `incomplete` | Result-obligation rows could not be fully derived. |
| `effect_budget_exhausted` | `incomplete` | The effect budget ran out. |
| `call_shape_coverage_incomplete` | `incomplete` | A call shape is incomplete, so its argument, group, and binding rows were not produced. |
| `jsx_projection_incomplete` | `incomplete` | A JSX attribute value could not be fully projected. |
| `result_limit_reached` | `incomplete` | The result `limit` was reached; more results exist. |
| `broad_query` | `advisory` | The query scanned the workspace without a name, path, or language anchor. |

## Limits

These are the default limits for `query_code`. Policy evaluation, and `--query-file`
with `--workspace-scaled-limits`, scale some execution limits by source volume.

### Query shape

| Limit | Value |
| --- | --- |
| RQL query source text | 64 KiB |
| RQL nesting depth | 128 |
| `limit` | 1 to 1000, default 100 |
| `where` globs | 128, each at most 1024 bytes |
| Language labels | 32 |
| Pattern nodes | 256 |
| Pattern nesting | 64 levels |
| Kinds in one `kind` or `not_kind` list | 32 |
| Patterns in one role list | 64 |
| Named arguments (`kwargs`) | 64, names at most 128 bytes |
| `name`, `text`, and `parameter_type` predicate source | 4096 bytes |
| `arity` bounds | 0 to 1024 |
| Capture label | 128 bytes |
| Steps per plan node | 16 |
| Set operands per node | 2 to 16 |
| Plan nodes | 64 |
| Plan depth | 16 |
| Entries in one occurrence, scope, binding, or candidate filter axis | 32 |
| Binding name | 256 bytes |
| Decorator-binding `module` or `imported_name` | 4096 bytes |
| Entries in one configuration filter axis | 32 |
| Configuration key | 4096 bytes |
| Segments in one configuration route | 64 |
| Row predicates per `filter` | 16 |
| Literals in one `in` set | 64 |
| Columns per `project` | 32 |
| Row field name | 256 bytes |
| `protocol_ref`, `plan_ref`, `taint_ref` | 3 to 192 bytes; namespace at most 63 bytes, name at most 128 bytes |

### Execution

| Limit | Value | When exceeded |
| --- | --- | --- |
| Scanned files | 20,000 | `execution_budget_exhausted`, `truncated: true` |
| Scanned source bytes | 128 MiB | `execution_budget_exhausted`, `truncated: true` |
| Structural fact nodes | 2,000,000 | `execution_budget_exhausted`, `truncated: true` |
| Seed and edge rows | 50,000 | `pipeline_budget_exhausted`, `truncated: true` |
| Provenance paths per result | 16 | `provenance_truncated: true` on the row |

### Semantic analysis

Semantic limits apply only when a semantic step reads a source file. Structural
queries and `explain` mode do not use them. Exhaustion reports
`semantic_budget_exhausted` and names one of the lanes `source`, `rows`,
`retained_bytes`, `steps`, or `files`.

| Limit | Value | Lane |
| --- | --- | --- |
| Materialized files | 256 | `files` |
| Source bytes | 16 MiB | `source` |
| Rows per semantic dimension | 1,000,000 | `rows` |
| Retained artifact and source bytes | 256 MiB | `retained_bytes` |
| Traversal steps | 1,000,000 | `steps` |

### Registered analyses

| Analysis | Limit | Value |
| --- | --- | --- |
| Typestate | Reached rows | 1,000,000 |
| Typestate | Finding candidates | 8,192 |
| Typestate | Steps per witness | 64 |
| Typestate | Expansions per witness | 4,096 |
| Typestate | Total witness expansions | 1,000,000 |
| Typestate | Witness bytes | 64 MiB |
| Value flow | Retained relations | 262,144 |
| Value flow | Retained bytes | 16 MiB |
| Value flow | Endpoints | 50,000 |
| Value flow | Witnesses | 4,096 |
| Value flow | Steps per witness | 4,096 |
| Value flow | Expansions per witness | 16,384 |
| Value flow | Bytes per witness | 4 MiB |
| Value flow | Total witness steps | 262,144 |
| Value flow | Total witness expansions | 1,048,576 |
| Value flow | Total witness bytes | 16 MiB |
| Taint | Findings | 50,000 |
| Taint | Projected bytes | 64 MiB |
| Taint | Origins per finding | 4,096 |
| Taint | Witnesses per finding | 4,096 |
| Taint | Steps per witness | 4,096 |
| Taint | Bytes per witness | 4 MiB |

`witness` options `max_steps` and `max_bytes` can only lower these limits.

## Static dependency evidence

`dependency_evidence` reads facts acquired from selected Cargo and JS/TS
manifests and lockfiles before query execution. A files-only checkout can supply
these facts without installed dependencies, declaration files, a build or a
semantic-pack artifact. Acquisition does not execute package managers, target
project scripts, lifecycle hooks or network requests. JS/TS supported formats
and their limitations are documented in [Language Support](/reference/languages/).

Each axis is an array of exact alternatives; different axes combine with AND.
JSON axes and their RQL options are:

| JSON | RQL | Meaning |
| --- | --- | --- |
| `ecosystems` | `:ecosystem`, `:ecosystems` | Package ecosystem; Cargo uses `cargo`, JS/TS packages use `npm`, and JS toolchain constraints use `npm-toolchain`. |
| `packages` | `:package`, `:packages` | Actual package names, independent of manifest aliases. |
| `kinds` | `:kind`, `:kinds` | `declared`, `constraint`, `locked`, `installed`, or `checksum`. Cargo file acquisition emits declared and locked facts. |
| `exact_versions` | `:exact-version`, `:exact_versions` | Exact recorded version strings. Declarations have requirements, not exact versions. |
| `version_ranges` | `:version-range`, `:version_ranges` | Version requirements matched against complete exact locked/installed evidence. Requires exactly `ecosystems: ["cargo"]` or `["npm"]`; each uses its ecosystem semantics, including prerelease rules. npm supports comparator sets, unions, caret/tilde, partial/wildcard and hyphen ranges. Arbitrary sources and tags remain unresolved. |
| `sources` | `:source`, `:sources` | Exact source identities. Registry URL and git revision identities remain distinct. |
| `declared_by` | `:declared-by`, `:declared_by` | Established owning BuildProject IDs from build topology identity. |
| `scopes` | `:scope`, `:scopes` | Recorded `compile`, `runtime`, `test`, `provided`, `optional`, `feature_gated`, or `unknown` scope. Cargo build requirements use `unknown` and retain their build kind as a condition. |

For example, a curated review can select an exact recorded package and source:

```lisp
(dependency-evidence
  :ecosystem cargo :package widget :kind locked
  :version-range "=1.2.3"
  :source "registry+https://github.com/rust-lang/crates.io-index")
```

For an npm package instance, use npm comparator syntax and select the proven
member through its `declared_by` ID when the policy requires ownership:

```lisp
(dependency-evidence
  :ecosystem npm :package example-lib :kind locked
  :version-range ">=1.0.0 <1.3.0")
```

Each identity filter and version predicate applies to the same stored row.
Peer constraints and engine requirements do not establish installation or the
installed runtime. Unsupported overrides and conditional applicability remain
explicit. A matching package in another member cannot supply this row's owner;
configuration mitigation needs the separately established correlation relation.

The `dependency_evidence` result row carries `id`, `path`, `ecosystem`, `package`,
`evidence_kind`, optional `version_requirement`, `exact_version`, `source`,
`locator`, and `declared_by`, plus `scope`, `conditions`, `source_digest`,
`start_byte`, `end_byte`, optional `range` (1-based character line/column
coordinates), and `complete`. Exact citations and source-slice hashes are derived
from the retained publication bytes, including overlays and older revisions;
queries do not reread current files to construct these citations.
Conditions retain manifest aliases,
workspace inheritance and its evidence, normal/dev/build kind, optional and
feature declarations, raw target conditions, patch inputs, checksums, git
revisions, and declaration-to-lock association candidates and reasons.
`complete` describes interpretation of that record, not dependency activation.

Raw lock facts have no member owner. A separate owned lock fact is emitted only
when selected manifest and lock evidence establish its association; it cites the
lock span and preserves the declaring manifest's path, snapshot and span as
conditions. Multiple versions, sources and ambiguous candidates remain separate.
A locked package does not prove installation, compilation or loading. Features
and target conditions do not prove the enabled configuration. A version policy
can request a review; it does not establish advisory exploitability.

Malformed input, missing or ambiguous associations, unsupported patches or Cargo
configuration, cancellation and acquisition limits remain incomplete diagnostics.
An empty incomplete answer cannot certify a clean project. `.cargo/config`
precedence, rustflags and selected target configuration are separate supported
configuration work; workspace co-occurrence does not establish applicability.
The seed accepts `where` over evidence files and rejects `languages`; select the
package ecosystem instead.

The same seed is available in an RQLP match selector:

```lisp
(policy :id "review.widget.version"
  :name "Review recorded widget version"
  :message "Review the cited Cargo dependency instance"
  :severity warning
  :analysis (analysis :type match
    :selector (rql
      (dependency-evidence
        :ecosystem cargo :package widget :kind locked
        :version-range "=1.2.3"
        :source "registry+https://github.com/rust-lang/crates.io-index"))))
```

Findings retain the exact dependency evidence ID, version, source, established
owner (when available), input digest, and source citation. Use an established
`declared_by` ID to restrict a policy to a particular member. A source match
must not be replaced with a package-name-only match when distinguishing registries
or git instances. Configuration mitigation requires an established component
relation; this seed does not infer one from files sharing a workspace.


### Dependency configuration mitigation

The registered `dependency-configuration` relation binds a recorded dependency
to an explicitly reviewed configuration mapping. `:owner` is the exact topology
identity carried by the dependency's `declared_by`, rather than a member name or
path pattern. The author declares the complete file set for this bounded claim
and each lower-to-higher override explicitly. This mapping does not discover
framework bindings, deployment settings, environment values, or an actual
runtime configuration.

```lisp
(filter :where ((mitigated eq false))
  (correlate
    :relation (dependency-configuration
      :owner "<exact declared_by identity>"
      :ecosystem npm :version-ranges [">=1 <1.3"]
      :documents ["packages/a/base.properties" "packages/a/override.properties"]
      :overrides [["packages/a/base.properties" "packages/a/override.properties"]]
      :values ["true"])
    :code (dependency-evidence :ecosystem npm :package example
      :kind locked :version-range "^1")
    :configuration (configuration-facts :format properties
      :key "mitigation.enabled")))
```

The JSON relation is `dependency_configuration` with `owner`, `ecosystem`,
`version_ranges`, `documents`, `overrides`, and `values`. npm and Cargo ranges
use their existing ecosystem semantics. The same exact dependency row supplies
owner and version; declared ranges and peer constraints cannot prove mitigation.
The configuration input selects one flat `.properties` key. Desired `values`
are exact plain scalar spellings; escaped, continued, or interpolated values
remain unsupported. Other formats and inferred framework precedence are outside
this relation's support boundary.

Resolution reads every occurrence in the full immutable mapped documents before
applying configuration row filters or comparing the desired value. A duplicate
key conflicts even if both spellings agree. Incomparable winning layers, missing
or malformed documents, unsupported values, cancellation, and limits retain
typed uncertainty. There are at most 32 documents, 128 override edges, 4096
contributions, and 16384 precedence steps, also constrained by query budgets. Repeated retained
configuration proof is capped at 8 MiB and the query semantic retained-byte
limit; exhaustion preserves an unmitigated witness with omitted proof.

Each input dependency remains a `cross_domain` witness. `mitigated` is true only
when the owner matches, the recorded locked/installed exact version supports the
mitigation, and complete effective evidence uniquely selects the desired value.
False means mitigation was not proved; it does not mean the component executes
or is exploitable. The filter above therefore retains affected witnesses under
unknown configuration and works unchanged in an RQLP match selector.

Rows retain `dependency_id`, the reviewed `owner`, `mapping_id`, canonical
`effective_configuration` proof/completeness/ordered contributions/precedence,
and exact `configuration_contributors` citations. Different-owner witnesses
carry no unrelated configuration pair. The dependency's lock citation anchors
the row, and CLI, MCP, and policy execution use the same evidence.
