---
title: Rune Query Language
description: Use the experimental S-expression frontend for Bifrost's query_code engine.
---

RQL, the Rune Query Language, is the experimental S-expression frontend for Bifrost's `query_code` engine. It is designed for interactive use in the REPL:

```bash
bifrost --root /path/to/project --repl
```

The default `bifrost` command still starts the MCP stdio server. Use `--repl` when you want a human-facing prompt with completion, history, multiline input, query validation, and readable search results.

## Relationship To CodeQuery

RQL is only a query language. It is not a second matcher or query engine.

RQL text is the single query authoring syntax. `.rql` files and editor buffers accept RQL text only, including unsaved queries sent through LSP. The REPL also accepts only RQL input; `:json` generates machine output. Canonical JSON is generated machine serialization, not authored query source.

Every RQL expression decodes to a validated `CodeQuery` before execution. The decoded query generates [canonical JSON](/code-query-json/) for machine serialization. MCP hosts with `query_code` call the same engine using canonical JSON inline, or they can load a complete saved `.rql` file through the exclusive `query_file` argument. MCP does not accept raw inline RQL, and the `core` toolset does not expose `query_code`; use `symbol|extended` or `searchtools`. See the Query and RQL Availability section of [MCP](/mcp/) for the complete surface matrix and [Code Querying](/code-querying/) for the schema and engine overview.

RQL targets the single supported CodeQuery schema version, 1. A standalone RQL query has no schema-version option. A policy selector can pin the version with `(rql :schema-version 1 QUERY)`. The [CodeQuery and RQL Vocabulary Reference](/reference/code-query/) lists every RQL form, alias, option, and value label.

Save a complete RQL expression in a workspace `.rql` file and run it without opening the REPL:

```bash
bifrost --query-file queries/audit.rql
```

An MCP agent can run the same saved file by calling `query_code` with `{"query_file":"queries/audit.rql"}`. The path is relative to the active workspace, and `query_file` cannot be combined with inline filters or other query fields.

For source-first examples across every structural adapter, see the [language tutorials](/code-query-tutorials/). Each page pairs executable RQL with its canonical JSON form and exact results.

Use `:json` in the REPL to inspect the canonical JSON generated for the current RQL query.

RQL is also the selector language nested inside [static-analysis policy
documents](/static-analysis-policies/). A `.rqlp` file is a distinct policy
language and contains one `(policy ...)` or diagnostic-neutral `(endpoint ...)`
document; it is not a saved query and cannot be run through `--query-file`.
Inline selectors use `(rql [:schema-version N] QUERY)`, while
`(rql-file [:schema-version N] :path "workspace/relative.rql")` defers one
saved selector to workspace-backed policy loading. Policy/endpoint and nested
RQL schema versions are resolved independently. JSON remains a CodeQuery and
reporting surface, not an alternate `.rqlp` authoring syntax.
Analysis-level shared selector context belongs to the policy language and is
described in [static-analysis policies](/static-analysis-policies/); it applies
to these RQL selectors but never changes the policy and RQL version lineages.

Use `:ir <language>` for the opposite direction: paste source code through a line containing only `:end`, then inspect the [Rune IR](/rune-ir/) produced by that language's real structural adapter and copy the generated starter RQL. Use the `tsx` label for TypeScript snippets that contain TSX; the `typescript` label uses the plain TypeScript grammar and does not produce `jsx_element` facts. `javascript` covers JavaScript source, including JSX. Rune IR is the normalized source-side representation matched by `CodeQuery`; it is not RQL's query-side IR.

## Complete Example

This query finds calls to `eval` inside a function, captures the first positional argument, limits the search to Python source files, and requests full ranges:

<!-- code-query-test:rql:complete -->
```lisp
; Semicolon comments run to the end of the line.
(result-detail full
  (limit 25
    (language python
      (where "src/**/*.py"
        (inside
          (function :capture "handler")
          (call
            :callee (name "eval")
            :args [(capture "argument")]))))))
```

Enter it at the prompt, run `:validate`, inspect the lowered version with `:json`, and execute it with `:run`.

## Syntax

RQL uses compact S-expressions. The following are independent forms, not one multi-expression query:

```lisp
(call :callee (name "eval") :args [(capture "arg")])
(function :name "handler")
(class :decorators [(name "Controller")])
(import :module "os")
(where "src/**/*.py" (call :callee (name "eval")))
(language python (call :callee (name "eval")))
(limit 25 (call :callee (name "eval")))
(result-detail full (call :callee (name "eval")))
(explain (call :callee (name "eval")))
(profile (call :callee (name "eval")))
(inside (function :name "handler") (call :callee (name "eval")))
(inside-decl (loop) (call :callee (name "open")))
(filter :where ((target_count gt 0)) (occurrences :class reference))
(project :columns (ast_id (target_count candidates)) (occurrences))
```

## Comments

Start a comment with `;` at the beginning of a line or after whitespace; it
continues to the next newline. RQL has no block-comment syntax. A semicolon in
a quoted string is ordinary text, not a comment.

<!-- code-query-test:rql:comments -->
```lisp
; Limit the search to production Python files.
(where "src/**/*.py"
  (call :callee (name "eval"))) ; exclude generated paths in a real query
```

Head symbols such as `call`, `function`, `class`, `module`, and `import` map to normalized structural kinds. Kind heads use the kind label exactly, with underscores: `(field_access ...)`, `(boolean_literal)`. Keyword fields such as `:callee`, `:args`, `:module`, `:decorators`, `:iterable`, and `:elements` map to normalized roles. Position decides which vocabulary a spelling belongs to: `(module :name "tests")` is the module-declaration kind, while `(import :module (name "fmt"))` constrains the module role of an import.

### Pattern grammar

A pattern is a kind head followed by any number of role options, property options, and predicate forms:

```text
(KIND [:ROLE VALUE | :PROPERTY VALUE | (PREDICATE ...)]*)
```

- A kind head with no arguments is valid, for example `(loop)`.
- A single-target role, such as `:callee`, `:receiver`, `:left`, or `:module`, takes a pattern or a string. The string is shorthand for a name: `:callee "run"` means `:callee (name "run")`.
- A list role, such as `:args`, `:decorators`, `:elements`, `:attributes`, or `:children`, takes a vector of patterns: `:args [(capture "first") (string_literal)]`.
- `:kwargs` takes a vector of `(ARGNAME PATTERN)` pairs: `:kwargs [(shell (boolean_literal :capture "shell_value"))]`.
- A property can be written as a keyword option or as a predicate form. `(function :name "run")` and `(function (name "run"))` are the same query.
- Callable asyncness is available as `(function :async true)` or `(function (async true))`; use `false` to select synchronous callables.
- `(await)` matches an await expression. `(program-point-of (await))` projects it to its unique `AsyncSuspend` program point and reports an incomplete result if that point is unavailable or ambiguous.
- A bare string directly inside a kind head is an error. Write `(function :name "register")`, not `(function "register")`.

Many forms have an underscore alias, such as `procedure_of` for `procedure-of`, and the sources have singular aliases, such as `occurrence` for `occurrences`. The reference lists every form and alias in its [query plan field](/reference/code-query/#query-plan-fields), [pattern](/reference/code-query/#patterns), and [step](/reference/code-query/#steps) tables.

Predicate forms constrain fields on a pattern. Each line below shows one predicate inside a kind head:

```lisp
(class (name "handler"))
(class (name/regex ".*Service"))
(call (text/regex "eval\\("))
(method (visibility public))
(method (visibility [public protected]))
(method (parameter-type "String"))
(method (parameter-type/regex "String"))
(call (arity 2))
(call (arity :min 1 :max 3))
(boolean_literal (boolean-value true))
(string_literal (value/regex "^https?://"))
(string_literal (value "https://example.com"))
(string_literal
  (value/regex "^http://")
  (not (or (value/regex "localhost") (value/regex "127\\."))))
(call (capture "argument"))
(function (has (call :callee (name "open"))))
(function (not-has (call :callee (name "eval"))))
(callable (not-kind lambda))
```

`value` and `value/regex` match the decoded value of a `string_literal`. The
value has its quotes removed and its language escape sequences decoded; raw
string literals use their raw contents. These predicates inspect a structural
literal fact, so they do not search source text for a string that merely looks
like a literal. Exact values use `(value "...")`; regular expressions use
`(value/regex "...")`.

`not` negates one pattern on the same node. `and` and `or` combine two or more
patterns on that node; the predicate spellings are `(and P Q ...)` and
`(or P Q ...)`. For example, `(string_literal (value/regex "^http://")
 (not (or (value/regex "localhost") (value/regex "127\\."))))` selects HTTP
literal values while excluding those two host forms. These logical forms are
pattern constraints, so they can be nested with ordinary kind, name, and value
predicates.

The keyword form `:arity N` accepts only an exact count. Use the `(arity :min N :max M)` predicate form for bounds; either bound may be omitted, but not both.

Wrapper forms control the query around the root pattern:

```lisp
(where "src/**/*.py" (call :callee (name "eval")))
(language python (call :callee (name "eval")))
(limit 25 (call :callee (name "eval")))
(result-detail full (call :callee (name "eval")))
(explain (call :callee (name "eval")))
(profile (call :callee (name "eval")))
(inside (function :name "handler") (call :callee (name "eval")))
(not-inside (function :name "test") (call :callee (name "eval")))
```

`where` accepts one or more globs. The globs in one `where` form are
alternatives. Repeated `where` forms and repeated `language` forms are separate
outer constraints and conjoin; language labels intersect, so statically
disjoint labels fail validation.

The language labels are `java`, `go`, `cpp`, `javascript`, `typescript`,
`python`, `rust`, `php`, `scala`, `csharp`, `ruby`, and `kotlin`. The family
`jvm` expands to `java`, `kotlin`, and `scala`, and the family `js-ts` expands
to `javascript` and `typescript`; duplicate members are removed. A `language`
form also accepts `c++`, `c#`, and any file extension that Bifrost indexes,
such as `py`, `tsx`, or `h`. Each one selects the whole language that owns it:
`tsx` selects every `typescript` file, and `c` or `h` selects every `cpp` file.
No RQL form infers a language label from the workspace. See the
[label table](/reference/code-query/#languages).

`explain` lowers and selects a plan without scanning workspace data. `profile` executes and returns the ordinary result plus structured measurements. They are mutually exclusive root controls and are not legal inside policy selectors. See [Explain and Profile CodeQuery](/code-query-explain-profile/) for the response schemas and measured production scheduling policy.

`result-detail full` publishes analyzer declaration identity. Every
declaration-valued `id`, `target_id`, `caller_id`, `callee_id`,
`procedure_id`, or `declaration_id` uses the same opaque `decl:v1:<hex>` token
for the same declaration. A declaration row also publishes `site_id`, that
token plus its exact byte span; joins never reconstruct either value from a
rendered kind, name, path, or line range. The same full-detail query preserves
these values through the CLI, MCP, and LSP transports.

Pipeline wrappers transform the result domain. Inner wrappers execute first. The examples below show common wrappers; the reference has [every step](/reference/code-query/#steps) with its input and output domains and options:

```lisp
(enclosing-decl (call :callee (name "audit")))
(file-of (function :name "handle"))
(imports-of (file-of (function :name "handle")))
(importers-of (importers-of (file-of (function :name "target"))))
(python-import-cycles (language python (import :module "helper")))
(supertypes (enclosing-decl (class :name "Service")))
(supertypes :depth 2 (enclosing-decl (class :name "Service")))
(subtypes :transitive true (enclosing-decl (class :name "BaseService")))
(owner (members (enclosing-decl (class :name "Service"))))
(references-of :proof proven (members (enclosing-decl (class :name "Service"))))
(used-by :reference-kinds [field-write] (members (enclosing-decl (class :name "Service"))))
(uses :surface lsp-references (enclosing-decl (method :name "handle")))
(callers :depth 2 :proof proven (enclosing-decl (method :name "sink")))
(callers :depth 2 :proof proven :completeness proven-subset (enclosing-decl (method :name "sink")))
(callees (enclosing-decl (method :name "handle")))
(call-input :receiver true (call-sites-from (enclosing-decl (method :name "handle"))))
(call-input :parameter-name "payload" (call-sites-to :proof proven (enclosing-decl (method :name "sink"))))
(call-argument :formal-name "payload"
  (resolved-call :resolves-to member.service.sink :proof declared
    (call-bindings (call-shape (call :callee (name "sink"))))))
(receiver-targets (call :callee "run" :receiver "service"))
(points-to :capture receiver (call :receiver (capture "receiver")))
(member-targets (references-of :proof proven (enclosing-decl (method :name "run"))))
(procedure-of (function :name "run"))
(program-point-of (await))
(cfg-entry (procedure-of (function :name "run")))
(cfg-exits (procedure-of (function :name "run")))
(cfg-successor-edges (cfg-entry (procedure-of (function :name "run"))))
(cfg-predecessor-edges (cfg-exits (procedure-of (function :name "run"))))
(cfg-edge-source (cfg-successor-edges (cfg-entry (procedure-of (function :name "run")))))
(cfg-edge-target (cfg-successor-edges (cfg-entry (procedure-of (function :name "run")))))
(target-of (file-of (class :name "Order")))
(source-set-of (file-of (class :name "Order")))
(topology-edges-of (target-of (file-of (class :name "Order"))))
```

The three build-topology steps (`target-of`, `source-set-of`, and
`topology-edges-of`) read Maven `pom.xml` files only. A workspace without a
readable Maven build, including a Gradle-only workspace, returns a
`topology_derivation_incomplete` diagnostic. A file that no build file claims
returns no row.

Typed set forms combine complete compatible pipelines and may themselves be wrapped by another step:

```lisp
(union query-a query-b ...)
(intersect query-a query-b ...)
(except query-a query-b ...)
(file-of
  (union
    (enclosing-decl (class :name "Legacy"))
    (enclosing-decl (class :name "Replacement"))))
```

All operands at one node must produce the same terminal domain. Union preserves first appearance by operand order; intersection and except preserve the first operand's order. Branch provenance and diagnostics use zero-based paths. See the executable [Typed Set Composition](/code-query-tutorials/set-composition/) cookbook.

The fourth expression performs two direct reverse-import hops. Hierarchy traversal is direct when no
option is supplied; `:depth N` returns the one-through-N closure, and `:transitive true` returns the
full indexed closure under the execution budget. Call traversal is also direct by default and
accepts finite `:depth N`, but not `:transitive`. `callers :proof proven :completeness
proven-subset` is the one explicit non-exhaustive contract: it returns only resolved proven caller
edges and labels the result as a proven subset, never as all callers. It remains diagnostic-visible
when a caller cannot be rendered as an indexed declaration, and is rejected without `:proof proven`
or on `callees`. `call-input` requires exactly one receiver, parameter-index, or parameter-name
selector. `resolved-call` consumes `call_binding` rows and retains only rows for one stable callable
identity with `exact` or `declared` proof. Its optional `:receiver-type` accepts either one exact
receiver identity or `(assignable-to ROOT)`, which accepts the source-backed workspace root and
every descendant produced by the analyzer's complete typed hierarchy. An incomplete, cancelled,
external, or model-only hierarchy fails closed. Unquoted identities are stable IDs. Quoted qualified
locators are resolved at a loaded-policy boundary and cannot execute as unresolved standalone
queries. `call-argument` also consumes and returns `call_binding` rows, selects exactly one formal
by name or zero-based index, and requires exact mapping, exhaustive coverage, a non-terminal row,
and a present argument identity. Python call-binding rows can state an exact missing-required-formal
absence and distinguish an unknown keyword; spreads and unresolved targets remain incomplete. Python
`callable_signature` rows expose `special_method_status` for known protocol methods, including
too-few, too-many, required-optional-argument, placeholder, and incomplete outcomes. `members`
returns direct declarations and `owner` recovers their exact declaring type. Reference and call
proof options may appear before the nested query. `receiver-targets` and `points-to` produce
`receiver_analysis` rows; `file-of`, `receiver-outcome`, and `receiver-evidence` may wrap them.
`member-targets` produces `member_target_analysis` rows; `file-of`, `receiver-outcome`, and
`field-write-value` may wrap them, but `receiver-evidence` may not. The two terminal receiver steps
also accept structural matches, reference sites, call sites, expression sites, and occurrence rows
directly, performing the same `receiver-targets` analysis internally. A receiver wrapper's optional
`:capture name` is legal only over a structural match and must name a declared positive capture.
Procedure, program-point, control-edge, receiver-analysis, member-target-analysis, receiver-outcome,
and receiver-evidence rows may all be projected through `file-of`. `:json` renders every wrapper as
an ordered `steps` array.

`resolved-value` retains a call-binding row or Python decorator structural match only when
the selected expression resolves to one exact declaration. Constructor calls resolve through their
callee. Unresolved, ambiguous, shadowed, unsupported, and budget-limited values remain incomplete.
Quoted qualified locators resolve only at a loaded-policy boundary. For example:

    (resolved-value
      :resolves-to "django.views.decorators.csrf.csrf_exempt"
      :proof exact
      (language python (decorator)))

Receiver wrappers consume the structured facts exposed by the selected adapter. Availability is not defined by a static language list: unsupported source forms preserve an explicit `unsupported` row and capability diagnostic. See [Receiver Traversal](/code-query-tutorials/receiver-traversal/) for allocation, factory, ambiguity, reference-site, and call-input examples with exact output.

### Typed row filtering and projection

Every terminal query domain publishes a row schema: ordered field names,
scalar types, nullability, and the accepted public labels of constrained enum
fields. `(filter :where (...) QUERY)` reads that schema and retains a row only
when every predicate holds:

```lisp
(filter :where (
    (class in [reference declaration])
    (target_count ge 1)
    (target_count le (field target_count))
    (target_id is-not-null))
  (occurrences))
```

The operators are `eq`, `ne`, `lt`, `le`, `gt`, `ge`, `is-null`,
`is-not-null`, and `in`. Quoted values are strings and stable identities;
non-negative numbers and booleans keep their types; bare values are checked
against the selected field's published enum labels. `(field NAME)` is the
unambiguous second-field operand. Ordered comparison is defined only for
integer fields. Comparison against an absent nullable field is false,
including `ne`; use `is-null` to select absence. One filter accepts 1 through
16 predicates, and an `in` set accepts 1 through 64 literals.

`(project :columns (...) QUERY)` publishes exactly the selected row fields to
a relational binding, in order. A bare field keeps its name and `(FIELD
NEW-FIELD)` renames it:

```lisp
(filter :where ((candidates gt 0))
  (project :columns (ast_id (target_count candidates) role)
    (occurrences)))
```

The projected schema preserves every source field's scalar type, nullability,
and constrained value domain; it also preserves the row's source and evidence
anchor. Later filters use projected names. More projections may compose, but
no analyzer traversal may follow a projection because a dynamic record is not
a registered analyzer input domain. A projection accepts 1 through 32 unique
output names.

## Procedure-Local CFG Inspection

The typed control-flow algebra is part of the same schema. `procedure-of` resolves the unique smallest source-backed executable procedure containing a structural match or declaration. `cfg-entry` and `cfg-exits` return validated boundary points. The successor and predecessor forms each traverse exactly one edge, and `cfg-edge-source` or `cfg-edge-target` projects an edge back to a point.

<!-- code-query-test:rql:cfg-entry-successor -->
```lisp
(cfg-edge-target
  (cfg-successor-edges
    (cfg-entry
      (procedure-of
        (language typescript
          (function :name "run"))))))
```

This returns `program_point` rows for targets of edges leaving `run`'s entry. Procedure, point, and edge rows include checkout-independent content-scoped IDs, exact source ranges, one `{proof, completeness, reason}` evidence object, and normal CodeQuery provenance. The optional reason carries a typed failure or limit; no composite quality label is published. Unsupported capabilities, partial semantic artifacts, cancellation, and exhausted budgets remain explicit diagnostics and cannot produce a falsely complete empty answer.

Semantic materialization is lazy and request-scoped. It has separate finite limits of 256 materialized files, 16 MiB of source, 1,000,000 rows per semantic dimension, 256 MiB retained semantic data, and 1,000,000 traversal steps. See the [limit tables](/reference/code-query/#limits). Repeating an edge form is how an authored query asks for another hop; no form silently computes an unbounded closure.

This CFG surface is a procedure-local inspection API. It does not cross call boundaries and does not provide an ICFG, data-flow, taint, typestate, finding, or witness engine. The registered typestate adapter below is the only typestate entry point.

`inside-decl` is containment that can match an enclosing callable itself, but stops before searching beyond a non-matching nested function, method, constructor, or lambda. For a Rust method declared in an `impl`, it can also match the resolved type declaration that owns the impl. Ordinary `inside` remains lexical and can cross those boundaries.

`(value-flow :plan-ref namespace:name query)` maps procedure rows to diagnostic-neutral flow endpoints backed by a host-registered `ValueFlowPlan`. `(witness ...)` also accepts flow endpoints and returns retained bounded flow paths. Endpoint reachability, exact/may certainty, and ambiguity remain explicit; one public `status` plus optional `reason` preserves semantic, solver, and query termination detail. The status labels and meanings are defined in the [JSON CodeQuery value-domain table](/code-query-json/#registered-value-flow-endpoints-and-witnesses). There is no `must` column until must analysis exists, and no policy classification is implied.

<!-- code-query-test:rql:value-flow-witness -->
```lisp
(witness :max-steps 32 :max-bytes 16384
  (value-flow :plan-ref "embedding:request-to-sink"
    (procedure-of (method :name "run"))))
```

`(taint :taint-ref namespace:name query)` maps exact procedure rows to `taint_finding` rows by projecting an immutable production result already registered by the host:

```lisp
(taint :taint-ref "request:http-to-database"
  (procedure-of (method :name "run")))
```

The form cannot load or compile policies, invoke propagation, reconstruct witnesses, or add classification. With matching limits its rows are field-for-field equal to the production outcome's public taint findings.

`(occurrences ...)` is a source in its own right, and `(occurrences-in ...)`, `(occurrences-of ...)` and `(occurrence-target ...)` are wrappers. `:class`, `:role`, and `:namespace` each accept one label or a vector of labels:

<!-- code-query-test:rql:occurrence-seed -->
```lisp
(language "rust"
  (occurrences :role [binder declaration_name] :namespace value))
```

<!-- code-query-test:rql:occurrences-in -->
```lisp
(occurrence-target
  (occurrences-in :class reference
    (function :name "handle")))
```

`occurrences-in` also accepts a lexical scope and returns only occurrences whose exact innermost scope is that row:

<!-- code-query-test:rql:occurrences-in-scope -->
```lisp
(occurrences-in :role global_directive
  (filter :where ((kind is-null))
    (language "python" (scopes))))
```

Containment for occurrences is `occurrences-in` over a structural query rather than `(inside ...)` on the source, so there is exactly one lexical-containment verifier. Scope membership uses the existing per-file lexical result and excludes occurrences in nested scopes. A language that has not declared support for a role a query names makes the run incomplete rather than answering it with zero rows.

## Lexical Scopes, Bindings and Resolution Candidates

Scope, binding, and candidate rows say *why* an identifier resolved the way it did. `(scopes ...)` and `(bindings ...)` are sources like `(occurrences ...)`; `(scope-of ...)`, `(scope-ancestors ...)`, `(bindings-in ...)`, `(binding-of ...)`, `(binding-occurrence ...)`, `(binding-uses ...)`, `(candidates-of ...)` and `(candidate-target ...)` are wrappers.

<!-- code-query-test:rql:scope-seed -->
```lisp
(language "java"
  (scopes :kind block))
```

<!-- code-query-test:rql:binding-seed -->
```lisp
(language "java"
  (bindings :kind [local parameter] :hoisting source_order))
```

The binding of an occurrence is the declaration of that name in effect at its exact position, computed from activation intervals and scope ancestry rather than from source-order co-presence. Composing it with `scope-of` answers the loop-invariance question -- is the value operated on inside this loop declared inside or outside the loop body?

<!-- code-query-test:rql:binding-of -->
```lisp
(scope-of
  (binding-of
    (language "java"
      (occurrences :role receiver_position))))
```

`:include-shadowed true` additionally returns the bindings the winner shadows, so "more than one binding of this name is in effect here" becomes a visible multi-row answer instead of a collapsed one.

`binding-uses` joins a binding to the reference occurrences whose `binding-of` answer is that exact binding. It derives the join from per-file occurrence and lexical-environment rows during the query. For example, this returns the reads of the parameter named `value`:

```lisp
(binding-uses
  (bindings :kind parameter :name "value"))
```

`python-uninitialized-variable` joins one value-reference occurrence to its
exact lexical binding and the same source-backed CFG read. It emits a complete
fact only when the local binding may be uninitialized on a modeled path. A
module or class binding, a global or builtin lookup, a closure binding, or an
open CFG identity makes the query incomplete instead of becoming a finding:

```lisp
(filter :where (
    (relation eq undefined_placeholder_variable)
    (outcome eq may_be_uninitialized)
    (completeness eq complete))
  (language python
    (python-uninitialized-variable
      (union
        (binding-uses (bindings))
        (occurrences :class reference :role [value_reference receiver_position])))))
```

Python comparison filters preserve the selected comparison row while checking its grammar-selected operands against lexical binding identities. `identical-operands` accepts a pair of bare names bound to the same declaration, or static attribute paths with the same members and the same bound root. Calls and other computed operands are outside this relation; unresolved supported names make the query incomplete. For example, this selects `value == value` and `self.field == self.field` when each pair shares its lexical root:

```lisp
(identical-operands
  (language "python" (comparison)))
```

`python-missing-self` further selects same-name comparisons inside a class method when the name has no local binding or explicit `global`/`nonlocal` directive and that class contains a structured `self.<name>` access whose `self` resolves to a method parameter:

```lisp
(python-missing-self
  (language "python" (comparison)))
```

Both filters report chained comparisons as structurally incomplete because their pairwise evaluation order is not represented as singular left/right roles.

Python's `global_directive` and `nonlocal_directive` occurrence roles expose the names written in those scope directives. Python export rows expose each literal member of module-level `__all__` as `python_all`; a dynamic or unavailable export surface keeps known members visible and marks the export answer incomplete.

```lisp
(language "python"
  (exports :form python_all))
```

## Qualified Paths and Their Segments

Qualified-path rows keep a path's identity visible segment by segment. `(paths ...)` is a source: one row per linear chain (`java.util.Map`, `crate::util::Widget`), anchored at its terminal segment's AST identity. `(segments-of ...)` returns each path's ordered segments with decoded identifier text (a quoted or raw identifier stays one segment) and the generic argument count the source spells; with `:resolved true`, every segment also carries its own prefix resolution, so "what is `util` in `crate::util::Widget`" is answerable at the segment. `(segment-target ...)` projects those per-segment resolutions onto workspace declarations.

<!-- code-query-test:rql:path-seed -->
```lisp
(language "rust"
  (paths :min-segments 3))
```

<!-- code-query-test:rql:segments-of -->
```lisp
(segments-of :resolved true
  (language "rust"
    (paths)))
```

A segment row states the adapter's namespace classification. Java and Rust qualifiers use `path_prefix`, meaning a module or a type; the segment's own resolution can refine that classification. An absent namespace means "not stated", never a guess. A language whose adapter does not answer the path axes makes the run incomplete rather than returning an empty complete answer.

<!-- code-query-test:rql:binding-of-shadowed -->
```lisp
(binding-of :include-shadowed true
  (language "rust"
    (occurrences :class reference)))
```

`(candidates-of ...)` lists what the resolver considered for a reference, filtered by `:tier`, `:outcome` and `:boundary`. `:outcome` accepts the two coarse outcomes (`selected`, `rejected`) and every typed rejection reason, so `:outcome shadowed_by_nearer` is exact while `:outcome rejected` stays readable.

<!-- code-query-test:rql:candidates-of -->
```lisp
(candidate-target
  (candidates-of :tier [lexical_binding explicit_import] :outcome selected
    (language "java"
      (occurrences :class reference))))
```

Three absences here are answers rather than gaps, and each reports an `incomplete` diagnostic where it matters. A candidate with no tier is *unattributed*, never weakest -- `:tier unattributed` selects exactly those rows, and a policy comparing tiers over one must be inconclusive. A trace whose completeness is `selection_only` says nothing by omitting a rejection. And `(candidate-target ...)` answers only for unit-backed candidates, because a lexical binding and an external route carry no workspace declaration at all.

## Canonical Reference Edges

Reference edges state "X uses Y" in one row shape, whichever derivation produced it. `(edges-of ...)` is the inverse projection -- every usage site the usage index enumerates for a declaration. `(edges-from ...)` is the forward one -- the resolver's own resolved targets for one exact token. `(edge-target ...)` walks an edge back to its indexed target declaration. Both edge wrappers accept `:reference-kinds`, `:proof`, `:surface`, `:usage`, `:relation` and `:site-class`.

<!-- code-query-test:rql:edges-of -->
```lisp
(edges-of :usage [reference] :site-class [use_site]
  (enclosing-decl
    (language "java"
      (callable :name "register"))))
```

<!-- code-query-test:rql:edges-from -->
```lisp
(edge-target
  (edges-from :reference-kinds [method-call]
    (language "java"
      (occurrences :class reference))))
```

The direction is a field on every row, not something read off which wrapper produced the set: `edge_provenance` is `forward` or `inverse` (renamed on the wire so the result item's branch-trace `provenance` cannot shadow it), and a parity claim is therefore a comparison across a field. `generation` names the workspace generation the derivation ran in, and rows from two generations describe two workspaces.

`:surface` is optional and, unlike `references-of`, has **no default**. The complete edge answer includes editor-only rows, so silently defaulting to `external-usages` would narrow the compared ground set without the author having said so.

Four absences are answers rather than gaps. An absent `ast_id` means the producer could not address the site token as an AST node, not that the edge is weaker. An absent `reference_kind` means no structured kind was classified, and is not a kind to compare against. An `owner_relation` of `unknown` is inconclusive and never silently equal to `external`. A `site_class` of `declaration_site` is editor-visible navigation rather than a runtime usage, which is why it is classified instead of dropped.

Only Java, Kotlin, Rust, Python, JavaScript, and TypeScript answer the forward projection. `(edges-from ...)` in any other language reports `edge_axis_unsupported` with `incomplete` impact -- never a clean empty answer -- and a derivation that was truncated, cancelled or failed reports `edge_derivation_incomplete`.

## Flow-Sensitive State and Flow Relations

`binding-of` is a *lexical* relation. It answers "which declaration does this name bind to under scoping rules", not "has an assignment to this binding executed before this read". The flow-sensitive family answers the second question, and it stands on the production control-flow graph alone.

`(state-events-of ...)` derives one row per establishment, kill, or read of a binding or of a property of a canonical binding base, each anchored to a program point of the seed procedure's CFG. `(flow-relations-of ...)` relates two such events. `(flow-source ...)` and `(flow-target ...)` project a relation back to its establishment end and its read end.

<!-- code-query-test:rql:state-events -->
```lisp
(state-events-of :class [establish read] :subject [binding]
  (procedure-of
    (function :name "handler")))
```

<!-- code-query-test:rql:flow-relations -->
```lisp
(flow-target
  (flow-relations-of :relation [reaching] :certainty [exact]
    (state-events-of
      (procedure-of
        (function :name "handler")))))
```

`:class` accepts `establish`, `kill` and `read`; `:subject` accepts `binding` and `property`; `:relation` accepts `reaching`, `dominates` and `same-evaluation`; `:certainty` accepts `exact` and `may`. Every axis is a list, and an omitted axis means "every value", never "no value".

The three relations say different things and are deliberately not folded together. `reaching` means some CFG path carries the establishment to the read with no intervening kill of the same subject. `dominates` means every entry-to-read path passes the establishment's program point. `same-evaluation` means the read feeds the very value the establishment assigns, so that establishment cannot serve that read -- `x = wrap(x)` is the canonical shape. Certainty is a separate axis: a reaching row is `exact` when the establishment is the *only* definition of the subject in the read's IN set **and** dominates it, and `may` otherwise. One-armed conditional establishment is the shape that separates the two.

Seeding matters. Seeded from a procedure, `(flow-relations-of ...)` returns every relation of that procedure. Seeded from a state event, it returns only the relations incident to that event -- both ends are matched, because an author asking about one write wants what it serves and an author asking about one read wants what serves it.

`(selected-property-relations-of program-point-query)` asks a different, explicit question: which stores reach the unique property read at one exact program point, and is that selected storage relation complete? Observe a property read with `state-events-of`, retaining that discovery response's coverage, then supply its `program_point_id` in a separate `(program-point-by-id :id "observed-id" procedure-query)` request. The content-scoped ID selects one physical point in the supplied current procedure; it does not claim complete AST/read discovery or semantic-overlay freshness. Missing, stale, wrong-procedure or incomplete point selection remains incomplete. The answer reuses the shared durable receiver/member identities and requires a closed local-allocation alias set and all relevant modeled endpoints. It can remain complete when an unrelated, proven disjoint property event has no public binding-root presentation. Existing whole-procedure coverage and postfilters retain their diagnostics. Projecting a scoped relation with `flow-source` or `flow-target` returns an event from the original aggregate derivation; subsequent ordinary relation queries use that aggregate coverage, rather than inheriting the selected proof. Undischarged runtime/control gaps, missing or ambiguous reads, uncertain aliases, escapes, ancestor replacement, exhausted budgets and cancellation remain incomplete. A complete storage relation preserves the written value's identity; it does not establish a scalar runtime value.


Four things are absences that are answers rather than gaps, and each says so. A row's `completeness` is `partial` when the derivation did not answer that row's own axis, and `uncovered_axes` names every axis the derivation left uncovered. A language whose adapter publishes no assignment for a binder yields no establishment for it and reports `flow_state_derivation_incomplete` rather than a proven-absent relation -- Go's `for x := range x` binder is exactly this case today. A control-flow algorithm that exhausts its budget emits *no rows at all* for its relation and reports `flow_state_derivation_incomplete`; a truncated relation set is never presented as a complete one. A field access whose base the IR does not flow from a binding contributes no property subject rather than an approximated one.

There is no lexical, textual, or source-order fallback anywhere on this surface, by construction: the derivation has no other evidence source to fall back to.

## Reviewed Result Contracts and Operation Uses

The result-contract pipeline joins exact call identity, indexed normal results,
success guards, and operation-sensitive use evidence from activated semantic
packs. A paired contract says that one result is valid when a predicate holds
for a separate condition result, such as `(resource, error)` being successful
when the error is null. A direct contract instead states a predicate on the
protected result itself, such as a nullable pointer being non-null. Return
shape alone establishes neither contract. `result-contract-calls` is the
lightweight positive-discovery filter: it retains a call shape only when every
canonical dispatch arm selects a reviewed result contract.
`call-result-contracts` then projects the contract rows, and
`result-contract-operation-uses` projects one `result_contract_use` row per
structured operation on the protected result.

```lisp
(result-contract-operation-uses
  (call-result-contracts
    (result-contract-calls
      (call-shape
        (call :callee (name "Open"))))))
```

The raw `call_result_contract` fields preserve the authored shape.
`result_ordinal` identifies the protected result. For a paired contract,
`condition_result_ordinal` identifies the separate condition result and
`predicate` is the predicate required of it; these two fields are always
present or absent together. `result_success_predicate` records a reviewed
predicate on the protected result: it is required for a direct contract and
may also record an independently reviewed correlation for a paired contract.
Both fields use the finite `null`, `non_null`, `true`, and `false` vocabulary.
For Boolean results, only a guard over the exact retained result identity
selects the corresponding true or false control edge; an overwrite or an
ambiguous reaching definition remains open.
A positive direct row therefore has `result_ordinal` and
`result_success_predicate`, but omits `condition_result_ordinal` and
`predicate`. A terminal row has `terminal = true`, omits all result ordinals
and predicates, and carries the reason no contract was established.

Each `result_contract_use` row keeps the acquisition identity and repeats
`result_ordinal`. Its optional `condition_result_ordinal` and
`acquisition_predicate` preserve the paired condition; both are absent for a
direct contract. `result_success_predicate` preserves the protected-result
predicate in either shape. `required_predicate` is different: when present, it
is the predicate required by this particular operation. The row also carries
the operation's source range and program point, its `dereference`, `field`,
`index`, `receiver_call`, or `call_argument` kind, and its `direct`, `deferred`,
or `captured` timing. A call-argument row also carries the zero-based
`parameter_ordinal`; its applicability comes from the procedure-entry
preconditions on every exact possible target. `applicability` is `required`,
`not_required`, or `unknown` according to the exact complete operation
contract. `guard` is independently `guarded`,
`unguarded`, `not_applicable`, or `unknown`; the originating pack, model, and
summary identities are present when known.

An authored policy can therefore select `applicability = required` and
`guard = unguarded` without treating every method call as a dereference.
Omitted, ambiguous, or incomplete operation knowledge stays open. The older
`result-contract-uses` wrapper remains available for clients that need one
aggregate row per acquisition, but its counts are not a substitute for the
typed per-operation relation when a finding claims that one particular use was
unsafe.

## Bounded Rewrite Paths

An analyzer that chases a chain of rewrites -- import-alias substitution, specifier rewriting, type-inference delegation -- is supposed to converge, and a cyclic input is what makes it loop forever. Three things make such a chase analysable rather than merely terminating: a *semantic state key* per step, a *declared finite bound*, and an *explicit terminal outcome*. `(rewrite-paths-of ...)` exposes all three as rows.

<!-- code-query-test:rql:rewrite-paths -->
```lisp
(rewrite-paths-of :domain [rust-import-alias] :outcome [cycle]
  (file-of
    (function :name "use_alias")))
```

`:domain` accepts `rust-import-alias`, the only declared domain today: the `use <module> as <alias>` chase in the Rust resolver. Its state key is the *root* of the module specifier, and that choice is the whole point. The rewrite replaces only the root, so the specifier grows on every hop and a whole-string visited set can never trip; the cycle lives in root space, because the binder maps each root to exactly one target. Its declared bound is the importing file's rewritable root count -- the size of the finite space the chase walks, not an arbitrary iteration cap.

`:outcome` accepts `converged`, `cycle` and `exceeded-budget`, and the three say different things. `converged` carries the `fixed_point` the chase stopped on. `cycle` carries the ordered `witness` whose last state repeats its first and closes the loop, which is a concrete counterexample a reader can replay. `exceeded-budget` carries only `explored`: it is *absence of evidence*, so it is never a proven cycle and never a clean convergence, and the termination assert maps it to an inconclusive result rather than to a pass or a finding.

Every row carries the ordered `steps`, each naming its `state_key`, its `input`, its `output` and the `rule` that fired, so the derivation is on the row rather than implied by it. The rows come from the production chase itself, instrumented in place -- there is no second walk of the binder, so a row that says `cycle` says the production resolver met that cycle.

A file no declared domain applies to answers empty and complete: there is nothing the derivation failed to compute. A derivation that genuinely could not run reports `rewrite_domain_unsupported` or `rewrite_path_derivation_incomplete` with `incomplete` impact instead, and never a clean empty answer.

## Caller-Driven Absent-Member Evidence

Given `normalize(value)` accessing `value.strip()` and `read_config()` calling
`normalize(123)`, a Python declaration model can prove that the integer receiver
does not declare `strip`. Inspect its retained caller-to-access evidence with:

<!-- code-query-test:rql:absent-member-witness -->
```lisp
(language python
  (witness :max-steps 32 :max-bytes 16384
    (absent-member
      (procedure-of (function :name "read_config")))))
```

Use `:max-steps 1` to request a one-step prefix. A longer path is explicitly
truncated; unavailable evidence carries its reason, not an invented path.
`file-of` accepts the resulting witness rows. Finding identity is site-based,
while witnesses retain distinct caller contexts. Unknown receivers, open
hierarchies, and incomplete member models block Proven absence findings; only
the explicit Conditional cases below retain a stated remainder.
Missing Python declaration coverage makes the absence query incomplete even
when no procedure is selected. See [the JSON contract](/code-query-json/)
for availability fields and aggregate limits.

The `conditional` proof tier may keep other receiver values as open
alternatives. It may also keep a possible member installation only when every
matching global dynamic write has no receiver bound and an Any member-name
set; the finding condition lists those write sites. A `DeclaredParameter`
origin qualifies only when its annotation resolves to one workspace class with
no workspace subclasses, unresolved or unmodeled external bases, or
attribute hooks such as `__getattr__`, `__getattribute__`, or `__setattr__`.
Its condition states the annotated type and that no workspace subclass exists.

## Registered Typestate Findings and Witnesses

The `typestate` step consumes an exact `procedure` and a namespaced `:protocol-ref`, plus `witness`, which consumes each resulting finding. The connected host must already have registered an in-memory compiled protocol and pre-resolved binding plan for that reference and current workspace generation.

<!-- code-query-test:rql:typestate-witness -->
```lisp
(witness :max-steps 32 :max-bytes 16384
  (typestate :protocol-ref "embedding:resource-lifecycle"
    (procedure-of
      (function :name "lifecycle"))))
```

This lowers to `procedure_of`, `typestate`, and `witness` JSON steps. The optional witness limits are non-negative reductions, so zero requests metadata without step payload. They cannot enlarge host limits, alter finding certainty, or rerun analysis. Findings are diagnostic-neutral: they carry protocol and binding hashes, canonical subject identity, kind, `may`/`must`/`inconclusive` certainty, proof/completeness, uncertainty, exact range, and witness counts—not severity, messages, classifications, or SARIF fields. Witnesses add one semantic evidence object, ordered source-backed steps, and truncation/omission metadata.

The query never accepts protocol paths, query-time bindings, or may/must mode changes. Missing/stale registrations, wrong procedure roots, unsupported/partial semantics, cancellation, and solver/finding/witness budgets remain explicit incomplete diagnostics. Explain mode needs no registration; results and profile resolve the immutable host snapshot before execution.

Only declarations indexed by the active workspace analyzer can appear. A visible usage of library code does not imply that the library declaration itself is indexed or queryable.

RQL is not yet a stable standalone external query API. It is intended to make interactive exploration pleasant while preserving `query_code` and JSON `CodeQuery` as the stable raw-query integration surface. The versioned RQLP schema separately records nested RQL schema resolution as part of a policy's loaded meaning.

## Commands

- `:help` shows command help and examples.
- `:doc <name>` shows documentation for commands, forms, kinds, roles, languages, examples, and row domains.
- `:examples` lists named examples.
- `:example <name>` loads a named example.
- `:kinds`, `:roles`, and `:languages` list the current vocabulary.
- `:ir <language>` captures source through `:end` and prints Rune IR plus starter RQL without indexing a workspace.
- `:validate` validates the current query without running it.
- `:json` prints canonical JSON for the current query.
- `:run` executes the current query.
- `:clear` clears the current query.
- `:quit` or `:exit` exits the REPL.

Press `Ctrl+C` once to cancel reflexively; press it twice in a row to quit.
