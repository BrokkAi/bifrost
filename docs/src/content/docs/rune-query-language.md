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

Every RQL expression lowers into [JSON `CodeQuery`](/code-query-json/) before validation and execution. MCP hosts with `query_code` call the same engine using canonical JSON inline, or they can load a complete saved `.rql` file through the exclusive `query_file` argument. MCP does not accept raw inline RQL, and the `core` toolset does not expose `query_code`; use `symbol|extended` or `searchtools`. See [MCP query and RQL availability](/mcp/#query-and-rql-availability) for the complete surface matrix and [Code Querying](/code-querying/) for the schema and engine overview.

RQL omits a schema version by default and therefore targets the compatible head, currently CodeQuery schema version 7. Use a root `:schema-version 2` through `:schema-version 6` option to pin an earlier vocabulary; explicit older versions reject later forms.

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

Use `:ir <language>` for the opposite direction: paste source code through a line containing only `:end`, then inspect the [Rune IR](/rune-ir/) produced by that language's real structural adapter and copy the generated starter RQL. Use the `tsx` language label for TypeScript snippets containing JSX. Rune IR is the normalized source-side representation matched by `CodeQuery`; it is not RQL's query-side IR.

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

Head symbols such as `call`, `function`, `class`, and `import` map to normalized structural kinds. Keyword fields such as `:callee`, `:args`, `:module`, and `:decorators` map to normalized roles.

Predicate forms constrain fields on a pattern:

```lisp
(name "handler")
(name/regex ".*Service")
(text/regex "eval\\(")
(capture "argument")
(has (call :callee (name "open")))
(not-has (call :callee (name "eval")))
(not-kind lambda)
```

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

`explain` lowers and selects a plan without scanning workspace data. `profile` executes and returns the ordinary result plus structured measurements. They are mutually exclusive root controls and are not legal inside policy selectors. See [Explain and Profile CodeQuery](/code-query-explain-profile/) for the response schemas and measured production scheduling policy.

Pipeline wrappers transform the result domain. Inner wrappers execute first:

```lisp
(enclosing-decl (call :callee (name "audit")))
(file-of (function :name "handle"))
(imports-of (file-of (function :name "handle")))
(importers-of (importers-of (file-of (function :name "target"))))
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
(receiver-targets (call :callee "run" :receiver "service"))
(points-to :capture receiver (call :receiver (capture "receiver")))
(member-targets (references-of :proof proven (enclosing-decl (method :name "run"))))
(procedure-of (function :name "run"))
(cfg-entry (procedure-of (function :name "run")))
(cfg-exits (procedure-of (function :name "run")))
(cfg-successor-edges (cfg-entry (procedure-of (function :name "run"))))
(cfg-predecessor-edges (cfg-exits (procedure-of (function :name "run"))))
(cfg-edge-source (cfg-successor-edges (cfg-entry (procedure-of (function :name "run")))))
(cfg-edge-target (cfg-successor-edges (cfg-entry (procedure-of (function :name "run")))))
```

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

The fourth expression performs two direct reverse-import hops. Hierarchy traversal is direct when no option is supplied; `:depth N` returns the one-through-N closure, and `:transitive true` returns the full indexed closure under the execution budget. Call traversal is also direct by default and accepts finite `:depth N`, but not `:transitive`. `callers :proof proven :completeness proven-subset` is the one explicit non-exhaustive contract: it returns only resolved proven caller edges and labels the result as a proven subset, never as all callers. It remains diagnostic-visible when a caller cannot be rendered as an indexed declaration, and is rejected without `:proof proven` or on `callees`. `call-input` requires exactly one receiver, parameter-index, or parameter-name selector. `members` returns direct declarations and `owner` recovers their exact declaring type. Reference and call proof options may appear before the nested query. Receiver wrappers produce terminal `receiver_analysis` rows; only `file-of` may wrap them. Their optional `:capture name` is legal only over a structural match and must name a declared positive capture. Procedure, program-point, control-edge, and receiver-analysis rows may all be projected through `file-of`. `:json` renders every wrapper as an ordered `steps` array.

Receiver wrappers consume the structured facts exposed by the selected adapter. Availability is not defined by a static language list: unsupported source forms preserve an explicit `unsupported` row and capability diagnostic. See [Receiver Traversal](/code-query-tutorials/receiver-traversal/) for allocation, factory, ambiguity, reference-site, and call-input examples with exact output.

## Procedure-Local CFG Inspection

Schema version 3 adds an explicit typed control-flow algebra. `procedure-of` resolves the unique smallest source-backed executable procedure containing a structural match or declaration. `cfg-entry` and `cfg-exits` return validated boundary points. The successor and predecessor forms each traverse exactly one edge, and `cfg-edge-source` or `cfg-edge-target` projects an edge back to a point.

<!-- code-query-test:rql:cfg-entry-successor -->
```lisp
(cfg-edge-target
  (cfg-successor-edges
    (cfg-entry
      (procedure-of
        (language typescript
          (function :name "run"))))))
```

This returns `program_point` rows for targets of edges leaving `run`'s entry. Procedure, point, and edge rows include checkout-independent content-scoped IDs, exact source ranges, mandatory proof/completeness evidence, and normal CodeQuery provenance. Unsupported capabilities, partial semantic artifacts, cancellation, and exhausted budgets remain explicit diagnostics and cannot produce a falsely complete empty answer.

Semantic materialization is lazy and request-scoped. It has separate finite limits of 256 materialized files, 16 MiB of source, 1,000,000 rows per semantic dimension, 64 MiB retained semantic data, and 1,000,000 traversal steps. Repeating an edge form is how an authored query asks for another hop; no form silently computes an unbounded closure.

This schema-v3 surface is a procedure-local CFG inspection API. It does not cross call boundaries and does not provide an ICFG, data-flow, taint, typestate, finding, or witness engine. Schema v4 adds only the registered typestate adapter below.

Schema v5 adds `inside-decl`: containment that can match an enclosing callable itself, but stops before searching beyond a non-matching nested function, method, constructor, or lambda. Ordinary `inside` remains lexical and can cross those boundaries.

Schema v6 adds `(value-flow :plan-ref namespace:name query)`, mapping procedure rows to diagnostic-neutral flow endpoints backed by a host-registered `ValueFlowPlan`. `(witness ...)` also accepts flow endpoints and returns retained bounded flow paths. Endpoint reachability, exact/may certainty, ambiguity, completion, and solver-budget status remain separate fields; no policy classification is implied.

<!-- code-query-test:rql:value-flow-witness -->
```lisp
(witness :max-steps 32 :max-bytes 16384
  (value-flow :plan-ref "embedding:request-to-sink"
    (procedure-of (method :name "run"))))
```

Schema v7 adds `(taint :taint-ref namespace:name query)`. It maps exact procedure rows to `taint_finding` rows by projecting an immutable production result already registered by the host:

```lisp
(taint :taint-ref "request:http-to-database"
  (procedure-of (method :name "run")))
```

The form cannot load or compile policies, invoke propagation, reconstruct witnesses, or add classification. With matching limits its rows are field-for-field equal to the production outcome's public taint findings.

Schema v8 adds the occurrence domain. `(occurrences ...)` is a source in its own right, and `(occurrences-in ...)`, `(occurrences-of ...)` and `(occurrence-target ...)` are wrappers. `:class`, `:role`, and `:namespace` each accept one label or a vector of labels:

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

Containment for occurrences is `occurrences-in` over a structural query rather than `(inside ...)` on the source, so there is exactly one lexical-containment verifier. A language that has not declared support for a role a query names makes the run incomplete rather than answering it with zero rows.

## Registered Typestate Findings and Witnesses

Schema version 4 adds `typestate`, which consumes an exact `procedure` and a namespaced `:protocol-ref`, plus `witness`, which consumes each resulting finding. The connected host must already have registered an in-memory compiled protocol and pre-resolved binding plan for that reference and current workspace generation.

<!-- code-query-test:rql:typestate-witness -->
```lisp
(witness :max-steps 32 :max-bytes 16384
  (typestate :protocol-ref "embedding:resource-lifecycle"
    (procedure-of
      (function :name "lifecycle"))))
```

This lowers to `procedure_of`, `typestate`, and `witness` JSON steps. The optional witness limits are non-negative reductions, so zero requests metadata without step payload. They cannot enlarge host limits, alter finding certainty, or rerun analysis. Findings are diagnostic-neutral: they carry protocol and binding hashes, canonical subject identity, kind, `may`/`must`/`inconclusive` certainty, proof/completeness, uncertainty, exact range, and witness counts—not severity, messages, classifications, or SARIF fields. Witnesses add ordered source-backed steps and truncation/omission metadata.

The query never accepts protocol paths, query-time bindings, or may/must mode changes. Missing/stale registrations, wrong procedure roots, unsupported/partial semantics, cancellation, and solver/finding/witness budgets remain explicit incomplete diagnostics. Explain mode needs no registration; results and profile resolve the immutable host snapshot before execution.

Only declarations indexed by the active workspace analyzer can appear. A visible usage of library code does not imply that the library declaration itself is indexed or queryable.

RQL is not yet a stable standalone external query API. It is intended to make interactive exploration pleasant while preserving `query_code` and JSON `CodeQuery` as the stable raw-query integration surface. The versioned RQLP schema separately records nested RQL schema resolution as part of a policy's loaded meaning.

## Commands

- `:help` shows command help and examples.
- `:doc <name>` shows documentation for commands, forms, kinds, roles, languages, and examples.
- `:examples` lists named examples.
- `:example <name>` loads a named example.
- `:kinds`, `:roles`, and `:languages` list the current vocabulary.
- `:ir <language>` captures source through `:end` and prints Rune IR plus starter RQL without indexing a workspace.
- `:validate` validates the current query without running it.
- `:json` prints canonical JSON for the current query.
- `:run` executes the current query.
- `:clear` clears the current query.
- `:quit` exits the REPL.

Press `Ctrl+C` once to cancel reflexively; press it twice in a row to quit.
