---
title: Policy Reference
description: Lookup tables for RQLP policy documents, the built-in policy catalog, policy selection, exit status, report formats, diagnostic codes, and review files.
---

This page lists every part of the static-analysis policy surface. It is a
lookup page. For a guided introduction, read
[Static-Analysis Policies](/static-analysis-policies/) first.

The tables come from the engine's registries: the RQLP schema registry, the
four built-in pack manifests, the report and SARIF renderers, and the review
file loaders. The binary can print some of these lists itself:

| Command | Prints |
| --- | --- |
| `bifrost --list-policies` | The built-in policy catalog as JSON: every pack and every policy with its ID, category, languages, required capabilities, hashes, and activation. |
| `bifrost scan --list-builtin-policies` | The same catalog. |
| `bifrost --version` | One `builtin-policy-pack ID@VERSION policies=N` line per pack and one `builtin-policy-catalog sha256=HEX` line. |
| `bifrost --list-row-schemas` | The row domains and fields that a relational assertion plan can bind (`bind`, `join`, `group`, `aggregate`). |
| MCP `list_policies` | The same catalog as `--list-policies`. |

`--list-policies` and `--list-row-schemas` cannot be combined with policy
selection or evaluation options.

## Built-in catalog source

The binary embeds four policy packs. Setting the environment variable
`BIFROST_POLICY_PACK_ROOT` to a directory replaces the embedded catalog
for every policy surface: `--list-policies`, `--version`, `bifrost scan`,
default runs, built-in selectors, and MCP. The directory must contain one
subdirectory per pack. Each subdirectory name must equal the pack ID and must
contain a `manifest.json` and the `policies/*.rqlp` files it lists. Bifrost
verifies each manifest and each policy's authored hash. An empty value, an
empty directory, a symlink, a malformed manifest, or a hash mismatch is an
error, and Bifrost does not fall back to the embedded catalog.

## Policy selection

The CLI and MCP select built-in policies with three selectors and add
workspace policies by file path.

| CLI flag | MCP `run_policy` field | Value |
| --- | --- | --- |
| `--policy-pack ID` | `policy_packs` | A built-in pack ID. |
| `--policy-category NAME` | `policy_categories` | A built-in category: `correctness`, `performance`, `security`, or `effects`. |
| `--policy-id ID` | `policy_ids` | A built-in policy ID. |
| `--policy-file PATH` | `policy_files` | A workspace-relative `.rqlp` policy file. |

Each CLI flag is repeatable. Each MCP field is an array of unique strings with
at least one item. MCP `explain_policy` accepts the same four fields.

These rules decide which built-in policies run:

1. Values of one selector form a union. `--policy-pack bifrost.code-smells
   --policy-pack bifrost.security` selects both packs.
2. Different selectors intersect. A built-in policy runs only when it matches
   every selector that has a value. `--policy-pack bifrost.code-smells
   --policy-category performance` runs the performance policies of that pack.
   `--policy-pack P --policy-id I` runs policy `I` only.
3. A value that names no known pack, category, or policy ID is an error, for
   example ``unknown built-in policy pack `nope` ``. A combination that matches
   no policy is also an error: `built-in policy selection matches no policy`.
   Both exit with status 2.
4. A policy whose catalog `activation` is `opt-in` runs only when
   `--policy-id` or `policy_ids` names it. Pack and category selectors, the
   default run, and `bifrost scan` never select an opt-in policy. Every other
   policy has activation `default`.
5. On the CLI, a policy invocation with no `--policy-file` and no built-in
   selector runs every built-in pack. `bifrost --root . --policy` is the plain
   form, and `bifrost scan [PATH]` does the same. Any `--policy-file` or
   built-in selector replaces this default.
6. `--policy-file` inputs run beside the selected built-in policies. With only
   `--policy-file`, no built-in policy runs. `--no-builtin-policies` states
   this explicitly: it requires at least one `--policy-file` and rejects
   `--policy-pack`, `--policy-category`, and `--policy-id`.
7. MCP `run_policy` has no default. At least one of the four fields is
   required.
8. When two inputs define the same policy ID, Bifrost excludes every
   definition and reports `duplicate-policy-id`. This includes a copied
   built-in policy that keeps its ID and is run beside the built-in pack.
9. Built-in policies run and appear in the report in catalog order.

### Policy-mode option rules

The full flag syntax is in the [CLI reference](/reference/cli/). These rules
apply to policy mode:

- Policy options cannot be combined with `--install`, `--query-file`,
  `--tool`, `--args`, `--mcp`, `--repl`, `--no-line-numbers`,
  `--workspace-scaled-limits`, or `--diff-snapshot-object-dir`.
- `--sources PATH` restricts policy evaluation to the named files,
  directories, or globs. It is repeatable.
- `--accept-current` cannot be combined with `--fail-on` or `--diff-base`.
- `--explain-finding`, `--explain-candidate`, and `--explain-near-misses`
  exclude each other. None can be combined with `--format`, `--fail-on`,
  `--suppressions-file`, `--scope-file`, `--baseline-file`,
  `--accept-current`, `--evaluation-date`, `--diff-base`, `--policy-timings`, `--policy-cost-hints`,
  `--verbose`, `--color`, or `--sources`. An explanation needs an explicit
  `--policy-file` or built-in selector, and the selection must resolve to one
  policy. `--explain-near-misses N` accepts 1 to 64.
- `--explain-generation HEX` requires one of the three explanation flags.
- `--verbose` and `--color` require `--format human`.
- `--policy-cost-hints <path>` reads a JSON object mapping non-empty policy IDs
  to non-negative integer milliseconds. Parallel batches start unknown policies
  first, then hinted policies from longest to shortest; hints never change the report.
- `--policy-timings` adds each policy's elapsed evaluation time to its report
  work metrics. It also prints the stage timings to standard error as one
  JSON object after the text `bifrost: policy stage timings`.

## Built-in policy catalog

The tables below list every policy in the embedded catalog, in catalog order.
The catalog has four packs and 71 policies. Run `bifrost --list-policies` to
print the catalog of the binary you have.

Categories are the values that `--policy-category` and `policy_categories`
accept, and that scope entries can name in `policy_categories`:

| Category | Packs |
| --- | --- |
| `correctness` | `bifrost.code-smells`, `bifrost.correctness` |
| `performance` | `bifrost.code-smells` |
| `security` | `bifrost.security` |
| `effects` | `bifrost.effects` |

The policy ID prefix (`bifrost.correctness.`, `bifrost.performance.`) is part
of the stable ID. It does not name the pack. For example,
`bifrost.correctness.dynamic-evaluation` is in the `bifrost.code-smells` pack.

### Catalog JSON fields

`bifrost --list-policies` prints `{"schema_version": 2, "packs": [...]}`. Each
pack object has these fields:

| Field | Meaning |
| --- | --- |
| `schema_version` | Manifest schema version, currently `2`. |
| `id` | Pack ID. |
| `version` | Pack version. |
| `name`, `description` | Human-readable pack name and summary. |
| `policies` | The pack's policies, in catalog order. |

Each policy object has these fields:

| Field | Meaning |
| --- | --- |
| `path` | Path of the policy source inside the pack, for example `policies/dynamic-evaluation.rqlp`. |
| `id` | Stable policy ID. Use it with `--policy-id`, `policy_ids`, suppressions, and scope entries. |
| `authored_hash`, `resolved_semantic_hash` | SHA-256 semantic hashes of the policy as authored and as resolved. |
| `category` | One of the four categories above. |
| `supported_languages` | Languages the policy claims. |
| `required_capabilities` | Analyzer capabilities the policy depends on. A policy that requires a capability this engine does not provide is reported as `not_run`. |
| `severity_rationale` | Why the policy has its severity. |
| `remediation` | What to do about a finding. |
| `activation` | `default` or `opt-in`. See [Policy selection](#policy-selection). |

### `bifrost.code-smells`

Version 2.16.0, 31 policies. Manifest description: Curated structured RQLP checks for bug-prone and potentially expensive source patterns.

| Policy ID | Category | Severity | Analysis | Languages | Activation | Reports |
| --- | --- | --- | --- | --- | --- | --- |
| `bifrost.correctness.contradictory-condition` | `correctness` | `warning` | `assertion` | `java`, `javascript`, `typescript`, `python`, `go` | `default` | A condition has a fixed truth value under proven scalar facts, so one arm cannot run. |
| `bifrost.correctness.discarded-pure-result` | `correctness` | `warning` | `assertion` | `java` | `default` | The result of the exact JDK 21 `String.trim()` call is discarded. |
| `bifrost.correctness.dynamic-evaluation` | `correctness` | `warning` | `match` | `python`, `javascript`, `typescript` | `default` | A call named `eval` or `exec` (Python) or `eval` or `Function` (JavaScript, TypeScript). |
| `bifrost.correctness.identical-conditional-branches` | `correctness` | `warning` | `assertion` | `java`, `javascript`, `typescript`, `python`, `rust`, `scala`, `php`, `ruby`, `kotlin`, `csharp`, `go`, `c`, `cpp` | `default` | Two arms of one conditional have equivalent bodies under proven reference identities. |
| `bifrost.correctness.ignored-status-result` | `correctness` | `note` | `assertion` | `java` | `default` | The Boolean status of the exact JDK 21 `Files.deleteIfExists(Path)` call is discarded. |
| `bifrost.correctness.repeated-branch-condition` | `correctness` | `warning` | `assertion` | `java`, `javascript`, `typescript`, `python`, `rust`, `scala`, `php`, `ruby`, `kotlin`, `csharp`, `go`, `c`, `cpp` | `default` | A later `if`/`else if` condition repeats an earlier one whose tested values cannot have changed. |
| `bifrost.correctness.redundant-boolean-branches` | `correctness` | `warning` | `assertion` | `java`, `javascript`, `typescript`, `python`, `rust`, `scala`, `php`, `ruby`, `csharp`, `kotlin`, `go`, `c`, `cpp` | `default` | The two paths of a conditional return opposite Boolean literals with no other work. |
| `bifrost.correctness.unsafe-deserialization` | `correctness` | `warning` | `match` | `python` | `default` | A call to `pickle.loads` or `pickle.load`. |
| `bifrost.correctness.python-absent-member` | `correctness` | `error` | `assertion` | `python` | `default` | A Python receiver can hold a fully classified class whose complete member surface lacks the accessed member. |
| `bifrost.correctness.python-absent-member-conditional` | `correctness` | `warning` | `assertion` | `python` | `default` | Other receiver values may remain unknown; listed global writes qualify only with no receiver bound and an Any member-name set. A declared parameter qualifies only for one annotated workspace class with no workspace subclasses, unresolved or unmodeled external bases, or attribute hooks. The finding states these conditions. |
| `bifrost.correctness.go-nil-dereference` | `correctness` | `error` | `assertion` | `go` | `default` | A Go dereference, field access, or reviewed receiver operation is reached with a `Nil` or `MaybeNil` fact. |
| `bifrost.correctness.go-wrong-error-on-failure-path` | `correctness` | `error` | `assertion` | `go` | `default` | On the exact failure path of a reviewed Go API, a returned call consumes a different error binding whose value is nil. |
| `bifrost.correctness.empty-failure-handler` | `correctness` | `warning` | `assertion` | `java`, `javascript`, `typescript`, `python`, `csharp`, `php`, `cpp`, `kotlin`, `ruby` | `default` | A `catch`, `except`, or `rescue` clause has no statements other than comments, empty statements, `pass`, or `...`. |
| `bifrost.correctness.c-self-assignment` | `correctness` | `warning` | `assertion` | `c` | `default` | A C assignment writes an initialized primitive local back to itself. |
| `bifrost.correctness.local-self-assignment` | `correctness` | `warning` | `assertion` | `java`, `javascript`, `typescript`, `python`, `csharp`, `kotlin`, `go`, `rust` | `default` | A direct assignment reads and writes the same initialized local binding. |
| `bifrost.correctness.failed-swap` | `correctness` | `warning` | `assertion` | `java`, `javascript`, `typescript`, `python`, `csharp`, `kotlin`, `go`, `rust` | `default` | Two adjacent local assignments `a = b; b = a` copy the first value back. |
| `bifrost.correctness.overwritten-unread-value` | `correctness` | `warning` | `assertion` | `java`, `javascript`, `typescript`, `python`, `go`, `csharp`, `kotlin`, `rust` | `default` | A local value is replaced on every path before it is read. |
| `bifrost.correctness.loop-body-never-repeats` | `correctness` | `warning` | `assertion` | `java`, `javascript`, `typescript`, `python`, `csharp`, `kotlin`, `go`, `rust`, `php` | `default` | Every path through a `while`, `for`, or `do` loop body leaves before the next iteration. |
| `bifrost.correctness.unreachable-statement` | `correctness` | `warning` | `assertion` | `java`, `javascript`, `typescript`, `python`, `csharp`, `kotlin`, `go`, `rust`, `php` | `default` | A statement inside a callable cannot be reached from the callable entry. |
| `bifrost.performance.loop-invariant-sort` | `performance` | `warning` | `assertion` | `rust`, `python`, `java`, `typescript`, `javascript` | `default` | A sort call inside a loop sorts a receiver whose value is established outside the loop. |
| `bifrost.performance.regex-compile-in-loop` | `performance` | `note` | `assertion` | `python`, `java`, `javascript`, `typescript`, `rust` | `default` | Review prompt: regular-expression compilation is written inside a loop. |
| `bifrost.performance.file-read-in-loop` | `performance` | `note` | `assertion` | `python`, `java`, `javascript`, `typescript`, `rust` | `default` | Review prompt: a file read is written inside a loop. |
| `bifrost.performance.serialization-in-loop` | `performance` | `note` | `assertion` | `python`, `java`, `javascript`, `typescript`, `rust` | `default` | Review prompt: serialization is written inside a loop. |
| `bifrost.performance.parsing-in-loop` | `performance` | `note` | `assertion` | `python`, `java`, `javascript`, `typescript`, `rust` | `default` | Review prompt: a parse call is written inside a loop. |
| `bifrost.performance.database-call-in-loop` | `performance` | `note` | `assertion` | `python`, `java`, `javascript`, `typescript` | `default` | Review prompt: a database call is written inside a loop. |
| `bifrost.performance.network-call-in-loop` | `performance` | `note` | `assertion` | `python`, `java`, `javascript`, `typescript`, `rust` | `default` | Review prompt: a network request is written inside a loop. |
| `bifrost.performance.subprocess-in-loop` | `performance` | `note` | `assertion` | `python`, `java`, `javascript`, `typescript` | `default` | Review prompt: a subprocess launch is written inside a loop. |
| `bifrost.performance.sleep-in-loop` | `performance` | `note` | `assertion` | `python`, `java`, `rust` | `default` | Review prompt: a sleep call is written inside a for-each loop. |
| `bifrost.performance.expensive-operation-in-nested-loop` | `performance` | `note` | `assertion` | `python`, `java`, `javascript`, `typescript`, `rust` | `default` | Review prompt: an expensive operation is written inside two nested loops. |
| `bifrost.correctness.rayon-in-blocking-lazy-init` | `correctness` | `warning` | `match` | `rust` | `default` | Review prompt: a blocking Rust lazy initializer contains rayon parallelism, which can self-deadlock. |

### `bifrost.correctness`

Version 0.1.0, 1 policy. Manifest description: Selectable lifecycle and ownership policies over reviewed acquisition families.

| Policy ID | Category | Severity | Analysis | Languages | Activation | Reports |
| --- | --- | --- | --- | --- | --- | --- |
| `bifrost.correctness.resource-lifecycle` | `correctness` | `error` | `typestate` | `go`, `java`, `javascript`, `kotlin`, `php`, `python`, `rust`, `scala`, `typescript` | `default` | A resource from the reviewed acquisition family reaches a normal or exceptional exit of its acquiring procedure while still open. |

### `bifrost.security`

Version 1.3.0, 29 policies. Manifest description: High-precision security policies backed by exact structural identity and value-flow evidence.

| Policy ID | Category | Severity | Analysis | Languages | Activation | Reports |
| --- | --- | --- | --- | --- | --- | --- |
| `bifrost.security.java.servlet-parameter-to-jdbc` | `security` | `error` | `taint` | `java` | `default` | `ServletRequest.getParameter(String)` reaches the SQL operand of `Statement.execute(String)` or `Statement.executeQuery(String)`. |
| `bifrost.security.java.system-getenv-to-runtime-exec` | `security` | `error` | `taint` | `java` | `default` | `System.getenv(String)` reaches the command operand of `Runtime.exec(String)`. |
| `bifrost.security.python.process-input-to-os-system` | `security` | `error` | `taint` | `python` | `default` | `os.environ` or `sys.argv` reaches the command operand of `os.system`. |

The declared-storage family has two policies per language. Every row is category `security`, activation `opt-in`, and has one language.

| Language | `stored-request-to-sql` (`taint`, `error`) | `store-requires-validation` (`flow`, `warning`) | Source display name | Sink display name |
| --- | --- | --- | --- | --- |
| C | `bifrost.security.c.stored-request-to-sql` | `bifrost.security.c.store-requires-validation` | request parameter | sqlite3 exec SQL |
| C++ | `bifrost.security.cpp.stored-request-to-sql` | `bifrost.security.cpp.store-requires-validation` | request parameter | sqlite3 exec SQL |
| C# | `bifrost.security.csharp.stored-request-to-sql` | `bifrost.security.csharp.store-requires-validation` | Request.Query get | SQL ExecuteRaw |
| Go | `bifrost.security.go.stored-request-to-sql` | `bifrost.security.go.store-requires-validation` | Request.FormValue | sql.Exec SQL |
| Java | `bifrost.security.java.stored-request-to-sql` | `bifrost.security.java.store-requires-validation` | ServletRequest.getParameter(String) | Statement.execute(String) SQL |
| JavaScript | `bifrost.security.javascript.stored-request-to-sql` | `bifrost.security.javascript.store-requires-validation` | Express req.param | pg Client.query SQL |
| Kotlin | `bifrost.security.kotlin.stored-request-to-sql` | `bifrost.security.kotlin.store-requires-validation` | call.parameters get | Statement.execute SQL |
| PHP | `bifrost.security.php.stored-request-to-sql` | `bifrost.security.php.store-requires-validation` | request parameter | mysqli query SQL |
| Python | `bifrost.security.python.stored-request-to-sql` | `bifrost.security.python.store-requires-validation` | Flask request.args.get | sqlite3 Cursor.execute SQL |
| Ruby | `bifrost.security.ruby.stored-request-to-sql` | `bifrost.security.ruby.store-requires-validation` | params.fetch | connection.execute SQL |
| Rust | `bifrost.security.rust.stored-request-to-sql` | `bifrost.security.rust.store-requires-validation` | request query value | SQL execute |
| Scala | `bifrost.security.scala.stored-request-to-sql` | `bifrost.security.scala.store-requires-validation` | request queryString get | Statement.execute SQL |
| TypeScript | `bifrost.security.typescript.stored-request-to-sql` | `bifrost.security.typescript.store-requires-validation` | Express req.param | pg Client.query SQL |

### `bifrost.effects`

Version 2.0.0, 10 policies. Manifest description: Configurable forbidden-network-effect specializations. Each policy asserts that every declaration a reviewed declaration-selection document selects reaches no declared network effect, directly or through workspace helpers. The effect is declared by a reviewed semantic model on the exact API identity; purity is never inferred from a name, a file name, a comment, or an unqualified annotation. The policies are opt-in, and a missing or invalid selection document fails activation instead of passing.

Every row is category `effects`, severity `error`, analysis `assertion`, activation `opt-in`, and has one language. Each policy imports its selection from `.bifrost/effect-boundaries/<language>-network-io.rqlp` and requires the `declaration-selection-imports` capability.

| Policy ID | Language |
| --- | --- |
| `bifrost.effects.csharp.selected-boundary-no-network-io` | C# |
| `bifrost.effects.go.selected-boundary-no-network-io` | Go |
| `bifrost.effects.java.selected-boundary-no-network-io` | Java |
| `bifrost.effects.javascript.selected-boundary-no-network-io` | JavaScript |
| `bifrost.effects.kotlin.selected-boundary-no-network-io` | Kotlin |
| `bifrost.effects.python.selected-boundary-no-network-io` | Python |
| `bifrost.effects.ruby.selected-boundary-no-network-io` | Ruby |
| `bifrost.effects.rust.selected-boundary-no-network-io` | Rust |
| `bifrost.effects.scala.selected-boundary-no-network-io` | Scala |
| `bifrost.effects.typescript.selected-boundary-no-network-io` | TypeScript |

## RQLP vocabulary

RQLP has one document schema version, `1`. Nested RQL selectors also have one
schema version, `1`. Omitting a version selects `1`. Pinning any other value
fails with `unsupported-policy-schema-version` or
`unsupported-rql-schema-version`.

A `.rqlp` file holds exactly one top-level document: `policy`, `endpoint`,
`endpoint-set-document`, or `declaration-selection-document`. Only `policy` is
executable. A record is a
parenthesized form whose first symbol is its label. Keyword fields are written
`:name value`. Each field may appear at most once in a record.

How to read the field tables:

- **Required** is relative to the place where the field is legal. For example,
  `:sources` is required in a `taint` analysis and is not legal in a `match`
  analysis.
- **Legal in** names the documents and analysis types that accept the record
  or field. "Policy, `taint`" means a policy document whose
  `(analysis :type taint)`. Inside an `endpoint-set-document`, the entry
  records of the declared `:kind` are legal.
- **Value** describes the accepted value. A set has no duplicates and a list
  keeps source order; both give their item limits.
- Some labels name more than one record, for example `all`, `any`,
  `assert`, `transform`, and `finding-combination`. The parent field decides
  which record applies. The headings below name the context.

### Documents and imports

#### `policy`

```lisp
(policy [:schema-version N] :id ID :name NAME :message MESSAGE :severity SEVERITY :analysis ANALYSIS ...)
```

Define one executable static-analysis policy. Top-level document of a policy file.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:schema-version` | optional | a supported positive schema version | `:schema-version N`. Pin the RQLP version exactly; omission selects the compatible lineage head. |
| `:id` | required | a stable lowercase policy identifier | `:id "lowercase.policy-id"`. Set the stable opaque policy and SARIF rule identity. |
| `:name` | required | a bounded human-readable name | `:name "Human name"`. Set the human-readable policy name. |
| `:message` | required | a static string or generated-message record | `:message "text" \| (generated-message ...)`. Set static finding text or the taint-only generated relation. |
| `:severity` | required | note, warning, error, unrated, or a cvss-severity record | `:severity note\|warning\|error\|unrated\|(cvss-severity ...)`. Set the policy reporting severity without changing analyzer certainty. |
| `:description` | optional | bounded human-readable descriptive text | `:description "text"`. Add bounded descriptive text. |
| `:help-uri` | optional | an absolute HTTP or HTTPS URI | `:help-uri "https://..."`. Link to absolute HTTP(S) remediation help. |
| `:tags` | optional | policy tags; set (no duplicates) of 0 to 64 items | `:tags [TAG...]`. Attach a duplicate-free set of bounded policy tags. |
| `:analysis` | required | an analysis record whose fields agree with its explicit type | `:analysis (analysis ...)`. Provide the explicitly typed diagnostic-neutral analysis declaration. |
| `:classification` | optional | a classification record | `:classification (classification ...)`. Add broad/refined taxonomy and optional CVSS policy. |
| `:report` | optional | a report record | `:report (report ...)`. Override bounded report retention defaults. |

#### `endpoint`

```lisp
(endpoint [:schema-version N] :id ID :name NAME :display-name TEXT :role source|sink ...)
```

Define one diagnostic-neutral reusable source or sink endpoint. Top-level document of a reusable endpoint file.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:schema-version` | optional | a supported positive schema version | `:schema-version N`. Pin the endpoint document version exactly. |
| `:id` | required | a stable lowercase endpoint identifier | `:id "lowercase.endpoint-id"`. Set the stable endpoint identity. |
| `:name` | required | a bounded human-readable name | `:name "Human name"`. Set the endpoint's human-readable name. |
| `:display-name` | required | bounded human-readable display text | `:display-name "Generated-message phrase"`. Set the phrase used verbatim in generated relationship messages. |
| `:description` | optional | bounded human-readable descriptive text | `:description "text"`. Add bounded endpoint description text. |
| `:help-uri` | optional | an absolute HTTP or HTTPS URI | `:help-uri "https://..."`. Link to absolute HTTP(S) endpoint documentation. |
| `:role` | required | source or sink | `:role source\|sink`. Declare whether the endpoint supplies or consumes a value. |
| `:categories` | required | opaque exact endpoint categories; set (no duplicates) of 1 to 64 items | `:categories [CATEGORY...]`. Attach opaque exact categories for explicit set composition. |
| `:selector` | required | an inline rql or deferred rql-file selector | `:selector (rql ...)\|(rql-file ...)`. Select the endpoint's diagnostic-neutral code sites. |
| `:binding` | required | matched-value, receiver, return-value, an indexed result record, or an argument record | `:binding matched-value\|receiver\|return-value\|(result :index N)\|(argument ...)`. Bind the selected matched value, receiver, singular return, indexed normal result, or argument. |
| `:taint` | optional | source-semantics or sink-semantics matching the endpoint role | `:taint (source-semantics ...)\|(sink-semantics ...)`. Optionally attach role-compatible taint semantics. |
| `:supersedes` | optional | endpoint identifiers; set (no duplicates) of 0 to 64 items | `:supersedes [ENDPOINT-ID...]`. Declare explicit same-event dominance edges. |

#### `endpoint-set-document`

```lisp
(endpoint-set-document [:schema-version N] :kind KIND [:language LANGUAGE] [:rql-schema-version N] :set (endpoint-set ...))
```

Define one standalone typed endpoint-set document for nested policy imports. Top-level document of an endpoint-set file.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:schema-version` | optional | a supported positive schema version | `:schema-version N`. Pin the standalone endpoint-set document version exactly. |
| `:kind` | required | one typed taint or value-flow endpoint-set kind | `:kind sources\|sinks\|sanitizers\|entry-points\|transforms\|external-models\|stores\|origins\|observations\|kills\|flow-transforms`. Declare the exact entry family accepted by this standalone document. |
| `:language` | optional | one or more public analyzer language labels or family aliases | `:language LANGUAGE`. Provide one inherited analyzer language default for selectors in this document. |
| `:rql-schema-version` | optional | a supported positive schema version | `:rql-schema-version N`. Provide one inherited RQL schema version default for selectors in this document. |
| `:set` | required | an endpoint-set record | `:set (endpoint-set ...)`. Provide the typed endpoint-set contents. |

#### `endpoint-set-file`

```lisp
(endpoint-set-file :path "workspace-relative.rqlp" [:sha256 HEX])
```

Reference one nested typed endpoint-set document by workspace-relative path. Legal in: policy, `taint` or `flow`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:path` | required | a validated workspace-relative path | `:path "workspace-relative.rqlp"`. Name one workspace-relative endpoint-set document. |
| `:sha256` | optional | a lowercase 64-hex SHA-256 value | `:sha256 "64-lower-hex"`. Optionally pin the imported endpoint-set semantic content hash. |

#### `declaration-selection-document`

```lisp
(declaration-selection-document [:schema-version N] :language LANGUAGE [:rql-schema-version N] :declarations [(rql ...)...])
```

Define one standalone reviewed set of exact declarations for a policy to import. Top-level document of a declaration-selection file.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:schema-version` | optional | a supported positive schema version | `:schema-version N`. Pin the standalone declaration-selection document version exactly. |
| `:language` | required | one public analyzer language label | `:language LANGUAGE`. Declare the one analyzer language of every selected declaration; it must equal the importing reference's language. A family alias such as `jvm` is rejected. |
| `:rql-schema-version` | optional | a supported positive schema version | `:rql-schema-version N`. Provide one inherited RQL schema version default for selectors in this document. |
| `:declarations` | required | one or more inline rql exact declaration selectors; set (no duplicates) of 1 to 16 items | `:declarations [(rql (enclosing-decl ...))...]`. List the exact declarations: each an inline enclosing-decl selector of a function, method, or class with an exact name, optionally inside one exactly named owner. |

An entry that is not exactly `(enclosing-decl DECLARATION)` or
`(enclosing-decl (inside-decl OWNER DECLARATION))` over a `function`, `method`,
or `class` pattern with an exact `:name` fails with
`declaration-selection-not-exact`; an entry of another language fails with
`declaration-selection-wrong-language`; an empty list fails with
`declaration-selection-empty`; and a nested `rql-file`,
`declaration-selection-file`, or `endpoint-set-file` fails with
`declaration-selection-nested-import`.

#### `declaration-selection-file`

```lisp
(declaration-selection-file :path "workspace-relative.rqlp" :language LANGUAGE)
```

Bind the declarations of one workspace-relative declaration-selection document; a missing or invalid document fails activation. Legal in: policy, `assertion`, as a `bind :query`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:path` | required | a validated workspace-relative path | `:path "workspace-relative.rqlp"`. Name one workspace-relative declaration-selection document. |
| `:language` | required | one public analyzer language label | `:language LANGUAGE`. Require the imported document to select declarations of exactly this analyzer language. |

The document is read when the policy activates against a workspace, never
before. A missing document fails with `declaration-selection-unavailable`, a
document of another kind with `declaration-selection-wrong-document`, and a
document of another language with `declaration-selection-wrong-language`. Each
failure is a `policy-validation-failed` diagnostic whose message names that
cause, and the policy does not run. The analysis's `:languages` and `:where`
scopes do not apply to an imported selection, so an analysis that sets either
rejects the reference with `declaration-selection-scope-conflict`.

### Analysis

#### `analysis`

```lisp
(analysis :type match|taint|typestate|assertion|flow ...)
```

Select and configure exactly one policy analysis kind. Legal in: policy, every analysis type.

| Field | Required | Legal in | Value | Meaning |
| --- | --- | --- | --- | --- |
| `:type` | required | policy, every analysis type | match, taint, typestate, assertion, or flow | `:type match\|taint\|typestate\|assertion\|flow`. Select the analysis variant; fields are never inferred from their presence. |
| `:subject` | optional | policy, `assertion` | an inline rql or deferred rql-file selector | `:subject (rql ...)\|(rql-file ...)`. Select the subject nodes each specialized assertion is evaluated at; required with :asserts. |
| `:asserts` | optional | policy, `assertion` | assert records; list (source order kept) of 1 to 64 items | `:asserts [(assert ...)...]`. Declare specialized occurrence, resolution, route, or identity invariants; required with :subject. |
| positional, repeated | optional | policy, `assertion` | bind, join, group, relational assert, and assert-selected-in-winning-tier records; list (source order kept) of 1 to 64 items | `(bind\|join\|group\|assert ...)...`. Declare a bounded source-ordered relational assertion plan. |
| `:selector` | required | policy, `match` | an inline rql or deferred rql-file selector | `:selector (rql ...)\|(rql-file ...)`. Select positive location-bearing match results. |
| `:mode` | required | policy, `taint`, `typestate`, or `flow` | the may analysis mode | `:mode may`. Select the schema-version-1 may analysis mode. |
| `:call-modeling` | optional | policy, `taint`, `typestate`, or `flow` | a call-modeling record | `:call-modeling (call-modeling :unmodeled paranoid\|optimistic\|require-model)`. Choose fallback behavior for unmodeled calls; omission defaults to paranoid. |
| `:threat-models` | optional | policy, `taint` | a non-empty set of threat-model values | `:threat-models [remote\|commandargs\|environment\|stdin\|file\|database...]`. Select active source kinds; omission defaults to `[remote]`. |
| `:on-unknown` | optional | policy, every analysis type | an on-unknown record | `:on-unknown (on-unknown :verdict abstain\|warn-unreliable\|fail-closed\|treat-may-as-finding)`. Choose what a verdict blocked by unknown evidence does; omission defaults to abstain. |
| `:languages` | optional | policy, every analysis type | one or more language labels, the aliases `c++` and `c#`, file extensions that one language owns (such as `py` or `tsx`), or the family aliases `jvm` and `js-ts`; list (source order kept) of 1 to 64 items | `:languages [LANGUAGE...]`. Conjoin one shared language scope with every inline RQL and referenced RQL selector in this analysis; `jvm` expands to [java, kotlin, scala] and `js-ts` expands to [javascript, typescript]. A label or extension ignores case, a leading dot, `-`, and `_`; family aliases must be exact. An unknown entry is `invalid-language-label`. |
| `:where` | optional | policy, every analysis type | one or more workspace-relative path globs; list (source order kept) of 1 to 64 items | `:where ["GLOB"...]`. Conjoin one shared workspace-relative path-glob scope with every inline RQL and referenced RQL selector in this analysis. |
| `:rql-schema-version` | optional | policy, every analysis type | a supported positive schema version | `:rql-schema-version N`. Pin the RQL schema version for selectors that omit their own; explicit selector pins must agree. This is independent of the RQLP document schema version. |
| `:sources` | required | policy, `taint` | an endpoint-set record | `:sources (endpoint-set ...)`. Compose the complete taint source set. |
| `:sinks` | required | policy, `taint` | an endpoint-set record | `:sinks (endpoint-set ...)`. Compose the complete taint sink set. |
| `:sanitizers` | optional | policy, `taint` | an endpoint-set record | `:sanitizers (endpoint-set ...)`. Compose optional sanitizer models; omission is empty. |
| `:stores` | optional | policy, `taint` | an endpoint-set record | `:stores (endpoint-set ...)`. Compose optional persistence-store models from local store-write and store-read entries; omission is empty. |
| `:entry-points` | optional | policy, `taint` | an endpoint-set record | `:entry-points (endpoint-set ...)`. Compose optional framework entry-point models; omission is empty. |
| `:transforms` | optional | policy, `taint` or `flow` | an endpoint-set record | `:transforms (endpoint-set ...)`. Compose optional policy-local input-to-output transforms; taint transforms may also rewrite labels. |
| `:external-models` | optional | policy, `taint` | an endpoint-set record | `:external-models (endpoint-set ...)`. Compose optional external transfer models; omission is empty. |
| `:origins` | required | policy, `flow` | an endpoint-set record | `:origins (endpoint-set :entries [(origin ...)...])`. Compose the complete value-flow origin set. |
| `:observations` | required | policy, `flow` | an endpoint-set record | `:observations (endpoint-set :entries [(observation ...)...])`. Compose the complete value-flow observation set. |
| `:kills` | optional | policy, `flow` | an endpoint-set record | `:kills (endpoint-set :entries [(kill ...)...])`. Compose optional value-flow kills; omission is empty. |
| `:finding-combinations` | optional | policy, `taint` | finding-combination records; set (no duplicates) of 0 to 256 items | `:finding-combinations [(finding-combination ...)...]`. Declare bounded explicit presentation/classification precedence rules. |
| `:subjects` | required | policy, `typestate` | a subject-set record | `:subjects (subject-set ...)`. Compose values newly tracked by typestate. |
| `:uncertainty` | required | policy, `typestate` | an uncertainty record | `:uncertainty (uncertainty ...)`. Declare explicit handling for subjects that escape the analysis root. |
| `:automaton` | required | policy, `typestate` | an automaton record | `:automaton (automaton ...)`. Declare the author-facing typestate automaton and terminal obligations. |

#### `call-modeling`

```lisp
(call-modeling :unmodeled paranoid|optimistic|require-model)
```

Choose fallback semantics for call arms without an executable body or applicable model. Legal in: policy, `taint`, `typestate`, or `flow`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:unmodeled` | required | paranoid, optimistic, or require-model | `:unmodeled paranoid\|optimistic\|require-model`. Choose conservative propagation, preserve-only propagation, or abstention when no call model applies. |

#### `on-unknown`

```lisp
(on-unknown :verdict abstain|warn-unreliable|fail-closed|treat-may-as-finding)
```

Declare what the run does when unknown or incomplete evidence blocked a verdict. Legal in: policy, every analysis type.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:verdict` | required | abstain, warn-unreliable, fail-closed, or treat-may-as-finding | `:verdict abstain\|warn-unreliable\|fail-closed\|treat-may-as-finding`. Abstain and exit unreliable, gate on retained findings alone, fail closed, or publish explicit may evidence as possible findings while preserving coverage obligations. |

### Selectors

#### `rql`

```lisp
(rql [:schema-version N] QUERY)
```

Embed one native RQL selector without rendering or reparsing it. Legal in: every document.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:schema-version` | optional | a supported positive schema version | `:schema-version N`. Pin the nested RQL version exactly; omission uses the RQL compatible head. |
| positional | required | one native RQL query expression | `QUERY`. Embed exactly one spanned RQL query subtree. |

#### `rql-file`

```lisp
(rql-file [:schema-version N] :path "workspace/relative.rql")
```

Reference one workspace-relative RQL selector for deferred loading. Legal in: every document.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:schema-version` | optional | a supported positive schema version | `:schema-version N`. Pin or constrain the referenced RQL document version. |
| `:path` | required | a validated workspace-relative path | `:path "queries/name.rql"`. Name one workspace-root-relative RQL file for deferred loading. |

### Ports

#### `argument`

```lisp
(argument :index N) | (argument :name "NAME")
```

Bind a zero-based argument index or exact formal argument name. Legal in: every document.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:index` | optional | a non-negative integer | `:index N`. Bind a zero-based argument index; mutually exclusive with name. |
| `:name` | optional | a bounded human-readable name | `:name "formal-name"`. Bind an exact formal argument name; mutually exclusive with index. |

#### `result`

```lisp
(result :index N)
```

Bind one zero-based normal call result. Legal in: every document.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:index` | required | a non-negative integer | `:index N`. Bind the zero-based normal result ordinal. |

#### `field`

```lisp
(field :name "NAME" :of (argument ...)|receiver)
```

Bind one named field of an argument or receiver as an external-model write destination. Legal in: policy, `taint`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:name` | required | a bounded human-readable name | `:name "field-name"`. Name the written field on the base port's object. |
| `:of` | required | receiver, return-value, an indexed result record, or an argument record; matched-value is forbidden | `:of (argument ...)\|receiver`. Bind the object whose field is written: an argument or the receiver. |

### Endpoint semantics and evidence

#### `source-semantics`

```lisp
(source-semantics :labels [LABEL...] [:evidence EVIDENCE])
```

Attach diagnostic-neutral taint source semantics to a source endpoint. Legal in: `endpoint` and `endpoint-set-document`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:labels` | required | normalized taint labels; set (no duplicates) of 1 to 64 items | `:labels [LABEL...]`. Declare the non-empty labels introduced by the endpoint. |
| `:evidence` | optional | an evidence or source-evidence record | `:evidence (evidence ...)`. Attach coherent source trust/entry evidence. |

#### `sink-semantics`

```lisp
(sink-semantics :accepts [LABEL...] [:tags [...]] [:impacts [...]])
```

Attach diagnostic-neutral taint sink semantics to a sink endpoint. Legal in: `endpoint` and `endpoint-set-document`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:accepts` | required | normalized taint labels; set (no duplicates) of 1 to 64 items | `:accepts [LABEL...]`. Declare the non-empty labels consumed by the endpoint. |
| `:tags` | optional | normalized sink tags; set (no duplicates) of 0 to 64 items | `:tags [TAG...]`. Attach exact sink tags for evidence predicates. |
| `:impacts` | optional | normalized sink impacts; set (no duplicates) of 0 to 64 items | `:impacts [IMPACT...]`. Attach exact sink impacts for evidence predicates. |

#### `evidence`

```lisp
(evidence [:trust-boundary VALUE] [:system-entry VALUE])
```

Record coherent source evidence; at least one field is required. Legal in: every document.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:trust-boundary` | optional | external, internal, or same-trust-zone | `:trust-boundary external\|internal\|same-trust-zone`. Describe the source trust boundary. |
| `:system-entry` | optional | a supported vulnerable-system entry kind | `:system-entry ENTRY`. Describe how the source enters the vulnerable system. |

#### `source-evidence`

```lisp
(source-evidence [:trust-boundary VALUE] [:system-entry VALUE])
```

Match coherent trust-boundary and system-entry facts from one source scenario. Legal in: policy, `taint`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:trust-boundary` | optional | external, internal, or same-trust-zone | `:trust-boundary external\|internal\|same-trust-zone`. Match the trust boundary on one coherent source fact. |
| `:system-entry` | optional | a supported vulnerable-system entry kind | `:system-entry ENTRY`. Match the system entry on the same coherent source fact. |

### Endpoint sets and endpoint selection

#### `endpoint-set`

```lisp
(endpoint-set [:include-sets [...]] [:include-matches [...]] [:entries [...]])
```

Compose a typed endpoint set from catalogs, endpoint matches, and local entries. A flow analysis composes only local entries. Legal in: policy, `taint` or `flow`.

| Field | Required | Legal in | Value | Meaning |
| --- | --- | --- | --- | --- |
| `:include-sets` | optional | policy, `taint` | catalog records; set (no duplicates) of 0 to 64 items | `:include-sets [(catalog ...)...]`. Include explicitly registered catalog endpoint sets; store sets reject this field but may import typed files. Legal only in `:sources`, `:sinks`, `:sanitizers`, `:transforms`, `:external-models`. |
| `:include-matches` | optional | policy, `taint` | match-directory or match-endpoints records; set (no duplicates) of 0 to 64 items | `:include-matches [(match-directory ...)\|(match-endpoints ...)...]`. Include explicitly selected source or sink endpoint leaves; other taint set kinds reject this field. Legal only in `:sources` or `:sinks`. |
| `:include-files` | optional | policy, `taint` or `flow` | endpoint-set-file dependency records; set (no duplicates) of 0 to 64 items | `:include-files [(endpoint-set-file :path "workspace-relative.rqlp" [:sha256 HEX])...]`. Include nested typed endpoint-set documents with optional semantic content pins. Legal only in taint or flow entry sets. |
| `:entries` | optional | policy, `taint` | policy-local source records; set (no duplicates) of 0 to 256 items | `:entries [(source ...)...]`. Add bounded policy-local source entries. Legal only in `:sources`. |
| `:entries` | optional | policy, `taint` | policy-local sink records; set (no duplicates) of 0 to 256 items | `:entries [(sink ...)...]`. Add bounded policy-local sink entries. Legal only in `:sinks`. |
| `:entries` | optional | policy, `taint` | policy-local sanitizer records; set (no duplicates) of 0 to 256 items | `:entries [(sanitizer ...)...]`. Add bounded policy-local sanitizer entries. Legal only in `:sanitizers`. |
| `:entries` | optional | policy, `taint` | policy-local store-write and store-read records; set (no duplicates) of 0 to 256 items | `:entries [(store-write ...)\|(store-read ...)...]`. Add bounded policy-local persistence-store entries. Legal only in `:stores`. |
| `:entries` | optional | policy, `taint` | policy-local entry-point records; set (no duplicates) of 0 to 256 items | `:entries [(entry-point ...)...]`. Add bounded policy-local entry-point entries. Legal only in `:entry-points`. |
| `:entries` | optional | policy, `taint` or `flow` | policy-local transform records; set (no duplicates) of 0 to 256 items | `:entries [(transform ...)...]`. Add bounded policy-local input-to-output transform entries. Legal only in `:transforms`. |
| `:entries` | optional | policy, `flow` | policy-local origin records; set (no duplicates) of 0 to 256 items | `:entries [(origin ...)...]`. Add bounded policy-local value-flow origin entries. Legal only in `:origins`. |
| `:entries` | optional | policy, `flow` | policy-local observation records; set (no duplicates) of 0 to 256 items | `:entries [(observation ...)...]`. Add bounded policy-local value-flow observation entries. Legal only in `:observations`. |
| `:entries` | optional | policy, `flow` | policy-local kill records; set (no duplicates) of 0 to 256 items | `:entries [(kill ...)...]`. Add bounded policy-local value-flow kill entries. Legal only in `:kills`. |
| `:entries` | optional | policy, `taint` | policy-local external-model records; set (no duplicates) of 0 to 256 items | `:entries [(external-model ...)...]`. Add bounded policy-local external-model entries. Legal only in `:external-models`. |

#### `catalog`

```lisp
(catalog :name ID :version N [:sha256 HEX])
(catalog :any-registered true :categories (any|all [CATEGORY...]))
```

Reference an explicitly registered, optionally content-pinned taint catalog. Legal in: policy, `taint`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:any-registered` | optional | `true` | Select registered catalogs; requires `:categories` and excludes `:name`, `:version`, and `:sha256`. |
| `:categories` | optional | `(any|all [CATEGORY...])` | Filter wildcard entries by declared categories. |
| `:name` | required | a stable lowercase policy identifier | `:name "catalog.id"`. Name an explicitly registered catalog. |
| `:version` | required | a positive integer | `:version N`. Select an exact positive catalog version. |
| `:sha256` | optional | a lowercase 64-hex SHA-256 value | `:sha256 "64-lower-hex"`. Optionally pin canonical typed catalog content. |

A rule pack may declare `catalogs` in `manifest.json`, for example
`"catalogs": [{"path": "catalogs/jdk-sinks.json", "semantic_hash": "<64-lowercase-hex>"}]`.
Paths are portable and relative to the pack root. Catalog JSON uses schema 1,
`name`, positive integer `version`, a declared `categories` vocabulary, and
`sources`, `sinks`, `sanitizers`, `transforms`, and `external_models` arrays.
Every entry category must belong to that catalog's vocabulary. Sanitizer,
transform and external-model entries accept optional `categories`; omission
means no categories. Policy-local auxiliary entries accept the same field.
The semantic hash pins canonical typed content, including the vocabulary.
Hash mismatches and conflicting duplicate name/version identities fail the run.

Use `(catalog :any-registered true :categories (any [sql-injection]))` in
`:include-sets` to select entries across all catalogs registered for this run.
`all` requires every listed category. Unknown categories are errors naming the
unknown identifier; predicates use the union of registered vocabularies.
Filtering precedes endpoint limits. Uncategorized auxiliary entries are excluded
from wildcard selection, and remain available through named references.
A wildcard that selects no entries is an error, including in an optional auxiliary
set or an empty registry.
A wildcard cannot be used in an exact `endpoint-ref`. Named references retain
their exact version and optional hash pin. The output's `packs.catalogs` lists
matched identities (`name`, `version`, `sha256`); finding provenance identifies
both the catalog and entry. Catalog-dependent policies read catalog content
from installed pack roots for each run, including dependencies imported through
endpoint-set files. Explicit policies without catalog dependencies do not open
unused installation roots. Catalog content is dropped with its run.

#### `match-directory`

```lisp
(match-directory :path PATH :scope direct|recursive [:role source|sink] [:phase PHASE] :categories (any|all [...]) [:manifest-sha256 HEX])
```

Select endpoint leaves transactionally from an explicit capability-rooted directory. Legal in: policy, `taint` or `typestate`.

| Field | Required | Legal in | Value | Meaning |
| --- | --- | --- | --- | --- |
| `:path` | required | policy, `taint` or `typestate` | a validated workspace-relative path | `:path "policies/endpoints"`. Name the capability-rooted endpoint directory. |
| `:scope` | required | policy, `taint` or `typestate` | direct or recursive | `:scope direct\|recursive`. Choose direct children or bounded recursive traversal. |
| `:role` | optional | policy, `typestate` | source or sink | `:role source\|sink`. Constrain a typestate endpoint trigger to one role; the decoder lifts it out of MatchDirectoryRef. Legal only as a typestate event or terminal-expectation trigger. |
| `:phase` | optional | policy, `typestate` | at-match, before-call, after-normal-return, or after-exceptional-return | `:phase PHASE`. Choose the typed typestate trigger phase; the decoder lifts it out of MatchDirectoryRef. Legal only as a typestate event or terminal-expectation trigger. |
| `:categories` | required | policy, `taint` or `typestate` | an exact any or all category predicate | `:categories (any\|all [CATEGORY...])`. Select endpoints by exact categories. |
| `:manifest-sha256` | optional | policy, `taint` or `typestate` | a lowercase 64-hex SHA-256 value | `:manifest-sha256 "64-lower-hex"`. Optionally pin the complete selected endpoint manifest. |

#### `match-endpoints`

```lisp
(match-endpoints :ids [ENDPOINT-ID...] [:role source|sink] [:phase PHASE])
```

Select exact endpoint IDs already present in the immutable endpoint index. Legal in: policy, `taint` or `typestate`.

| Field | Required | Legal in | Value | Meaning |
| --- | --- | --- | --- | --- |
| `:ids` | required | policy, `taint` or `typestate` | endpoint identifiers; set (no duplicates) of 1 to 64 items | `:ids [ENDPOINT-ID...]`. Name a non-empty finite exact endpoint set. |
| `:role` | optional | policy, `typestate` | source or sink | `:role source\|sink`. Constrain a typestate exact-endpoint trigger to one role; the decoder lifts it out of the set reference. Legal only as a typestate event or terminal-expectation trigger. |
| `:phase` | optional | policy, `typestate` | at-match, before-call, after-normal-return, or after-exceptional-return | `:phase PHASE`. Choose the typed exact-endpoint trigger phase; the decoder lifts it out of the set reference. Legal only as a typestate event or terminal-expectation trigger. |

#### `any` (category predicate)

```lisp
(any [CATEGORY...])
```

Require at least one exact category from a non-empty set. Legal in: policy, `taint` or `typestate`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| positional | required | opaque exact endpoint categories; set (no duplicates) of 1 to 64 items | `[CATEGORY...]`. Provide the non-empty exact category set. |

#### `all` (category predicate)

```lisp
(all [CATEGORY...])
```

Require every exact category from a non-empty set. Legal in: policy, `taint` or `typestate`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| positional | required | opaque exact endpoint categories; set (no duplicates) of 1 to 64 items | `[CATEGORY...]`. Provide the non-empty exact category set. |

#### `categories`

```lisp
(categories :any [...] | :all [...])
```

Select endpoints by an exact any-or-all category predicate. Legal in: policy, `taint` or `typestate`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:any` | optional | opaque exact endpoint categories; set (no duplicates) of 1 to 64 items | `:any [CATEGORY...]`. Match at least one exact category; mutually exclusive with all. |
| `:all` | optional | opaque exact endpoint categories; set (no duplicates) of 1 to 64 items | `:all [CATEGORY...]`. Match every exact category; mutually exclusive with any. |

#### `endpoints`

```lisp
(endpoints [ENDPOINT-REF...])
```

Select a finite exact set of local, catalog, or match endpoint identities. Legal in: policy, `taint` or `typestate`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| positional | required | endpoint-ref records; set (no duplicates) of 1 to 64 items | `[ENDPOINT-REF...]`. Provide a non-empty exact endpoint reference set. |

#### `endpoint-ref`

```lisp
(endpoint-ref (:local ID | :catalog CATALOG :entry ID | :match-endpoint ID))
```

Name one endpoint in the current policy, an explicit catalog, or the endpoint index. Legal in: policy, `taint` or `typestate`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:local` | optional | a lowercase local entry identifier | `:local "entry-id"`. Reference a policy-local endpoint entry. |
| `:catalog` | optional | a catalog record | `:catalog (catalog ...)`. Reference an endpoint in an explicitly named catalog. |
| `:entry` | optional | a lowercase local entry identifier | `:entry "entry-id"`. Name the catalog entry when catalog is selected. |
| `:match-endpoint` | optional | a stable lowercase endpoint identifier | `:match-endpoint "endpoint-id"`. Reference one explicitly loaded match endpoint. |

### Taint entries

#### `source`

```lisp
(source :id ID :display-name TEXT :categories [...] :selector SELECTOR :bind PORT :labels [...] [:threat-model KIND] [:evidence EVIDENCE])
```

Declare one policy-local taint source. Legal in: policy, `taint`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:id` | required | a lowercase local entry identifier | `:id "entry-id"`. Set the policy-local source identity. |
| `:display-name` | required | bounded human-readable display text | `:display-name "phrase"`. Set the generated-message phrase for this source. |
| `:categories` | required | opaque exact endpoint categories; set (no duplicates) of 1 to 64 items | `:categories [CATEGORY...]`. Attach exact source categories. |
| `:selector` | required | an inline rql or deferred rql-file selector | `:selector SELECTOR`. Select the source sites. |
| `:bind` | required | matched-value, receiver, return-value, an indexed result record, or an argument record | `:bind PORT`. Bind the source value at each selected site. |
| `:labels` | required | normalized taint labels; set (no duplicates) of 1 to 64 items | `:labels [LABEL...]`. Declare the non-empty labels introduced by the source. |
| `:threat-model` | optional | `remote`, `commandargs`, `environment`, `stdin`, `file`, or `database` | `:threat-model KIND`. Classify the source for analysis-level threat-model selection; omission keeps it active for every selection. |
| `:evidence` | optional | an evidence or source-evidence record | `:evidence (evidence ...)`. Attach coherent source trust/entry evidence. |

#### `sink`

```lisp
(sink :id ID :display-name TEXT :categories [...] :selector SELECTOR :dangerous-operand PORT :accepts [...] [:tags [...]] [:impacts [...]])
```

Declare one policy-local taint sink. Legal in: policy, `taint`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:id` | required | a lowercase local entry identifier | `:id "entry-id"`. Set the policy-local sink identity. |
| `:display-name` | required | bounded human-readable display text | `:display-name "phrase"`. Set the generated-message phrase for this sink. |
| `:categories` | required | opaque exact endpoint categories; set (no duplicates) of 1 to 64 items | `:categories [CATEGORY...]`. Attach exact sink categories. |
| `:selector` | required | an inline rql or deferred rql-file selector | `:selector SELECTOR`. Select the sink sites. |
| `:dangerous-operand` | required | matched-value, receiver, return-value, an indexed result record, or an argument record | `:dangerous-operand PORT`. Bind the sink operand that consumes tainted data. |
| `:accepts` | required | normalized taint labels; set (no duplicates) of 1 to 64 items | `:accepts [LABEL...]`. Declare the non-empty labels accepted by the sink. |
| `:tags` | optional | normalized sink tags; set (no duplicates) of 0 to 64 items | `:tags [TAG...]`. Attach exact sink tags. |
| `:impacts` | optional | normalized sink impacts; set (no duplicates) of 0 to 64 items | `:impacts [IMPACT...]`. Attach exact sink impacts. |

#### `sanitizer`

```lisp
(sanitizer :id ID :selector SELECTOR :input PORT :output PORT :removes [LABEL...])
(sanitizer :id ID :selector SELECTOR
  :when (result true|false|nil|non-nil [:index k])
  :sanitizes receiver|(argument :index k)
  [:requires [REQUIREMENT...]] :removes [LABEL...])
```

Declare one policy-local sanitizer. Legal in: policy, `taint`. Use exactly one
form: a transfer with `:input` and `:output`, or a conditional sanitizer with
`:when` and `:sanitizes`. Do not mix the two forms.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:id` | required | a lowercase local entry identifier | `:id "entry-id"`. Set the sanitizer identity. |
| `:selector` | required | an inline rql or deferred rql-file selector | `:selector SELECTOR`. Select sanitizer calls or values. |
| `:input` | required for transfer | matched-value, receiver, return-value, an indexed result record, or an argument record | `:input PORT`. Bind the sanitizer input value. |
| `:output` | required for transfer | matched-value, receiver, return-value, an indexed result record, or an argument record | `:output PORT`. Bind the sanitizer output value. |
| `:when` | required for conditional | `(result true)`, `(result false)`, `(result nil)`, or `(result non-nil)`, with optional `:index k` inside the record | Choose the accepting branch; `k` selects a zero-based call result. |
| `:sanitizes` | required for conditional | `receiver` or `(argument :index k)` | Choose the call operand whose taint labels are removed on that branch. |
| `:requires` | optional, conditional form | a non-empty list of requirement records | Every requirement must hold. Duplicate records are rejected. |
| `:removes` | required | normalized taint labels; set (no duplicates) of 1 to 64 items | Remove only these labels from the selected flow; other labels remain. |

Each requirement is `(receiver ATTR)` or `(argument :index k ATTR)`, with
exactly one attribute:

| Attribute | Meaning |
| --- | --- |
| `:constant true` | Require a compile-time constant. |
| `:equals LIT` | Require the decoded constant value to equal a string, number, or Boolean literal. The language must decode a string literal's payload; otherwise the guard declines. |
| `:result-of SELECTOR` | Require the operand to originate from a call matched by the selector. Use the same inline `rql` or deferred `rql-file` forms as `:selector`. |

A requirement can follow a local only through a unique single writer that
dominates its use at the call. Out-of-range argument or result indices are
rejected where the call's arity is known.

For a multi-result call, supply `:index k` for the tested result.
Conditional sanitizers require a direct condition on the call result;
storing that result in a local and testing it later declines. The
sanitized carrier needs a unique binding origin and a resolved type whose
referent is immutable. The guard declines when the language cannot report
the carrier's type, or when the type is unknown or its referent is mutable.

Example fragment for a test predicate contract and a policy-defined label:

```lisp
(sanitizer :id prefix
  :selector (rql :schema-version 1
    (language go (call :callee (name "HasPrefix"))))
  :when (result true)
  :sanitizes (argument :index 0)
  :requires [(argument :index 1 :constant true)]
  :removes [example.checked])
```

Here only `example.checked` is removed from argument zero on the accepting
branch. A decline leaves the flow unsanitized. If that flow produces a
finding, the decline appears as advisory related-location evidence labelled
`sanitizer prefix declined: REASON`; it never creates a finding of its own or
makes a result incomplete by itself.

#### `store-write`

```lisp
(store-write :id ID :selector SELECTOR :store STORE [:key PORT] [:instance PORT] :input PORT)
```

Declare that the selected call writes its input port's value into the named persistence store, optionally discriminated by a key port and an instance port. Legal in: policy, `taint`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:id` | required | a lowercase local entry identifier | `:id "entry-id"`. Set the store-write identity in the shared local taint entry namespace. |
| `:selector` | required | an inline rql or deferred rql-file selector | `:selector SELECTOR`. Select the store-writing calls. |
| `:store` | required | a lowercase persistence store name | `:store STORE`. Name the persistence store this call writes into; write and read entries sharing one store name form a persistence boundary. |
| `:key` | optional | matched-value, receiver, return-value, an indexed result record, or an argument record | `:key PORT`. Optionally bind the port carrying the key the write is stored under. |
| `:instance` | optional | matched-value, receiver, return-value, an indexed result record, or an argument record | `:instance PORT`. Optionally bind the port carrying the store instance the write targets. |
| `:input` | required | matched-value, receiver, return-value, an indexed result record, or an argument record | `:input PORT`. Bind the port whose value the call writes into the store. |

#### `store-read`

```lisp
(store-read :id ID :selector SELECTOR :store STORE [:key PORT] [:instance PORT] :output PORT)
```

Declare that the selected call's output port returns data from the named persistence store under the same optional key and instance dimensions. Legal in: policy, `taint`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:id` | required | a lowercase local entry identifier | `:id "entry-id"`. Set the store-read identity in the shared local taint entry namespace. |
| `:selector` | required | an inline rql or deferred rql-file selector | `:selector SELECTOR`. Select the store-reading calls. |
| `:store` | required | a lowercase persistence store name | `:store STORE`. Name the persistence store this call reads from; write and read entries sharing one store name form a persistence boundary. |
| `:key` | optional | matched-value, receiver, return-value, an indexed result record, or an argument record | `:key PORT`. Optionally bind the port carrying the key the read looks up. |
| `:instance` | optional | matched-value, receiver, return-value, an indexed result record, or an argument record | `:instance PORT`. Optionally bind the port carrying the store instance the read targets. |
| `:output` | required | matched-value, receiver, return-value, an indexed result record, or an argument record | `:output PORT`. Bind the port that returns data read from the store. |

#### `entry-point`

```lisp
(entry-point :id ID :selector SELECTOR :parameter (argument ...) :labels [LABEL...])
```

Declare one framework-invoked entry point: the analysis roots the selected procedure declaration and taints the bound formal parameter on entry. Legal in: policy, `taint`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:id` | required | a lowercase local entry identifier | `:id "entry-id"`. Set the entry-point identity. |
| `:selector` | required | an inline rql or deferred rql-file selector | `:selector SELECTOR`. Select the entry-point procedure declarations. |
| `:parameter` | required | an argument record naming the tainted formal parameter | `:parameter (argument :index N)\|(argument :name "NAME")`. Bind the formal parameter tainted on entry. |
| `:labels` | required | normalized taint labels; set (no duplicates) of 1 to 64 items | `:labels [LABEL...]`. Declare the non-empty labels the parameter carries on entry. |

#### `transform` (entry)

```lisp
(transform :id ID :selector SELECTOR :input PORT :output PORT [:removes [...]] [:adds [...]])
```

Declare one policy-local input-to-output transform; taint may also rewrite labels. Legal in: policy, `taint` or `flow`.

| Field | Required | Legal in | Value | Meaning |
| --- | --- | --- | --- | --- |
| `:id` | required | policy, `taint` or `flow` | a lowercase local entry identifier | `:id "entry-id"`. Set the transform identity. |
| `:selector` | required | policy, `taint` or `flow` | an inline rql or deferred rql-file selector | `:selector SELECTOR`. Select transform calls or values. |
| `:input` | required | policy, `taint` or `flow` | matched-value, receiver, return-value, an indexed result record, or an argument record | `:input PORT`. Bind the transform input value. |
| `:output` | required | policy, `taint` or `flow` | matched-value, receiver, return-value, an indexed result record, or an argument record | `:output PORT`. Bind the transform output value. |
| `:removes` | optional | policy, `taint` | normalized taint labels; set (no duplicates) of 0 to 64 items | `:removes [LABEL...]`. Declare labels removed by the transform. |
| `:adds` | optional | policy, `taint` | normalized taint labels; set (no duplicates) of 0 to 64 items | `:adds [LABEL...]`. Declare labels added by the transform; removes and adds cannot both be empty. |

#### `external-model`

```lisp
(external-model :id ID :selector SELECTOR :transfers [TRANSFER...])
```

Declare typed transfer behavior for one external API. Legal in: policy, `taint`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:id` | required | a lowercase local entry identifier | `:id "entry-id"`. Set the external model identity. |
| `:selector` | required | an inline rql or deferred rql-file selector | `:selector SELECTOR`. Select the modeled external calls. |
| `:transfers` | required | transfer records; set (no duplicates) of 1 to 256 items | `:transfers [(transfer ...)...]`. Declare a duplicate-free semantic set of typed port transfers. |

#### `transfer`

```lisp
(transfer :from PORT :to PORT :labels [LABEL...] :effect EFFECT)
```

Move selected labels between two typed external-model ports. Legal in: policy, `taint`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:from` | required | receiver, return-value, an indexed result record, or an argument record; matched-value is forbidden | `:from receiver\|return-value\|(result :index N)\|(argument ...)`. Bind the transfer input call port; matched-value is forbidden. |
| `:to` | required | an external-model call port, or a field record naming one written field of an argument or receiver; matched-value is forbidden | `:to receiver\|return-value\|(result :index N)\|(argument ...)\|(field :name "NAME" :of PORT)`. Bind the transfer output call port or one written field of an argument or receiver; matched-value is forbidden. |
| `:labels` | required | normalized taint labels; set (no duplicates) of 1 to 64 items | `:labels [LABEL...]`. Select the non-empty labels affected by this transfer. |
| `:effect` | required | propagate, sanitize, or transform transfer semantics | `:effect propagate\|(sanitize ...)\|(transform ...)`. Choose propagation, sanitization, or transformation. |

#### `sanitize`

```lisp
(sanitize :removes [LABEL...])
```

Remove one or more labels during an external transfer. Legal in: policy, `taint`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:removes` | required | normalized taint labels; set (no duplicates) of 1 to 64 items | `:removes [LABEL...]`. Declare the non-empty labels removed by the effect. |

#### `transform` (transfer effect)

```lisp
(transform [:removes [...]] [:adds [...]])
```

Remove and/or add labels during an external transfer. Legal in: policy, `taint`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:removes` | optional | normalized taint labels; set (no duplicates) of 0 to 64 items | `:removes [LABEL...]`. Declare labels removed by the effect. |
| `:adds` | optional | normalized taint labels; set (no duplicates) of 0 to 64 items | `:adds [LABEL...]`. Declare labels added by the effect; removes and adds cannot both be empty. |

#### `finding-combination` (rule)

```lisp
(finding-combination :id ID :source PREDICATE :sink PREDICATE :message TEXT ...)
```

Override generic presentation for one finite source/sink endpoint combination. Legal in: policy, `taint`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:id` | required | a lowercase finding-combination identifier | `:id "combination-id"`. Set the stable combination identity. |
| `:source` | required | a categories or endpoints predicate | `:source (categories ...)\|(endpoints ...)`. Select the finite source endpoint identities covered by this rule. |
| `:sink` | required | a categories or endpoints predicate | `:sink (categories ...)\|(endpoints ...)`. Select the finite sink endpoint identities covered by this rule. |
| `:message` | required | bounded human-readable display text | `:message "static text"`. Replace the generic message for the winning combination. |
| `:severity` | optional | note, warning, error, unrated, or a cvss-severity record | `:severity SEVERITY`. Optionally replace the policy severity for this combination. |
| `:add-classifications` | optional | classification-id records; set (no duplicates) of 0 to 64 items | `:add-classifications [(classification-id ...)...]`. Add taxonomy classifications for the winning combination. |
| `:supersedes` | optional | finding-combination identifiers; set (no duplicates) of 0 to 64 items | `:supersedes [COMBINATION-ID...]`. Declare explicit presentation precedence over other combinations. |

### Flow entries

#### `origin`

```lisp
(origin :id ID :display-name TEXT :selector SELECTOR :bind PORT)
```

Declare one value-flow origin: the site and typed port where the tracked value is established. Legal in: policy, `flow`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:id` | required | a lowercase local entry identifier | `:id "entry-id"`. Set the policy-local origin identity. |
| `:display-name` | required | bounded human-readable display text | `:display-name "phrase"`. Set the reported phrase for this origin. |
| `:selector` | required | an inline rql or deferred rql-file selector | `:selector SELECTOR`. Select the origin sites. |
| `:bind` | required | matched-value, receiver, return-value, an indexed result record, or an argument record | `:bind PORT`. Bind the established value at each selected origin site. |

#### `observation`

```lisp
(observation :id ID :display-name TEXT :selector SELECTOR :observed-operand PORT)
```

Declare one value-flow observation: the site and typed port that consumes the tracked value. Legal in: policy, `flow`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:id` | required | a lowercase local entry identifier | `:id "entry-id"`. Set the policy-local observation identity. |
| `:display-name` | required | bounded human-readable display text | `:display-name "phrase"`. Set the reported phrase for this observation. |
| `:selector` | required | an inline rql or deferred rql-file selector | `:selector SELECTOR`. Select the observation sites. |
| `:observed-operand` | required | matched-value, receiver, return-value, an indexed result record, or an argument record | `:observed-operand PORT`. Bind the operand whose value the observation consumes. |

#### `kill`

```lisp
(kill :id ID :selector SELECTOR :input PORT :output PORT)
```

Declare one value-flow kill: at this site the output port no longer carries the tracked value established at the input port. Legal in: policy, `flow`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:id` | required | a lowercase local entry identifier | `:id "entry-id"`. Set the policy-local kill identity. |
| `:selector` | required | an inline rql or deferred rql-file selector | `:selector SELECTOR`. Select the kill sites. |
| `:input` | required | matched-value, receiver, return-value, an indexed result record, or an argument record | `:input PORT`. Bind the value the kill consumes. |
| `:output` | required | matched-value, receiver, return-value, an indexed result record, or an argument record | `:output PORT`. Bind the value the kill establishes; it no longer carries the tracked provenance. |

### Typestate

#### `subject-set`

```lisp
(subject-set [:include-matches [...]] [:entries [...]])
```

Compose the values newly tracked by a typestate policy. Legal in: policy, `typestate`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:include-matches` | optional | match-directory or match-endpoints records; set (no duplicates) of 0 to 64 items | `:include-matches [MATCH-SET...]`. Include source endpoint leaves as newly tracked subjects. |
| `:entries` | optional | subject records; set (no duplicates) of 0 to 256 items | `:entries [(subject ...)...]`. Add policy-local subject seed selectors. |

#### `subject`

```lisp
(subject :id ID :selector SELECTOR :subject BINDING)
```

Declare one policy-local typestate seed and its bound subject. Legal in: policy, `typestate`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:id` | required | a lowercase local entry identifier | `:id "subject-id"`. Set the policy-local subject identity. |
| `:selector` | required | an inline rql or deferred rql-file selector | `:selector SELECTOR`. Select values that begin typestate tracking. |
| `:subject` | required | matched-value, receiver, return-value, an indexed result record, or an argument record | `:subject BINDING`. Bind the newly tracked value. |

#### `uncertainty`

```lisp
(uncertainty :escape inconclusive)
```

Make escape capability gaps explicit. Legal in: policy, `typestate`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:escape` | required | the inconclusive uncertainty policy | `:escape inconclusive`. Mark subjects escaping the analysis root as incomplete. |

#### `automaton`

```lisp
(automaton :states [...] :initial STATE :accepting-states [...] :error-states [...] :events [...] :transitions [...] [:terminal-expectations [...]])
```

Define the public typestate states, events, transitions, and terminal obligations. Legal in: policy, `typestate`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:states` | required | typestate state identifiers; set (no duplicates) of 1 to 256 items | `:states [STATE...]`. Declare every typestate state. |
| `:initial` | required | a lowercase typestate state identifier | `:initial STATE`. Select the declared initial state. |
| `:accepting-states` | required | typestate state identifiers; set (no duplicates) of 1 to 256 items | `:accepting-states [STATE...]`. Declare non-absorbing states that satisfy terminal expectations. |
| `:error-states` | required | typestate state identifiers; set (no duplicates) of 1 to 256 items | `:error-states [STATE...]`. Declare states whose transitions produce policy violations. |
| `:events` | required | event records; set (no duplicates) of 1 to 256 items | `:events [(event ...)...]`. Declare the bounded typed event set. |
| `:transitions` | required | transition records; set (no duplicates) of 1 to 4096 items | `:transitions [(transition ...)...]`. Declare deterministic state/event transitions. |
| `:terminal-expectations` | optional | terminal-expectation records; set (no duplicates) of 0 to 256 items | `:terminal-expectations [(terminal-expectation ...)...]`. Declare explicit or implicit terminal accepting-state obligations. |

#### `event`

```lisp
(event :id ID (:calls CALLS | :matches MATCH-SET | :on SEMANTIC-EVENT) ...)
```

Define one direct-call, endpoint, or semantic typestate event. Legal in: policy, `typestate`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:id` | required | a lowercase typestate event identifier | `:id EVENT`. Set the stable event identity. |
| `:calls` | optional | a calls record | `:calls (calls ...)`. Trigger on a direct selector call; exclusive with matches and on. |
| `:matches` | optional | a match-directory or match-endpoints record | `:matches MATCH-SET`. Trigger on selected endpoint observations; exclusive with calls and on. |
| `:on` | optional | a normal-procedure-exit, exceptional-procedure-exit, or suspension-boundary record | `:on SEMANTIC-EVENT`. Trigger on an implicit semantic event; exclusive with calls and matches. |
| `:applies-to-subjects` | optional | a categories or endpoints predicate | `:applies-to-subjects ENDPOINT-PREDICATE`. Restrict the event to a finite resolved subject set. |
| `:supersedes` | optional | typestate event identifiers; set (no duplicates) of 0 to 64 items | `:supersedes [EVENT...]`. Declare explicit same-observation event dominance. |

#### `calls`

```lisp
(calls :selector SELECTOR :subject BINDING :phase PHASE)
```

Observe a direct call selector using one tracked receiver, return, or argument binding. Legal in: policy, `typestate`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:selector` | required | an inline rql or deferred rql-file selector | `:selector SELECTOR`. Select direct call observations. |
| `:subject` | required | receiver, return-value, an indexed result record, or an argument record | `:subject receiver\|return-value\|(result :index N)\|(argument ...)`. Bind the already tracked object at the call. |
| `:phase` | required | at-match, before-call, after-normal-return, or after-exceptional-return | `:phase PHASE`. Observe before the call or after a specific continuation. |

#### `transition`

```lisp
(transition :from STATE :on EVENT :to STATE)
```

Apply one deterministic typestate transition. Legal in: policy, `typestate`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:from` | required | a lowercase typestate state identifier | `:from STATE`. Name the declared source state. |
| `:on` | required | a lowercase typestate event identifier | `:on EVENT`. Name the declared triggering event. |
| `:to` | required | a lowercase typestate state identifier | `:to STATE`. Name the declared destination state. |

#### `terminal-expectation`

```lisp
(terminal-expectation :id ID (:matches MATCH-SET | :on SEMANTIC-EVENT) :expected-states [...])
```

Require an accepting state after an explicit or implicit terminal observation. Legal in: policy, `typestate`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:id` | required | a lowercase typestate expectation identifier | `:id EXPECTATION`. Set the stable expectation identity. |
| `:matches` | optional | a match-directory or match-endpoints record | `:matches MATCH-SET`. Observe an explicit endpoint terminal; exclusive with on. |
| `:on` | optional | a normal-procedure-exit, exceptional-procedure-exit, or suspension-boundary record | `:on SEMANTIC-EVENT`. Observe normal or exceptional analysis-root exit; exclusive with matches. |
| `:applies-to-subjects` | optional | a categories or endpoints predicate | `:applies-to-subjects ENDPOINT-PREDICATE`. Restrict the expectation to a finite resolved subject set. |
| `:expected-states` | required | typestate state identifiers; set (no duplicates) of 1 to 256 items | `:expected-states [ACCEPTING-STATE...]`. Name the non-empty accepting-state subset required at the terminal. |
| `:supersedes` | optional | typestate expectation identifiers; set (no duplicates) of 0 to 64 items | `:supersedes [EXPECTATION...]`. Declare explicit same-terminal expectation dominance. |

#### `normal-procedure-exit`

```lisp
(normal-procedure-exit :scope analysis-root)
```

Observe normal completion of the outer analysis root. Legal in: policy, `typestate`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:scope` | required | the analysis-root exit scope | `:scope analysis-root`. Limit the implicit normal terminal to the outer analysis root. |

#### `exceptional-procedure-exit`

```lisp
(exceptional-procedure-exit :scope analysis-root)
```

Observe exceptional completion of the outer analysis root. Legal in: policy, `typestate`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:scope` | required | the analysis-root exit scope | `:scope analysis-root`. Limit the implicit exceptional terminal to the outer analysis root. |

#### `suspension-boundary`

```lisp
(suspension-boundary :scope analysis-root)
```

Observe suspension boundaries of the outer analysis root. Legal in: policy, `typestate`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:scope` | required | the analysis-root exit scope | `:scope analysis-root`. Limit the suspension boundary to the outer analysis root. |

### Assertion: relational plan

#### `bind`

```lisp
(bind :name NAME :query SELECTOR)
```

Bind one named typed row relation from a CodeQuery. Legal in: policy, `assertion`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:name` | required | a bounded row binding, group, or aggregate name | `:name NAME`. Set the unique row binding name. |
| `:query` | required | an inline rql, deferred rql-file, declaration-selection-file, or procedure-effects-of selector | `:query (rql ...)\|(rql-file ...)\|(declaration-selection-file ...)\|(procedure-effects-of ...)`. Execute one typed CodeQuery as the binding source. |

#### `procedure-effects-of`

```lisp
(procedure-effects-of :binding NAME)
```

Bind the procedure effects of the declarations an earlier row binding selects, so both bindings read one selection. Legal in: policy, `assertion`, as a `bind :query`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:binding` | required | a bounded row binding, group, or aggregate name | `:binding NAME`. Name the earlier row binding whose selected declarations feed procedure-effects. |

The named binding must come earlier and use an inline `rql` query or a
`declaration-selection-file`; otherwise the policy fails with
`unknown-row-binding` or `invalid-procedure-effects-input`.

#### `join`

```lisp
(join :left NAME :right NAME [:kind inner|semi|anti] :on ((LEFT RIGHT)...))
```

Join two named row relations by registered equal-typed fields. Legal in: policy, `assertion`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:left` | required | a bounded row binding, group, or aggregate name | `:left NAME`. Name the left row binding. |
| `:right` | required | a bounded row binding, group, or aggregate name | `:right NAME`. Name the right row binding. |
| `:kind` | optional | inner, semi, or anti | `:kind inner\|semi\|anti`. Choose an inner join, a semi join that keeps matching left rows without the right relation columns, or an anti-join that keeps left rows with no partner; omission means inner. |
| `:on` | required | one or more equality field pairs; list (source order kept) of 1 to 16 items | `:on ((LEFT-FIELD RIGHT-FIELD)...)`. Declare equal-typed field pairs relative to the left and right bindings. |

#### `group`

```lisp
(group :name NAME :by (BINDING.FIELD...) (aggregate ...) ...)
```

Group joined rows by registered fields and compute named aggregates. Legal in: policy, `assertion`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:name` | required | a bounded row binding, group, or aggregate name | `:name NAME`. Set the unique row group name. |
| `:by` | required | one or more binding.field row references; list (source order kept) of 1 to 16 items | `:by (BINDING.FIELD...)`. Choose the typed row fields that identify each group. |
| positional, repeated | required | aggregate records; list (source order kept) of 1 to 32 items | `(aggregate ...)...`. Declare the source-ordered aggregates computed for the group. |

#### `aggregate`

```lisp
(aggregate :name NAME :op min|max|count|count-distinct|any|all|ordered-equal|set-equal|subset [:value BINDING.FIELD] [:left COLUMN|(BINDING.POSITION BINDING.VALUE) :right COLUMN|(BINDING.POSITION BINDING.VALUE)] [:where ((BINDING.FIELD OP VALUE)...)] )
```

Compute one bounded typed aggregate within a row group. Legal in: policy, `assertion`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:name` | required | a bounded row binding, group, or aggregate name | `:name NAME`. Set the unique aggregate name within its group. |
| `:op` | required | min, max, count, count-distinct, any, all, ordered-equal, set-equal, or subset | `:op min\|max\|count\|count-distinct\|any\|all\|ordered-equal\|set-equal\|subset`. Choose the bounded aggregate operation. |
| `:value` | optional | a binding.field row reference | `:value BINDING.FIELD`. Select the typed input field the fold reads: an integer field for min or max, a boolean field for any or all, any field for count-distinct. |
| `:where` | optional | zero or more typed row predicates, each (BINDING.FIELD eq\|ne\|lt\|le\|gt\|ge VALUE-OR-FIELD), (BINDING.FIELD regex STRING), (BINDING.FIELD is-null\|is-not-null), or (BINDING.FIELD in (VALUE...)); list (source order kept) of 0 to 16 items | `:where ((BINDING.FIELD OP VALUE)...)`. Conjoin bounded typed predicates a row must satisfy to contribute to the fold. |
| `:left` | optional | a stable-key COLUMN for set-equal/subset or a (POSITION-FIELD VALUE-FIELD) ordered sequence | `:left COLUMN\|(BINDING.POSITION BINDING.VALUE)`. Name the left stable-key column for set-equal/subset, or the integer position and value columns for ordered-equal. |
| `:right` | optional | a stable-key COLUMN for set-equal/subset or a (POSITION-FIELD VALUE-FIELD) ordered sequence | `:right COLUMN\|(BINDING.POSITION BINDING.VALUE)`. Name the right stable-key column for set-equal/subset, or the ordered-equal sequence; both sides must have the same scalar type. |

#### `assert` (relational plan)

```lisp
(assert [:id ID] :group NAME :value NAME :cardinality (exactly|at-least|at-most N))
```

Assert a cardinality over one named aggregate in every row group. Legal in: policy, `assertion`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:id` | optional | a lowercase local entry identifier | `:id ID`. Optionally override the stable assertion identity derived from group and aggregate names. |
| `:group` | required | a bounded row binding, group, or aggregate name | `:group NAME`. Name the row group being asserted. |
| `:value` | required | a bounded row binding, group, or aggregate name | `:value NAME`. Name the aggregate being asserted. |
| `:cardinality` | required | an exactly, at-least, or at-most cardinality record | `:cardinality (exactly\|at-least\|at-most N)`. Set the expected aggregate cardinality. |

#### `assert-selected-in-winning-tier`

```lisp
(assert-selected-in-winning-tier :id ID :site NAME :candidates NAME [:cardinality (exactly|at-least|at-most N)])
```

Require the selected candidate of every overload-selection row to sit in the winning applicability tier, meaning the set of candidates the resolver's own applicability check accepted. Authoring sugar: it lowers to one inner join on site_ast_id, one group keyed on the site, one counting aggregate over selected applicable candidates, and one cardinality assertion, and adds no evaluation rule of its own. Legal in: policy, `assertion`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:id` | required | a lowercase local entry identifier | `:id ID`. Set the assertion identity, which also names the row group this sugar declares. |
| `:site` | required | a bounded row binding, group, or aggregate name | `:site NAME`. Name the binding holding one overload-selection row per call site. |
| `:candidates` | required | a bounded row binding, group, or aggregate name | `:candidates NAME`. Name the binding holding the callable-applicability rows of the same sites. |
| `:cardinality` | optional | an exactly, at-least, or at-most cardinality record | `:cardinality (exactly\|at-least\|at-most N)`. Bound the number of candidates that are both selected and applicable; omission means exactly 1. State (exactly 0) to assert an unresolved site and (at-least 2) to assert an ambiguous one. |

### Assertion: specialized assertions

#### `assert` (occurrence, inside `:asserts`)

```lisp
(assert :id ID :at CAPTURE :role ROLE :expect declaration|reference|binding|none [:cardinality (exactly N)] [:namespace NAMESPACE] [:require-target true|false])
```

Require or forbid occurrences at one captured AST node with exact cardinality. Legal in: policy, `assertion`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:id` | required | a lowercase local entry identifier | `:id "assert-id"`. Set the stable assertion identity used by finding anchors and messages. |
| `:at` | required | an RQL capture name bound by the subject selector | `:at CAPTURE`. Name the subject capture whose AST node the occurrence rows are joined to; it must capture the identifier token itself, never its enclosing declaration. |
| `:role` | required | one occurrence role from the analyzer registry | `:role ROLE`. Name the asserted occurrence role; capability reporting narrows to exactly this role. |
| `:expect` | required | declaration, reference, binding, or none | `:expect declaration\|reference\|binding\|none`. Name the expected occurrence class, or none to forbid any occurrence at the role. |
| `:cardinality` | optional | an exactly, at-least, or at-most cardinality record | `:cardinality (exactly N)\|(at-least N)\|(at-most N)`. Bound the joined row count; omission means exactly 1, and :expect none means exactly 0. |
| `:namespace` | optional | type, value, module, macro, label, or path_prefix | `:namespace NAMESPACE`. Additionally require the joined rows to resolve in one naming space. |
| `:require-target` | optional | true or false | `:require-target true\|false`. Count only reference-class rows whose semantic target resolved; omission is false. |

#### `assert-resolution`

```lisp
(assert-resolution :id ID :at CAPTURE :role ROLE :expect-tier TIER [:at-least true|false] [:forbid-tier TIER] [:require-unique true|false])
```

Require the resolver's selected candidate for one captured reference to sit at, or above, one precedence tier. Legal in: policy, `assertion`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:id` | required | a lowercase local entry identifier | `:id "assert-id"`. Set the stable assertion identity used by finding anchors and messages. |
| `:at` | required | an RQL capture name bound by the subject selector | `:at CAPTURE`. Name the subject capture whose reference the candidate rows are joined to; it must capture the identifier token itself. |
| `:role` | required | one occurrence role from the analyzer registry | `:role ROLE`. Name the reference-class occurrence role being resolved; capability reporting narrows to exactly this role. |
| `:expect-tier` | required | one precedence tier from the analyzer registry | `:expect-tier TIER`. Name the precedence tier the selected candidate must sit at. |
| `:at-least` | optional | true or false | `:at-least true\|false`. Accept any tier at least as strong as the expected one; omission requires the exact tier. |
| `:forbid-tier` | optional | one precedence tier from the analyzer registry | `:forbid-tier TIER`. Forbid any selection at one named tier, which is how the anti-fallback contract is spelled. |
| `:require-unique` | optional | true or false | `:require-unique true\|false`. Require exactly one selected candidate, making ambiguity a violation rather than a silent pick; omission is false. |

#### `assert-binding-scope`

```lisp
(assert-binding-scope :id ID :at CAPTURE :role ROLE :declared inside|outside :relative-to CAPTURE)
```

Require the binding of one captured reference to be declared inside or outside a second captured node. Legal in: policy, `assertion`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:id` | required | a lowercase local entry identifier | `:id "assert-id"`. Set the stable assertion identity used by finding anchors and messages. |
| `:at` | required | an RQL capture name bound by the subject selector | `:at CAPTURE`. Name the subject capture whose binding-of answer is asserted about. |
| `:role` | required | one occurrence role from the analyzer registry | `:role ROLE`. Name the reference-class occurrence role being reached from; capability reporting narrows to exactly this role. |
| `:declared` | required | inside or outside | `:declared inside\|outside`. Require the binding's declaring scope to be contained, or not contained, in the related capture. |
| `:relative-to` | required | an RQL capture name bound by the subject selector | `:relative-to CAPTURE`. Name the second subject capture whose node interval the declaring scope is compared against. |

#### `assert-value-origin`

```lisp
(assert-value-origin :id ID :at CAPTURE :role ROLE :established inside|outside :relative-to CAPTURE)
```

Require the value read at one captured reference to be established -- by its binding's declaring scope, or by an assignment reaching that binding -- inside or outside a second captured node. Legal in: policy, `assertion`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:id` | required | a lowercase local entry identifier | `:id "assert-id"`. Set the stable assertion identity used by finding anchors and messages. |
| `:at` | required | an RQL capture name bound by the subject selector | `:at CAPTURE`. Name the subject capture whose value origin is asserted about. |
| `:role` | required | one occurrence role from the analyzer registry | `:role ROLE`. Name the reference-class occurrence role being reached from; capability reporting narrows to exactly this role. |
| `:established` | required | inside or outside | `:established inside\|outside`. Require the value's origin -- its binding's declaring scope, or an assignment reaching that binding -- to be contained, or not contained, in the related capture. |
| `:relative-to` | required | an RQL capture name bound by the subject selector | `:relative-to CAPTURE`. Name the second subject capture whose node interval the value origins are compared against. |

#### `assert-origin-shape`

```lisp
(assert-origin-shape :id ID :at LOOP_CAPTURE :anchor CAPTURE :role ROLE :shape collection-literal :max-elements N)
```

Require the captured loop's iterated expression to provably originate from a collection literal with at most N elements. Inverted polarity: anything short of positive proof -- a loop with no iterated expression in evidence, no lexical binding, no establishing initializer, or a non-qualifying initializer -- violates and keeps the finding, which anchors at the anchor capture. Legal in: policy, `assertion`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:id` | required | a lowercase local entry identifier | `:id "assert-id"`. Set the stable assertion identity used by finding anchors and messages. |
| `:at` | required | an RQL capture name bound by the subject selector | `:at CAPTURE`. Name the captured loop whose iterated expression's origin shape is asserted about. The loop joins to its iterated expression internally; a loop that does not iterate an expression in evidence (a while loop, a counting for) violates rather than abstaining. |
| `:anchor` | required | an RQL capture name bound by the subject selector | `:anchor CAPTURE`. Name the capture the finding anchors to, so two subject matches sharing one iterated expression stay distinct findings. Must be bound by every selector alternative. |
| `:role` | required | one occurrence role from the analyzer registry | `:role ROLE`. Name the reference-class occurrence role the origin join reads from; capability reporting narrows to exactly this role. |
| `:shape` | required | collection-literal | `:shape collection-literal`. Name the required origin shape. The only shape today is collection-literal: an array, list, set, dictionary, or tuple display literal. |
| `:max-elements` | required | a positive integer | `:max-elements N`. Bound the qualifying literal's element count. A literal with more elements does not satisfy the assert. |

#### `assert-boundary`

```lisp
(assert-boundary :id ID :at CAPTURE :role ROLE :forbid-fallback-past external_declared_unindexed|external_unknown)
```

Forbid a name-only fallback selection once resolution reached or passed one authoritative boundary. Legal in: policy, `assertion`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:id` | required | a lowercase local entry identifier | `:id "assert-id"`. Set the stable assertion identity used by finding anchors and messages. |
| `:at` | required | an RQL capture name bound by the subject selector | `:at CAPTURE`. Name the subject capture whose reference the candidate rows are joined to. |
| `:role` | required | one occurrence role from the analyzer registry | `:role ROLE`. Name the reference-class occurrence role being resolved; capability reporting narrows to exactly this role. |
| `:forbid-fallback-past` | required | external_declared_unindexed or external_unknown | `:forbid-fallback-past external_declared_unindexed\|external_unknown`. Name the boundary strength at or past which a name-only fallback selection is forbidden. |

#### `assert-generation`

```lisp
(assert-generation :id ID :at CAPTURE [:kind KIND] [:cardinality (exactly N)] [:forbid-dynamic true|false])
```

Require one captured generation site to materialize an exact generated set, optionally forbidding dynamic inputs. Legal in: policy, `assertion`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:id` | required | a lowercase local entry identifier | `:id "assert-id"`. Set the stable assertion identity used by finding anchors and messages. |
| `:at` | required | an RQL capture name bound by the subject selector | `:at CAPTURE`. Name the subject capture addressing the generation site node itself. |
| `:kind` | optional | one generation kind from the analyzer registry | `:kind KIND`. Restrict the joined site rows to one generation kind. |
| `:cardinality` | optional | an exactly, at-least, or at-most cardinality record | `:cardinality (exactly N)`. Require the literal site's generated set to satisfy this cardinality. |
| `:forbid-dynamic` | optional | true or false | `:forbid-dynamic true\|false`. Report a dynamic generation site as a finding instead of an inconclusive verdict. |

#### `assert-declaration-state`

```lisp
(assert-declaration-state :id ID :at CAPTURE [:origin ORIGIN] [:declaration-only true|false] [:config-gated true|false])
```

Require one captured declaration's state row to carry an expected origin, declaration-only flag, or configuration gate. Legal in: policy, `assertion`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:id` | required | a lowercase local entry identifier | `:id "assert-id"`. Set the stable assertion identity used by finding anchors and messages. |
| `:at` | required | an RQL capture name bound by the subject selector | `:at CAPTURE`. Name the subject capture addressing the declaration node whose state is asserted. |
| `:origin` | optional | parsed, generated, or recovered | `:origin ORIGIN`. Require the state row's origin to be exactly this value. |
| `:declaration-only` | optional | true or false | `:declaration-only true\|false`. Require the state row's declaration-only flag to match. |
| `:config-gated` | optional | true or false | `:config-gated true\|false`. Require the state row's configuration gate to match. |

#### `assert-edge-parity`

```lisp
(assert-edge-parity :id ID :at CAPTURE :role ROLE [:surface external-usages|lsp-references])
```

Require field-for-field agreement between the forward and inverse reference-edge projections at the captured token, within one workspace generation. Legal in: policy, `assertion`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:id` | required | a lowercase local entry identifier | `:id "assert-id"`. Set the stable assertion identity used by finding anchors and messages. |
| `:at` | required | an RQL capture name bound by the subject selector | `:at CAPTURE`. Name the subject capture; it must capture the identifier token whose edges are compared. |
| `:role` | required | one occurrence role from the analyzer registry | `:role ROLE`. A reference-class role compares forward to inverse; declaration_name compares the declaration's inverse listing to forward. |
| `:surface` | optional | external-usages or lsp-references | `:surface external-usages\|lsp-references`. Compare only edges of one usage surface; omission compares the complete row set. |

#### `assert-edge-class`

```lisp
(assert-edge-class :id ID :at CAPTURE :role ROLE :axis relation|usage|site-class|kind [:require [..]] [:forbid [..]] [:surface external-usages|lsp-references])
```

Require or forbid typed classifications on the captured token's reference edges. Legal in: policy, `assertion`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:id` | required | a lowercase local entry identifier | `:id "assert-id"`. Set the stable assertion identity used by finding anchors and messages. |
| `:at` | required | an RQL capture name bound by the subject selector | `:at CAPTURE`. Name the subject capture; it must capture the identifier token whose edges are classified. |
| `:role` | required | one occurrence role from the analyzer registry | `:role ROLE`. A reference-class role reads the token's forward edges; declaration_name reads the declaration's inverse listing. |
| `:axis` | required | relation, usage, site-class, or kind | `:axis relation\|usage\|site-class\|kind`. Name the classification axis the constraint applies to. |
| `:require` | optional | one or more classification labels of the constrained axis | `:require [value ...]`. Every edge's value on the axis must be one of these labels. |
| `:forbid` | optional | one or more classification labels of the constrained axis | `:forbid [value ...]`. No edge's value on the axis may be one of these labels. |
| `:surface` | optional | external-usages or lsp-references | `:surface external-usages\|lsp-references`. Classify only edges of one usage surface; omission classifies the complete row set. |

#### `assert-canonical`

```lisp
(assert-canonical :id ID :at CAPTURE :role ROLE :equals CAPTURE :equals-role ROLE [:distinct true|false])
```

Require two captured tokens' resolved declarations to share, or not share, one canonical identity. Legal in: policy, `assertion`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:id` | required | a lowercase local entry identifier | `:id "assert-id"`. Set the stable assertion identity used by finding anchors and messages. |
| `:at` | required | an RQL capture name bound by the subject selector | `:at CAPTURE`. Name the subject capture whose resolved declarations carry the first canonical identity. |
| `:role` | required | one occurrence role from the analyzer registry | `:role ROLE`. Name the subject token's reference-class occurrence role; capability reporting narrows to exactly this role. |
| `:equals` | required | an RQL capture name bound by the subject selector | `:equals CAPTURE`. Name the second capture whose resolved declarations carry the compared canonical identity. |
| `:equals-role` | required | one occurrence role from the analyzer registry | `:equals-role ROLE`. Name the second token's occurrence role. |
| `:distinct` | optional | true or false | `:distinct true\|false`. Invert the requirement: the two selections must share no canonical identity; omission requires a shared one. |

#### `assert-route`

```lisp
(assert-route :id ID :at CAPTURE :role ROLE :to CAPTURE :to-role ROLE [:via HOP] [:forbid HOP])
```

Require an identity route from the captured site to a second capture's declaration, optionally via or never via one hop kind. Legal in: policy, `assertion`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:id` | required | a lowercase local entry identifier | `:id "assert-id"`. Set the stable assertion identity used by finding anchors and messages. |
| `:at` | required | an RQL capture name bound by the subject selector | `:at CAPTURE`. Name the subject capture whose site the route starts from. |
| `:role` | required | one occurrence role from the analyzer registry | `:role ROLE`. Name the subject token's occurrence role; capability reporting narrows to exactly this role. |
| `:to` | required | an RQL capture name bound by the subject selector | `:to CAPTURE`. Name the capture whose resolved declaration the route must terminate at. |
| `:to-role` | required | one occurrence role from the analyzer registry | `:to-role ROLE`. Name the target token's occurrence role. |
| `:via` | optional | one identity route hop kind from the analyzer registry | `:via HOP`. Require at least one hop of this kind on the route. |
| `:forbid` | optional | one identity route hop kind from the analyzer registry | `:forbid HOP`. Never follow hops of this kind, so a route needing one does not exist for this assert. |

#### `assert-round-trip`

```lisp
(assert-round-trip :id ID :at CAPTURE :role ROLE)
```

Require forward resolution and inverse enumeration to round-trip the captured site. Legal in: policy, `assertion`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:id` | required | a lowercase local entry identifier | `:id "assert-id"`. Set the stable assertion identity used by finding anchors and messages. |
| `:at` | required | an RQL capture name bound by the subject selector | `:at CAPTURE`. Name the subject capture whose site is round-tripped. |
| `:role` | required | one occurrence role from the analyzer registry | `:role ROLE`. Name the subject token's occurrence role; capability reporting narrows to exactly this role. |

#### `assert-flow-establishment`

```lisp
(assert-flow-establishment :id ID :at CAPTURE :role ROLE [:require dominated|reached] [:forbid-same-evaluation true|false])
```

Require control flow to have established the captured subject before the read: some path carries an establishment to it (:require reached, the default), or every entry-to-read path passes one (:require dominated). Optionally forbid an establishment from serving a read of its own evaluation. Legal in: policy, `assertion`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:id` | required | a lowercase local entry identifier | `:id "assert-id"`. Set the stable assertion identity used by finding anchors and messages. |
| `:at` | required | an RQL capture name bound by the subject selector | `:at CAPTURE`. Name the subject capture; it must capture the identifier token whose read is asserted about. |
| `:role` | required | one occurrence role from the analyzer registry | `:role ROLE`. Name the occurrence role the read is spelled at; capability reporting narrows to exactly this role. |
| `:require` | optional | dominated or reached | `:require dominated\|reached`. Require an establishment on some path (reached, the default) or on every entry-to-read path (dominated). |
| `:forbid-same-evaluation` | optional | true or false | `:forbid-same-evaluation true\|false`. Additionally forbid an establishment from serving a read inside its own evaluation. |

#### `assert-rewrite-termination`

```lisp
(assert-rewrite-termination :id ID :domain DOMAIN [:scope CAPTURE])
```

Require every bounded rewrite chase of one declared finite domain to converge within the bound the domain declares for itself. A repeated semantic state is a finding with its ordered witness; an exhausted budget is absence of evidence and makes the run inconclusive. Legal in: policy, `assertion`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:id` | required | a lowercase local entry identifier | `:id "assert-id"`. Set the stable assertion identity used by finding anchors and messages. |
| `:domain` | required | one bounded rewrite domain from the analyzer registry | `:domain DOMAIN`. Name the declared finite rewrite domain whose chases must converge. |
| `:scope` | optional | an RQL capture name bound by the subject selector | `:scope CAPTURE`. Narrow the file set to the files whose subject rows bind this capture; omission states the domain terminates on every analyzed file. |

#### `exactly`

```lisp
(exactly N)
```

Require exactly N joined occurrence rows. Legal in: policy, `assertion`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| positional | required | a non-negative integer | `N`. Provide the exact required row count. |

#### `at-least`

```lisp
(at-least N)
```

Require at least N joined occurrence rows. Legal in: policy, `assertion`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| positional | required | a non-negative integer | `N`. Provide the inclusive lower bound on the row count. |

#### `at-most`

```lisp
(at-most N)
```

Require at most N joined occurrence rows. Legal in: policy, `assertion`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| positional | required | a non-negative integer | `N`. Provide the inclusive upper bound on the row count. |

### Report, message, and severity

#### `generated-message`

```lisp
(generated-message :relation can-reach)
```

Generate the fixed source-display can-reach sink-display message after proven flow. Legal in: policy, `taint`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:relation` | required | the can-reach generated relation | `:relation can-reach`. Select the fixed can-reach relation renderer. |

#### `cvss-severity`

```lisp
(cvss-severity :when-unscored unrated|note|warning|error)
```

Derive severity from CVSS with an explicit unscored fallback. Legal in: policy, every analysis type.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:when-unscored` | required | note, warning, error, or unrated | `:when-unscored unrated\|note\|warning\|error`. Set the fallback when no complete CVSS assessment exists. |

#### `report`

```lisp
(report [:witness WITNESS] [:witnesses-per-finding N] [:origins-per-finding N])
```

Bound witness and origin retention for each finding. Legal in: policy, every analysis type.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:witness` | optional | a witness record | `:witness (witness ...)`. Override the per-witness bounds. |
| `:witnesses-per-finding` | optional | a non-negative integer | `:witnesses-per-finding N`. Bound retained witnesses per finding. |
| `:origins-per-finding` | optional | a non-negative integer | `:origins-per-finding N`. Bound retained dependency origins per finding. |

#### `witness`

```lisp
(witness [:max-steps N] [:max-bytes N])
```

Bound the retained steps and encoded bytes of one witness. Legal in: policy, every analysis type.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:max-steps` | optional | a non-negative integer | `:max-steps N`. Bound retained steps in one witness. |
| `:max-bytes` | optional | a non-negative integer | `:max-bytes N`. Bound encoded bytes in one witness. |

### Classification and CVSS

#### `classification`

```lisp
(classification :fallback CLASSIFICATION [:refinements [...]] [:cvss CVSS])
```

Declare a broad taxonomy classification, ordered refinements, and optional CVSS policy. Legal in: policy, every analysis type.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:fallback` | required | a classification-id record | `:fallback (classification-id ...)`. Preserve one broad taxonomy classification for every finding. |
| `:refinements` | optional | ordered refinement records; list (source order kept) of 0 to 128 items | `:refinements [(refinement ...)...]`. Apply bounded refinements in source order. |
| `:cvss` | optional | a cvss record | `:cvss (cvss ...)`. Optionally establish evidence-backed CVSS Base metrics. |

#### `classification-id`

```lisp
(classification-id :taxonomy "NAME" :id "IDENTIFIER" [:name "DISPLAY NAME"])
```

Name one taxonomy classification without deriving semantics from its text. Legal in: policy, every analysis type.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:taxonomy` | required | a bounded exact taxonomy name | `:taxonomy "NAME"`. Name the taxonomy exactly. |
| `:id` | required | a bounded exact taxonomy identifier | `:id "IDENTIFIER"`. Name the taxonomy identifier exactly. |
| `:name` | optional | a bounded human-readable name | `:name "Display name"`. Add optional taxonomy display text. |

#### `refinement`

```lisp
(refinement :when PREDICATE :add [CLASSIFICATION...])
```

Add classifications when a typed evidence predicate holds. Legal in: policy, every analysis type.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:when` | required | a typed classification evidence predicate | `:when PREDICATE`. Select complete typed evidence for this refinement. |
| `:add` | required | classification-id records; set (no duplicates) of 1 to 64 items | `:add [(classification-id ...)...]`. Add a non-empty duplicate-free classification set. |

#### `all` (classification predicate)

```lisp
(all [PREDICATE...])
```

Require every non-empty child evidence predicate. Legal in: policy, every analysis type.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| positional | required | typed evidence predicate records; set (no duplicates) of 1 to 256 items | `[PREDICATE...]`. Provide the non-empty duplicate-free child predicate set. |

#### `any` (classification predicate)

```lisp
(any [PREDICATE...])
```

Require at least one non-empty child evidence predicate. Legal in: policy, every analysis type.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| positional | required | typed evidence predicate records; set (no duplicates) of 1 to 256 items | `[PREDICATE...]`. Provide the non-empty duplicate-free child predicate set. |

#### `analysis-type`

```lisp
(analysis-type :is match|taint|typestate)
```

Match the current typed analysis kind. Legal in: policy, every analysis type.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:is` | required | match, taint, typestate, assertion, or flow | `:is match\|taint\|typestate`. Match one exact analysis kind. |

#### `source-categories`

```lisp
(source-categories (:any [...] | :all [...]))
```

Match exact categories on the resolved source endpoint. Legal in: policy, `taint`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:any` | optional | opaque exact endpoint categories; set (no duplicates) of 1 to 64 items | `:any [CATEGORY...]`. Match any listed source category; exclusive with all. |
| `:all` | optional | opaque exact endpoint categories; set (no duplicates) of 1 to 64 items | `:all [CATEGORY...]`. Match all listed source categories; exclusive with any. |

#### `sink-categories`

```lisp
(sink-categories (:any [...] | :all [...]))
```

Match exact categories on the resolved sink endpoint. Legal in: policy, `taint`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:any` | optional | opaque exact endpoint categories; set (no duplicates) of 1 to 64 items | `:any [CATEGORY...]`. Match any listed sink category; exclusive with all. |
| `:all` | optional | opaque exact endpoint categories; set (no duplicates) of 1 to 64 items | `:all [CATEGORY...]`. Match all listed sink categories; exclusive with any. |

#### `source-labels`

```lisp
(source-labels (:any [...] | :all [...]))
```

Match normalized labels on the resolved source endpoint. Legal in: policy, `taint`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:any` | optional | normalized taint labels; set (no duplicates) of 1 to 64 items | `:any [LABEL...]`. Match any listed source label; exclusive with all. |
| `:all` | optional | normalized taint labels; set (no duplicates) of 1 to 64 items | `:all [LABEL...]`. Match all listed source labels; exclusive with any. |

#### `sink-tags`

```lisp
(sink-tags (:any [...] | :all [...]))
```

Match normalized tags on the resolved sink endpoint. Legal in: policy, `taint`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:any` | optional | normalized sink tags; set (no duplicates) of 1 to 64 items | `:any [TAG...]`. Match any listed sink tag; exclusive with all. |
| `:all` | optional | normalized sink tags; set (no duplicates) of 1 to 64 items | `:all [TAG...]`. Match all listed sink tags; exclusive with any. |

#### `sink-impacts`

```lisp
(sink-impacts (:any [...] | :all [...]))
```

Match normalized impacts on the resolved sink endpoint. Legal in: policy, `taint`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:any` | optional | normalized sink impacts; set (no duplicates) of 1 to 64 items | `:any [IMPACT...]`. Match any listed sink impact; exclusive with all. |
| `:all` | optional | normalized sink impacts; set (no duplicates) of 1 to 64 items | `:all [IMPACT...]`. Match all listed sink impacts; exclusive with any. |

#### `finding-combination` (predicate)

```lisp
(finding-combination :id ID)
```

Match the selected intentional finding-combination identity. Legal in: policy, `taint`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:id` | required | a lowercase finding-combination identifier | `:id COMBINATION`. Match one selected finding-combination ID. |

#### `typestate-expectation`

```lisp
(typestate-expectation :id ID)
```

Match the violated typestate terminal-expectation identity. Legal in: policy, `typestate`.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:id` | required | a lowercase typestate expectation identifier | `:id EXPECTATION`. Match one violated terminal-expectation ID. |

#### `cvss`

```lisp
(cvss :version "4.0" :emit when-base-complete :metric-rules [METRIC...])
```

Establish evidence-backed CVSS v4.0 Base metrics without authored scores. Legal in: policy, every analysis type.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:version` | required | the string 4.0 | `:version "4.0"`. Select the only schema-version-1 CVSS authoring version. |
| `:emit` | required | when-base-complete | `:emit when-base-complete`. Emit a score only when all Base metrics are established coherently. |
| `:metric-rules` | required | CVSS metric records; list (source order kept) of 1 to 256 items | `:metric-rules [(metric ...)...]`. Declare non-empty bounded evidence-backed Base metric rules. |

#### `metric`

```lisp
(metric :name BASE-METRIC :value VALUE :when PREDICATE :basis policy-assertion :scope SCOPE :evidence-refs [...] :rationale TEXT [:assumptions [...]])
```

Establish one static CVSS Base metric from typed policy evidence. Legal in: policy, every analysis type.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| `:name` | required | one of the eleven CVSS v4.0 Base metric names | `:name AV\|AC\|AT\|PR\|UI\|VC\|VI\|VA\|SC\|SI\|SA`. Name one authorable CVSS v4.0 Base metric. |
| `:value` | required | a value legal for the selected CVSS Base metric | `:value LEGAL-BASE-VALUE`. Set a value legal for the selected Base metric; X is never authorable. |
| `:when` | required | a typed CVSS evidence predicate | `:when PREDICATE`. Select complete typed evidence that establishes the metric. |
| `:basis` | required | policy-assertion | `:basis policy-assertion`. Declare the only authorable static evidence basis. |
| `:scope` | required | vulnerable-system, subsequent-system, or global | `:scope vulnerable-system\|subsequent-system\|global`. Name the system scope required by the selected metric. |
| `:evidence-refs` | required | policy evidence references; set (no duplicates) of 1 to 64 items | `:evidence-refs [EVIDENCE-REF...]`. Cite a non-empty set of resolvable typed evidence facts. |
| `:rationale` | required | bounded human-readable display text | `:rationale "text"`. Explain the static metric assertion. |
| `:assumptions` | optional | bounded strings; set (no duplicates) of 0 to 64 items | `:assumptions ["text"...]`. Record bounded explicit assumptions without changing evidence identity rules. |

#### `all` (CVSS evidence predicate)

```lisp
(all [CVSS-EVIDENCE-PREDICATE...])
```

Require every non-empty child CVSS evidence predicate. Legal in: policy, every analysis type.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| positional | required | typed CVSS evidence predicate records; set (no duplicates) of 1 to 256 items | `[CVSS-EVIDENCE-PREDICATE...]`. Provide the non-empty duplicate-free child CVSS evidence predicate set. |

#### `any` (CVSS evidence predicate)

```lisp
(any [CVSS-EVIDENCE-PREDICATE...])
```

Require at least one non-empty child CVSS evidence predicate. Legal in: policy, every analysis type.

| Field | Required | Value | Meaning |
| --- | --- | --- | --- |
| positional | required | typed CVSS evidence predicate records; set (no duplicates) of 1 to 256 items | `[CVSS-EVIDENCE-PREDICATE...]`. Provide the non-empty duplicate-free child CVSS evidence predicate set. |

### Atom values

An atom is an unquoted symbol from a closed set. An unknown spelling fails with
`invalid-enum-value`, and the message lists every accepted spelling. Some
values have an alternative spelling, shown in parentheses.

#### Analysis type

Used by `(analysis :type ...)`.

| Spelling | Meaning |
| --- | --- |
| `match` | Execute a direct location-bearing selector. |
| `taint` | Declare set-oriented taint propagation inputs. |
| `typestate` | Declare endpoint-bound protocol tracking. |
| `assertion` | Declare correlated occurrence invariants over captured AST nodes. |
| `flow` | Declare policy-authored generic bounded value flow. |

#### Generated message relation

Used by `(generated-message :relation ...)`.

| Spelling | Meaning |
| --- | --- |
| `can-reach` | Render source display, can reach, and sink display after proven flow. |

#### Severity

Used by `:severity`, `(cvss-severity :when-unscored ...)`.

| Spelling | Meaning |
| --- | --- |
| `unrated` | Do not assign a fixed report level. |
| `note` | Report at note level. |
| `warning` | Report at warning level. |
| `error` | Report at error level. |

#### Endpoint role

Used by `(endpoint :role ...)`, `:role` on `match-directory` and `match-endpoints`.

| Spelling | Meaning |
| --- | --- |
| `source` | The endpoint introduces or identifies a tracked value. |
| `sink` | The endpoint consumes or observes a tracked value. |

#### Endpoint-set kind

Used by `(endpoint-set-document :kind ...)`.

| Spelling | Meaning |
| --- | --- |
| `sources` | A standalone source endpoint set. |
| `sinks` | A standalone sink endpoint set. |
| `sanitizers` | A standalone sanitizer endpoint set. |
| `entry-points` | A standalone entry-point endpoint set. |
| `transforms` | A standalone taint transform endpoint set. |
| `external-models` | A standalone external-model endpoint set. |
| `stores` | A standalone store endpoint set. |
| `origins` | A standalone value-flow origin endpoint set. |
| `observations` | A standalone value-flow observation endpoint set. |
| `kills` | A standalone value-flow kill endpoint set. |
| `flow-transforms` | A standalone value-flow transform endpoint set. |

#### Port

Used by `:binding`, `:bind`, `:dangerous-operand`, `:input`, `:output`, `:observed-operand`, `:key`, `:instance`, `:subject`.

| Spelling | Meaning |
| --- | --- |
| `matched-value` | Bind the location-bearing value selected directly by non-call RQL. |
| `receiver` | Bind the call receiver. |
| `return-value` | Bind the normal return value. |

#### Typestate call port

Used by `(calls :subject ...)` and external-model ports.

| Spelling | Meaning |
| --- | --- |
| `receiver` | Bind the already tracked call receiver. |
| `return-value` | Bind the already tracked normal return value. |

#### Analysis mode

Used by `(analysis :mode ...)`.

| Spelling | Meaning |
| --- | --- |
| `may` | Report flows or protocol paths that may occur. |

#### Unmodeled call behavior

Used by `(call-modeling :unmodeled ...)`.

| Spelling | Meaning |
| --- | --- |
| `paranoid` | Conservatively propagate every transfer justified by structured call-site metadata. |
| `optimistic` | Preserve existing facts without adding flows through the unseen body. |
| `require-model` | Abstain from input-dependent transfer when no exact or curated model applies. |

#### Unknown verdict

Used by `(on-unknown :verdict ...)`.

| Spelling | Meaning |
| --- | --- |
| `abstain` | Keep the findings, publish the inconclusive completion, and exit unreliable. The default. |
| `warn-unreliable` | Keep the findings and the inconclusive completion, mark them unreliable, and exit on the findings alone. |
| `fail-closed` | Treat the blocked verdict as a gate failure at the policy severity, and name the unknown that caused it. |
| `treat-may-as-finding` | Publish explicit may evidence as possible findings with its reasons; unmet coverage obligations still make the run inconclusive. Flow and taint already retain possible findings under every verdict. |

#### Trust boundary

Used by `(evidence :trust-boundary ...)`, `(source-evidence :trust-boundary ...)`.

| Spelling | Meaning |
| --- | --- |
| `external` | The value crosses an external trust boundary. |
| `internal` | The value originates inside the system trust boundary. |
| `same-trust-zone` | The value remains in the same trust zone. |

#### System entry

Used by `(evidence :system-entry ...)`, `(source-evidence :system-entry ...)`.

| Spelling | Meaning |
| --- | --- |
| `vulnerable-system-network-stack` | The value enters through the vulnerable system network stack. |
| `downloaded-artifact` | The value enters through a downloaded artifact. |
| `local-input` | The value enters through local input. |
| `adjacent-network` | The value enters from an adjacent network. |
| `physical` | The value requires physical access. |

#### Directory scope

Used by `(match-directory :scope ...)`.

| Spelling | Meaning |
| --- | --- |
| `direct` | Inspect only direct directory children. |
| `recursive` | Inspect the bounded subtree recursively. |

#### Transfer effect

Used by `(transfer :effect ...)`; the records `(sanitize ...)` and `(transform ...)` are the other two effects.

| Spelling | Meaning |
| --- | --- |
| `propagate` | Propagate the selected labels unchanged. |

#### Uncertainty policy

Used by `(uncertainty :escape ...)`.

| Spelling | Meaning |
| --- | --- |
| `inconclusive` | Mark the policy run incomplete rather than assuming behavior. |

#### Observation phase

Used by `:phase` on `calls`, `match-directory`, and `match-endpoints`.

| Spelling | Meaning |
| --- | --- |
| `at-match` | Observe a direct matched value. |
| `before-call` | Observe the bound value before call execution. |
| `after-normal-return` | Observe after the normal continuation. |
| `after-exceptional-return` | Observe after the exceptional continuation. |

#### Exit scope

Used by `:scope` on `normal-procedure-exit`, `exceptional-procedure-exit`, `suspension-boundary`.

| Spelling | Meaning |
| --- | --- |
| `analysis-root` | Observe only the outer demand procedure, not helper returns. |

#### CVSS version

Used by `(cvss :version ...)`.

| Spelling | Meaning |
| --- | --- |
| `4.0` | Use CVSS version 4.0. |

#### CVSS emit policy

Used by `(cvss :emit ...)`.

| Spelling | Meaning |
| --- | --- |
| `when-base-complete` | Score only a coherent complete Base vector. |

#### CVSS basis

Used by `(metric :basis ...)`.

| Spelling | Meaning |
| --- | --- |
| `policy-assertion` | Establish a static metric from verified policy evidence. |

#### CVSS metric scope

Used by `(metric :scope ...)`.

| Spelling | Meaning |
| --- | --- |
| `vulnerable-system` | The metric concerns the vulnerable system. |
| `subsequent-system` | The metric concerns a subsequent system. |
| `global` | The metric is global rather than system-scoped. |

#### Evidence reference

Used by `(metric :evidence-refs [...])`.

| Spelling | Meaning |
| --- | --- |
| `policy:self` | Reference the policy assertion itself. |
| `selector:PATH` (prefix `selector:`) | Reference one stable selector semantic path. |

#### Occurrence role

Used by `:role`, `:equals-role`, `:to-role` on specialized assertions.

| Spelling | Meaning |
| --- | --- |
| `declaration_name` | The name token of a declaration head. |
| `binder` | A pure binding introduction. |
| `label_or_key` | A label, keyword-argument name, or keyed-field position. |
| `type_operand` | An identifier consumed as a type. |
| `path_segment` | A non-terminal segment of a qualified path. |
| `import_alias` | The locally introduced alias name in an import or export. |
| `import_target` | The imported or exported source name. |
| `receiver_position` | The receiver of a member access or call. |
| `member_position` | The member name in a member access or call. |
| `pattern_position` | A non-binding identifier inside a pattern. |
| `generated_source` | A token whose presence generates declarations elsewhere. |
| `value_reference` | A plain read or write of a value in expression position. |

#### Expected occurrence

Used by `(assert :expect ...)`.

| Spelling | Meaning |
| --- | --- |
| `declaration` | Require declaration-class rows at the asserted role. |
| `reference` | Require reference-class rows at the asserted role. |
| `binding` | Require binding-class rows at the asserted role. |
| `none` | Forbid any occurrence at the asserted role. |

#### Occurrence namespace

Used by `(assert :namespace ...)`.

| Spelling | Meaning |
| --- | --- |
| `type` | The type naming space. |
| `value` | The value naming space. |
| `module` | The module naming space. |
| `macro` | The macro naming space. |
| `label` | The label naming space. |
| `path_prefix` | The qualifier naming space: a non-terminal path segment names a module or a type, decided by lookup rather than by syntax. |

#### Generation kind

Used by `(assert-generation :kind ...)`.

| Spelling | Meaning |
| --- | --- |
| `accessor_macro` | A member-generating attribute macro such as attr_accessor. |
| `alias_macro` | An alias-generating call such as alias_method. |
| `preprocessor_definition` | A #define that materializes a macro unit. |

#### Declaration origin

Used by `(assert-declaration-state :origin ...)`.

| Spelling | Meaning |
| --- | --- |
| `parsed` | Extracted from its own declaration node in a clean parse. |
| `generated` | Materialized by a macro-like construct with no declaration node of its own. |
| `recovered` | Reconstructed from a broken parse by analyzer recovery. |

#### Precedence tier

Used by `:expect-tier`, `:forbid-tier` on `assert-resolution`.

| Spelling | Meaning |
| --- | --- |
| `lexical_binding` | A binding introduced by the lexical environment. |
| `own_member` | A member declared by the enclosing type itself. |
| `inherited_member` | A member inherited from a supertype. |
| `explicit_import` | A name introduced by an explicit single-name import. |
| `package_or_module` | A name reachable in the same package or module. |
| `wildcard_import` | A name introduced by an on-demand or wildcard import. |
| `external_root` | A name reached through an external declaration root. |
| `name_only_fallback` | A selection made by bare-name scan after structured routes were available. |

#### Declared containment

Used by `:declared` on `assert-binding-scope`, `:established` on `assert-value-origin`.

| Spelling | Meaning |
| --- | --- |
| `inside` | The declaring scope is contained in the named capture. |
| `outside` | The declaring scope is not contained in the named capture. |

#### Origin shape

Used by `(assert-origin-shape :shape ...)`.

| Spelling | Meaning |
| --- | --- |
| `collection-literal` | A collection display literal: an array, list, set, dictionary, or tuple literal. |

#### Boundary strength

Used by `(assert-boundary :forbid-fallback-past ...)`.

| Spelling | Meaning |
| --- | --- |
| `external_declared_unindexed` | The lookup reached an external root the build declares but nothing indexed. |
| `external_unknown` | The lookup reached ground nothing is known about. |

#### Usage surface

Used by `:surface` on `assert-edge-parity` and `assert-edge-class`.

| Spelling | Meaning |
| --- | --- |
| `external-usages` (also `external_usages`) | Compare only edges the external-usage surface counts. |
| `lsp-references` (also `lsp_references`) | Compare every editor-visible edge, imports and self receivers included. |

#### Edge-class axis

Used by `(assert-edge-class :axis ...)`.

| Spelling | Meaning |
| --- | --- |
| `relation` | Constrain the owner relation between the site's encloser and the target. |
| `usage` | Constrain the usage kind of the edge. |
| `site-class` (also `site_class`) | Constrain whether the site is a use site or a declaration site. |
| `kind` | Constrain the structured source-reference kind of the edge. |

#### Establishment requirement

Used by `(assert-flow-establishment :require ...)`.

| Spelling | Meaning |
| --- | --- |
| `reached` | Some control-flow path carries an establishment to the read. |
| `dominated` | Every entry-to-read path passes an establishment. |

#### Rewrite domain

Used by `(assert-rewrite-termination :domain ...)`.

| Spelling | Meaning |
| --- | --- |
| `rust-import-alias` (also `rust_import_alias`) | The Rust import-alias specifier chase, keyed on the specifier root and bounded by the importing file's binder root count. |

#### Route hop

Used by `:via` and `:forbid` on `assert-route`.

| Spelling | Meaning |
| --- | --- |
| `alias` | A local respelling of a declaration: an import alias or a type alias. |
| `import` | An import binding that brings a declaration's name into a file or scope. |
| `export` | An export site that makes a local declaration reachable from outside its file or module. |
| `re_export` | An export whose subject comes from elsewhere, forwarding identity onward. |
| `partial_part` | One physical part of a declaration source spells in several pieces. |
| `declaration_definition_peer` | The peer link between a declaration head and its definition body. |
| `nested_owner` | The projection from a nested declaration onto its owner. |
| `implementation` | The link from an abstract member to a concrete member implementing it. |
| `generated_peer` | The link between a synthetic declaration and its source declaration. |

#### Boolean

Used by flag fields such as `:require-target`, `:at-least`, `:distinct`, `:forbid-dynamic`.

| Spelling | Meaning |
| --- | --- |
| `true` | Enable the flag. |
| `false` | Disable the flag. |

#### Join kind

Used by `(join :kind ...)`.

| Spelling | Meaning |
| --- | --- |
| `inner` | Retain rows with matching right-side rows. |
| `semi` | Retain left rows that have at least one matching right-side row, without carrying the right relation columns. |
| `anti` | Retain left rows with no matching right-side row. |

#### Aggregate operator

Used by `(aggregate :op ...)`.

| Spelling | Meaning |
| --- | --- |
| `min` | Compute the minimum integer value. |
| `count` | Count retained rows. |
| `count-distinct` | Count distinct non-null typed values. |
| `max` | Compute the maximum integer value. |
| `any` | Fold a boolean column to one when some contributing row is true, and to zero otherwise. |
| `all` | Fold a boolean column to one when every contributing row is true, and to zero otherwise. A group with no contributing row folds to one. |
| `set-equal` | One when the distinct present left and right stable-key values are equal as sets, zero otherwise. |
| `subset` | One when every distinct present left stable-key value occurs on the right, zero otherwise. |
| `ordered-equal` | Compare two ordered row sequences position by position: one when they hold the same value at every position and have the same length, zero otherwise. |

#### CVSS v4.0 Base metrics

`(metric :name ...)` accepts the eleven CVSS v4.0 Base metric names. Each
metric accepts only the values in its row. `:scope` must match the metric's
system scope.

| `:name` | Metric | Legal `:value` | Scope |
| --- | --- | --- | --- |
| `AV` | Attack Vector | `N`, `A`, `L`, `P` | `vulnerable-system` |
| `AC` | Attack Complexity | `L`, `H` | `vulnerable-system` |
| `AT` | Attack Requirements | `N`, `P` | `vulnerable-system` |
| `PR` | Privileges Required | `N`, `L`, `H` | `vulnerable-system` |
| `UI` | User Interaction | `N`, `P`, `A` | `vulnerable-system` |
| `VC` | Vulnerable System Confidentiality | `H`, `L`, `N` | `vulnerable-system` |
| `VI` | Vulnerable System Integrity | `H`, `L`, `N` | `vulnerable-system` |
| `VA` | Vulnerable System Availability | `H`, `L`, `N` | `vulnerable-system` |
| `SC` | Subsequent System Confidentiality | `H`, `L`, `N` | `subsequent-system` |
| `SI` | Subsequent System Integrity | `H`, `L`, `N` | `subsequent-system` |
| `SA` | Subsequent System Availability | `H`, `L`, `N` | `subsequent-system` |

A scored CVSS assessment requires all eleven metrics. A policy never supplies a
numeric score.

## Exit status

Every policy run (`--policy`, `--policy-file`, built-in selectors, and
`bifrost scan`) exits with one of three statuses. MCP `run_policy` returns the
same value as the computed policy status.

| Status | Meaning |
| --- | --- |
| `0` | The run is reliable, no active finding met the `--fail-on` threshold, and no suppression record is orphaned. |
| `1` | The run is reliable, and at least one active finding met the threshold or at least one suppression record has `orphan_state: orphaned`. |
| `2` | The run is unreliable, or the command could not run. Status 2 takes precedence over status 1. |

An orphaned suppression record gives status 1 even with `--fail-on never`.

A run is unreliable, and exits 2, when any of these is true:

- The CLI rejected an argument, a selector, or a combination of options.
- The run stopped at its deadline (`execution.termination` is set).
- The report has a report diagnostic with severity `error`. Every report
  diagnostic code except `workspace-model-inert` has severity `error`.
- The report dropped diagnostics (`diagnostics_truncated: true`).
- A policy run's completion is `inconclusive`, `unsupported`, or `failed`, or
  it is `not_run` after the user explicitly named its policy ID.
  The exception: an `inconclusive` run whose policy declares
  `(on-unknown :verdict warn-unreliable)` or `(on-unknown :verdict
  fail-closed)` does not make the batch unreliable.
- No finding met the threshold and a policy run's completion is
  `proven_subset`. A proven subset cannot support a clean result.

An active finding is a finding that no suppression, scope entry, or baseline
entry claims, and, under `--diff-base`, whose disposition is `new`.

`--fail-on` thresholds:

| Value | A finding gates when its severity is |
| --- | --- |
| `never` | Never. Orphaned suppressions still give status 1. |
| `finding` | Any severity, including `unrated`. |
| `note` | `note`, `warning`, or `error`. |
| `warning` (default) | `warning` or `error`. |
| `error` | `error`. |

With `(on-unknown :verdict fail-closed)`, an inconclusive run counts as a
finding at the policy's severity.

The explanation flags (`--explain-finding`, `--explain-candidate`,
`--explain-near-misses`) exit 0 whenever they produce an answer, whatever the
answer says, and 2 when they cannot produce one. `--accept-current` exits 0
after it writes the baseline and 2 when the run is unreliable.

## Completion states

Each entry of `runs[]` has a `completion` object. Its `type` is one of seven
values.

| `type` | Extra fields | Reliable | Exhaustive | Zero findings can exit 0 | SARIF notification ID |
| --- | --- | --- | --- | --- | --- |
| `complete` | none | yes | yes | yes | none |
| `proven_subset` | `codes`: the CodeQuery diagnostic codes that limited the search | yes | no | no; exits 2 | `BIFROST_POLICY_PROVEN_SUBSET` (warning) |
| `proven_by_summary` | none | yes | no | yes | `BIFROST_POLICY_PROVEN_BY_SUMMARY` (warning) |
| `inconclusive` | `reasons`: list of incomplete reasons; `scope`: which files the verdict concerns | no | no | no; exits 2 unless `on-unknown` says otherwise | `BIFROST_POLICY_INCONCLUSIVE` (warning) |
| `not_run` | `unavailable_capabilities`: unavailable capability labels and reasons; `selected_by`: explicit policy ID or pack/category/default | yes for implicit selection; no for an explicit policy ID | no | implicit selection does not affect the exit status; explicit ID exits 2 | `BIFROST_POLICY_NOT_RUN` (note) |
| `unsupported` | `capability`: the missing capability | no | no | no; exits 2 | `BIFROST_POLICY_UNSUPPORTED` (warning) |
| `failed` | `reasons`: list of failure reasons | no | no | no; exits 2 | `BIFROST_POLICY_FAILED` (error) |

- **Reliable** means the run's findings are trustworthy evidence. A reliable
  run with a gated finding exits 1.
- **Exhaustive** means a zero-finding result proves absence from analyzed code.
  Only `complete` is exhaustive.
- `proven_subset`: every retained finding is proven, but the run searched
  only part of the program. Zero findings is not a clean result.
- `proven_by_summary`: the result is precise, but it depends on authored
  external procedure summaries rather than on analyzed code. A clean result is
  a claim under those summaries, not proof from code.
- `not_run`: the policy was selected, but a required capability was
  unavailable. It has no findings and makes no absence claim. The report keeps
  it separate from policies that ran. A pack, category, or default selection
  remains reliable; an explicitly named policy ID exits 2 because Bifrost
  could not honor that request.

An `inconclusive` run's `scope` says which files the blocked verdict
concerns, tagged by `type`:

- `files`: `files` lists workspace-relative paths, sorted and spelled like a
  finding's `primary.path`. Every finding the run could have missed lies in one
  of these files, so its verdict on any other file is as reliable as a
  `complete` run's. At most 256 files are listed; `truncated: true` means
  more were left out, and the list then makes no promise.
- `run`: at least one cause could not be tied to files, so the verdict
  concerns the whole run.

An assertion that judges each file on its own names the files it could not
conclude. A taint run whose solve could not finish names the files of every
sink the policy bound, where every taint finding is anchored, rather than the
file where the solve stopped. A relational assertion with no join that
bounds an unfiltered `count` above by zero (`exactly 0` or `at-most 0`), as
the code-smell rules do, names the files of the rows it could not see, when
every query diagnostic behind the gap names them in `withheld_rows_path`.
Every other cause, such as budgets, incomplete selectors and report
retention, is `run`.

`inconclusive` reasons: `cancelled`, `deadline_exceeded`,
`query_result_limit`, `batch_finding_limit`, `scanned_file_budget`,
`source_byte_budget`, `fact_node_budget`, `pipeline_row_budget`,
`import_graph_budget`, `reference_candidate_budget`, `no_analyzable_files`,
`partial_discovery`, `capability_incomplete`,
`endpoint_dominance_undecidable`, `stable_anchor_unavailable`,
`report_retention_budget`, `cvss_variant_budget`,
`projection_scenario_membership_budget`,
`organizational_risk_overlay_budget`.

`failed` reasons: `invalid_execution_plan`,
`workspace_snapshot_unavailable`, `source_read_failed`, `workspace_io`,
`ambiguous_endpoint_dominance`, `ambiguous_typestate_binding`,
`conflicting_organizational_risk_overlay`, `internal_invariant`.

`unsupported` capability, tagged by `type`:

| `type` | Fields |
| --- | --- |
| `taint_evaluation` | none |
| `typestate_evaluation` | none |
| `query_feature` | `language`, `feature` |
| `query_domain` | `domain`, optional `capability`, and `reason`: `capability_unavailable`, `provider_unavailable`, `pack_unavailable`, or `cross_domain_operator_unavailable` |

## Canonical JSON report

`--format json` prints the canonical policy report. MCP `run_policy` returns
the same document. Its `schema_version` is `6`. The human and SARIF renderers
read the same document, so the three formats agree on finding IDs, hashes,
locations, severity, certainty, completion, evidence, and classifications.

### Top-level object

Fields appear in this order. Fields marked "when present" are omitted when
they do not apply.

| Field | Type | Meaning |
| --- | --- | --- |
| `schema_version` | integer | Always `6`. |
| `evaluation` | object | The evaluation date and the review file sources. See below. |
| `execution` | object | Timing and progress metadata. See below. |
| `rules` | array | One rule descriptor per loaded policy. |
| `runs` | array | One run object per evaluated policy and one `not_run` object for each selected policy skipped for an unavailable capability. |
| `suppressions` | array | One suppression review per loaded suppression record. |
| `scope` | array | One scope review per loaded scope entry. |
| `diff` | object, when present | The diff review. Present only with `--diff-base` or MCP `diff_base`. |
| `incremental` | object, when present | What the run reused from the policy-unit cache. |
| `packs` | object, when present | Semantic-model pack activation decisions. |
| `baseline` | object, when present | The baseline review. Present only when a baseline document loaded. |
| `diagnostics` | array | Report diagnostics. See [Report diagnostic codes](#report-diagnostic-codes). |
| `diagnostics_truncated` | Boolean | True when diagnostics were dropped. This makes the run exit 2. |
| `omitted_diagnostics_lower_bound` | integer | At least this many diagnostics were dropped. |
| `worst_omitted_diagnostic_severity` | string or null | `note`, `warning`, or `error` for the worst dropped diagnostic. |

`evaluation`:

| Field | Meaning |
| --- | --- |
| `evaluation_date` | The UTC date used for suppression expiry and baseline acceptance, `YYYY-MM-DD`. |
| `suppression_sources` | One `{path, state}` per configured suppression file: the three conventional files in order, or the one file that `--suppressions-file` names. A file that does not exist is listed with state `not_found`. |
| `scope_path` | The scope file path. |
| `scope_document_state` | State of the scope file. |

A document state is `not_evaluated`, `not_found`, `loaded`, or `invalid`.

`execution`:

| Field | Meaning |
| --- | --- |
| `total_elapsed_ms` | Total elapsed time. Successful reports keep it at `0` so the output is deterministic. |
| `stage_timings` | `{stage, elapsed_ms}` entries. Stages: `policy_selection`, `suppression_preflight`, `workspace_snapshot`, `policy_registration`, `policy_preparation`, `diff_base`, `policy_evaluation`, `report_construction`. |
| `termination` | `null`, or `deadline_exceeded` when the run stopped at its deadline. |
| `terminal_stage` | The stage that was running when the run stopped, or `null`. |
| `active_policy_id` | The policy that was running when the run stopped, or `null`. |
| `completed_policy_ids`, `pending_policy_ids` | Progress at the time the run stopped. |

### Rule descriptor

Each `rules[]` entry describes one loaded policy.

| Field | Meaning |
| --- | --- |
| `policy_id` | Stable policy ID. |
| `policy_hash` | SHA-256 semantic hash of the resolved policy. |
| `analysis_type` | `match`, `taint`, `typestate`, `assertion`, or `flow`. |
| `policy_schema` | `{version, origin}`. `origin` is `explicit`, `implicit_compatible`, or `referenced_document_explicit`. |
| `selector_schemas` | `{path, resolution}` for every selector. `path` is a JSON pointer into the policy, for example `/analysis/selector`. `resolution` has the same shape as `policy_schema`. |
| `endpoint_dependencies`, `match_directory_manifests`, `endpoint_set_dependencies` | The endpoint, match-directory, and endpoint-set inputs the policy resolved. |
| `precedence_manifest` | `{edges}`: the finding-combination precedence edges. |
| `name`, `description`, `help_uri`, `tags` | Policy metadata. `description` and `help_uri` can be null. |
| `message` | `{type: "static", text}` or `{type: "generated", relation: "can_reach"}`. |
| `severity` | `{type: "fixed", level}` with `level` `note`, `warning`, or `error`; `{type: "unrated"}`; or `{type: "cvss", when_unscored}`. |

### Run object

| Field | Meaning |
| --- | --- |
| `policy_id`, `policy_hash`, `analysis_type` | The policy that ran. |
| `completion` | The completion state. See [Completion states](#completion-states). |
| `findings` | Retained findings. |
| `diagnostics` | Run diagnostics. Each has `code` (tagged by `type`), `severity`, `impact`, `family`, `message`, `family_count`, `primary`, and `related`. |
| `diagnostics_truncated` | True when run diagnostics were folded or dropped. |
| `obligations` | Unmet negative-proof obligations of an assertion policy. Each names the `assertion`, the `kind` (`absence_requires_exhaustive_coverage` or `verdict_requires_witnessed_rows`), the `group`, and the `group_key`. |
| `obligations_truncated`, `omitted_obligations_lower_bound` | Obligation truncation. |
| `work` | Work counters: `scanned_files`, `scanned_source_bytes`, `fact_nodes`, `pipeline_rows`, `examined_references`, `retained_findings`, `omitted_findings_lower_bound`, `retained_report_bytes`, and `metrics`. `--policy-timings` adds elapsed time to `metrics`. |
| `authored_arm_closures` | When present, evidence that an authored model closed a dispatch arm. |
| `unknown_verdict` | When present, the policy's declared `on-unknown` verdict, applied to an inconclusive run. |

Run diagnostic `impact` values: `advisory`, `declared_non_exhaustive`,
`finding_partial`, `run_incomplete`, `run_unsupported`, `run_failed`.
Run diagnostic `code.type` values: `code_query` (with a nested CodeQuery
`code`), `unsupported_analysis`, `stable_anchor_unavailable`,
`endpoint_dominance_undecidable`, `evaluation_failure`, `empty_selection`,
`unknown_verdict_fail_closed`, `batch_finding_limit`,
`report_retention_budget`, `cvss_variant_budget`,
`projection_scenario_membership_budget`,
`organizational_risk_overlay_budget`.

### Finding object

| Field | Meaning |
| --- | --- |
| `id` | Finding ID: 64 lowercase hex digits. |
| `identity_stability` | `strong` or `weak`. Only a strong ID is stable across runs and can be suppressed or baselined. |
| `policy_id`, `policy_hash`, `analysis_type` | The policy that produced the finding. |
| `severity` | `unrated`, `note`, `warning`, or `error`. |
| `message` | Finding text. |
| `classification` | `{type: "unclassified"}`, or `{type: "classified", broad, refinements}`. |
| `certainty` | `{type: "definite"}` or `{type: "possible", reasons}`. |
| `completeness` | `{type: "complete"}` or `{type: "partial", reasons}`. |
| `primary` | `{path, byte_span: {start, end}, region: {start_line, start_column, end_line, end_column}}`. `path` is workspace-relative with forward slashes. |
| `related` | Related locations, each with a `relationship` such as `source`, `sink`, `origin`, `evidence`, `witness_step`, or `declaration`. |
| `related_truncated`, `omitted_related_locations_lower_bound` | Related-location truncation. |
| `evidence` | Typed evidence, tagged by `type`: `match`, `taint`, `typestate`, `assertion`, or `flow`. |
| `evidence_refs_truncated`, `omitted_evidence_refs_lower_bound` | Evidence-reference truncation. |
| `cvss` | CVSS assessments, or null. |
| `organizational_risk` | Organizational risk assessment, or null. |
| `proof` | `{state, reasons, evidence_refs}`. `state` is `proven`, `unproven`, or `ambiguous`. |
| `witnesses` | Bounded witness paths. |
| `witnesses_truncated`, `omitted_witnesses_lower_bound` | Witness truncation. |
| `display_path` | When present, the display path of a taint finding. |
| `suppression` | `null`, or the applied suppression: `identity_stability`, `status`, `reason`, `policy_hash_at_acceptance`, `accepted_by`, `accepted_at`, `expires_at`, and `policy_hash_state`. |
| `scope` | `null`, or the scope entry that claimed the finding: `{path, reason}`. |
| `diff` | When present (diff runs): `{disposition, weak_identity}`. `disposition` is `new` or `persisting`. A weak identity is always `new`. |
| `baseline` | When present (baselined findings): `reason`, optional `accepted_by`, `accepted_at`, and `policy_hash_state`. |

`certainty` `possible` reasons and `completeness` `partial` reasons are typed
lists. Finding `partial` reasons: `query_provenance_truncated`,
`related_locations_truncated`, `origins_truncated`,
`source_scenarios_truncated`, `typestate_scenarios_truncated`,
`witness_truncated`, `evidence_truncated`, `declared_non_exhaustive`,
`proof_partial`, `stable_anchor_weak`.

### Review objects

Suppression review, one per entry of `suppressions[]`:

| Field | Values | Meaning |
| --- | --- | --- |
| `policy_id`, `finding_id` | | The record's join key. |
| `identity_stability`, `status`, `reason`, `policy_hash_at_acceptance`, `accepted_by`, `accepted_at`, `expires_at` | | Copied from the record. |
| `match_state` | `strong_finding`, `current_finding_not_strong`, `finding_absent`, `policy_not_evaluated`, `policy_incomplete` | How the record joined this run. `finding_absent` requires a completed run that proves absence. |
| `temporal_state` | `current`, `expired` | `expired` when the evaluation date is after `expires_at`. |
| `policy_hash_state` | `matching`, `drifted`, `unknown` | Comparison of `policy_hash_at_acceptance` with the current hash. `unknown` when either is missing. |
| `orphan_state` | `resolved`, `orphaned`, `path_not_analyzed`, `path_unrecorded` | Whether the record still resolves to a finding. `orphaned` gives exit status 1. |
| `applied` | Boolean | True when the record claimed a finding. |
| `result_omitted` | Boolean | True when the review result did not fit the report retention budget. |
| `rekey_candidates` | list of finding IDs | Only on an orphaned record: up to 8 unclaimed finding IDs of the same policy in the record's file. |

Scope review, one per entry of `scope[]`: the entry's `path`, `reason`,
`exclude_roots`, `policy_ids`, and `policy_categories`, plus
`matched_findings` (count), `excluded_root_files` (count, omitted when zero),
`applied` (true when the entry matched a finding or excluded a root), and
`result_omitted`.

Diff review (`diff`):

| Field | Meaning |
| --- | --- |
| `base_revision` | The revision as given to `--diff-base`. |
| `base_commit` | The resolved commit. |
| `degraded` | True when the base evaluation was unreliable and every head finding gates. |
| `unqualified_policies` | Policies whose base run was not reliable: `{policy_id, completion, completion_detail, diagnostics}`. |
| `new_count`, `persisting_count`, `fixed_count` | Exact counts. |
| `fixed` | Up to 256 `{policy_id, finding_id}` of base findings the head no longer produces. |
| `fixed_truncated` | True when `fixed` was cut at 256. |

Incremental review (`incremental`): `base` is `evaluated` or `reused`.
`policies` holds one entry per policy with `policy_id`, `mode` (`sliced` or
`full`), `units_total`, `units_reused`, `units_recomputed`,
`units_unbounded`, `lookups_replayed`, the `base_` counterparts of the reuse
and replay counts, and, for a `full` policy, `widen_reason`. The widen
reasons are listed in
[What a second run reuses](/static-analysis-policies/#what-a-second-run-reuses).

Pack activation review (`packs`):

| Field | Meaning |
| --- | --- |
| `document_path` | The packs document path, `.bifrost/packs.json`, or an empty string when only catalog evidence is present and no activation review exists. |
| `dependency_mode` | `default` (no packs document), `configured`, or `disabled` (empty `ecosystems`). |
| `ecosystems` | Ecosystems considered. |
| `complete` | True when activation evidence was complete. |
| `decisions` | `{pack, status, reason}` per pack. `reason` is omitted when there is none. `status` is `selected`, `version_mismatch`, `missing`, `incompatible`, or `rejected`. Each Python, PHP, Rust, TypeScript, and JavaScript workspace has a row for its expected standard-library pack, whose `reason` starts with the language. A row whose `pack` is `node:<module>` is a Node built-in module the workspace imports that no active pack declares. |
| `decisions_truncated` | True when decisions were dropped. |
| `catalogs` | Matched taint catalog identities as `{name, version, sha256}`. Omitted when none matched. |

Baseline review (`baseline`):

| Field | Meaning |
| --- | --- |
| `document_path` | The baseline file path. |
| `reason`, `accepted_by`, `accepted_at` | Batch metadata from the document. `accepted_by` is omitted when absent. |
| `entry_count` | Number of entries in the document. |
| `applied_count` | Entries that claimed a finding. |
| `claimed_count` | Entries whose finding a suppression or scope entry already claimed. |
| `not_strong_count` | Entries whose current finding has a weak identity. |
| `stale_count` | Entries that a completed run proves absent. |
| `policy_not_evaluated_count` | Entries whose policy did not run. |
| `policy_incomplete_count` | Entries whose policy ran but not exhaustively. |
| `drifted_count` | Entries whose policy hash changed since acceptance. |
| `result_omitted_count` | Entries whose review did not fit the retention budget. |
| `entries` | Up to 256 entries that need attention: everything except applied entries with a matching hash. |
| `entries_truncated` | True when `entries` was cut. The counts stay exact. |

Each baseline entry review has `policy_id`, `finding_id`, `match_state`
(`strong_finding`, `finding_claimed`, `current_finding_not_strong`,
`finding_absent`, `policy_not_evaluated`, `policy_incomplete`),
`policy_hash_state` (`matching`, `drifted`, `unknown`), `applied`, `stale`,
and `result_omitted`.

## SARIF output

`--format sarif` writes SARIF 2.1.0 with one run. Region columns use Unicode
code points (`columnKind: unicodeCodePoints`), and artifact URIs are
workspace-relative under `uriBaseId: SRCROOT`.

### Rules

`tool.driver.rules[]` has one reporting descriptor per policy. `id` is the
policy ID. `shortDescription` is the policy name, `fullDescription` is the
description (or the message when there is none), `helpUri` is the policy's
`:help-uri`, and `defaultConfiguration.level` comes from the policy severity
(`unrated` maps to `none`). `properties.tags` holds the policy tags, and
`properties["bifrost.ruleDescriptor"]` holds the full
[rule descriptor](#rule-descriptor).

### Results

One result per retained finding.

| SARIF field | Value |
| --- | --- |
| `ruleId`, `ruleIndex` | The policy. |
| `message.text` | The finding message. |
| `level` | `error`, `warning`, `note`, or `none` (unrated). |
| `kind` | `review` for a finding with `possible` certainty; `informational` for an unrated finding; omitted otherwise. |
| `baselineState` | Diff runs only: `new`, or `unchanged` for a persisting finding. Fixed base findings are not emitted as results. |
| `locations`, `relatedLocations` | The primary location and the related locations. Each related location has `properties["bifrost.relationship"]` and `properties["bifrost.evidenceRefs"]`. |
| `codeFlows` | Taint findings with a display path: one code flow. |
| `partialFingerprints["bifrostFinding/v1"]` | The finding ID. Present only for a strong identity. |
| `suppressions` | One entry when a suppression or the baseline claims the finding. See below. |

Result `properties`:

| Key | Value |
| --- | --- |
| `bifrost.findingId` | Finding ID. |
| `bifrost.policyHash` | Policy semantic hash. |
| `bifrost.analysisType` | Analysis type. |
| `bifrost.identityStability` | `strong` or `weak`. |
| `bifrost.severity` | Finding severity. |
| `bifrost.unrated` | `true` for an unrated finding; omitted otherwise. |
| `bifrost.runCompletion` | The run's completion object. |
| `bifrost.findingCompleteness` | The finding's completeness object. |
| `bifrost.certainty` | The certainty object. |
| `bifrost.classification` | The classification object. |
| `bifrost.evidence` | The typed evidence object. |
| `bifrost.relatedLocationsTruncated`, `bifrost.omittedRelatedLocationsLowerBound` | Related-location truncation. |
| `bifrost.evidenceRefsTruncated`, `bifrost.omittedEvidenceRefsLowerBound` | Evidence-reference truncation. |
| `bifrost.cvss` | CVSS assessments; omitted when absent. |
| `bifrost.organizationalRisk` | Organizational risk; omitted when absent. |
| `bifrost.proof` | The proof object. |
| `bifrost.witnessesTruncated`, `bifrost.omittedWitnessesLowerBound` | Witness truncation. |
| `bifrost.diffDisposition` | Diff runs only: `new` or `persisting`. |

A code flow carries `bifrost.displayPathSchemaVersion`,
`bifrost.representativeWitnessId`, `bifrost.witnessIds`,
`bifrost.canonicalIncomplete`, `bifrost.omittedMeaningfulSteps`,
`bifrost.alternativesTruncated`, `bifrost.omittedAlternativePathsLowerBound`,
and `bifrost.omittedWitnessesLowerBound`. Each thread-flow location carries
`bifrost.kind`.

A `suppressions` entry has `kind: "external"`, `status: "accepted"`, and the
reason as `justification`. For a suppression, its `properties` hold
`bifrost.identityStability`, `bifrost.acceptedBy` (when set),
`bifrost.acceptedAt`, `bifrost.expiresAt` (when set),
`bifrost.policyHashAtAcceptance` (when set), and `bifrost.policyHashState`.
For a baseline entry, they hold `bifrost.decision: "baseline"`,
`bifrost.acceptedBy` (when set), `bifrost.acceptedAt`, and
`bifrost.policyHashState`. A scoped finding has no `suppressions` entry; its
scope decision is in the run's `bifrost.scopeReviews`.

### Run properties

| Key | Value |
| --- | --- |
| `bifrost.execution` | The `execution` object. |
| `bifrost.incremental` | The `incremental` review; omitted when absent. |
| `bifrost.policyReportSchemaVersion` | `5`. |
| `bifrost.policyEvaluation` | The `evaluation` object. |
| `bifrost.policyRuns` | Per policy: `policy_id`, `policy_hash`, `analysis_type`, `completion`, `diagnostics`, `diagnostics_truncated`, and `work`. |
| `bifrost.suppressionReviews` | The suppression reviews. |
| `bifrost.scopeReviews` | The scope reviews. |
| `bifrost.diffBaseline` | The diff review; omitted when absent. |
| `bifrost.packActivation` | The pack activation review; omitted when absent. |
| `bifrost.baseline` | The baseline review; omitted when absent. |
| `bifrost.reportDiagnostics` | The report diagnostics. |
| `bifrost.reportDiagnosticsTruncated`, `bifrost.omittedReportDiagnosticsLowerBound` | Report diagnostic truncation. |
| `bifrost.worstOmittedReportDiagnosticSeverity` | Worst dropped diagnostic severity; omitted when none. |

### Invocation and notifications

`runs[].invocations[]` has one invocation:

| Field | Value |
| --- | --- |
| `exitCode` | The policy exit status (0, 1, or 2). The CLI sets it; a library renderer without an outcome omits it. |
| `exitCodeDescription` | `Policy gate passed: no gated findings` (0), `Policy gate failed: findings or policy obligations met the failure threshold` (1), or `Policy analysis was incomplete or invalid and is unreliable` (2). |
| `executionSuccessful` | `false` when any report diagnostic is an error, diagnostics were dropped, the run stopped at its deadline, any policy run is not reliable, or the exit status is 2. |
| `toolExecutionNotifications` | One notification per report diagnostic, one for dropped diagnostics, and one per policy run whose completion is not `complete`. |

Notification `descriptor.id` values:

| ID | Level | Emitted for |
| --- | --- | --- |
| a report diagnostic code, for example `policy-load-failed` | the diagnostic severity | One report diagnostic. `properties["bifrost.reportDiagnostic"]` holds the diagnostic. See [Report diagnostic codes](#report-diagnostic-codes). |
| `BIFROST_REPORT_DIAGNOSTICS_TRUNCATED` | worst omitted severity, or warning | Dropped report diagnostics. `properties` hold `bifrost.diagnosticsTruncated` and `bifrost.omittedDiagnosticsLowerBound`. |
| `BIFROST_POLICY_PROVEN_SUBSET` | warning | A `proven_subset` run. |
| `BIFROST_POLICY_PROVEN_BY_SUMMARY` | warning | A `proven_by_summary` run. |
| `BIFROST_POLICY_INCONCLUSIVE` | warning | An `inconclusive` run. |
| `BIFROST_POLICY_UNSUPPORTED` | warning | An `unsupported` run. |
| `BIFROST_POLICY_FAILED` | error | A `failed` run. |

A policy-run notification's `properties` hold `bifrost.policyId`,
`bifrost.policyHash`, `bifrost.completion`, `bifrost.diagnosticsTruncated`,
`bifrost.omittedDiagnosticsLowerBound`, `bifrost.authoredArmClosures` (when
present), and `bifrost.obligations` (when the run has unmet obligations:
`count`, up to four `kinds`, and truncation fields). A notification is
information about the run. Its ID alone is not a failure verdict; read
`exitCode` for that.

## Report diagnostic codes

Report diagnostics are in the JSON report's top-level `diagnostics` array and
in SARIF `toolExecutionNotifications`. Each has `code`, `severity`,
`message`, optional `source` (a workspace-relative path or source identity),
optional `byte_range`, and `related` locations. Use the code for automation;
message wording can change.

Every code has severity `error`, and so makes the run exit 2, except
`workspace-model-inert`, which is a `warning`.

| Code | Meaning | Next step |
| --- | --- | --- |
| `workspace-snapshot-deadline-exceeded` | The workspace snapshot was not ready within the request's time budget. No policy ran. | Retry after workspace initialization finishes. |
| `diff-base-deadline-exceeded` | The time budget expired while the diff base was evaluated. No policy ran against the head. | Retry, or run without `--diff-base` to measure the head alone. |
| `diff-base-unreliable` | The diff base resolved, but its evaluation was not reliable. Every head finding gates, and the diff review has `degraded: true`. | Read the message for the base's failure, fix it, and rerun. |
| `diff-base-policy-unqualified` | One policy's base run was not reliable. That policy uses full gating. | Read the policy's completion and diagnostics in the message and in `diff.unqualified_policies`. |
| `suppression-load-failed` | A suppression file is malformed, unsafe, oversized, or conflicts with another. None of that file applies. | Fix the file named in `source`. Limits are in [Suppression file](#suppression-file). |
| `suppression-audit-retention-exceeded` | Suppression or scope reviews did not fit the report retention budget. | Remove dead records, or split the run into smaller selections. |
| `scope-load-failed` | The scope file is malformed or exceeds a limit. None of it applies. | Fix the file named in `source`. Limits are in [Scope file](#scope-file). |
| `scope-audit-retention-exceeded` | Scoped finding results did not fit the report retention budget. | Narrow the selection or the scope entries. |
| `baseline-load-failed` | The baseline file is malformed or exceeds a limit. None of it applies. | Fix or regenerate the file with `--accept-current`. |
| `baseline-audit-retention-exceeded` | Baselined finding results did not fit the report retention budget. | Narrow the selection. |
| `packs-load-failed` | `.bifrost/packs.json` could not be read or parsed. | Fix the packs document. |
| `pack-activation-failed` | Semantic-model pack activation failed. | Read the named pack and reason in the message. |
| `workspace-model-load-failed` | A reviewed model under `.bifrost/semantic-models/` could not be discovered, compiled, registered, or activated. | Fix the model file named in `source`. |
| `workspace-model-inert` | Warning. A reviewed workspace model registered but stayed inactive behind its review gate, so it contributed nothing. | Add an `enable` entry for the model's pack to `.bifrost/packs.json` if you intend to use it. |
| `policy-load-failed` | A policy file could not be read. | Check the path and permissions. |
| `policy-parse-failed` | The policy text is not one well-formed S-expression document: too large, invalid, incomplete, missing, or followed by a second document. | Fix the syntax at `byte_range`. |
| `policy-validation-failed` | The policy parsed but is invalid, or a dependency such as an endpoint-set file is missing or invalid. | Fix the declaration at `byte_range`, or create the missing dependency. |
| `not-executable-endpoint` | An `endpoint` or `endpoint-set-document` file was passed as a policy root. | Pass the policy that imports it instead. |
| `duplicate-policy-id` | Two inputs define the same policy ID. Every definition is excluded. | Give each policy a unique ID, or do not run a copy beside the original. |
| `duplicate-endpoint-id` | Two endpoints share an ID. | Give each endpoint a unique ID. |
| `policy-count-limit` | The run loaded more policies than the registry allows. | Split the run. |
| `endpoint-count-limit` | The run loaded more endpoints than the registry allows. | Reduce the endpoint set. |
| `match-directory-limit` | A `match-directory` exceeds its entry or candidate limits. | Narrow the directory or use `:scope direct`. |
| `match-directory-manifest-mismatch` | A `match-directory` content does not match its `:manifest-sha256`. | Update the pin or restore the reviewed directory. |
| `unsupported-policy-schema-version` | A policy or endpoint pins a schema version the engine does not have. | Pin `:schema-version 1` or omit it. |
| `unsupported-rql-schema-version` | A selector pins an RQL schema version the engine does not have. | Pin `:schema-version 1` or omit it. |
| `conflicting-rql-schema-version` | An `rql-file` wrapper and the file it references pin different RQL versions. | Make the two pins agree, or remove one. |
| `explicit-policy-schema-version-required` | With `--require-explicit-schema-versions`, a policy or endpoint omits `:schema-version`. | Add `:schema-version 1`. |
| `explicit-rql-schema-version-required` | With `--require-explicit-schema-versions`, a selector omits its RQL version. | Add `:schema-version 1` to the selector. |

## Review files

All three review files are JSON documents with `schema_version: 1`. Unknown
fields are rejected. Paths inside them are workspace-relative, use forward
slashes, and contain no `.` or `..` components. A missing file means no
decisions. A malformed, oversized, or invalid file applies none of its
records, produces a report diagnostic, and makes the run exit 2. Dates are
`YYYY-MM-DD`. The [configuration files reference](/reference/configuration-files/)
lists every file Bifrost reads.

| File | Override | MCP field |
| --- | --- | --- |
| `.bifrost/suppressions.json`, `.bifrost/suppressions.private.json`, `.bifrost/suppressions.local.json` | `--suppressions-file PATH` replaces all three with one file. | `suppression_file` |
| `.bifrost/policy-scope.json` | `--scope-file PATH` | `scope_file` |
| `.bifrost/baseline.json` | `--baseline-file PATH` | `baseline_file` |

A finding is claimed by at most one mechanism, in this order: suppression,
then scope, then baseline.

### Suppression file

By default Bifrost reads `.bifrost/suppressions.json`,
`.bifrost/suppressions.private.json`, and `.bifrost/suppressions.local.json`,
in that order, and merges their records. Each file is optional. Two records
that claim the same finding are rejected.

```json
{
  "schema_version": 1,
  "suppressions": [
    {
      "policy_id": "bifrost.correctness.dynamic-evaluation",
      "finding_id": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      "path": "src/migrate.py",
      "identity_stability": "strong",
      "status": "accepted",
      "reason": "This evaluator runs only a checked-in migration script",
      "policy_hash_at_acceptance": "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
      "accepted_by": "security-review",
      "accepted_at": "2026-07-27",
      "expires_at": "2026-10-27"
    }
  ]
}
```

| Field | Required | Value | Limit |
| --- | --- | --- | --- |
| `schema_version` | yes | `1` | |
| `suppressions` | yes | array of records | 512 records per file, and 512 across the merged files |
| `policy_id` | yes | policy ID | |
| `finding_id` | yes | 64 lowercase hex digits | |
| `identity_stability` | yes | `strong` | |
| `status` | yes | `accepted` | |
| `reason` | yes | non-blank text | 4,096 bytes |
| `accepted_at` | yes | date | |
| `path` | no | workspace-relative file the finding was reported in | 1,024 bytes |
| `policy_hash_at_acceptance` | no | 64 lowercase hex digits | |
| `accepted_by` | no | non-blank text | 256 bytes |
| `expires_at` | no | date; the record stays active on this date and expires after it | |

A file is at most 256 KiB. `policy_id` and `finding_id` are the join key;
`path` is never part of it. Record `path` so that a run can tell an orphaned
record (`orphan_state: orphaned`, exit 1) from a record whose file the run did
not analyze. The `--suppressions-file` path is at most 1,024 bytes. The review
fields are listed in [Review objects](#review-objects).

### Scope file

```json
{
  "schema_version": 1,
  "scopes": [
    {
      "path": "fixtures/smells",
      "reason": "Intentional smell corpus used as policy test fixtures.",
      "exclude_roots": true
    },
    {
      "path": "test",
      "reason": "Test code is not performance-sensitive.",
      "policy_categories": ["performance"]
    }
  ]
}
```

| Field | Required | Value | Limit |
| --- | --- | --- | --- |
| `schema_version` | yes | `1` | |
| `scopes` | yes | array of entries | 256 entries |
| `path` | yes | workspace-relative directory | 1,024 bytes |
| `reason` | yes | non-blank text | 4,096 bytes |
| `exclude_roots` | no | Boolean, default `false` | |
| `policy_ids` | no | non-empty list of unique policy IDs | 64 values |
| `policy_categories` | no | non-empty list of unique categories | 64 values |

A file is at most 256 KiB. An entry with no `policy_ids` and no
`policy_categories` applies to every policy. Otherwise it applies to a policy
whose ID or category is listed. Categories exist only for built-in policies.
`path` matches by whole path components: `test` covers `test/a.py` but not
`tests/a.py`. Two entries may share a path only when their selectors differ.
`exclude_roots: true` also removes matching files as analysis starting roots;
taint, flow, and typestate policies cannot honor it and run unreliable.

### Baseline file

```json
{
  "schema_version": 1,
  "reason": "Bulk baseline acceptance of existing findings via --accept-current",
  "accepted_at": "2026-10-01",
  "policies": [
    {
      "policy_id": "bifrost.correctness.dynamic-evaluation",
      "policy_hash_at_acceptance": "2000b90cff88f7a3f786ab9ad7e8e3e2f124345bfc84e08152200adb3c398edf",
      "finding_ids": [
        "1ea04d764dbb0855bd1e6b983ba46956db5f08ba789812b4ed43ea4b365f05ac"
      ]
    }
  ]
}
```

| Field | Required | Value | Limit |
| --- | --- | --- | --- |
| `schema_version` | yes | `1` | |
| `reason` | yes | non-blank text | 4,096 bytes |
| `accepted_by` | no | non-blank text | 256 bytes |
| `accepted_at` | yes | date | |
| `policies` | yes | array of policy records | |
| `policies[].policy_id` | yes | policy ID | |
| `policies[].policy_hash_at_acceptance` | no | 64 lowercase hex digits | |
| `policies[].finding_ids` | yes | finding IDs | 100,000 entries in the whole file |

A file is at most 16 MiB. The `--baseline-file` path is at most 1,024 bytes.

`--accept-current` runs the selected policies and writes this file:

- It records every current strong finding that no suppression or scope entry
  claims. Weak-identity findings are never written; their count is printed.
- `reason` is always `Bulk baseline acceptance of existing findings via
  --accept-current`, and `accepted_at` is the evaluation date
  (`--evaluation-date`, or today's UTC date).
- It overwrites the target file. It writes `.bifrost/baseline.json` unless
  `--baseline-file` names another path.
- It exits 0 after writing. An unreliable run writes nothing and exits 2.
- It cannot be combined with `--fail-on` or `--diff-base`.
