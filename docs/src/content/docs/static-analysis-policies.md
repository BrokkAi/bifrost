---
title: Static-Analysis Policies
description: Author reusable RQLP rules and endpoints, run structural and semantic policies, and interpret complete human, JSON, or SARIF reports.
---

Bifrost static-analysis policies are human-readable S-expressions stored in
`.rqlp` files. They add stable rule identity, reporting metadata, composition,
and completeness semantics around native [Rune Query Language
(RQL)](/rune-query-language/) selectors. JSON is available as a normalized or
reporting form, but it is not an alternate RQLP authoring syntax.

Standard-library-style policy rules and semantic models are maintained in
[Bifrost-packs](https://github.com/BrokkAi/bifrost-packs). Submit shared open
content there; third-party library content normally has a separate private
authoring home. A public benchmark exception needs a maintainer classification
decision. Parser, evaluation, catalog, and reporting changes belong in
the engine repository. Pack releases have independent versions and compatibility
metadata.

> **Current execution boundary:** Bifrost executes match-, taint-, typestate-,
> assertion-, and flow-analysis policies. Taint and flow resolve typed endpoint
> bindings, compile compatible demand, run bounded set-oriented propagation,
> and render retained findings. Unsupported or incomplete semantic boundaries
> remain non-clean completion states rather than empty successful results.

> **Important:** An RQL selector returns analysis candidates. An endpoint
> selector match is diagnostic-neutral. Neither an endpoint match nor the
> co-presence of a source and sink proves reachability, and neither creates a
> finding by itself.

Every policy endpoint selector is one RQL query, inline as `(rql ...)` or
loaded from `(rql-file ...)`. Endpoint selection does not have a separate row
sublanguage. When an endpoint needs an exact modeled call operand, the
`resolved-call` and `call-argument` RQL pipeline steps retain `call_binding`
rows while enforcing callable identity and exact actual-to-formal evidence.
Relational `bind`, `filter`, `project`, `join`, `group`, and `aggregate`
records belong to assertion plans; they are not endpoint selector forms.

The [policy reference](/reference/policies/) lists every RQLP record, field,
and atom value, the policy catalog, the report formats, the
diagnostic codes, and the review file formats. This page explains how to use
them.

## One Document Per File

Every `.rqlp` file contains exactly one top-level document:

| Document | Purpose | Executable root? |
| --- | --- | --- |
| `(policy ...)` | Defines one rule, its report metadata, and exactly one `match`, `taint`, `typestate`, `assertion`, or `flow` analysis. | Yes. |
| `(endpoint ...)` | Names one reusable, diagnostic-neutral source or sink selector with categories and a typed value/API binding. | No. It is loaded only as a dependency. |
| `(endpoint-set-document ...)` | Groups reusable entries of one declared taint or flow endpoint-set kind. | No. Import it through `endpoint-set-file`. |

Passing an endpoint to `--policy-file` is an error; Bifrost does not turn it
into a match policy behind the author's back.

### A runnable match policy

This complete checked fixture selects direct Python call syntax whose callee is
named `eval`:

<!-- policy-doc-test:rqlp:tests/fixtures/policies/dynamic-eval.rqlp -->
```lisp
; Match policies are executable diagnostics. Omitting :schema-version selects
; the latest compatible policy schema, currently version 1.
(policy
  :id "bifrost.security.dynamic-eval"
  :name "No dynamic evaluation"
  :message "Dynamic evaluation is forbidden"
  :severity warning
  :description "Reject calls that execute source text as Python code."
  :tags ["security" "code-execution"]
  :analysis
    (analysis
      :type match
      :selector
        (rql
          (language python
            (call :callee (name "eval"))))))
```

Every analysis type has its own typed execution contract. For `match`, an RQL
result is evidence for the surrounding policy, so the policy—not the
selector—owns the finding message, severity, identity, and completion state. A
callee name match is still a structural fact; it does not by itself prove
runtime dispatch. Flow policies likewise report typed incompleteness when the
declared value-flow ports cannot be established, rather than treating an empty
result as proof of safety or correctness.

The documentation test runs that exact policy against this source through the
current `bifrost` binary:

<!-- policy-doc-test:source:dynamic-eval -->
```python
def run(user_code):
    return eval(user_code)
```

With `--fail-on never`, the complete human report is:

<details>
<summary>Checked current output</summary>

<!-- policy-doc-test:human:dynamic-eval -->
```text
1 finding | Analysis complete

Findings
  [warning] bifrost.security.dynamic-eval: Dynamic evaluation is forbidden
    Location: app.py:2:12
    Certainty: definite; proof: proven; completeness: complete


Analysis warnings
note: policy bifrost.security.dynamic-eval inferred policy schema 1 and RQL schema 1

Dependency models
  Coverage: complete
  Mode: default; ecosystems: python
  Details: --verbose or --format json
```

</details>

The same run with the default `warning` threshold produces identical report
text and exits 1. Add `--verbose` to include the complete finding identity,
evidence, provenance, proof, classification, rule schema, and manifest record.

Policy evaluation units preserve the same row-level `{proof, completeness,
reason}` evidence object that direct CodeQuery results carry.
This object survives unit serialization and reuse without recreating a composite
quality label or dropping a typed limitation reason.

## Built-in Policy Packs

The v0.13 production core has an empty product-rule catalog. Hosts acquire
compatible, verified content separately and supply its installed root to the
engine. The following four pack identities describe the external baseline;
their presence in this documentation does not mean they are installed or
enabled.

| Pack | What it checks |
| --- | --- |
| `bifrost.code-smells` | Bug-prone patterns, proven correctness defects, and performance review prompts. |
| `bifrost.correctness` | Resource lifecycle: a resource left open at the exit of the procedure that acquired it. |
| `bifrost.security` | Taint rules from untrusted input to SQL text or a shell command, and the opt-in declared-storage family. |
| `bifrost.effects` | Network-effect boundaries: a declaration you select must not reach a declared network call. |

The [policy reference](/reference/policies/) lists baseline policies with
its ID, category, severity, analysis type, languages, and activation. Every
rule is an ordinary `.rqlp` source with a stable ID and a semantic hash. Its
pack manifest also records the category, claimed languages, required
capabilities, severity rationale, remediation, and activation.

After a host supplies a verified catalog, run its default policies:

```sh
bifrost --root . --policy
```

With no supplied rules, a scan is explicitly not evaluated; an empty catalog
does not establish that the project is clean. `bifrost scan .` uses the same
selected catalog and prints the activated pack versions and the
catalog hash on stderr. To run a subset, name it with `--policy-pack`,
`--policy-category`, or `--policy-id`. MCP `run_policy` accepts the same
selectors as `policy_packs`, `policy_categories`, and `policy_ids`, but has no
default selection. The selection rules are:

- Repeating one selector widens the selection. `--policy-pack
  bifrost.code-smells --policy-pack bifrost.security` runs both packs.
- Combining different selectors narrows it. `--policy-pack bifrost.code-smells
  --policy-category performance` runs only the performance policies of the
  code-smell pack.
- A selection that matches no policy exits with status 2.
- A policy whose catalog `activation` is `opt-in` runs only when
  `--policy-id` or `policy_ids` names it. Pack, category, and default runs
  never include it. Today the opt-in policies are the 26 declared-storage
  policies of `bifrost.security`.
- `--policy-file` alone runs only the named files. Add
  `--no-builtin-policies` to make a run fail if it would otherwise include a
  catalog policy.

`bifrost --list-policies` and MCP `list_policies` print the catalog of the
running host. `bifrost --version` prints each selected pack's ID, version, and
policy count and the catalog SHA-256. Pack release versions are independent
of the engine version.

Setting `BIFROST_POLICY_PACK_ROOT` to a directory of extracted packs
supplies the catalog for every policy surface: `--list-policies`,
`--version`, `bifrost scan`, default runs, built-in selectors, and MCP. Each
subdirectory is one pack with a `manifest.json` and its `policies/*.rqlp`
files. Bifrost verifies each manifest and each policy's authored hash. An
empty value, an empty directory, or an invalid pack is an error; Bifrost does
not fall back to legacy regression sources. Acquisition, compatibility
admission, and verified offline-cache reuse belong to the host; the engine
does not fetch a live authoring repository.

The match policies are review-oriented: a call name or lexical location is
evidence of the parsed shape, not proof of runtime dispatch, loop invariance,
or measured cost. Assertion, taint, flow, and typestate policies report only
what their analysis establishes, and state their limits in their own
descriptions.

### Built-in code-smell pack

`bifrost.code-smells` contains 31 policies in two categories, `correctness`
and `performance`. All of them have activation `default`.

**Structural correctness checks.** These assertion policies report a defect
only from exact structural or semantic evidence:

- `contradictory-condition`: a condition whose outcome is fixed by proven
  scalar facts, so one arm cannot run.
- `identical-conditional-branches`, `repeated-branch-condition`, and
  `redundant-boolean-branches`: conditionals whose arms are equivalent, whose
  later condition repeats an earlier one, or whose two paths return opposite
  Boolean literals.
- `empty-failure-handler`: a `catch`, `except`, or `rescue` clause with no
  statements other than comments, empty statements, `pass`, or `...`. A C#
  exception filter selects an exception but does not handle it.
- `local-self-assignment`, `c-self-assignment`, `failed-swap`, and
  `overwritten-unread-value`: local assignments that copy a value back to
  itself, swap incorrectly, or write a value that is replaced before any read.
- `loop-body-never-repeats`: a `while`, `for`, or `do` loop whose body always
  leaves before the next iteration. Iteration loops such as Java enhanced
  `for`, Python `for`, and Go `for range` are not assessed, because one pass
  over the first element is a common deliberate idiom.
- `unreachable-statement`: a statement inside a callable that no path from the
  callable's entry reaches. Statements outside callables, such as
  JavaScript module-level code, are not assessed.
- `discarded-pure-result` and `ignored-status-result` (Java): the result of
  the exact JDK 21 `String.trim()` call, or the Boolean status of the exact
  `Files.deleteIfExists(Path)` call, is discarded.

When the evidence for one of these checks is partial, for example an
unsupported predicate or an inexact source mapping, the run is inconclusive
rather than clean. `contradictory-condition` reports a complete result for a
function only when the analysis of that function has no gaps and decides every
condition in it. A condition on a value that the analysis cannot decide, such
as a test of a function parameter, leaves the run inconclusive. [Scan a
Codebase](/scan-a-codebase/) shows both cases in a real run. Each policy's description names the shapes it does not
decide. The description is in the report's `rules[].description`, in the
SARIF rule's `fullDescription`, and in `--verbose` human output.

**Dynamic evaluation and unsafe deserialization.** These two match policies
report calls named `eval` or `exec` in Python, calls named `eval` or
`Function` in JavaScript and TypeScript, and calls to `pickle.loads` or
`pickle.load` in Python.

**Python absent members.** `bifrost.correctness.python-absent-member` follows
caller values to a member access. It reports only a fully classified receiver
whose complete class surface proves the member absent. Unknown receivers,
unresolved bases, dynamic attributes, and incomplete member models do not
produce a finding. Missing Python declaration-model coverage makes the run
inconclusive. That coverage needs the released Python standard-library pack,
`bifrost.python-stdlib`. It activates only when it is installed and the project
declares a CPython version in `.python-version`, `pyproject.toml`
`requires-python`, `setup.cfg`, or `setup.py`. A clean run means that no proven absence was found, not that
every runtime receiver was classified. Inspect `(witness (absent-member ...))`
for the retained origin-to-access evidence; missing or truncated evidence is
labeled. `python-absent-member-conditional` keeps the class absence conditional
when other receiver values may also reach the access. It may also retain a
possible installation by a listed global dynamic write only when every matching
write has no receiver bound and an Any member-name set; the condition names the
write sites. A `DeclaredParameter` origin qualifies only when its annotation
resolves to one workspace class with no workspace subclass, unresolved or
unmodeled external base, or attribute hook such as `__getattr__`,
`__getattribute__`, or `__setattr__`. Its condition states the annotated type
and that no workspace subclass exists. Bounded or member-attributed writes,
and incomplete member models, still suppress the finding.

**Go.** Two Go policies use canonical API identity, so unrelated functions
or methods with the same name never enter them:

- `go-nil-dereference` reports a dereference, field access, or reviewed
  receiver operation reached with an exact `Nil` or `MaybeNil` fact. It also
  reports an operation that requires a valid result of a reviewed API before
  the result's success condition is proved. The reviewed APIs are the `os`
  paired-result functions (`(*os.File).Close`, `Read`, `Seek`, and `Stat`
  tolerate a nil receiver and do not report; `File.Name` does),
  `net.Dial`, `net.DialTimeout`, `net.Listen` (the `Accept`, `Close`, and
  `Addr` operations), and `encoding/pem.Decode`, whose nullable block is valid
  only when it is non-nil. Passing an unchecked `pem.Decode` block to
  `crypto/x509.IsEncryptedPEMBlock` reports at the argument. Unknown scalar
  facts, nil-tolerant methods, and arbitrary pointer receiver calls do not
  report. Missing or ambiguous operation knowledge stays incomplete.
- `go-wrong-error-on-failure-path` reports a call returned from the exact
  failure edge of a reviewed Go API when that call consumes a different error
  binding whose reaching value is Go's zero value. A correct condition result,
  an independent sentinel, a direct return, a statement-only call, a
  success-arm use, or an incomplete origin does not match. The rule covers
  returned call arguments only.

**Performance.** `bifrost.performance.loop-invariant-sort` is an assertion
policy. It reports a sort call inside a loop only when the sorted receiver's
value is established outside the loop: its binding is declared outside and no
assignment inside the loop reaches it. It claims Rust, Python, Java,
TypeScript, and JavaScript.

The other nine performance policies are review prompts with severity `note`:
regular-expression compilation, file reads, serialization, parsing, database
calls, network calls, subprocess launches, and sleeps written inside a loop,
and expensive operations written inside two nested loops. Their messages begin
"Review whether ..." because lexical containment cannot prove that the
operation repeats per iteration or that the loop is hot. With the default
`--fail-on warning` they appear in the report without failing the run. Pass
`--fail-on note` to make them gate.

Each prompt withdraws itself when the enclosing for-each loop's iterated
expression provably resolves to a collection literal with at most eight
elements. The proof reads declarator-established bindings: JavaScript and
TypeScript `const`, `let`, and `var`, Rust `let`, and Java local declarators.
Every establishing initializer must qualify, so a literal later reassigned
from a call still reports. These iterated values are out of evidence and keep
reporting: while and counting loops, call results, parameters, Java fields,
Java `new String[] {...}` array-creation expressions, Python names bound only
by assignment, and Rust `[value; length]` repeat arrays. For
`expensive-operation-in-nested-loop`, the withdrawal looks at the inner loop.
A small outer loop over an unbounded inner loop still reports.

`sleep-in-loop` matches only for-each loops (`for_loop`). A sleep inside a
condition-controlled `while` loop is usually the mechanism of a poll or
bounded backoff and does not match. Counting loops that a language cannot
distinguish from iteration, such as Go's single `for` and C-style `for`, are
outside the rule.

The Rust selectors of the performance prompts recognize the standard slice
`sort*` family, `Regex::new`, `fs::read` and `fs::read_to_string`,
`serde_json::{to_string, to_vec, from_str, from_slice}`,
`bincode::{serialize, deserialize}`, `toml::from_str`, direct `reqwest::get`
and `ureq::{get, post}` requests, and `thread::sleep`. The pack does not claim
Rust database or subprocess coverage.

**Rayon in blocking lazy initializers.**
`bifrost.correctness.rayon-in-blocking-lazy-init` is a Rust review prompt for
a blocking lazy-init call (`OnceLock::get_or_init`,
`OnceLock::get_or_try_init`, `Once::call_once`, `LazyLock::new`) whose
initializer closure lexically contains rayon parallelism (`par_iter`,
`into_par_iter`, `par_bridge`, `par_chunks`). When the first initialization
runs on a rayon worker, the initializer's parallel join can steal a sibling
job that re-enters the same cell and waits on it forever. The match is lexical
containment, not proof of a deadlock. Bare `rayon::join`, `rayon::scope`, and
`ThreadPool::install` are excluded because their unqualified names are too
generic.

### Built-in correctness pack

`bifrost.correctness` contains one typestate policy,
`bifrost.correctness.resource-lifecycle`. It reports a resource that reaches a
normal or exceptional exit of the procedure that acquired it while it is still
open. Only the acquiring procedure is an analysis root, so a helper's return
is never treated as an exit.

The shipped rule tracks one reviewed acquisition family per language:

| Languages | Acquire | Close |
| --- | --- | --- |
| Java, JavaScript, TypeScript, Kotlin, Scala | `openResource(...)` | `closeResource(resource)` or `resource.close()` |
| Python, Rust, PHP | `open_resource(...)` | `close_resource(resource)` or `resource.close()` |
| Go | `open_resource(...)` | `close_resource(resource)` |

Java `try (...)`, Python `with`, and Go `defer` close the resource they name.
A close inside a workspace helper discharges the caller's obligation when the
helper closes the parameter it received on every supported exit path. Every
event is bound to the tracked resource, so a close on an
unrelated object, or a call that only spells `open` or `close`, does not count.

The rule observes the close at both its normal and its exceptional
continuation. A close in a `try`/`finally` block discharges both obligations.
A bare close at the end of the procedure leaves the exceptional obligation,
because the close operation's own failure is not proof of release. Escape,
ownership-transfer, and alias shapes that the analysis does not support make
the run inconclusive rather than clean.

The pack claims Go, Java, JavaScript, Kotlin, PHP, Python, Rust, Scala, and
TypeScript. C, C++, C#, and Ruby are not claimed: the reviewed close does not
yet bind in those languages, so a corrected close would still report.

Typestate call events may also require a direct Boolean argument value. Add
`:condition (argument-condition :argument (argument :index 0) :equals true)`
inside a `:calls` record to match only a call whose selected argument is the
semantic Boolean constant `true`. The condition is evaluated from semantic
value facts, so a parameter or computed value does not match it and keeps the
run incomplete. Argument conditions currently accept positional indexes and
Boolean equality only.

To check your own API, copy the rule and replace its acquisition and close
selectors with your project's exact factory and close identities. Give the
copy its own policy ID and run it with `--policy-file`.

### Built-in security pack

`bifrost.security` has three taint policies with activation `default`:

| Policy ID | Source | Sink |
| --- | --- | --- |
| `bifrost.security.java.servlet-parameter-to-jdbc` | `ServletRequest.getParameter(String)` | The `sql` operand of `Statement.execute(String)` or `Statement.executeQuery(String)` |
| `bifrost.security.java.system-getenv-to-runtime-exec` | `System.getenv(String)` | The command operand of `Runtime.exec(String)` |
| `bifrost.security.python.process-input-to-os-system` | `os.environ` and `sys.argv` | The command operand of `os.system` |

Each rule binds exact declarations through semantic identity and
actual-to-formal evidence, then follows value flow. The JDBC rule does not
treat `PreparedStatement` value binding as a SQL-text sink. The `Runtime.exec`
rule excludes `Runtime.exec(String[])`. `os.system` runs its command in a
subshell, so text from the environment or the argument vector changes the
command that runs. Same-named methods of unrelated classes never match. A
witnessed flow through an open dispatch is retained as possible, unproven,
partial evidence. An unresolved binding makes the run inconclusive instead of
clean.

#### Declared storage

The declared-storage family has two policies for each of 13 languages:
JavaScript, TypeScript, Python, Java, Rust, Go, Ruby, C, C++, PHP, Scala, C#,
and Kotlin. Both are opt-in: they run only when `--policy-id` or `policy_ids`
names them.

- `bifrost.security.<language>.stored-request-to-sql` (taint, `error`)
  reports a request value that the application writes to its own declared
  store in one place, reads back in another, and passes to the SQL-text
  operand of a database driver. The write-to-read edge appears in the finding
  as a declared model assumption, not as an observed database connection.
- `bifrost.security.<language>.store-requires-validation` (flow, `warning`)
  reports a request value that reaches the declared store write without
  passing through the validator the workspace configured. It never claims
  that every application must validate before storage, and a function merely
  named `validate` never satisfies it.

The two obligations are independent. A parameterized query removes only the
SQL flow, and passing the validator never sanitizes SQL.

Each policy imports reviewed endpoint-set documents from fixed paths in the
workspace. Create them before you select the policy:

| File | `:kind` | Used by | Declares |
| --- | --- | --- | --- |
| `.bifrost/endpoint-sets/stores/<language>-declared-store.rqlp` | `stores` | `stored-request-to-sql` | The `store-write` and `store-read` calls, the store name, and the key and instance ports. |
| `.bifrost/endpoint-sets/observations/<language>-declared-store-write.rqlp` | `observations` | `store-requires-validation` | The store write and the operand that must carry a validated value. |
| `.bifrost/endpoint-sets/kills/<language>-required-validator.rqlp` | `kills` | `store-requires-validation` | The validator call, its input, and its output. |

`<language>` is the policy's language label: `javascript`, `typescript`,
`python`, `java`, `rust`, `go`, `ruby`, `c`, `cpp`, `php`, `scala`, `csharp`,
or `kotlin`. Selecting a policy without its documents fails activation with a
`policy-validation-failed` diagnostic that names the missing file, and the run
exits 2. A missing model never counts as a passed check.

The policies select the request source and the SQL sink themselves; the
[policy reference](/reference/policies/) lists them per language. For
example, the Python policies read Flask `request.args.get` through a class
named `RequestValues` and write SQL through `Cursor.execute`. These three
Python documents declare a `JobStore` class whose `put(key, value)` writes the
store and whose `get(key)` reads it, and a `SearchTermValidator.validate`
method:

```lisp
; .bifrost/endpoint-sets/stores/python-declared-store.rqlp
(endpoint-set-document
  :schema-version 1
  :kind stores
  :language python
  :rql-schema-version 1
  :set (endpoint-set :entries [
      (store-write :id job-store-put
        :selector (rql :schema-version 1
          (language python
            (call-sites-to :proof proven
              (enclosing-decl
                (inside-decl (class :name "JobStore") (method :name "put"))))))
        :store job-store
        :key (argument :index 0)
        :instance receiver
        :input (argument :index 1))
      (store-read :id job-store-get
        :selector (rql :schema-version 1
          (language python
            (call-sites-to :proof proven
              (enclosing-decl
                (inside-decl (class :name "JobStore") (method :name "get"))))))
        :store job-store
        :key (argument :index 0)
        :instance receiver
        :output return-value)]))
```

```lisp
; .bifrost/endpoint-sets/observations/python-declared-store-write.rqlp
(endpoint-set-document
  :schema-version 1
  :kind observations
  :language python
  :rql-schema-version 1
  :set (endpoint-set :entries [
      (observation :id job-store-put-value
        :display-name "JobStore.put stored value"
        :selector (rql :schema-version 1
          (language python
            (call-sites-to :proof proven
              (enclosing-decl
                (inside-decl (class :name "JobStore") (method :name "put"))))))
        :observed-operand (argument :index 1))]))
```

```lisp
; .bifrost/endpoint-sets/kills/python-required-validator.rqlp
(endpoint-set-document
  :schema-version 1
  :kind kills
  :language python
  :rql-schema-version 1
  :set (endpoint-set :entries [
      (kill :id search-term-validator-validate
        :selector (rql :schema-version 1
          (language python
            (call-sites-to :proof proven
              (enclosing-decl
                (inside-decl (class :name "SearchTermValidator") (method :name "validate"))))))
        :input (argument :index 0)
        :output return-value)]))
```

Replace the class and method names with your application's store and
validator. The key contract separates channels by their proven key constants,
and the instance contract separates store objects that are proven distinct.
Then run both obligations:

```sh
bifrost --root . \
  --policy-id bifrost.security.python.stored-request-to-sql \
  --policy-id bifrost.security.python.store-requires-validation
```

The C# taint row does not conclude today: C# taint discovery over the two
matched endpoints is incomplete, so `bifrost.security.csharp.stored-request-to-sql`
reports an inconclusive run (`partial_discovery`) rather than reporting the
flow.

### Rust SQL-injection taint support

A Rust taint run with `:unmodeled require-model` concludes only when every
call it crosses is analyzed source, a reviewed model, or one of the Rust
standard-library facts the engine carries. Anything else keeps the run
`inconclusive` and names the unmodeled call or the unresolved identity; an
empty result from incomplete discovery is never reported as clean. The
reviewed Rust models below describe transitional engine regression coverage,
not a released pack to copy from the engine. For production use, obtain
separately delivered, reviewed content or author a workspace model under
`.bifrost/semantic-models/`. The retained regression stubs mimic each crate's
API shape; they do not claim compatibility with a specific crate release.

The engine's Rust standard-library facts are Bifrost-authored and apply only
where the resolver proves the standard identity: a string literal or `&str`
binding for the `str` methods, and the `std`/`core` prelude for the other
names, with no shadowing item, `use`, or glob import. They model their calls at
the same tier as analyzed code, so a run that needs nothing else concludes
`complete`. Reviewed model summaries are authored claims about code Bifrost did
not analyze, so a run that needs one concludes `proven_by_summary` instead,
unless the summary states no transfer at all.

| Area | Supported | Status |
| --- | --- | --- |
| Std facts (engine) | `str::to_owned`, `str::len`, `Ok`, `Err`, `Some`, `String::new`; `String + &str`; drops of `String`, and of `Option`, `Result`, `Vec`, `Box` whose type arguments are themselves covered; references (a borrowed temporary, which a `let` keeps alive to the end of its block, must itself be covered), primitives, tuples, arrays, and workspace structs and enums without type parameters, attributes, or a `drop` member | Complete |
| Std sources (model) | `std::env::var` and `std::env::args()` return values, `std::env::args().nth(i)` return value, `std::io::Stdin::read_line` buffer argument (`std::io::stdin().read_line(&mut buffer)`), with `Result::unwrap`, `Option::unwrap`, and `Args::nth` as transfers | Proven by summary |
| Std sources | A zero-argument `std::env::args()` selected directly | Complete: an exact empty call-binding partition is a usable call site for a return-value source |
| SQL sinks (model) | `postgres::Client::{execute, query, query_one, query_opt}` (SQL text is argument 0, bound values argument 1), `batch_execute`, `prepare`; `rusqlite::Connection::{execute, execute_batch, prepare}`, `rusqlite::Statement::execute` | Complete: the summaries carry no transfer, so bound values reach neither the result nor the receiver, and the SQL text is observed at the call |
| SQL sinks | `rusqlite::Connection::query_row` and other callback forms; `sqlx::query`, `sqlx::query_as`, `sqlx::Executor::execute`; `diesel::sql_query`; `tokio_postgres` and other `async fn` calls | Incomplete: no reviewed model; callbacks need a callable-argument contract, crate-root functions such as `sqlx::query` need a single-segment owner identity, and `async fn` bodies are deferred execution the adapter does not lower |
| Receivers | A method on a string literal, a `&str`, a reviewed std prelude type, a `use`-imported external type behind built-in references, or the result of a modeled call whose model declares its return type | Complete |
| Receivers | Trait objects, generic receivers, user `Deref` wrappers, unannotated bindings of an external call's result | Incomplete: no exact receiver type |
| Value construction | `+` on `String` and `&str`; a source bound to a `&mut local` argument reaches the local; `let` bindings and wildcard `let` temporaries | Complete |
| Value construction | `format!` and other macros, `String::push_str` and builders, closures, `async` blocks, `?`, `match`/`if let` destructuring that may drop owned values | Incomplete: macros and closures are not lowered, and these drops are outside the inert-drop proof |
| Drops of external values | `let _ = client.execute(..)` where the result's type comes from an external crate | Incomplete: needs a drop-glue fact in the declaration schema (follow-up to the in-code std table) |
| Framework sources | Axum and Actix extractors (`Query<T>`, `Path<T>`, `Json<T>`), handler parameters as entry points, `http::HeaderMap::get` | Incomplete: no reviewed model |
| Shipped policy | A general Rust request-to-SQL policy | Not shipped: author sources and sinks with `resolved-call` selectors that name the reviewed identity, such as `(call-argument :formal-index 0 (resolved-call :resolves-to "postgres.Client.execute" :proof declared ...))` |

### Built-in network-effect boundary pack

`bifrost.effects` contains ten assertion policies, one per language: C#, Go,
Java, JavaScript, Kotlin, Python, Ruby, Rust, Scala, and TypeScript. Each has
the ID `bifrost.effects.<language>.selected-boundary-no-network-io`, category
`effects`, and severity `error`.

#### Network-effect boundary

Each policy asserts that **explicitly selected declarations** reach no
declared network effect, directly or through workspace helpers. The
obligation never comes from a name, a file name, a comment, or an unqualified
annotation. It comes from two reviewed artifacts:

- a semantic model that declares the effect `bifrost.network_io` on the exact
  API identity; and
- a declaration-selection document that names the exact declarations the
  repository reviewed.

The policy does not contain its selection. It imports the document at a
reserved workspace path, `.bifrost/effect-boundaries/<language>-network-io.rqlp`,
so the released policy ID runs unchanged for every repository:

```lisp
(bind :name selected
  :query (declaration-selection-file
    :path ".bifrost/effect-boundaries/javascript-network-io.rqlp"
    :language javascript))
(bind :name effect
  :query (procedure-effects-of :binding selected))
```

Both bindings read the one document: `procedure-effects-of` takes the
procedure effects of exactly the declarations `selected` binds, so the
selection and the effect input cannot drift apart.

The document holds exact declaration selectors only. Each entry is an inline
`(enclosing-decl DECLARATION)` or `(enclosing-decl (inside-decl OWNER
DECLARATION))`, where each pattern is a `function`, `method`, or `class` with
an exact `:name` and no other constraint. A document lists at most 16
declarations. This one selects the JavaScript fixture's `total`:

<!-- policy-doc-test:rqlp:tests/fixtures/golden/declaration-selection-import/javascript/selection.rqlp -->
```lisp
;; The reviewed selection a host writes for the javascript fixture trees: the
;; one boundary the network-effect fixtures protect.
(declaration-selection-document
  :schema-version 1
  :language javascript
  :declarations [
    (rql (enclosing-decl (function :name "total")))])
```

The policies are opt-in: they run only when `--policy-id` names them, never in
`bifrost --root . --policy` or `bifrost scan`. A selected policy whose
document is missing, empty, malformed, of another document kind, or of
another language does not run. The report carries a `policy-validation-failed`
diagnostic whose message names the cause, such as
`declaration-selection-unavailable` ("no protected declarations configured"),
`declaration-selection-empty`, `declaration-selection-not-exact`,
`declaration-selection-nested-import`, `declaration-selection-wrong-document`,
or `declaration-selection-wrong-language`. An unconfigured policy is never a
clean result. The document rejects nested file references (`rql-file`,
`declaration-selection-file`, `endpoint-set-file`), because they would resolve
against the scanned checkout.

The run's `policy_hash` covers the imported declarations, not their spelling:
reordering entries or editing comments keeps it, and selecting another
declaration changes it. The policy ID, and its catalog `authored_hash`, stay
those of the released rule.

To configure the obligation:

1. Write the selection document to
   `.bifrost/effect-boundaries/<language>-network-io.rqlp`.
2. Put the language's reviewed model under `.bifrost/semantic-models/`. Go
   needs no file.
3. Run the released policy:
   `bifrost --root . --policy-id bifrost.effects.<language>.selected-boundary-no-network-io --fail-on error`.

A host that scans repositories it does not trust owns both reserved paths: it
deletes whatever the checkout holds there and writes its own reviewed
selection and model bytes before the run. Without the reviewed model, a
selected declaration that reaches the API leaves the effect set open, so the
run is inconclusive with an `absence-requires-exhaustive-coverage`
obligation; it is never clean.

| Language | Modeled API and written arity | Model to install |
| --- | --- | --- |
| C# | `System.Net.Http.HttpClient.SendAsync`, arity 1 | `semantic-packs/web-network/csharp/bifrost.web-network-csharp.json` |
| Go | `net/http.Get`, arity 1 | None. The embedded `bifrost.go.stdlib.net-http` pack declares it. |
| Java, Kotlin, Scala | `java.net.URL.openConnection()`, arity 0 | `semantic-packs/web-network/jvm/bifrost.web-network-jvm.json`, one model for all three |
| JavaScript | `globalThis.fetch` | `semantic-packs/web-network/javascript/bifrost.web-network-javascript.json` |
| TypeScript | `globalThis.fetch` | `semantic-packs/web-network/typescript/bifrost.web-network-typescript.json` |
| PHP | the cURL builtin `curl_exec`, arity 1 | `semantic-packs/web-network/php/bifrost.web-network-php.json` |
| Python | `urllib.request.urlopen` | `semantic-packs/web-network/python/bifrost.web-network-python.json` |
| Ruby | `Net::HTTP.get`, arity 1, and `request` on a `Net::HTTP.new` result | `semantic-packs/web-network/ruby/bifrost.web-network-ruby.json` |
| Rust | `std::net::TcpStream::connect`, arity 1 | `semantic-packs/web-network/rust/bifrost.web-network-rust.json` |

The model paths in this table are relative to
[Bifrost-packs](https://github.com/BrokkAi/bifrost-packs/tree/main/semantic-packs/web-network),
which owns their authoring and delivery. The engine's retained copies are
transitional test inputs; do not use the engine tree as an authoring source.

`(exactly 0)` is an absence claim, so it is conclusive only when the effect
relation's coverage is exhaustive. A selected declaration that reaches a
helper the analyzer cannot expand leaves the effect set open. The run then
publishes an unmet obligation and exits 2 rather than reporting a clean
result. Findings retain the selected root, the helper chain, the exact API,
and the declared effect's pack, model, and summary provenance. The relational
row publishes `depth`, `classification` (direct or transitive), `certainty`,
`timing`, `coverage`, and a bounded witness chain.

How each language binds its modeled API:

- **JavaScript and TypeScript.** A bare `fetch(...)` binds
  `globalThis.fetch` only when the identifier has no lexical binding at the
  call site. A module-local `fetch`, an imported `fetch`, a parameter, or a
  reassignment creates no identity and therefore no effect.
- **Java, Kotlin, and Scala.** The JVM model is declared once for the whole
  JVM realm, because the three languages compile to one classpath. A Kotlin
  receiver written as a value, `val url = URL(address)` and then
  `url.openConnection()`, binds through the value's constructor. A Scala
  receiver typed as `java.net.URL` binds the same identity. A workspace class
  with its own `openConnection` method stays a workspace call.
- **Rust.** `std::net::TcpStream::connect(addr)` and
  `TcpStream::connect(addr)` after `use std::net::TcpStream;` both bind the
  identity. A workspace type also named `TcpStream` with its own `connect`
  binds the workspace declaration and carries no effect.
- **Ruby.** `Net::HTTP.get(address)` binds through the constant path. The same
  model types the result of `Net::HTTP.new`, so `http.request(req)` on a local
  or chained constructor binds the reviewed instance member. One- and
  two-argument requests carry the effect. Construction with one or two
  arguments has a reviewed effect-free summary. Reassigning the local to an
  unknown value keeps a later request unresolved. A workspace class also
  spelled `Net::HTTP` resolves inside the workspace. A helper reached through
  a workspace member call concludes only when the receiver is exact and its
  method table is closed. The receiver must be a constant path, a
  `Const.new(...)` expression, or a local that only ever holds
  `Const.new(...)` of one class. The class and every ancestor must be declared
  once in the workspace, and every superclass and mixin must resolve. No
  ancestor may define `method_missing`, another dispatch hook, `new`, or
  `allocate`. The caller's file and the files that declare those classes must
  not rewrite methods: no `define_method` of the called name, `alias_method`,
  `class_eval`, `send`, refinement, or dynamic `require`. A call on `self`,
  a parameter, or an instance variable stays open, because a subclass can
  answer it. So does `Const.new` on a class that declares no `initialize`.
  Rewrites spelled in other files are outside the proof's scope.
- **C#.** Awaited calls of `SendAsync` propagate the effect. Unexpanded
  deferred callbacks and other arities keep the absence claim open. Parameter
  and explicitly typed local receivers bind; field and property receivers do
  not yet.
- **PHP.** `curl_exec($handle)` binds the global builtin through PHP's own
  function lookup: an unqualified call tries the caller's namespace first, so
  a workspace function such as `App\curl_exec` wins and carries no effect,
  while `\curl_exec($handle)` names the builtin directly. The same model gives
  `curl_init` with one argument a reviewed effect-free summary. Other arities
  keep the absence claim open.
- **Go.** The Go import binder expands the call's `http` qualifier to the
  `net/http` import path, so the identity never rests on the spelling `Get`.

In every language, a helper the analyzer cannot expand leaves the absence claim
open rather than clean.

A repository that authors its own policy may still inline its selection.
This repository-owned JavaScript policy selects a module-level function named
`total`:

<!-- policy-doc-test:rqlp:tests/fixtures/network-effect-boundary/policies/javascript.rqlp -->
```lisp
; Network-effect boundary for one explicitly selected JavaScript declaration.
;
; The rule family is shared; only the declaration-selection block below and the
; activated language model differ per language. `total` is not pure because it
; is named `total`: the reviewed configuration on this repository selects that
; exact declaration, and a repository that configures nothing carries no
; obligation at all.
;
; The join
; --------
; `procedure-effects` projects one row per (procedure, effect id) with the
; classification (direct or transitive), certainty, timing, coverage and a
; bounded witness chain. Rows are keyed on the declaration domain's own
; `procedure_id`, so the join to the selected relation is declaration-identity
; equality.
;
; The absence claim
; -----------------
; `(exactly 0)` is an absence claim, so it is conclusive only when the effect
; relation's coverage is exhaustive. A selected declaration that reaches an
; unresolved helper leaves the effect set open; the run then publishes an unmet
; obligation and exits 2 rather than reporting a clean verdict.
(policy
  :schema-version 1
  :id "bifrost.effects.javascript.selected-boundary-no-network-io"
  :name "Selected JavaScript boundary reaches no network effect"
  :message "the selected JavaScript boundary reaches the declared network effect"
  :severity error
  :description "One explicitly selected JavaScript declaration must not reach a declared network effect, directly or through workspace helpers. The effect is declared by a reviewed semantic model on the exact external API identity, never inferred from a function name, a file name, a comment, or an unqualified annotation."
  :help-uri "https://bifrost.brokk.ai/static-analysis-policies/#network-effect-boundary"
  :tags ["effects" "network" "boundary" "javascript"]
  :analysis
    (analysis
      :type assertion
      ; ---------------------------------------------------------------------
      ; Declaration-selection block (the repository's reviewed configuration).
      ; Replace the pattern below with the exact declaration this repository
      ; protects, for example:
      ;   (language javascript
      ;     (inside-decl (class :name "PriceCalculator")
      ;       (method :name "total")))
      ; ---------------------------------------------------------------------
      (bind :name selected
        :query (rql :schema-version 1
          (language javascript
            (enclosing-decl (function :name "total")))))
      (bind :name effect
        :query (rql :schema-version 1
          (language javascript
            (procedure-effects
              (enclosing-decl (function :name "total"))))))
      (join :left selected :right effect :on ((id procedure_id)))
      (group :name selected-boundary :by (selected.id)
        (aggregate :name network-effects :op count
          :where ((effect.effect_id eq "bifrost.network_io")
                  (effect.derivation eq declared))))
      (assert :group selected-boundary :value network-effects :cardinality (exactly 0))))
```

This example keeps the shipped `:id`. Run it with `--policy-file` only, or give
your copy its own ID before you run it together with the selected external
`bifrost.effects` pack.

## Schema Versions And Selectors

Policy/endpoint schema versions and nested RQL schema versions resolve
independently:

| Source form | Omitted version | Explicit version |
| --- | --- | --- |
| `(policy ...)` or `(endpoint ...)` | Select the newest compiled-in version in the compatible policy lineage (currently 1). | An exact pin; unsupported versions fail instead of falling back. |
| `(rql QUERY)` | Select the compatible RQL head (currently 1). | Add `:schema-version N` for an exact RQL pin. |
| `(rql-file :path "queries/rule.rql")` | With no wrapper pin, an explicit pin in the referenced document wins; if both omit a version, resolve the compatible RQL head. | A wrapper pin is exact; an explicit referenced-document pin must agree. |

File-backed selectors have four version-resolution cases:

| `rql-file` wrapper | Referenced `.rql` document | Result |
| --- | --- | --- |
| Omitted | Native query with no version envelope | Resolve the latest compatible RQL version (currently 1); the version is inferred. |
| Exact pin `N` | Native query with no version envelope | Use exact `N`; the wrapper supplies the explicit pin. |
| Omitted | `(rql :schema-version N QUERY)` | Use exact `N`; the referenced document supplies the explicit pin. |
| Exact pin `N` | `(rql :schema-version N QUERY)` | Use exact `N`; the agreeing referenced-document pin is retained as the resolution origin. |

If the wrapper and referenced document pin different versions, loading fails
with `conflicting-rql-schema-version`; an exact unsupported version also fails
instead of falling back. A referenced `.rql` file accepts only a raw native
query or the exact `(rql :schema-version N QUERY)` envelope shown above.
Source-only editor validation cannot read the referenced file, so it reports
this resolution as deferred until workspace loading.

Omission is a safe compatibility fallback, not “accept any latest schema.” The
engine chooses only a registered compatible successor. Use explicit pins for a
reproducible release artifact, or run with
`--require-explicit-schema-versions` to reject every inferred policy, endpoint,
and RQL version in the dependency closure.

An inline `(rql ...)` selector is lowered directly from the nested S-expression.
An `(rql-file ...)` selector names one workspace-relative `.rql` file and is
resolved only by a workspace-backed loader. There is no ambient policy,
endpoint, query, catalog, environment, or network discovery.

### Analysis-Shared Selector Context

An analysis may declare selector context once:

```lisp
(analysis
  :languages [java]
  :where ["src/java/**" "src/generated/java/**"]
  :rql-schema-version 1
  :type match
  :selector (rql (call :callee (name "eval"))))
```

`:languages` is a list of language labels or family aliases. An entry can be a
language label such as `java` or `cpp`, the alias `c++` or `c#`, or a file
extension that one language owns, such as `py` or `tsx`. A label or extension
ignores case, a leading dot, `-`, and `_`. The family aliases `jvm` and `js-ts`
must be written exactly. An unknown entry fails to load with
`invalid-language-label`. Tags, display names, and inferred identities are not
accepted. The [languages reference](/reference/languages/) lists every label
and extension. Shared RQL
defines `jvm` as exactly `[java kotlin scala]` and `js-ts` as exactly
`[javascript typescript]`. Alias expansion is concrete before composition:
`[jvm java]` and `[js-ts typescript]` deduplicate their members instead of
erroring, and concrete aliases can compose as `[jvm js-ts]`. Family membership
is fixed; changing membership is an explicit schema/version decision, never a
silent addition.

There is no separate `tsx` analyzer language. The `typescript` label covers both
`.ts` and TSX-bearing `.tsx` source, while `javascript` covers `.js`, `.mjs`,
`.cjs`, and JSX-bearing `.jsx` source, so `tsx` names `typescript`. The label
selects files by the language that owns their extension. Bifrost does not infer
a language from a policy tag, a workspace listing, or a qualified name.

The shared language and path constraints are conjoined outer constraints. A
selector with no local language or path scope inherits the analysis scope. A
selector with an explicit scope is conjoined with it; shared context never
replaces local context. Language sets intersect, and statically disjoint
language sets fail to load. Paths use ordinary set logic without glob-subset
guessing: one `:where` list is one OR group, while the language constraint and
path constraint are AND groups. Thus the example accepts either path pattern in
Java source. An explicit `(where "src/java/**" (where "src/acme/**" QUERY))`
form represents two separate path constraints, so both must accept a path.

Every local selector receives this context before execution, semantic
projection, and hashing:

- `match :selector`
- taint source, sink, sanitizer, transform, external-model, entry-point,
  store-write, and store-read selectors
- flow origin, observation, and kill selectors
- typestate subject selectors and direct `calls` selectors
- assertion `:subject` selectors and relational `bind :query` selectors

Endpoint, category, catalog, and derived-bind references do not acquire a
second RQL meaning. A `bind :from NAME :step STEP` expands an already typed row
relation; only its `:query` form is an RQL selector. The same rule preserves
row selectors and their destination vocabulary in relational assertions.

The hoisted context is sugar for the equivalent explicit selector form. The
match example therefore canonicalizes to the same effective typed query,
findings, completion state, semantic representation, and semantic hash as:

```lisp
:selector
  (rql :schema-version 1
    (language java
      (where "src/java/**" "src/generated/java/**"
        (call :callee (name "eval")))))
```

Repeated explicit wrapper forms conjoin; there is no additional shared-RQL
group syntax in policy schema version 1. Keep the examples above within one
analysis if you mean one OR path group and one explicit language family.

`:rql-schema-version` is a nested RQL pin, not a policy pin; the policy and RQL
lineages remain independent. A local inline selector with no pin inherits the
analysis pin. If it has an explicit pin, the two must agree. For `rql-file`,
the analysis pin supplies the wrapper pin when the wrapper omits one; the usual
wrapper-versus-referenced-document agreement rules then apply. A conflict among
the analysis, wrapper, inline selector, or referenced document fails with the
available source locations. Source-only editor validation still cannot read a
workspace `.rql` file, so that final file agreement remains deferred until
workspace-backed loading.

There is no default that silently overrides either side. An empty or narrower
result caused by conjoined scopes is a real result, not a shared-context error;
only languages that provably have no intersection are rejected statically.

### Receiver-Type Constraints

In an endpoint selector or a relational binding query, `resolved-call
:receiver-type` constrains the resolved declaring owner of the selected member.
In both places it is an
owner-membership constraint, not a constraint on the syntactic receiver
expression or on the complete set of runtime values that might arrive at the
call.

The scalar form remains exact-owner equality:

```lisp
(resolved-call :resolves-to "com.acme.Base.sink" :proof exact
  :receiver-type "com.acme.Base"
  query)
```

The inclusive form accepts the named workspace type and every descendant proven
by that language's typed hierarchy:

```lisp
(resolved-call :resolves-to "com.acme.Child.sink" :proof exact
  :receiver-type (assignable-to "com.acme.Base")
  query)
```

Inside an assertion plan, put the same scalar or `(assignable-to ROOT)` value
on the `resolved-call` step inside the binding's `(rql ...)` query.

For Java, `com.acme.Base` therefore matches a member owned by `Base` and by
proven subclasses or interface implementations. It does not match an unrelated
class that happens to define a method with the same name. Scala and other
languages can use the same authoring form only where their native typed
hierarchy can expand the workspace family completely; otherwise the run keeps
its typed incompleteness. Availability is proved by the resolver, not inferred
from the syntax.

The root must resolve to a source-backed workspace declaration. A model-only or
external root, a missing hierarchy provider, or a hierarchy that cannot be
obtained completely is a typed receiver-hierarchy incompleteness, never a
name-based fallback or a silently empty family. A retained positive proves that
the resolved member owner is in the family; it does not prove exhaustive runtime
dispatch. A clean negative additionally requires the existing exhaustive
call-binding and dispatch evidence.

This form stays in policy schema version 1. Its canonical loaded-policy form
distinguishes exact equality from inclusive assignability, so the two forms have
different semantic hashes.

## Reusable Endpoints

An endpoint has a stable ID, a human display phrase, one `source` or `sink`
role, exact opaque categories, one selector, and one binding. Bindings can name
the matched value, receiver, return value, or an argument by zero-based index or
formal name. Optional taint semantics declare source labels/evidence or sink
accepted labels; they still do not make the endpoint a diagnostic.

Taint source entries may also carry `:threat-model` with one of `remote`,
`commandargs`, `environment`, `stdin`, `file`, or `database`. A taint analysis
may select its active kinds with `:threat-models [KIND ...]`; when the field is
omitted, the analysis selects `[remote]`. A source without `:threat-model` is
active for every selection, which keeps policy-local sources compatible with
older policies. A classified source whose kind is outside the active set is
excluded before plan compilation. If that filtering removes every source, the
run is incomplete and includes a typed run-incomplete diagnostic rather than
reporting a clean empty result. The selected kind is retained beside the source
identity and display name in taint finding evidence.

<!-- policy-doc-test:rqlp:tests/fixtures/policies/endpoints/http-request-parameter.rqlp -->
```lisp
; A reusable match-only source. Loading this file never creates a diagnostic.
(endpoint
  :id "bifrost.sources.http-request-parameter"
  :name "HTTP request parameter"
  :display-name "User-controlled I/O"
  :description "A value supplied by an external HTTP request."
  :role source
  :categories [input.user-controlled io.external]
  :selector
    (rql
      (language python
        (call :callee (name "request_parameter"))))
  :binding return-value
  :taint
    (source-semantics
      :labels [attacker-controlled]
      :evidence
        (evidence
          :trust-boundary external
          :system-entry vulnerable-system-network-stack))
  :supersedes [])
```

Aggregate policies opt into endpoints with either:

- `(match-directory ...)`, which names one capability-rooted directory, a
  `direct` or `recursive` scope, and an exact `(any [...])` or `(all [...])`
  category predicate; or
- `(match-endpoints :ids [...])`, which selects exact endpoint IDs already in
  the immutable endpoint index.

Directory traversal is explicit, bounded, symlink-free, `.rqlp`-only, and can
pin `:manifest-sha256`. The directory semantic-hash projection contains its
selection predicate plus only the selected endpoint identities and their full
semantic hashes. The report's richer manifest also retains the reference path,
directory, scope, role, categories, definition and selector schemas, and
analysis-projection hashes. Imported endpoints become dependencies of the
policy; they do not create extra policy runs.

Endpoint `:supersedes` edges express same-event dominance. They apply only when
semantic compilation later establishes that two endpoints describe the same
event, role, and binding. Bifrost never infers precedence from selector text,
directory order, source location, message wording, or “more specific-looking”
categories. A missing target, cycle, or ambiguous live winner is an error.

### Catalogs

Large machine-managed taint libraries can be registered before policy loading
through `TaintCatalogRegistry` as typed values, canonical JSON bytes, or an
explicit workspace-relative JSON path. A policy then names a catalog by
`(catalog :name "catalog.id" :version N)` and may add `:sha256`.
Registration is versioned, content-addressed, bounded, and transactional. It
does not scan directories or access the network. Catalog JSON is a machine
registration contract, not a second human `.rqlp` syntax; human reusable
source/sink leaves should normally use endpoint documents.

### Shared Typed Endpoint Sets

When the same typed boundary belongs to several policies, put its entries in
one standalone endpoint-set document and import that document from each policy.
The document declares its entry kind (`sources`, `sinks`, `sanitizers`,
`entry-points`, `transforms`, `external-models`, `stores`, `origins`,
`observations`, `kills`, or `flow-transforms`). An import is a typed dependency:
it copies the declared entries into the importing set after checking the kind,
schema pins, path, and optional semantic hash. It is not textual substitution,
and the imported document is not an executable policy root.

Typestate `subject-set` and event triggers use different typed models: subjects
seed protocol objects, while events bind observations to protocol transitions.
They do not accept `:include-files`. Reuse their existing `:include-matches`
endpoint references where supported; taint or flow entries cannot substitute
for protocol subjects or events.

Import paths are portable workspace-relative paths. Absolute paths, `..`,
environment expansion, and symlinks escaping the workspace are rejected.
Nested imports use the same workspace root and are subject to file, depth,
entry, and retained-byte limits. Cycles, conflicting entries, and failed pins
prevent registration of the importing policy.

The following complete example declares a persistence boundary once. The
write and read selectors are Java examples; the same document shape accepts
the other analyzer languages supported by the selected entries.

`policies/shared-store.rqlp`:

```lisp
(endpoint-set-document
  :schema-version 1
  :kind stores
  :language java
  :rql-schema-version 1
  :set (endpoint-set :entries [
    (store-write :id put-primary
      :selector (rql :schema-version 1
        (language java (call :callee (name "put"))))
      :store primary
      :key (argument :index 0)
      :input (argument :index 1))
    (store-read :id get-primary
      :selector (rql :schema-version 1
        (language java (call :callee (name "get"))))
      :store primary
      :key (argument :index 0)
      :output return-value)]))
```

An importing policy keeps its own source and sink declarations and imports the
store set at the `:stores` endpoint-set position. Save this policy as
`policies/acme-user-input-reaches-shared-store.rqlp`:

```lisp
(policy
  :schema-version 1
  :id "acme.user-input-reaches-shared-store"
  :name "User input reaches a shared store"
  :message "tainted data reaches a sink through the shared store"
  :severity warning
  :analysis (analysis
    :type taint
    :mode may
    :call-modeling (call-modeling :unmodeled require-model)
    :sources (endpoint-set :entries [
      (source :id request :display-name "request input"
        :categories [input.user]
        :selector (rql :schema-version 1
          (language java (call :callee (name "source") :arity 0)))
        :bind return-value
        :labels [untrusted])])
    :sinks (endpoint-set :entries [
      (sink :id sensitive :display-name "sensitive sink"
        :categories [data.sensitive]
        :selector (rql :schema-version 1
          (language java (call :callee (name "sink") :arity 1)))
        :dangerous-operand (argument :index 0)
        :accepts [untrusted])])
    :stores (endpoint-set :include-files [
      (endpoint-set-file
        :path "policies/shared-store.rqlp")]))))
```

Run the policy from the workspace root with the CLI:

```sh
bifrost --root . \
  --policy-file policies/acme-user-input-reaches-shared-store.rqlp \
  --evaluation-date 2026-09-14 \
  --fail-on warning
```

MCP `run_policy` accepts the same policy file in `policy_files` and resolves
the imported path relative to the workspace root. Editors run policies through
the separate `bifrost-lsp` program, which sends a `bifrost/runPolicy` request;
see [LSP Server](/lsp/). A second policy can import the same document;
each policy retains its own finding identity while the report records the
shared document's source, entry identities, and semantic hash; the resolved
entries retain their analysis projection hashes and endpoint-set provenance.
Changing an imported entry therefore changes every dependent policy hash. Add
`:sha256` to `endpoint-set-file` when the workspace wants an exact lower-case
SHA-256 semantic pin for the resolved document.

Endpoint-set imports preserve the existing set-oriented taint batching: two
compatible policies that import the same typed set remain eligible for one
batch, while a missing or incompatible dependency fails closed during bounded
loading. Use local entries when a boundary is specific to one policy; use a
shared document when its typed meaning is authored once and reviewed as a
dependency.

## Analysis Types

| Type | Public authoring model | Evaluation in this release |
| --- | --- | --- |
| `match` | One inline or file-backed RQL selector returning supported, location-bearing terminal results. | Executable. |
| `taint` | Set-oriented sources, sinks, sanitizers, transforms, external models, and optional finding combinations. | Executes the production compiler, compatible batch planner, solver, retained report, and human/JSON/SARIF projection. |
| `typestate` | Tracked subjects, typed events, deterministic transitions, uncertainty rules, and terminal expectations. | Executes query-local semantic bindings and emits production findings with stable identity, primary/related locations, bounded witnesses, and completeness metadata. |
| `assertion` | Either a subject selector that captures identifier tokens plus one or more specialized invariants about the [occurrence](/rune-query-language/) each captured token carries and about how it resolved (`assert`, `assert-resolution`, `assert-binding-scope`, `assert-value-origin`, `assert-origin-shape`, `assert-boundary`, `assert-generation`, `assert-declaration-state`, `assert-edge-parity`, `assert-edge-class`, `assert-canonical`, `assert-route`, `assert-round-trip`, `assert-flow-establishment`, or `assert-rewrite-termination`); or a relational plan of `bind`, `join`, `group`, `aggregate`, `assert`, and `assert-selected-in-winning-tier` records over typed rows. | Executes. Correlates captures to occurrence, candidate, and binding rows by AST identity and emits one multi-location finding per violated invariant or violated row group. |
| `flow` | Neutral origins, observations, kills, and policy-local transforms over typed value-flow ports. | Executes bounded value-flow propagation. Uncertain or unbindable typed ports remain incomplete rather than producing a clean verdict. |

The [policy reference](/reference/policies/#rqlp-vocabulary) lists every
record and field of each analysis type, with its signature, whether it is
required, and its legal values.

### Taint: broad libraries, specific findings

The taint policy below selects every compatible user-controlled source and
sensitive-data sink from one explicit directory. The generated fallback uses
the fixed `{source display-name} can reach {sink display-name}` relation. A
specific combination supplies more actionable wording:

<details>
<summary>Checked taint policy fixture</summary>

<!-- policy-doc-test:rqlp:tests/fixtures/policies/attacker-controlled-to-sensitive-sinks.rqlp -->
```lisp
; Broad compatible source/sink pairs use the generated relation. The specific
; PII combination supplies a more actionable message and explicitly wins.
(policy
  :schema-version 1
  :id "bifrost.security.attacker-controlled-to-sensitive-sinks"
  :name "Attacker-controlled data reaches a sensitive sink"
  :message (generated-message :relation can-reach)
  :severity warning
  :analysis
    (analysis
      :type taint
      :mode may
      :sources
        (endpoint-set
          :include-matches [
            (match-directory
              :path "tests/fixtures/policies/endpoints"
              :scope recursive
              :categories (all [input.user-controlled]))])
      :sinks
        (endpoint-set
          :include-matches [
            (match-directory
              :path "tests/fixtures/policies/endpoints"
              :scope recursive
              :categories (any [data.pii data.sensitive]))])
      :finding-combinations [
        (finding-combination
          :id "user-input-to-pii"
          :source (categories :all [input.user-controlled])
          :sink (categories :all [data.pii data.sensitive])
          :message "User-controlled I/O can reach sensitive user PII"
          :supersedes [])]))
```

</details>

A generated message is emitted only after the taint analysis reports an
actual compatible source/sink meeting. Merely matching both endpoint selectors
does **not** license “can reach.” For one actual pair, an applicable explicit
combination replaces the generated default. If multiple explicit combinations
apply, `:supersedes` must leave one unique winner; it never creates a second
solver run or duplicate finding.

Categories, display phrases, and finding messages select and present this
composition. They do not become propagation keys or change the solver's
set-oriented run identity.

### Policy-local sanitizers: bind the declared entity and value

A taint policy can declare a sanitizer directly under `:sanitizers`. This is
different from a `sanitize` effect in a semantic-pack procedure summary: the
transfer form selects the sanitizer call, binds its declared input and
output ports, and removes only the labels listed in `:removes` from that
declared value flow. A conditional form instead removes those labels from a
call operand on an accepting branch.

The selector is part of the sanitizer's identity. When a policy means one
specific declaration, select that declaration and lift it to its proven call
sites; do not use a bare callee name that could also match an unrelated
method. The following fragment models `Clean.scrub(String)` and removes the
`input.user-controlled` label from its returned value:

```lisp
:sanitizers
  (endpoint-set :entries [
    (sanitizer :id clean-scrub
      :selector (rql :schema-version 1
        (language java
          (call-sites-to :proof proven
            (enclosing-decl
              (inside-decl
                (class :name "Clean")
                (method :name "scrub"))))))
      :input (argument :name "value")
      :output return-value
      :removes [input.user-controlled])])
```

`inside-decl` scopes the declaration to `Clean`, and `call-sites-to
:proof proven` retains only calls bound to that declaration. `:input` and
`:output` are value-flow ports, so an unrelated same-named method, a
non-reaching sanitizer call, or a different argument does not receive the
removal. If the selected sanitizer is unresolved or ambiguous, the policy
run must remain non-conclusive (or retain the finding); an empty finding set
alone is never evidence that an uncertain sanitizer made the value safe.

For a conditional sanitizer, replace `:input` and `:output` with
`:when (result true|false|nil|non-nil [:index k])` and
`:sanitizes receiver` or `:sanitizes (argument :index k)`. The optional result
index is zero-based and belongs inside the `result` record. Supply it for a
multi-result call. The two forms cannot be mixed.

This short test contract illustrates the conditional form with a
policy-defined label. Choose the intended declaration's proven call sites
when a policy needs to distinguish same-named predicates.

```lisp
:sanitizers
  (endpoint-set :entries [
    (sanitizer :id prefix
      :selector (rql :schema-version 1
        (language go (call :callee (name "HasPrefix"))))
      :when (result true)
      :sanitizes (argument :index 0)
      :requires [(argument :index 1 :constant true)]
      :removes [example.checked])])
```

The contract removes only `example.checked` from argument zero on the
accepting branch; any other labels remain. `:requires` is optional. When
present, it must be non-empty, without duplicate records, and all its items
must hold. Each item is `(receiver ATTR)` or `(argument :index k ATTR)`, with
exactly one of these attributes:

- `:constant true` requires a compile-time constant.
- `:equals LIT` compares its decoded value with a string, number, or Boolean
  literal. The language must decode string literal payloads; if it cannot,
  the guard declines.
- `:result-of SELECTOR` requires a result of a call matched by the selector,
  using the same inline `rql` or deferred `rql-file` forms as `:selector`.

When a requirement follows a local, that local must have a unique single
writer that dominates the tested call. The condition itself must test the
call result directly: storing it in `ok` and testing `ok` later declines.
The sanitized carrier must have a unique binding origin and a resolved type
whose referent is immutable. The guard declines when the language cannot
report the carrier's type, or when the type is unknown or its referent is
mutable. Indices must be within the call's arity where it is known.

A decline leaves the flow unsanitized. If a finding is still reported for
that flow, its related-location evidence explains
`sanitizer prefix declined: REASON`. This note is advisory: it is never a
finding of its own and does not itself make the result incomplete.

### Policy-local transforms: carry a value across an exact seam

A taint policy can declare a policy-local transform under `:transforms`. It
selects one exact call or value site and binds the input and output ports. The
transform is a pass-through from input to output, with the labels changed as
the declared set operation `(input - removes) union adds`. At least one
`:removes` or `:adds` label is required, so an empty taint transform is a
load-time authoring error.

```lisp
:transforms
  (endpoint-set :entries [
    (transform :id normalize-user
      :selector (rql (language java
        (call :callee (name "normalizeUser"))))
      :input (argument :index 0)
      :output return-value
      :removes [user-controlled]
      :adds [normalized])])
```

Taint transform sets may compose catalog entries, but not match-endpoint sets.
Their selector and ports are typed evidence: a transform does not apply to a
lookalike call or an unbound operand. A structurally bound but uncertain port
still contributes a possible flow and keeps the result inconclusive. Finding
provenance retains the source's original labels, while
`reached_source_labels` reports the labels carried at the sink after every
transform on the witness.

A flow analysis may use the same `:transforms` field with the neutral form:

```lisp
:transforms
  (endpoint-set :entries [
    (transform :id normalize-user
      :selector (rql (language java
        (call :callee (name "normalizeUser"))))
      :input (argument :index 0)
      :output return-value)])
```

Flow transforms carry the tracked value from `:input` to `:output` without
label fields and compose only local entries. If either typed port is uncertain
or cannot be bound, the flow result remains typed-incomplete; it is not
converted into a clean verdict.

### External models: declare a procedure's transfer semantics

A taint policy can declare, under `:external-models`, that the calls its
selector identifies have exactly the declared transfer semantics. The
declaration is opaque: for a modeled call the analyzed body -- if one is even
present in the workspace -- is ignored, the declared transfers run on the
caller side, and only the listed labels move. This is the standalone-CLI form
of an external procedure summary; it needs no semantic-pack catalog, and it
is the surface that satisfies `(call-modeling :unmodeled require-model)` for
a call the analysis must not enter.

Each `(external-model ...)` entry names a selector and a duplicate-free set
of transfers. A transfer moves its `:labels` from the `:from` input port
(an argument or the receiver) to the `:to` output port. The output can be a
call port -- `return-value`, `(result :index N)`, `receiver`, or an argument
-- or one named field of an argument or the receiver, written as
`(field :name "payload" :of (argument :index 1))`. The field form is a
store-through summary with field precision: only the named field of the
written object is tainted, and a sibling field of the same object stays
clean. An `:effect` of `propagate` moves the labels unchanged, and
`(sanitize :removes [...])` removes labels at the seam; a transfer whose
sanitize effect removes everything it moves is an explicit no-flow
declaration, which is how a summary states "this procedure's result carries
nothing from this input" over a body that would say otherwise.

```lisp
:external-models
  (endpoint-set :entries [
    (external-model :id bridge-pass
      :selector (rql :schema-version 1
        (language java
          (call-sites-to :proof proven
            (enclosing-decl
              (inside-decl
                (class :name "Bridge")
                (method :name "pass"))))))
      :transfers [
        (transfer :from (argument :index 0) :to return-value
          :labels [input.user-controlled] :effect propagate)])
    (external-model :id bridge-deposit
      :selector (rql :schema-version 1
        (language java
          (call-sites-to :proof proven
            (enclosing-decl
              (inside-decl
                (class :name "Bridge")
                (method :name "deposit"))))))
      :transfers [
        (transfer :from (argument :index 0)
          :to (field :name "payload" :of (argument :index 1))
          :labels [input.user-controlled] :effect propagate)])])
```

The declaration is load-bearing, and its failure modes stay honest. A
selector that matches nothing leaves the calls unmodeled, so under
`require-model` the run stays typed-incomplete rather than silently clean.
An unproven or partial selection applies the declared semantics but keeps
the run from concluding. A field destination binds only when exactly one
observable location for that field of the written object exists in the
solve; a field nothing can read makes the write a complete no-op, and an
ambiguous destination leaves the run non-conclusive instead of writing a
guessed location. Shipped semantic-pack summaries still take precedence at
a call they cover. External-model transform effects (`:effect (transform ...)`)
remain a typed compile refusal; policy-local transforms are the supported
transform surface.

### Framework entry points: synthesize a root for an uncalled handler

Real framework code is entered through handlers no analyzed caller invokes:
the framework calls `onRequest` with attacker-controlled arguments, and the
workspace contains no call site for it. A taint policy declares such a
procedure under `:entry-points`; the analysis then roots the selected
declaration itself, and the bound formal parameter carries the declared
labels on entry, so the handler-internal flow is decided rather than
silently unreachable.

```lisp
:entry-points
  (endpoint-set :entries [
    (entry-point :id request-handler
      :selector (rql :schema-version 1
        (language java
          (method (name "onRequest"))))
      :parameter (argument :index 0)
      :labels [input.user-controlled])])
```

The selector names procedure *declarations* (RQL `method` / `function`
kinds), so the binding is entity identity, not name shape: a lookalike
handler the policy does not select stays un-rooted and reports no flow. The
`:parameter` port is an argument record only — `(argument :index N)` or
`(argument :name "name")` — naming the formal of the selected declaration; a
declared parameter the procedure does not have fails the run instead of
reporting a vacuous clean. An entry point behaves as a source-role endpoint
in reports and finding origins; under `(call-modeling :unmodeled
require-model)` the declaration is load-bearing: removing it returns the
handler to the honest un-rooted outcome.

### Persistence stores: link a write to a read across opaque code

A taint policy can declare a persistence boundary under `:stores`: one
procedure writes its tainted argument into a named store, another reads from
the same store and returns it, and taint flows write-to-read even when the
store's own implementation is opaque to the analysis (an empty body, an
external service, a framework cache). A boundary is a pair of entries sharing
one `:store` name:

```lisp
:stores
  (endpoint-set :entries [
    (store-write :id put-primary
      :selector (rql :schema-version 1
        (language java (call :callee (name "put"))))
      :store primary
      :key (argument :index 0)
      :instance receiver
      :input (argument :index 1))
    (store-read :id get-primary
      :selector (rql :schema-version 1
        (language java (call :callee (name "get"))))
      :store primary
      :key (argument :index 0)
      :instance receiver
      :output return-value)])
```

The write's `:input` port names the value that enters the store and the
read's `:output` port the value that leaves it. The declaration is
load-bearing: without both halves there is no flow across the boundary, and
an undeclared write/read pair contributes nothing.

`:key` and `:instance` are optional discrimination dimensions, each an
ordinary value-flow port of the selected call. A write reaches a read only
when the store names are equal and neither dimension separates the pair:

- A direct plain, escape-free string literal proves a key identity from its
  content, so `put("a", x)` does not reach `get("b")`.
- Java local copies can also prove a finite set of literal keys. The analysis
  uses every reaching definition before the selected call, including both
  conditional arms. Two complete disjoint sets separate; overlapping sets
  still join. The initial bounds are 64 origin links, 4096 work units, 16
  distinct literals, and 1 MiB of source per query. These are analysis limits,
  not a guarantee that every expression below them is supported.
- An instance identity is proven only when the port's operand resolves to
  exactly one declaration (for example a static field or module binding), so
  `alpha.put(...)` does not reach `beta.get(...)`.
- Every other case joins: an undeclared dimension means the whole store, and
  a dimension the analysis cannot prove (an unknown origin, a field read,
  a call result, an unresolvable receiver, or an exhausted bound) must not
  manufacture a separation. Cyclic copy origins and unqualified language
  binding contracts also join. Joining can only add flows,
  which is the sound direction for a may-analysis.

A store declaration also models its selected call outright: nothing flows
through the call directly, and taint crosses only via the declared boundary.
A store call whose own dispatch the analysis cannot resolve therefore stops
blocking a complete verdict -- the declaration is the model. Completion
stays honest in the other direction: when the write side of a boundary could
not be analyzed completely, no store-fed verdict is reported complete, and a
partially evidenced store binding keeps the run non-conclusive exactly as an
uncertain sanitizer does.

### Assertion: what the parser must say about a token

An assertion policy is a conformance rule about the analyzer's own output. The
subject selector captures identifier tokens; each `assert` states the
occurrence role, class, and cardinality that token must carry. The correlation
is an equality on AST identity -- the captured node and the occurrence row name
the same arena node -- so an assertion can never be satisfied by a coincidence
of spelling or range.

<details>
<summary>Checked assertion policy fixture</summary>

<!-- policy-doc-test:rqlp:tests/fixtures/policies/role-fidelity.rqlp -->
```lisp
; Assertion policies are diagnostic-neutral conformance rules. The subject
; selector finds candidate tokens; each `assert` states what the parser must
; say about the token captured under `:at`, joined by AST identity rather than
; by spelling. Omitting :schema-version selects the latest compatible policy
; schema, currently version 1.
(policy
  :id "bifrost.conformance.logger-is-never-rebound"
  :name "Logger is never rebound"
  :message "The module logger must be read, never rebound by a local of the same name"
  :severity warning
  :description "A local named `logger` shadows the module logger and silently changes which sink receives the record."
  :tags ["correctness" "shadowing"]
  :analysis
    (analysis
      :type assertion
      :subject
        (rql
          (identifier :text/regex "^logger$" :capture "token"))
      :asserts [
        (assert
          :id no-rebinding
          :at "token"
          :role binder
          :expect none)]))
```

</details>

`:at` must name a capture on the **token** being asserted about, not on its
declaration. Capturing `(function :name "render")` addresses the function node,
while the occurrence lives on the identifier inside it, so the two would
correctly fail to join and the assert would report an absence.

`:expect` is one of `declaration`, `reference`, `binding`, or `none`, and
`:cardinality` is `(exactly N)`, `(at-least N)`, or `(at-most N)`, defaulting to
`(exactly 1)`. `:expect none` and `(exactly 0)` mean the same thing and must
agree; a role whose class can never satisfy the stated `:expect` is rejected
when the document loads rather than evaluated to a guaranteed verdict.
`:namespace` narrows to `type`, `value`, `module`, `macro`, or `label`, and
`:require-target` additionally demands that reference-class rows resolved.

#### Asserting how a name resolved

Four further assert records state *why* a name means what it means. They share
the subject selector, the AST-identity join, and the soundness rules above, and
each carries a required `:role` naming the reference-class occurrence role it is
about, so capability reporting narrows to exactly that role.

`(assert-resolution :id ID :at CAPTURE :role ROLE :expect-tier TIER)` requires
the candidate the resolver selected to sit at one precedence tier. The tiers are
ordered strongest first -- `lexical_binding`, `own_member`, `inherited_member`,
`explicit_import`, `package_or_module`, `wildcard_import`, `external_root`,
`name_only_fallback` -- and `:at-least true` accepts any tier at least as strong
as the named one. `:forbid-tier TIER` removes one tier from the accepted range,
and `:require-unique true` makes ambiguity a violation rather than a silent
pick. A combination no tier can satisfy is rejected when the document loads.

`(assert-binding-scope :id ID :at CAPTURE :role ROLE :declared inside|outside
:relative-to CAPTURE2)` requires the binding actually in effect at the captured
reference to be declared inside, or outside, a second captured node. This is the
loop-invariance predicate: capture a loop and the receiver of a call inside it,
then require the receiver's binding to be declared inside the loop. The half
that declares it outside -- and therefore sorts the same list on every iteration
-- is the finding. `:relative-to` may not name the same capture as `:at`, whose
containment is fixed.

`(assert-value-origin :id ID :at CAPTURE :role ROLE :established inside|outside
:relative-to CAPTURE2)` asks the same shape of question about the value rather
than the binder: it requires the value read at the captured reference to be
*established* inside, or outside, a second captured node. The requirement is
over the union of the binding's lexical declaring scope,
explicit assignment targets, and loop-target occurrences already classified as
`loop_variable` bindings by the language adapter. An establishment target's
original source position is compared with the captured region; its `binding-of`
answer is compared with the receiver's selected binding. The lexical owning
scope is separate: a Python loop target can establish a value inside a loop
while remaining a local of the enclosing function. Repeated binding tokens and
assignments join by canonical binding identity, never the spelled name, so a
write to a shadowing namesake exempts nothing. An outer loop's target does not
establish a value inside an inner loop merely because both use the same binding.

This is supported lexical establishment evidence, not an exhaustive analysis of
iteration writes or arbitrary receiver mutation. For example, existing-variable
iteration targets need not introduce a `loop_variable` binding in every language.
Missing or conflicting canonical binding evidence for a discovered target, an
incomplete inventory, row limits and cancellation cannot prove an outside origin. The predicate does not
prove that a deferred body executes or that collection contents are unchanged.

`(assert-boundary :id ID :at CAPTURE :role ROLE :forbid-fallback-past
external_declared_unindexed|external_unknown)` forbids a `name_only_fallback`
selection once resolution reached or passed one authoritative boundary. It is a
prohibition, so a reference where nothing was selected satisfies it.

`(assert-canonical :id ID :at CAPTURE :role ROLE :equals CAPTURE :equals-role
ROLE [:distinct true])` requires the two captured tokens' resolved declarations
to share one canonical identity -- language, namespace, ordered kind-tagged
name segments, and generic arity, compared structurally and never by rendered
text. `:distinct true` inverts it: the selections must share none, which is how
a same-terminal decoy (two `Map`s under different owners) is separated from the
true target. `:equals` may not name the same capture as `:at`, whose comparison
is fixed.

`(assert-route :id ID :at CAPTURE :role ROLE :to CAPTURE :to-role ROLE [:via
HOP] [:forbid HOP])` requires an identity route from the captured site to what
the `:to` capture resolves to. The traversal follows the identity-preserving
hop kinds (alias, import, export, re_export) plus whatever `:via` names, and
`:via` additionally requires at least one hop of that kind on the matching
route -- `(assert-route ... :via re_export)` is how "this facade genuinely
forwards the origin" is spelled. A traversal that ends in a cycle or a
truncation is inconclusive, never evidence of absence.

What counts as a re-export follows each language's own rule. Rust re-exports
through `pub use`, and JavaScript and TypeScript through `export ... from`.
Python names no re-export in its syntax, so Bifrost applies the rule its typing
ecosystem enforces (PEP 484 stub semantics, which pyright and mypy apply in
strict mode): a name on the module's `__all__`, either redundant-alias form
(`from x import y as y`, `import x as x`), and `from x import *` as one star
hop are re-exports. A plain `from .impl import helper` in a package
`__init__.py` that states no `__all__` is not; the facade convention alone does
not make a name public, and the import relation already reports it. When a
module computes its `__all__` (`__all__ = build()`, `__all__.extend(other)`),
membership is unknown, so that file's import, export and re-export rows report
incomplete and an absent re-export proves nothing.

`(assert-round-trip :id ID :at CAPTURE :role ROLE)` requires forward
resolution and inverse enumeration to close: every declaration the site's
route reaches must reach the site back through inverse edges over the involved
files. The mined regressions this family answers are the ones where the
forward and inverse sides of one indirection quietly disagreed.

Three absences make these asserts inconclusive rather than passing or failing:
a selected candidate whose recording seam could not name a tier (an absent tier
is not the weakest tier); an assert that needs the whole considered set on a
language whose resolver records selections but not rejections; and a reference
for which nothing was selected at all. A capture with no lexical binding in
effect is not one of them -- that is a complete answer, so a containment
requirement over an absent binding is simply skipped.

#### Relational assertions over typed rows

The asserts above each address one captured token. An assertion policy can
instead state an invariant over named relations of typed rows. It replaces
`:subject` and `:asserts` with a plan: `(bind :name NAME :query (rql ...))`
names the rows produced by one RQL query; row-local filtering, projection,
call selection, argument selection, and analyzer expansion are steps inside
that query; `(join ...)` relates two bindings by equal-typed registered fields;
`(group ...)` groups the joined rows by
registered fields and computes named `(aggregate ...)` values; and `(assert
:group NAME :value NAME :cardinality ...)` bounds one aggregate in every group.
A group that violates its assertion becomes one finding anchored at the exact
source ranges of the rows that produced it. A binding the query engine had to
truncate makes the run inconclusive, never clean; the run's diagnostics then
name each assertion whose verdict that truncation blocked.

##### Discovering the row fields

The rows are a registry, not a convention, so the fields, scalar types,
nullability, join keys, enum values, and admitted expansions are all published.
`bifrost --list-row-schemas` prints the whole versioned catalog as
`bifrost_relation_schema/v1` JSON, without constructing a workspace. The REPL's
`:doc <row-domain>` prints one domain of that same catalog, and the validator
enforces exactly what the catalog states, so a field named there is a field the
plan can bind.

The first lines `:doc call_argument` prints, as an example of the shape:

```
call_argument — row domain for relational policy bindings
id: stable_id (join key)
group_id: stable_id (join key)
site_id: stable_id (join key)
argument_index: integer
```

Enum columns list their admitted public values, and each domain ends with the
`expansions: STEP -> DOMAIN` RQL steps that may extend a query producing that
domain. The catalog prints canonical underscore step names such as
`receiver_outcome`; authored RQL also accepts its hyphenated
`receiver-outcome` spelling.

The catalog is the source of truth; this page does not restate it. A field
reference the catalog does not carry fails at policy load time, and the
`unknown field` diagnostic lists the complete set of fields the binding does
carry.

##### Row predicates

The RQL `(filter :where (...) QUERY)` step takes a bounded conjunction of typed
row tests. Its field names are unqualified because the query carries exactly
one current row schema. An aggregate's existing `:where` uses the same
operators over qualified `BINDING.FIELD` references. Each test is one list,
and the operator decides its shape:

- `(FIELD eq|ne|lt|le|gt|ge VALUE)` compares a query-row field with a literal.
  `eq` and `ne` are defined for every field; the four ordered operators need an
  integer field, because no other registry scalar carries an order that
  survives a rename.
- `(FIELD eq|ne|lt|le|gt|ge (field OTHER-FIELD))` compares two fields of the
  same query row instead. The explicit `field` form keeps a bare public enum
  label unambiguous. Both fields must hold the same scalar type.
- `(FIELD is-null)` and `(FIELD is-not-null)` test presence.
  They are admitted only over fields the row registry marks optional; over a
  field the registry always populates they would be constants, so they are an
  authoring error rather than a question.
- `(FIELD in (VALUE ...))` tests membership in a bounded literal set of
  one through 64 values.

Every comparison against an absent value is false, including `ne`. Three-valued
logic would make `(x ne "a")` true for rows that state nothing about `x` at
all, which is the opposite of what an invariant about `x` means. Say `is-null`
when you mean absent.

##### Filtering and projecting a relation

`(filter :where ((FIELD OP OPERAND) ...) QUERY)` keeps only rows satisfying
every listed predicate. It preserves the query's row schema and its source and
evidence anchors.

`(project :columns (FIELD (FIELD NEW-FIELD) ...) QUERY)` selects the fields a
relational binding publishes. A bare entry keeps its field name; a two-item
entry renames it. The resulting schema contains exactly those fields, in the
authored order, with each source field's scalar type, nullability, and public
enum value domain. A later filter reads the projected names. A projection must
be terminal apart from more projection or filter steps because analyzer steps
consume a registered domain, not an arbitrary dynamic record.

##### Joins

`:kind` chooses how a join combines its two relations, and omitting it means
`inner`:

- `inner` keeps every matching pair and carries both relations' columns.
- `semi` keeps the left rows that have at least one partner and carries the
  left columns only, so it filters without multiplying rows.
- `anti` keeps the left rows that have no partner.

An anti-join is sound only over a right relation that was read exhaustively. If
the right relation was truncated or partly unreadable, its output rows exist
only because nothing was found to remove them, so they support no verdict and
the run reports an unmet obligation instead of a clean pass.

A join never pairs programming-code rows with configuration rows. Equal
spellings, equal paths, or two rows in one repository prove no relation, so a
plan that joins a code binding to a `configuration-facts` binding fails at load
time. Correlate them inside one selector with the registered `correlate`
operator, which pairs a code row with a configuration fact only through a
structural relation, or require both with `require-both`, which pairs nothing.
A `cross_domain` binding produced by either operator may join a
`configuration-facts` binding on `configuration_id`, which is that fact's own
stable `id`. See [Code And Configuration
Correlation](/code-query-json/#code-and-configuration-correlation).

##### Aggregates

The aggregate operations are `count`, `count-distinct`, `min`, `max`, `any`,
`all`, `ordered-equal`, `set-equal`, and `subset`. `count` folds rows; `count-distinct` folds any
column; `min` and `max` fold an integer column; `any` and `all` fold a boolean
column to one or zero, so one cardinality assertion can state every fold. `any`
is one when some contributing row is true, `all` is one when every contributing
row is true, and a group with no contributing row folds `all` to one and `any`
to zero. `ordered-equal` compares two ordered sequences instead, each named by
its own integer position field and the value read at that position:

```lisp
(aggregate :name parity :op ordered-equal
  :left (arg.argument_index arg.name)
  :right (param.parameter_index param.label))
```

It yields one when the two sequences hold the same value at every position and
have the same length, and zero otherwise, so `:cardinality (exactly 1)` states
complete list parity. Position awareness is the point: a call that passes the
same named arguments in a different order is equal to the declaration as a set
and different as a list. A sequence is recovered from the group's rows rather
than from row order, so two states are undefined and never reported as parity:
a row that states no position, and two rows that claim one position and
disagree.

Whether a length difference is visible is a property of your join, not of the
predicate. Joining on the compared value keeps only positions that already
matched on both sides, and two such projections have equal length by
construction; joining on a correlation key instead -- one call site to one
callable -- puts both complete sequences in the group.

`set-equal` and `subset` compare two columns from the contributing rows as
sets of distinct present values. Both columns must have the same stable-key
type (`stable_id` or `declaration_identity`); display strings, integers,
booleans, and enum labels are not identity keys. Duplicates and row order do
not affect the result. Absent values do not contribute a set member.

```lisp
(aggregate :name same-targets :op set-equal
  :left observed.target_id :right expected.target_id)
(aggregate :name allowed-targets :op subset
  :left observed.target_id :right expected.target_id)
```

`set-equal` yields one when the sets are equal. `subset` yields one when every
left value occurs on the right. Otherwise they yield zero. Two empty sets are
equal, and an empty left set is a subset of every right set. An empty source
creates no group; a group's `:where` filter can leave an empty fold. Join on
the group correlation key, not the compared values, to avoid discarding the
very differences the assertion should find.

The existing `max_values_per_group` bound limits contributing tuples before
set construction, including duplicates. Truncation makes the result incomplete.
An incomplete set comparison cannot publish a verdict; it reports
`absence_requires_exhaustive_coverage` with the reasons that prevented a
complete comparison. Relational execution also checks cancellation while
loading rows, projecting, filtering, indexing and probing joins, building and
folding groups, and checking assertions. Cancellation discards partial
findings and reports an incomplete result with the `cancelled` reason.

##### A plan that uses the whole surface

The rule below states that no member access rejects a candidate: the semi join
keeps only the sites the receiver analysis described, the fold's `:where`
compares two integer columns of the same row, and `max` reports how many
candidates the offending site actually weighed.

```lisp
(policy
  :id "example.relational.no-rejected-candidate"
  :name "Member accesses reject no candidate"
  :message "a member access must select every candidate it considered"
  :severity error
  :analysis (analysis
    :type assertion
    (bind :name site :query
      (rql (occurrences :role [member_position])))
    (bind :name outcome :query
      (rql (receiver-outcome (occurrences :role [member_position]))))
    (bind :name selection :query
      (rql (member-selection (occurrences :role [member_position]))))
    (join :left site :right outcome :kind semi :on ((ast_id site_ast_id)))
    (join :left site :right selection :on ((ast_id site_ast_id)))
    (group :name by-site :by (site.ast_id)
      (aggregate :name considered :op max :value selection.candidate_count
                 :where ((selection.selected_count lt selection.candidate_count))))
    (assert :group by-site :value considered :cardinality (exactly 0))))
```

`(assert-selected-in-winning-tier :id ID :site NAME :candidates NAME
[:cardinality ...])` is authoring sugar over the callable-applicability rows.
`:site` names a binding of `overload-selection` rows and `:candidates` a
binding of `callable-applicability` rows for the same sites. It lowers to one
inner join on `site_ast_id`, one group keyed on the site, one aggregate
counting the candidates that are both `selected` and `applicable`, and one
cardinality assertion -- exactly what you could write by hand, which is why it
reports through the same finding path. The winning tier is the set of
candidates the resolver's own applicability check accepted. The default
cardinality `(exactly 1)` is the uniquely resolved site; `(exactly 0)` states a
site where the resolver accepted nothing; `(at-least 2)` states a site that
bound more than one accepted candidate.

An undecided candidate is not an accepted one. A candidate whose verdict is
`unknown` -- the language does not report the callable axis, or it never
recorded that declaration's parameter list -- is not counted, so a site whose
candidates are all undecided counts zero accepted candidates and violates the
default cardinality. Bind the sites your invariant is about, and read the
`overload-selection` row's `resolution` and `supported` fields when you need to
tell an undecidable site from a resolved one. A site the resolver enumerated no
candidate for contributes no tuple to the join at all, so it forms no group and
is never asserted.

#### Completeness in a relational plan

A relational assertion counts rows, so it is sensitive to a set that is empty
because nobody could read it rather than because it is genuinely empty. Today
exactly one producer suppresses a set that way: a call shape whose `coverage`
is not `exact`. A macro-derived or otherwise unreadable argument list emits no
argument-group and no argument row at all, precisely so it cannot look
byte-identical to a real zero-argument call.

A suppressed shape reports that gap on **every row family derived from it**,
not only on the `call_shape` row itself. Deriving the shape emits a
`call_shape_coverage_incomplete` diagnostic of `incomplete` impact naming the
site and the coverage that suppressed it, so the query that projects
`call_argument_groups`, `call_arguments` or `call_bindings` from that shape is
`incomplete` too, and the run that binds any of them is inconclusive rather
than clean. Both of these plans therefore reach the same verdict, for the same
reason, on the same macro-derived site:

```lisp
; Binds the mandatory shape row beside the arguments it heads.
(bind :name shape :query (rql (call-shape (occurrences :role [member_position]))))
(bind :name arg :query
  (rql (call-arguments (call-argument-groups
    (call-shape (occurrences :role [member_position]))))))
(join :left shape :right arg :on ((site_id site_id)))
```

```lisp
; Binds only the projected argument rows. The suppressed shape they were
; derived from still makes the run inconclusive (issue #1949).
(bind :name arg :query
  (rql (call-arguments (call-argument-groups
    (call-shape (occurrences :role [member_position]))))))
```

Binding the shape row remains worth writing when your invariant reads the
shape's own fields -- its `coverage`, `call_kind` or `callee_name` -- or when
you need the site to appear in the join even where it has no arguments. It is
no longer the only way to keep a suppressed shape from reading as clean.

Nothing weaker poisons the run. An `unknown_shape` overload summary, an
undecided candidate verdict, and a signature whose arity the language never
recorded all publish exact values in their own fields and emit every row they
head, so a whole file is never reported inconclusive because one site in it was
undecidable. Exclude those rows with `:where` when your invariant needs them
excluded.

#### A worked loop-invariance rule

The rule below is the reason `assert-value-origin` exists, and it is the one the
external `bifrost.code-smells` pack contains. A structural rule that only asks "is
this call written inside a loop" cannot tell a collection built inside the loop
and canonicalized once from a collection built before the loop and re-sorted on
every pass; the second is the waste worth reporting and the first is not. The
requirement is therefore that the sorted receiver's value be *established*
inside the loop -- declared there, or assigned there -- and the violation is the
half established by neither.

<details>
<summary>Checked loop-invariance rule (the shipped pack source)</summary>

<!-- policy-doc-test:rqlp:crates/bifrost-policy/policy-packs/bifrost.code-smells/policies/loop-invariant-sort.rqlp -->
```lisp
; Promoted from the #1474 Milestone 6 prototype (issue #1598). The naive
; sort-in-loop containment rule this replaces asked "is a sort call written
; inside a loop?" and measured a ~100% false-positive rate on this repository:
; in almost every finding the sorted value was created inside the loop, so the
; work was inherent to the iteration. This rule asks the intended question --
; loop *invariance* of the receiver. The requirement is that the sorted
; receiver's value be established inside the loop; the violation, and the
; finding, is the invariant half: the same value, created once outside,
; re-sorted on every pass.
;
; Two origins establish a value, and the requirement is over their union: the
; declaring scope of the binding in effect at the receiver, and any assignment
; whose left operand reaches that same binding. The second half is what keeps
; a receiver declared before the loop but overwritten on every pass out of the
; report; in Rust, Java, TypeScript and JavaScript such a write introduces no
; binder, so a declaration-only predicate would call it invariant. The join to
; an assignment is binding identity, never the spelled name.
;
; Boundaries, carried verbatim from the prototype because containment cannot
; decide them:
; - A receiver that is a field projection (`group.packages.sort()`) has no
;   receiver-position occurrence for the assert to address, so the rule
;   abstains under either polarity. It decides nothing there.
; - A call written inside a closure or other deferred body inside the loop is
;   reported because it is lexically inside the loop. Containment can say
;   where the call is written; it cannot say how many times the body runs. The
;   message says so rather than claiming per-iteration cost. A sort guarded by
;   a condition that leaves the loop is the same class of fact: the rule
;   reports where the call is written, not how often control reaches it.
(policy
  :schema-version 1
  :id "bifrost.performance.loop-invariant-sort"
  :name "Loop-invariant receiver sorted on every iteration"
  :message "this receiver's value is established outside the enclosing loop and never re-established inside it, so every iteration re-sorts the same value; if the call sits in a closure or other deferred body, it is reported because it is written inside the loop, not because it is proven to run once per iteration"
  :severity warning
  :description "The sorted receiver's value is established outside the enclosing loop -- its binding is declared outside and no assignment inside the loop reaches that binding -- so the loop re-sorts one unchanged-identity value on every pass. Sort once before the loop, or maintain order incrementally. Receivers that are field projections of another value are outside this rule's evidence and are not reported either way."
  :help-uri "https://bifrost.brokk.ai/static-analysis-policies/#built-in-code-smell-pack"
  :tags ["performance" "collections" "loop" "code-smell"]
  :analysis
    (analysis
      :type assertion
      :subject
        (rql
          :schema-version 1
          (union
            (language rust
              (inside (loop :capture "region")
                      (call :callee (name/regex "^(sort|sort_by|sort_by_key|sort_by_cached_key|sort_unstable|sort_unstable_by|sort_unstable_by_key)$")
                            :receiver (identifier :capture "target"))))
            (language python
              (inside (loop :capture "region")
                      (call :callee (name "sort") :receiver (identifier :capture "target"))))
            (language java
              (inside (loop :capture "region")
                      (call :callee (name "sort") :receiver (identifier :capture "target"))))
            (language typescript
              (inside (loop :capture "region")
                      (call :callee (name "sort") :receiver (identifier :capture "target"))))
            (language javascript
              (inside (loop :capture "region")
                      (call :callee (name "sort") :receiver (identifier :capture "target"))))))
      :asserts [
        (assert-value-origin :id established-inside :at "target" :role receiver_position
                             :established inside :relative-to "region")
      ]))
```

</details>

Two boundaries in that rule are worth copying into any rule built on this
predicate. A receiver that is a *field projection* of the loop variable
(`group.packages.sort()`) is not addressed at all: the capture is the projection
rather than an occurrence of a receiver role, so the assert abstains, under
either polarity. And a call inside a closure is reported because it is written
inside the loop, which is a lexical fact rather than a claim about how often the
body runs -- so the message says exactly that instead of asserting per-iteration
cost. The same limit applies to a sort a condition guards before leaving the
loop: containment says where the call is written, not how often control reaches
it.

Soundness is stricter here than for a match policy, because `none` and
`exactly` are claims about a *set*. If the subject query or the occurrence scan
is incomplete for any reason -- an adapter that marks the asserted role
unsupported, a truncated result, an exhausted budget -- the run reports
`inconclusive` with **no** findings, which is never a clean result. A partial row set
can make a satisfied assertion look violated as easily as the reverse, so an
assertion over incomplete input is never a pass and never a clean.

### Typestate: endpoint reuse plus protocol rules

Typestate policies reuse endpoint selectors and bindings for tracked subjects
and phase-specific API observations, then add a protocol automaton:

<details>
<summary>Checked typestate policy fixture</summary>

<!-- policy-doc-test:rqlp:tests/fixtures/policies/resource-lifecycle.rqlp -->
```lisp
; Typestate reuses categorized endpoint selectors, then adds protocol state.
(policy
  :id "bifrost.correctness.resource-lifecycle"
  :name "Resource lifecycle"
  :message "Resource can leave its analysis root without being closed"
  :severity error
  :analysis
    (analysis
      :type typestate
      :mode may
      :call-modeling (call-modeling :unmodeled paranoid)
      :subjects
        (subject-set
          :include-matches [
            (match-directory
              :path "tests/fixtures/policies/endpoints"
              :scope recursive
              :categories (all [resource.acquire]))]
          :entries [])
      :uncertainty
        (uncertainty
          :escape inconclusive)
      :automaton
        (automaton
          :states [open closed violated]
          :initial open
          :accepting-states [closed]
          :error-states [violated]
          :events [
            (event
              :id close
              :matches
                (match-directory
                  :path "tests/fixtures/policies/endpoints"
                  :scope recursive
                  :role sink
                  :phase after-normal-return
                  :categories (all [resource.close]))
              :supersedes [])]
          :transitions [
            (transition :from open :on close :to closed)]
          :terminal-expectations [
            (terminal-expectation
              :id "normal-exit-closed"
              :on (normal-procedure-exit :scope analysis-root)
              :expected-states [closed]
              :supersedes [])
            (terminal-expectation
              :id "exceptional-exit-closed"
              :on (exceptional-procedure-exit :scope analysis-root)
              :expected-states [closed]
              :supersedes [])])))
```

</details>

Endpoint observations retain their matched-value, receiver, return, or argument
binding and their observation phase. Accepting states are not absorbing: later
events can transition away from them. Normal and exceptional **analysis-root**
exits can require that an accepting state was already reached; helper returns
remain interprocedural transfers, not implicit terminals. A terminal-expectation
violation is distinct from a transition into an error state.

`:call-modeling` is shared by taint and typestate policies. `paranoid` is the
default when the record is omitted and conservatively models transfers that are
justified by the structured call site. `optimistic` preserves existing facts
without introducing unseen-body transfers, while `require-model` abstains when
no applicable model exists. Every fallback retains incomplete call-boundary
evidence; none of these settings turns an unresolved call into proof of safety.

`:on-unknown` is a different question and is accepted on every analysis type:
`:call-modeling` decides which facts cross an unmodeled call, while
`:on-unknown` decides what the run does once some verdict could not be reached
at all. See [Declare What An Unknown Result Does](#declare-what-an-unknown-result-does).

Endpoint categories and display/report text remain outside automaton and
interprocedural-summary keys; the protocol analysis consumes resolved endpoint
identity, binding, phase, and behavior.

## Checked Normalized Fragments

These compact JSON fragments are generated from the parsed typed authoring
model and checked against the complete fixture golds. They show normalized
authored JSON only: unresolved file, endpoint, directory, or catalog references
can remain, and this form is not a policy-hash input. The reported
`policy_hash` comes from the distinct loaded and composed canonical semantic
model after the loader has resolved the complete dependency closure. Rendered
report JSON is a third projection over policy runs and findings; it is neither
of those definition forms. JSON is not accepted as `.rqlp` source in any role.

Endpoint source semantics:

<!-- policy-doc-test:json:tests/fixtures/policies/endpoints/http-request-parameter.normalized.json#/taint -->
```json
{
  "evidence": {
    "system_entry": "vulnerable_system_network_stack",
    "trust_boundary": "external"
  },
  "labels": [
    "attacker-controlled"
  ],
  "type": "source"
}
```

The explicit taint presentation rule:

<!-- policy-doc-test:json:tests/fixtures/policies/attacker-controlled-to-sensitive-sinks.normalized.json#/analysis/finding_combinations/0 -->
```json
{
  "add_classifications": [],
  "id": "user-input-to-pii",
  "message": "User-controlled I/O can reach sensitive user PII",
  "sink": {
    "predicate": {
      "categories": [
        "data.pii",
        "data.sensitive"
      ],
      "type": "all"
    },
    "type": "categories"
  },
  "source": {
    "predicate": {
      "categories": [
        "input.user-controlled"
      ],
      "type": "all"
    },
    "type": "categories"
  },
  "supersedes": []
}
```

Typestate terminal obligations:

<!-- policy-doc-test:json:tests/fixtures/policies/resource-lifecycle.normalized.json#/analysis/automaton/terminal_expectations -->
```json
[
  {
    "expected_states": [
      "closed"
    ],
    "id": "exceptional-exit-closed",
    "supersedes": [],
    "trigger": {
      "event": {
        "scope": "analysis_root",
        "type": "exceptional_procedure_exit"
      },
      "type": "semantic_event"
    }
  },
  {
    "expected_states": [
      "closed"
    ],
    "id": "normal-exit-closed",
    "supersedes": [],
    "trigger": {
      "event": {
        "scope": "analysis_root",
        "type": "normal_procedure_exit"
      },
      "type": "semantic_event"
    }
  }
]
```

## An Executable P0 Walkthrough

This walkthrough uses two reference policies to show the whole policy
substrate: exact semantic selection, policy-authored value flow, declarative
effects, bounded relational assertions, explicit behavior when analysis is
incomplete, and one canonical report behind the human, JSON, SARIF, CLI, and
MCP surfaces.

Neither policy needs new analyzer code. Each is a `.rqlp` document. The second
also needs one reviewed semantic model, which is data as well.

### The example workspaces

Every example below is a small workspace that you can create from the sources
on this page. Reference policy A uses this layout:

```text
acme-flow/
  policies/acme-validated-value-reaches-store.rqlp   reference policy A, shown below
  src/AcmeApi.java                                   the exact APIs and the near miss
  src/App.java                                       one of the three App.java variants
```

Create one workspace for each `App.java` variant, because the three variants
declare the same class. Run the policy from any directory:

```sh
bifrost --root acme-flow --policy-file policies/acme-validated-value-reaches-store.rqlp
```

`src/AcmeApi.java` declares the source, the validator, the exact API, and a
near-miss class with a method of the same name:

```java
package com.acme;

/** The value origin reference policy A tracks. */
public final class AcmeSource {
    public static String read() {
        return "raw";
    }
}

/** The only procedure that may establish a value for AcmeStore.put. */
public final class AcmeValidator {
    public static String validate(String value) {
        return value;
    }
}

/** The exact API reference policy A observes. */
public final class AcmeStore {
    public void put(String value) {
    }
}

/**
 * The near miss. `AcmeCache.put(String)` shares the member name `put` with
 * `AcmeStore.put(String)` and is otherwise unrelated. Exact selection means
 * no finding ever attaches to a call of this method.
 */
public final class AcmeCache {
    public void put(String value) {
    }
}
```

<details>
<summary>The three <code>src/App.java</code> variants</summary>

The violating variant stores an unvalidated value:

```java
package com.acme;

public final class App {
    void storesAnUnvalidatedValue(AcmeStore store, AcmeCache cache) {
        String value = AcmeSource.read();
        // The near miss: the same member name on an unrelated class. Reference
        // policy A must not report this line.
        cache.put(value);
        // The violation: an unvalidated value reaches the exact API.
        store.put(value);
    }
}
```

The clean variant validates directly and through a helper, and stores an
unvalidated value only in the near-miss class:

```java
package com.acme;

public final class App {
    /** Directly validated: the kill runs on the value's own path. */
    void storesADirectlyValidatedValue(AcmeStore store) {
        String value = AcmeValidator.validate(AcmeSource.read());
        store.put(value);
    }

    /** Validated through a workspace helper: the kill runs interprocedurally. */
    void storesAHelperValidatedValue(AcmeStore store) {
        String value = AcmeSource.read();
        store.put(validated(value));
    }

    static String validated(String value) {
        return AcmeValidator.validate(value);
    }

    /**
     * An unvalidated value reaching the near-miss class. The tree stays clean,
     * which is the second half of the exact-selection proof.
     */
    void fillsAnUnrelatedCache(AcmeCache cache) {
        cache.put(AcmeSource.read());
    }
}
```

The unreliable variant passes the value through a wrapper that the workspace
does not declare:

```java
package com.acme;

public final class App {
    /**
     * The wrapper is not resolvable in this workspace, so the value's path
     * through it is unknown. No spelling of reference policy A may report this
     * tree as clean.
     */
    void storesThroughAnUnresolvedWrapper(AcmeStore store) {
        String value = AcmeSource.read();
        store.put(AcmeUnknownWrapper.wrap(value));
    }
}
```

</details>

### Reference policy A: a validated value reaches an exact API

The invariant: every value `AcmeStore.put` stores must have been established by
`AcmeValidator.validate`.

<!-- policy-doc-test:rqlp:tests/fixtures/policy-substrate-p0/policies/acme-validated-value-reaches-store.rqlp -->
```lisp
; Reference policy A of the issue-2433 P0 epic, Java edition:
; "a validated value reaches an exact API".
;
; The invariant is a correctness rule, not a security rule. Every value
; AcmeStore.put stores must have been established by AcmeValidator.validate.
; The analysis carries no labels, categories, tags or impacts: a flow policy
; tracks one thing, whether the value an origin establishes reaches an
; observation without passing a kill.
;
; Exact selection
; ---------------
; Each endpoint selects call sites of one exact declaration rather than
; call text that merely ends in `put`:
;
;     (call-sites-to :proof proven
;       (enclosing-decl (inside-decl (class :name "AcmeStore") (method :name "put"))))
;
; `inside-decl` narrows the seed to the member of one named type, and
; `call-sites-to :proof proven` returns only call sites the definition
; resolver bound to that declaration. The fixture tree contains
; `AcmeCache.put(String)`, a same-named member of an unrelated class, and no
; finding attaches to it.
;
; Actual-to-formal binding
; ------------------------
; The observation binds `(argument :name "value")`, the formal `AcmeStore.put`
; declares, not `(argument :index 0)`, the ordinal the call happens to write it
; at. The port resolves the name through the caller/callee binding of the
; selected call, so it names the same operand whether the call is written
; positionally, as Java writes it here, or by keyword, as the Python edition of
; this policy writes it. `issue_2496_named_flow_port.rs` pins that the two
; spellings report the same sites on this tree.
;
; Selecting through `call-input` and binding `matched-value` is still not a
; substitute: when the actual is itself a call, `call-input` names that inner
; call exactly and the port then binds the inner call's operand.
;
; Unmodeled calls stay paranoid so a call whose body the analyzer cannot see
; still propagates. The abstention fixture runs the same rule with
; `:unmodeled require-model`.
(policy
  :schema-version 1
  :id "bifrost.p0.acme-validated-value-reaches-store"
  :name "Unvalidated value reaches AcmeStore.put"
  :message "a value AcmeValidator.validate never established reached AcmeStore.put"
  :severity warning
  :description "AcmeStore.put must only store values established by AcmeValidator.validate. A value that reaches put from AcmeSource.read without passing validate breaks that invariant."
  :help-uri "https://bifrost.brokk.ai/static-analysis-policies/"
  :tags ["flow" "provenance" "java"]
  :analysis
    (analysis
      :type flow
      :mode may
      :call-modeling (call-modeling :unmodeled paranoid)
      :origins
        (endpoint-set :entries [
          (origin :id acme-source-read
            :display-name "AcmeSource.read"
            :selector (rql :schema-version 1
              (language java
                (call-sites-to :proof proven
                  (enclosing-decl
                    (inside-decl (class :name "AcmeSource") (method :name "read"))))))
            :bind return-value)])
      :observations
        (endpoint-set :entries [
          (observation :id acme-store-put
            :display-name "AcmeStore.put"
            :selector (rql :schema-version 1
              (language java
                (call-sites-to :proof proven
                  (enclosing-decl
                    (inside-decl (class :name "AcmeStore") (method :name "put"))))))
            :observed-operand (argument :name "value"))])
      :kills
        (endpoint-set :entries [
          (kill :id acme-validate
            :selector (rql :schema-version 1
              (language java
                (call-sites-to :proof proven
                  (enclosing-decl
                    (inside-decl (class :name "AcmeValidator") (method :name "validate"))))))
            :input (argument :name "value")
            :output return-value)])))
```

Three things make this exact rather than name-shaped:

1. `(inside-decl (class :name "AcmeStore") (method :name "put"))` seeds on the
   member of one named type.
2. `(enclosing-decl ...)` lifts that match to the declaration.
3. `(call-sites-to :proof proven ...)` returns only call sites the definition
   resolver bound to that declaration.

`src/AcmeApi.java` also declares `AcmeCache.put(String)`, a same-named member
of an unrelated class. The violating `App.java` calls both. Run:

```sh
bifrost --root acme-flow --policy-file policies/acme-validated-value-reaches-store.rqlp
```

The report has one finding, on `store.put(value)`. The exit status is 1 and the
completion is `complete`. No finding attaches to `cache.put(value)`.

With the clean `App.java`, which validates one value directly and one through a
workspace helper and stores an unvalidated value only in the near-miss class,
the same command exits 0 with completion `complete`. The kill makes that
result clean: delete the `:kills` block and both validated flows are reported.

With the unreliable `App.java`, an unresolvable wrapper sits between the origin
and the observation. The run ends with completion `inconclusive` under both
`:unmodeled paranoid` and `:unmodeled require-model`. An unresolved call is
never a clean result.

#### The same policy on Python

The Python edition is the same document with its own `:id`
(`bifrost.p0.acme-validated-value-reaches-store-python`) and
`(language python)` in each of the three selectors. Save it as
`policies/acme-validated-value-reaches-store-python.rqlp` in a workspace that
holds `api.py` and one of the app files below. It reaches the same results:
exit 1 with one finding on `store.put(value)` and none on the near-miss
`cache.put(value)`, and exit 0 on the validated tree.

<details>
<summary>The Python sources</summary>

`api.py`:

```python
"""The Python edition of reference policy A's API tree.

Every class is `@final`. That is not decoration: PEP 591 is Python's own
closed-dispatch declaration, and it is what lets `store.put(value)` name one
exact target instead of "this member or any override a subclass may add". The
Java edition spells the same claim `public final class`. Drop the decorator and
the tree stays correct, but every run over it becomes inconclusive.
"""

from typing import final


@final
class AcmeSource:
    """The value origin reference policy A tracks."""

    @staticmethod
    def read():
        return "raw"


@final
class AcmeValidator:
    """The only procedure that may establish a value for AcmeStore.put."""

    @staticmethod
    def validate(value):
        return value


@final
class AcmeStore:
    """The exact API reference policy A observes."""

    def put(self, value):
        pass


@final
class AcmeCache:
    """The near miss.

    `AcmeCache.put` shares the member name `put` with `AcmeStore.put` and is
    otherwise unrelated. Exact selection means no finding ever attaches to a
    call of this method.
    """

    def put(self, value):
        pass
```

`finding_app.py`:

```python
from api import AcmeCache, AcmeSource, AcmeStore


def stores_an_unvalidated_value(store: AcmeStore, cache: AcmeCache):
    value = AcmeSource.read()
    # The near miss: the same member name on an unrelated class. Reference
    # policy A must not report this line.
    cache.put(value)
    # The violation: an unvalidated value reaches the exact API.
    store.put(value)
```

`clean_app.py`:

```python
from api import AcmeCache, AcmeSource, AcmeStore, AcmeValidator


def stores_a_directly_validated_value(store: AcmeStore):
    """Directly validated: the kill runs on the value's own path."""
    value = AcmeValidator.validate(AcmeSource.read())
    store.put(value)


def fills_an_unrelated_cache(cache: AcmeCache):
    """An unvalidated value reaching the near-miss class.

    The tree stays clean, which is the second half of the exact-selection
    proof.
    """
    cache.put(AcmeSource.read())
```

`inconclusive_app.py`:

```python
"""Two Python shapes that keep the combined run open while it still decides.

The keyword call is an exact finding through semantic call bindings. The
helper-validated call is not a finding, and cannot be one: its origin read
reaches a static method through an instance, which the adapter's attribute
resolution does not prove, so the value is never tracked from the origin. The
run reports the keyword violation and stays open rather than reading as clean.
"""

from api import AcmeSource, AcmeStore, AcmeValidator


def stores_an_unvalidated_value_by_name(store: AcmeStore):
    """A keyword actual binds directly to the semantic formal named `value`."""
    value = AcmeSource.read()
    store.put(value=value)


def stores_a_helper_validated_value(store: AcmeStore):
    """A helper-carried kill whose origin read the adapter cannot prove.

    `read` is declared `@staticmethod`, so `source.read()` is an instance
    attribute read whose resolution is not proven and whose value therefore
    never enters the tracked flow. The run stays incomplete with a
    `partial_discovery` reason instead of reporting the value as established.
    The same helper shape over the proven `AcmeSource.read()` origin concludes.
    """
    source = AcmeSource()
    value = validated(source.read())
    store.put(value)


def validated(value):
    return AcmeValidator.validate(value)
```

</details>

Two facts have to hold for that, and both are visible in the source:

1. The receiver's type is evident at the call. An annotated parameter
   (`store: AcmeStore`), a local assigned exactly one visible constructor call
   (`store = AcmeStore()`), a direct `AcmeStore().put(...)` chain, and `self`
   all qualify. A bare untyped parameter does not, and a local that two
   assignments give two different classes does not; those return no proven row
   rather than a guess.
2. The target's dispatch is closed. Java gets this from `final`; Python gets it
   from PEP 591's `@final`, on the method or on its class. Without it the same
   tree still reports the same finding, but a clean verdict is refused: a
   subclass could override `put`, so the resolved member is not proven to be
   the complete target set.

`inconclusive_app.py` ends inconclusive. Its keyword call `store.put(value=value)`
binds the formal named `value` exactly and is reported as a definite finding.
Its second function reads the origin as `source.read()` on an instance of
`AcmeSource`. That read reaches a static method through an instance, which the
Python adapter does not prove, so the value is never tracked from the origin.
The run reports the keyword finding and stays `inconclusive` with reason
`partial_discovery` rather than reading as clean.

#### The same policy on TypeScript

The TypeScript edition is again the same document, with the `:id`
`bifrost.p0.acme-validated-value-reaches-store-typescript` and
`(language typescript)` in each selector. Over a workspace with `api.ts` and
one app file it reaches the same results: exit 1 with one finding on
`store.put(value)` and none on the near-miss `cache.put(value)`, and exit 0 on
the validated tree.

<details>
<summary>The TypeScript sources</summary>

`api.ts`:

```ts
// The TypeScript edition of reference policy A's API tree.
//
// Every class declares a `private constructor`. That is not decoration: a
// private constructor is TypeScript's own statement that the class cannot be
// extended (`class D extends AcmeStore` refuses to compile), so no subclass,
// and therefore no override, exists. It is what lets `store.put(value)` name
// one exact target instead of "this member or any override a subclass may
// add". The Java edition spells the same claim `public final class`; the
// Python edition spells it `@final`. Make the constructors public and the
// tree stays correct, but every run over it becomes inconclusive.

export class AcmeSource {
  private constructor() {}

  /** The value origin reference policy A tracks. */
  static read(): string {
    return "raw";
  }
}

export class AcmeValidator {
  private constructor() {}

  /** The only procedure that may establish a value for AcmeStore.put. */
  static validate(value: string): string {
    return value;
  }
}

export class AcmeStore {
  private constructor() {}

  /** The exact API reference policy A observes. */
  put(value: string): void {}
}

/**
 * The near miss.
 *
 * `AcmeCache.put` shares the member name `put` with `AcmeStore.put` and is
 * otherwise unrelated. Exact selection means no finding ever attaches to a
 * call of this method.
 */
export class AcmeCache {
  private constructor() {}

  put(value: string): void {}
}
```

`finding_app.ts`:

```ts
import { AcmeCache, AcmeSource, AcmeStore } from "./api";

export function storesAnUnvalidatedValue(store: AcmeStore, cache: AcmeCache): void {
  const value = AcmeSource.read();
  // The near miss: the same member name on an unrelated class. Reference
  // policy A must not report this line.
  cache.put(value);
  // The violation: an unvalidated value reaches the exact API.
  store.put(value);
}
```

`clean_app.ts`:

```ts
import { AcmeCache, AcmeSource, AcmeStore, AcmeValidator } from "./api";

/** Directly validated: the kill runs on the value's own path. */
export function storesADirectlyValidatedValue(store: AcmeStore): void {
  const value = AcmeValidator.validate(AcmeSource.read());
  store.put(value);
}

/**
 * An unvalidated value reaching the near-miss class.
 *
 * The tree stays clean, which is the second half of the exact-selection
 * proof.
 */
export function fillsAnUnrelatedCache(cache: AcmeCache): void {
  cache.put(AcmeSource.read());
}

/**
 * A TypeScript annotation states a structural contract, not the nominal owner
 * of the initializer. The exact AcmeCache value must keep its own `put` target
 * rather than borrowing AcmeStore.put from the compatible annotation.
 */
export function fillsAnUnrelatedCacheThroughStoreShapedBinding(cache: AcmeCache): void {
  const store: AcmeStore = cache;
  store.put(AcmeSource.read());
}
```

`structural_receiver_app.ts`:

```ts
// The structural-receiver shape reference policy A cannot prove, by itself.
//
// This file is the only region in its fixture: there is no workspace helper
// and no kill on any path. `policy_substrate_p0.rs` pins what the run reports
// for it, so a change to the helper region's handling cannot change this
// result.

import { AcmeSource } from "./api";

/**
 * A structurally-typed receiver keeps the target set open.
 *
 * `StoreLike` is satisfied by any object with a matching `put`, so the call
 * has no exact target: no proven row exists for `AcmeStore.put`.
 */
interface StoreLike {
  put(value: string): void;
}

export function storesThroughAStructuralType(store: StoreLike): void {
  store.put(AcmeSource.read());
}
```

`helper_kill_app.ts`:

```ts
// The helper-kill shape reference policy A still cannot conclude about.
//
// The kill that validates the value runs inside a workspace helper rather than
// on the observed path. The run stays inconclusive rather than clean, and the
// finding does not attach to the near-miss class. This file is its own
// fixture, so a change that carries the helper's return across the call
// changes only this shape's result.
//
// `policy_substrate_p0.rs` pins this shape. The structural-receiver shape is
// pinned separately in `structural_receiver_app.ts`.

import { AcmeSource, AcmeStore, AcmeValidator } from "./api";

/**
 * A kill that runs inside a workspace helper rather than on this path.
 *
 * The Java edition concludes on the same shape. The TypeScript edition does
 * not yet, so the run stays inconclusive instead of reporting the value as
 * established.
 */
export function storesAHelperValidatedValue(store: AcmeStore): void {
  const value = validated(AcmeSource.read());
  store.put(value);
}

function validated(value: string): string {
  return AcmeValidator.validate(value);
}
```

</details>

The same two facts carry it. The receiver's type is evident at the call — an
annotated parameter (`store: AcmeStore`), a `const` assigned exactly one
visible constructor call, a direct `new AcmeStore().put(...)` chain, the class
name itself for a static member, or `this` inside the owner — and a local two
assignments give two different classes returns no proven row rather than a
guess. And the target's dispatch is closed. TypeScript has no `final` keyword;
its own statement that a class cannot be extended is a `private constructor`,
which is what the fixture classes declare. Make the constructors public and
the same tree reports the same finding but refuses the clean verdict, exactly
as Java without `final` and Python without `@final` would.

The two shapes still left open are split into one fixture each.
`structural_receiver_app.ts` holds a receiver typed by a structural interface,
whose implementation set no declaration closes. Its run completes with no
finding and one advisory `empty_selection` diagnostic, because the receiver
binds no proven `AcmeStore.put` call. `helper_kill_app.ts` holds a kill that
runs inside a workspace helper rather than on the stored value's own path. Its
run stays `inconclusive` with reason `partial_discovery`.

### Binding the actual passed to a named formal

The analyzer publishes the actual-to-formal relation, and it is exact in both
syntaxes. This query returns the operand bound to formal `value` at every call
of the exact API:

```lisp
(call-input :parameter-name "value"
  (call-sites-to :proof proven
    (enclosing-decl
      (inside-decl (class :name "AcmeStore") (method :name "put")))))
```

For an endpoint that must retain the full call-binding row and pin a reviewed
callable identity, use the endpoint-specific RQL pipeline:

```lisp
(call-argument :formal-name "value"
  (resolved-call :resolves-to member.acme-store.put :proof declared
    (call-bindings
      (call-shape (call :callee (name "put"))))))
```

`resolved-call` accepts `:proof exact|declared` and an optional
`:receiver-type`. An unquoted identity is a stable analyzer/model ID. A quoted
qualified name is resolved once, with provenance, while the policy is loaded
against its workspace and active semantic models. `call-argument` accepts
exactly one `:formal-name` or zero-based `:formal-index`; it retains only a
non-terminal row with an argument identity, exact mapping, and exhaustive
actual coverage. Those guarantees are why `call-input :parameter-name` is not
an equivalent endpoint selector: `call-input` projects the expression site and
does not retain the call-binding proof row.

Over the violating Java workspace it returns one row, the operand of
`store.put(value)`. Over a Python workspace that contains both
`store.put(value)` and `store.put(value=value)`, it returns both operands, so a
named call binds formal `value` the same way a positional one does.

Reference policy A binds the same formal directly, as a value-flow port:

```lisp
:observed-operand (argument :name "value")
```

The port resolves the name against the selected call's own caller/callee
binding, so it names the operand of formal `value` whether the call passes it
by position or by keyword. Both editions of reference policy A use the port.
`(argument :name "value")` and `(argument :index 0)` report the same sites and
reach the same result on every example workspace above. The keyword call in
`inconclusive_app.py` is reported as a definite finding through the same
binding.

The ordinal a name resolves to is the callee's, not the call's. Python declares
its receiver, `self`, in the parameter list, and the lowering that mints formal
ordinals consumes it, so formal `value` of `AcmeStore.put(self, value)` is
ordinal 0 and not ordinal 1. The port reads each ordinal off the procedure's own
parameter value rather than off declaration order, which is what keeps
`(argument :name "value")` and `(argument :index 0)` the same claim in a
language that writes its receiver down. Naming the receiver itself is not a
binding at all: `(argument :name "self")` is the same diagnostic as any other
formal the target does not declare as a port.

The resolution is evidence-carrying, not name-shaped:

- A formal name the selected call's exactly resolved target does not declare is
  a diagnostic, not a silent non-match. The run reports `capability_incomplete`
  and exits 2.
- A callee the analyzer cannot resolve exactly degrades the endpoint's proof and
  completeness, exactly as any other unproven binding does, so a run over that
  code cannot be clean. Python's untyped receivers are this case.
- A call site where the name identifies no single actual -- neither a resolved
  formal ordinal nor a written keyword, an open argument group, or two dispatch
  targets that map the formal to different operands -- is a refused row: the run
  names the port and the site and reports `capability_incomplete`.
- Every resolved dispatch candidate has to agree. A call through an interface
  resolves to each implementation, and Java binds an implementation by signature
  rather than by parameter name, so one of them may declare the formal under
  another name. That call is refused too: what one candidate declares is that
  candidate's evidence, not the call's, and neither a confident sibling nor a
  keyword label written at the call site may answer for the set. A candidate
  whose parameter list cannot be read is the same refusal, because an unreadable
  declaration is a shortfall and not a statement that the formal is absent.

Selecting through `call-input` and binding `matched-value` is still not a
substitute: when the actual is itself a call, `call-input` names that inner call
exactly, and the port then binds the inner call's operand instead of the outer
one.

### Reference policy B: a forbidden transitive effect

The invariant: a procedure annotated `@Pure` must not reach the namespaced
effect `acme.network_io`, directly or through a workspace helper.

First the data. One reviewed semantic model declares the effect on one exact
API identity:

```json
{
  "schema_version": 2,
  "pack_id": "acme.http-effects",
  "version": "1.0.0",
  "producer": { "name": "acme-platform", "version": "1.0.0" },
  "language": "java",
  "ecosystem": "maven",
  "compatibility": {
    "bifrost": ">=0.8.0, <1.0.0",
    "toolchains": []
  },
  "provenance": {
    "source": "acme-platform",
    "revision": "reviewed"
  },
  "license": "Apache-2.0",
  "completeness": "complete",
  "safety": { "generated_code_only": false, "review_required": false },
  "shards": [
    {
      "id": "acme.http-effects.client",
      "activation": [{ "configurations": ["acme.http-effects"] }],
      "payload": {
        "kind": "procedure_summaries",
        "summaries": [
          {
            "id": "summary.acme-http-client.send",
            "target": {
              "path": "com/acme/AcmeHttpClient.java",
              "symbol": "com.acme.AcmeHttpClient.send(java.lang.String)",
              "has_receiver": true,
              "parameter_count": 1
            },
            "completeness": "complete",
            "transfers": [
              {
                "input": { "kind": "parameter", "ordinal": 0 },
                "exit_kind": "normal",
                "output": { "kind": "normal_return" }
              }
            ],
            "effects": [],
            "declared_effects": [
              { "id": "acme.network_io", "timing": "immediate", "certainty": "definite" }
            ]
          },
          {
            "id": "summary.acme-http-client.send-later",
            "target": {
              "path": "com/acme/AcmeHttpClient.java",
              "symbol": "com.acme.AcmeHttpClient.sendLater(java.lang.String)",
              "has_receiver": true,
              "parameter_count": 1
            },
            "completeness": "complete",
            "transfers": [
              {
                "input": { "kind": "parameter", "ordinal": 0 },
                "exit_kind": "normal",
                "output": { "kind": "normal_return" }
              }
            ],
            "effects": [],
            "declared_effects": [
              { "id": "acme.network_io", "timing": "deferred", "certainty": "definite" }
            ]
          }
        ]
      }
    }
  ]
}
```

Save it as `.bifrost/semantic-models/acme-http-client.json`. Then the policy:

<!-- policy-doc-test:rqlp:tests/fixtures/policy-substrate-p0/policies/acme-pure-has-no-network-io.rqlp -->
```lisp
; Reference policy B of the issue-2433 P0 epic:
; "a forbidden transitive effect".
;
; A reviewed semantic model declares that the exact API
; `com.acme.AcmeHttpClient.send(java.lang.String)` performs the namespaced
; effect `acme.network_io`. This relational policy asserts that no procedure
; carrying the `@Pure` annotation reaches that effect, directly or through
; workspace helpers.
;
; The marker
; ----------
; `(method :decorators [(name "Pure")])` is the annotation match. The Java
; adapter normalizes `annotation` and `marker_annotation` nodes under a
; declaration's modifiers into the shared `decorators` role, so `@Pure` is
; matched the same way a Python decorator or a C# attribute would be. The
; match is on the annotation's written name, not on a resolved annotation
; type, so an unrelated `@Pure` from another package would also match.
;
; The join
; --------
; `procedure-effects` projects one row per (procedure, effect id), carrying
; `depth`, `classification` (direct or transitive), `certainty`, `timing`,
; `coverage`, and a bounded witness chain. The row is keyed on the
; `declaration` domain's own `procedure_id`, so the join to the marker
; relation is declaration-identity equality.
;
; The absence claim
; -----------------
; `(exactly 0)` is an absence claim, so it is conclusive only when the effect
; relation's coverage is exhaustive. A procedure with an unresolved callee
; leaves the effect set open; the run then publishes an unmet obligation and
; exits 2 rather than reporting a clean verdict.
(policy
  :schema-version 1
  :id "bifrost.p0.acme-pure-has-no-network-io"
  :name "Pure procedures perform no network I/O"
  :message "a procedure annotated @Pure reaches the acme.network_io effect"
  :severity error
  :description "A procedure annotated @Pure must not reach acme.network_io, directly or through a helper. The effect is declared on the exact API AcmeHttpClient.send by a reviewed workspace semantic model."
  :help-uri "https://bifrost.brokk.ai/static-analysis-policies/"
  :tags ["effects" "purity" "java"]
  :analysis (analysis
    :type assertion
    (bind :name pure
      :query (rql :schema-version 1
        (language java (enclosing-decl (method :decorators [(name "Pure")])))))
    (bind :name effect
      :query (rql :schema-version 1
        (language java
          (procedure-effects (enclosing-decl (method :decorators [(name "Pure")]))))))
    (join :left pure :right effect :on ((id procedure_id)))
    (group :name pure-procedure :by (pure.id)
      (aggregate :name network-effects :op count
        :where ((effect.effect_id eq "acme.network_io")
                (effect.derivation eq declared))))
    (assert :group pure-procedure :value network-effects :cardinality (exactly 0))))
```

`(method :decorators [(name "Pure")])` is the annotation match. The Java
adapter normalizes `annotation` and `marker_annotation` nodes under a
declaration's modifiers into the shared `decorators` role, so a Java
annotation, a Python decorator, and a C# attribute are all matched the same
way. The match is on the annotation's *written name*, not on a resolved
annotation type: an unrelated `@Pure` from another package would also match.

`procedure-effects` publishes one row per (procedure, effect id) with `depth`,
`classification`, `certainty`, `timing`, `coverage`, and a bounded witness
chain, keyed on the `declaration` domain's own `procedure_id` and repeating
that declaration's `site_id`. `procedure_id` is the analyzer's opaque
`decl:v1:<hex>` token, byte-identical to the declaration row's `id`; it is not
derived from the displayed kind, name, path, or range. The join is therefore
declaration-identity equality, and the witness's
`witness_effect_site_id` is an id equality against the direct `call_effect`
row, so "show me the exact call this transitive finding came from" is a join
rather than a text search.

The schema-v1 `timing` field preserves the semantic pack's authored
`immediate`, `deferred`, or `unknown` schedule. The additive
`execution_timing` field uses the analyzer's canonical execution labels;
common effect rows report `same_evaluation`, `same_invocation`,
`different_task`, `deferred_callback`, or `unknown`, and the complete finite
domain is published by the query schema. Bifrost composes the modeled schedule
with the exact source call and every transitive call edge before it publishes
`execution_timing`; an unsupported or conflicting composition becomes
`unknown`. In particular, authored `immediate` means "before the modeled call
returns," so it composes as `same_invocation`, not the stronger
`same_evaluation` claim.

Reference policy B uses this workspace layout:

```text
acme-effects/
  .bifrost/semantic-models/acme-http-client.json   the reviewed model above
  policies/acme-pure-has-no-network-io.rqlp        reference policy B
  src/com/acme/Pure.java                           the @Pure marker
  src/com/acme/AcmeHttpClient.java                 the modeled API
  src/com/acme/App.java                            one of the App.java variants
```

```sh
bifrost --root acme-effects --policy-file policies/acme-pure-has-no-network-io.rqlp
```

<details>
<summary>The Java sources for reference policy B</summary>

`src/com/acme/Pure.java`:

```java
package com.acme;

/**
 * The purity marker reference policy B joins on. The policy matches the
 * annotation's written name through the shared `decorators` role, so nothing
 * about this declaration is load-bearing beyond its name.
 */
public @interface Pure {
}
```

`src/com/acme/AcmeHttpClient.java`:

```java
package com.acme;

/**
 * The exact API the workspace semantic model annotates with the namespaced
 * effect `acme.network_io`.
 */
public final class AcmeHttpClient {
    /** Declared with timing `immediate`. */
    public String send(String url) {
        return url;
    }

    /** Declared with timing `deferred`. */
    public String sendLater(String url) {
        return url;
    }
}
```

The violating `src/com/acme/App.java`:

```java
package com.acme;

public final class App {
    /** Direct: depth 1, classification `direct`. A finding. */
    @Pure
    void pureCallsTheApiDirectly(AcmeHttpClient client) {
        client.send("https://example.test");
    }

    /** Transitive: depth 2, classification `transitive`. A finding. */
    @Pure
    void pureCallsTheApiThroughAHelper(AcmeHttpClient client) {
        relay(client);
    }

    static void relay(AcmeHttpClient client) {
        client.send("https://example.test");
    }

    /** The same helper, no marker. The policy joins on the marker, so no finding. */
    void unannotatedCallsTheHelper(AcmeHttpClient client) {
        relay(client);
    }

    /** A marked procedure whose whole reachable call graph is analyzed and clean. */
    @Pure
    void pureCallsAProvenCleanHelper() {
        leaf();
    }

    static void leaf() {
    }
}
```

The clean `src/com/acme/App.java`:

```java
package com.acme;

public final class App {
    /**
     * Every callee below this marked procedure is a workspace procedure with a
     * readable body and no declared effect, so the effect relation's coverage
     * is exhaustive and the absence claim is provable.
     */
    @Pure
    void pureCallsAProvenCleanHelper() {
        leaf();
    }

    static void leaf() {
    }
}
```

The unreliable `src/com/acme/App.java`:

```java
package com.acme;

public final class App {
    /**
     * The gateway is not resolvable in this workspace, so the effect set below
     * this marked procedure is open. The zero-cardinality claim becomes an
     * unmet obligation rather than a clean verdict.
     */
    @Pure
    void pureCallsAnUnresolvedTarget(Object gateway) {
        AcmeUnknownGateway.dispatch(gateway);
    }
}
```

</details>

With the violating `App.java`, the policy reports two findings, the direct
call at depth 1 and the helper call at depth 2, and exits 1. The same helper
without the marker is not reported, and neither is a marked procedure whose
whole reachable call graph is analyzed and clean.

With the clean `App.java`, the run exits 0 with completion `complete`, because
the effect relation's coverage is `exhaustive` and the absence claim is
therefore provable.

With the unreliable `App.java`, the run exits 2 and publishes the blocked
claim as data:

```json
{
  "assertion": "pure-procedure-network-effects",
  "kind": "absence_requires_exhaustive_coverage",
  "group": "pure-procedure",
  "group_key": "decl:v1:59e27161404b54b1d60f747be5e1020fcb8082f51266f172c2797fa2432ca5b7",
  "reasons": ["capability_incomplete"]
}
```

The human report counts the blocked verdicts in its scan view and names each
one in its audit view. SARIF publishes the census on the run-level
`BIFROST_POLICY_INCONCLUSIVE` notification and mints no result, because an
obligation is the absence of a claim and not a claim about a source location.

An obligation that a solver-backed relation blocked also names the analysis
partition it is about. A flow, taint, typestate or type-flow row carries what
its own solve proved about the partition that solve enumerated -- the value-flow
plan, the typestate protocol, the taint sink, or the member-access class set --
so a query that returned every row it has can still leave a partition
unenumerated. The relation's coverage is the meet of the executed query's
envelope and every row's own coverage, and the blocked verdict reports which
partitions made it weaker:

```json
{
  "assertion": "no-tainted-sink",
  "kind": "absence_requires_exhaustive_coverage",
  "group": "by-sink",
  "partitions": [{ "family": "flow_endpoint", "root": "value-flow:1" }],
  "reasons": ["partial_discovery"]
}
```

`partitions` is absent when the blocked claim is about the executed query's own
scope rather than one solver root, and `partitions_truncated` is `true` when the
bounded list dropped a name. A positive verdict never depends on this: a count
above an upper bound publishes from an unfinished solve, because rows nobody
read could only raise it.

### Activating the model

A semantic model reaches the analyzer through one of two routes. Both routes
feed one activation, so a workspace can use either or both:

| Route | Location | Opt-in | Activated by |
| --- | --- | --- | --- |
| Reviewed workspace models | `.bifrost/semantic-models/*.json`, `*.yaml`, and `*.yml` | the directory exists | CLI policy runs without `--sources` (`--policy`, `--policy-file`, and `bifrost scan`); `SearchToolsService` sessions only with `BIFROST_WORKSPACE_SEMANTIC_MODELS=on` |
| Installed catalog | the catalog `.bifrost/packs.json` names | the document configures ecosystems; an absent document uses the ambient default | CLI policy runs and every `SearchToolsService` session: the MCP server, one-shot `--tool` and `--query-file` runs, a policy run with `--sources`, and the Rust and Python libraries |

Use the reviewed workspace route for a model you write and check in beside your
policies. Put the file in `.bifrost/semantic-models/`, commit it, and a CLI
policy run activates it. You need no packs document and no catalog
install. Reference policy B runs this way.

Use the installed catalog for a pack that ships with a dependency. The shared
packs document names the catalog and dependency ecosystems. An absent
document uses the default catalog and the ecosystems that serve the languages
in the workspace. The default catalog is in the Bifrost cache directory, or in
memory when the analyzer keeps no persisted cache. The
[semantic pack reference](/reference/semantic-packs/) gives the exact rule. An empty `ecosystems` array explicitly disables that route.
Activation evidence comes from dependency discovery and remains subject to
compatibility and review gates.

Three rules keep the reviewed route honest.

- **A model that cannot be read fails the run.** If discovery cannot finish, or
  a file will not compile or register, the report carries a
  `workspace-model-load-failed` diagnostic and the run exits 2. A checked-in
  model is never skipped in silence, because a missing model changes verdicts.
- **The review gate is not bypassed.** A model with
  `safety.review_required: true` stays inert until an `enable` entry in
  `.bifrost/packs.json` names its pack id. While it is inert, the report
  carries a `workspace-model-inert` warning that names the pack id and the
  remedy. The warning does not by itself make the run unreliable: the
  evaluation that ran without the model reports its own incompleteness when it
  has any.
- **A diff run activates both sides.** The base revision activates the reviewed
  models its own tree checked in, so adding or removing a model shows up as
  changed findings rather than as noise.

Workspace sources outrank installed and shipped sources when both offer a
model for the same key. The activation provenance names the workspace source,
and the report's `packs` review lists every activation decision.

### Explaining a finding and a near miss

`explain_finding` says why a retained finding exists, by projecting the
evidence the run already kept; it executes nothing, so it cannot disagree with
the report it reads. `explain_candidate` says why one explicit candidate
position was not reported, by re-executing bounded prefixes of the selector
plan. `rank_near_misses` says which subjects came closest, by relaxing the
policy's own declared predicates over a bounded candidate set.

Over reference policy A's own flow run, `explain_finding` answers about the
`store.put` finding directly. The root sits on the observation the tracked
value reached; under it are the origin the value entered at, the retained
witness path as one `derivation` node per step in path order with each step's
exact site, and the finding's certainty, proof, witness retention,
completeness, and the run's completion. Each of those last five is `satisfied`
when the retained evidence licenses the claim and `unknown` when it does not —
never `failed`. A finding whose witness was truncated, or which retained no
witness at all, says so in that node rather than presenting a short path as a
whole one. Taint findings explain the same way in the security vocabulary,
naming each origin's label and source scenario.

Over the exact-selection view of reference policy A — the same selector as a
`match` policy — the `store.put` call explains as `satisfied`, and the
near-miss `cache.put` candidate explains as `failed`, which means the analyzer
finished, declared its result exhaustive, and the candidate was still not
there. That is different from `unknown`, which means the analyzer never
established the answer. A consumer may act on `failed`; a consumer must not
read `unknown` as evidence of absence.

`explain_finding` serves every family a run can produce: `match`, `assertion`,
`flow`, `taint`, and `typestate`. A relational assertion finding explains its
assertion, group key, contributing rows, and any coverage obligations; when
those rows are `procedure_effect` rows it also publishes one `effect_derivation`
node per declared-effect chain, naming the reviewed declaration, the call chain
that reached it, and the timing that classification was composed under. A
typestate finding explains its protocol subject, the violating transition or
unmet terminal expectation stated as expected beside observed, and the same
bounded witness paths a flow finding publishes. `explain_candidate` serves
`match` and `assertion` policies, and a relational candidate reports the first
complete binding query it is absent from. Row-local RQL filters and projections
execute as part of that binding query and are not a second policy-level replay
stage. Joins, group keys, and aggregates are still not replayed, so a candidate
that survives every binding is `unknown`, never `satisfied`. `typestate`
`why-not` is refused with an explicit adapter-unavailable answer that names the
supported analysis types.

### Explaining a flow or taint candidate

A flow or taint finding is a value that enters at one site and is observed at
another, so its `why-not` candidate is a pair: the **source** position (a flow
origin or a taint source) and the **observation** position (a flow observation
or a taint sink). `explain_flow_candidate` takes the pair, and each position
resolves, under the same containment rule a `match` candidate uses, to the
innermost site that a compiled endpoint of that role binds. A single position
is refused for these families, and a source position is refused for `match`
and `assertion`, so a question is never silently answered about a different
value.

Nothing the run retained answers this question, so the explanation runs the
production pipeline itself: the ordinary taint compiler, then the ordinary
solver over only the analysis regions that bind both sites, under the one
workspace generation and semantic-model snapshot pinned for the question. The
tree has one stage per step, in order:

| Stage | `satisfied` | `failed` |
| --- | --- | --- |
| `origin_endpoint` / `source_endpoint` | an endpoint binds the source position | no endpoint binds it, and every endpoint selector finished |
| `observation_endpoint` / `sink_endpoint` | an endpoint binds the observation position | no endpoint binds it, and every endpoint selector finished |
| `analysis_region` | a compiled region binds both sites | no region binds both, and no region was skipped or refused |
| `propagation` | the solver reaches the observation, and the policy reports the finding | the candidate regions solved to a fixed point with complete coverage, and no path reaches the observation |
| `kill_attribution` / `sanitizer_attribution` | with the policy's kills removed, the same route reaches the observation, and every retained path passes a declared kill | with the kills removed, the observation is still unreached |

A reached candidate names the finding an ordinary run reports, with the same
identity, retained witnesses, certainty, proof, and completeness. Over
reference policy A's clean tree, the helper-validated value explains as
`failed` at `propagation`, and `kill_attribution` names `acme-validate` at the
exact `AcmeValidator.validate(value)` call inside the helper, with the
counterfactual path that passes it. The kill is matched to that path by
program-point identity, not by location text. The near-miss `cache.put` call
fails at `observation_endpoint`.

Every analysis limit is `unknown`, never `failed`, and is published as a
`boundary:<kind>` child that carries the run's own incomplete reasons:

| Boundary | Meaning |
| --- | --- |
| `unresolved_call` | a call has neither a completely resolved target nor an applicable complete model: unknown dispatch, or a missing model |
| `model_unavailable` | an activated model could not be compiled for the policy, for example two packs that summarize one procedure differently |
| `unsupported_flow` | the policy declares semantics this route does not replay; persistence-store crossings are seeded across every region, so a store-declaring policy is answered this way |
| `cancelled` | the question was cancelled |
| `analysis_budget`, `output_budget`, `region_budget` | a solver, retention, or region-discovery budget ran out |
| `discovery_incomplete`, `refused_site` | an endpoint selector did not finish, or a selector row bound no single site |
| `call_binding`, `semantic_gap`, `endpoint_evidence`, `open_coverage`, `semantic_unavailable`, `invalid_plan` | the remaining typed causes the solver and compiler already report |

Each answer is bounded. At most two production passes run, each under the
policy's own budget: the authored policy, and, for a negative whose regions
bind kills, the policy with its kills removed. `max_prefix_executions` caps the
passes; a limit of one leaves the attribution `unknown`. Ordinary evaluation
never runs either pass and retains nothing for them.

### Pinning the workspace an answer is about

A `why` answer re-evaluates the policy and a `why-not` answer re-executes
bounded prefixes, both against whatever the analyzer holds now — while the
finding identity or candidate position you are asking about came from a report
produced over one exact workspace. Every answer therefore states the
`workspace_generation` it was produced under: the analyzer's own content
identity over the analyzed file set, each language's analysis epoch, and the
analyzer configuration. It carries no absolute path and no process-local
counter, so it survives a process boundary and compares equal across two
byte-equal checkouts.

Read that value once, then pass it back — `--explain-generation <HEX>` on the
CLI, `workspace_generation` on the MCP tool — and a request that arrives after
the workspace moved is refused with a stated mismatch instead of being answered
about a different run. Omitting it keeps the previous behaviour: the answer is
about whatever the analyzer currently holds.

For MCP, the JSON-RPC error data has `kind: "stale_workspace_generation"`,
`requested`, `current`, and `retryable: true`. Read a current generation before
retrying; resending the obsolete pin cannot make it current.

### Ranking the near misses

`explain_candidate` answers about a position you already suspect. When you are
refining a rule you usually want the opposite question: which subjects nearly
matched, and which predicate stopped each one. That is the bounded near-miss
ranking, published as its own versioned document,
`bifrost_policy_near_miss/v1`, rather than as a node kind inside
`bifrost_policy_explanation/v2` — an explanation is a tree about one subject,
and a ranking is an ordered list over many.

The distance is the policy's own declared predicates and nothing else. A
selector's seed carries a **scope** — its kind union, language filter, and path
globs — and a set of **predicates**: the root's name, text, arity, visibility,
parameter type, and role sub-patterns, plus the `inside`, `inside_decl`, and
`not_inside` containment. The ranking runs a ladder of selectors: the scope
alone, then the scope with one declared predicate restored, and so on up to the
selector you wrote. Every rung runs the whole pipeline, so its rows are
subjects in the policy's own final domain. A subject's distance is how many
conjuncts remain from the first rung that stopped returning it, and that rung's
predicate is named as its `failing_conjunct`. Nothing else contributes: no
embedding, no model score, no text similarity, no proximity.

Containment is restored last on purpose, and that ordering is what makes the
answer useful. Over the exact-selection view of reference policy A the ladder
is `scope`, `root.name`, `inside_decl`. The `store.put` call clears all three
and ranks first at distance 0. The near-miss `cache.put` call satisfies the
member name and fails only the class it is declared inside, so it ranks second
at distance 1 with `inside_decl` named. The unrelated `AcmeSource.read()` call
in the same file fails the member name too and ranks third at distance 2 with
`root.name` named.

Candidates are never scanned for by default. You either supply the list of
positions to measure, or you ask for a separately budgeted search whose scope
is the policy's own seed. A policy whose seed declares no kind union has no
bounded scope at all — relaxing its name would leave a wildcard over every node
in the workspace — so it is refused rather than searched. A supplied position
that the scope excludes reports `scope` as its failing conjunct instead of
being dropped without comment.

`failed` and `unknown` mean here exactly what they mean everywhere else in the
schema, and `unknown` is never distance. A subject is `failed` only when the
rung that dropped it completed and declared itself exhaustive; otherwise it is
`unknown` and carries the incomplete reasons. A ladder the execution budget cut
short leaves every subject still standing `unknown`, never `satisfied`.
Undecided subjects report the conjunct count they were observed to reach, the
same as decided ones, and the ranking breaks ties by decidedness, so
incompleteness never moves a subject further away than the evidence puts it.

A ranking serves `match` and `assertion` policies, because it relaxes a
selector plan and a flow, taint, or typestate policy has none. `why-not` over a
flow or taint policy runs the solver instead, as described above. Reference policy A is itself a flow
policy, which is why the ranking above is asked about its equivalent `match`
view. For a relational policy the candidates come from the first row binding's
source query and each further binding is one membership conjunct; a subject
that clears every binding is `unknown`, not `satisfied`, because the joins,
group keys, and aggregates still stand between a row and a violation and none
of them is replayed.

### Reaching the explanations without library code

The MCP tool `explain_policy` takes one policy selection plus exactly one of
`finding_id`, `candidate`, or `near_misses`, and returns the structured
document. The CLI accepts `--explain-finding <ID>`, `--explain-candidate
<PATH:BYTE_START[-BYTE_END]>`, or `--explain-near-misses <N>` beside
`--policy-file` or a built-in selector that names one policy, and prints the
same JSON. For a flow or taint policy the candidate is the observation
position, and the source position is `candidate_source` on MCP and
`--explain-candidate-source <PATH:BYTE_START[-BYTE_END]>` on the CLI. The
library, the CLI, and MCP return the same outcome, subject, and node tree, node
identifiers included, for the same question. All three exit 0 whenever an answer
was produced, whatever its outcome and even when a ranking is empty, and 2 only
when none could be. Both surfaces also accept the optional workspace-generation
pin described above, on any of the three questions.

The CLI always searches the policy's own seed scope. `--explain-near-misses N`
retains N subjects, from 1 to 64, and uses the default execution budget for the
ladder. MCP `explain_policy` `near_misses` takes exactly one of `candidates`,
an explicit list of positions, or `enumerate_from_policy_seed`, the same seed
search the CLI uses. It also accepts `max_candidates`, the number of subjects
to retain, and `max_executions`, the number of bounded queries the ranking may
run.
What a bound removed is reported in the document's truncation record in the
same `*_truncated` plus `omitted_*_lower_bound` form the explanation schema
uses, so a caller can raise the right one.

A `why` question through either surface evaluates the policy once to obtain the
run its finding came from. That evaluation does not activate semantic-model
packs, because activation belongs to the host that owns the analyzer's
lifecycle. A finding that exists only because an activated pack modeled a call
is therefore reported as "the run retains no finding with identity …" rather
than explained from a differently-modeled run.

### P0 capability boundaries

| Capability | Today | Boundary |
| --- | --- | --- |
| Exact call selection | `call-sites-to :proof proven` over an `inside-decl` seed | Java, Python, and TypeScript all answer. Python and TypeScript prove the row whenever the receiver's type is evident at the call — annotated, constructed in the same procedure, or `self`/`this` — and return nothing rather than a guess when it is not. A clean *flow* verdict additionally needs the target's dispatch closed: `final` on Java, `@final` on Python, and a `private constructor` on TypeScript, the language's own statement that the class cannot be extended |
| Actual-to-formal binding | `call-input :parameter-name` binds positional and named syntax exactly, and `(argument :name "...")` is a value-flow port for flow and taint endpoints, which both editions of reference policy A bind through | The port needs the callee's parameter list, so an unresolved callee degrades the endpoint rather than binding; a formal the resolved target does not declare is a diagnostic, and a declared receiver such as Python's `self` is not a formal; and every resolved dispatch candidate must agree that the name reaches this operand, so a call through an interface whose implementations name the formal differently is refused |
| Declared effects | `declared_effects` on a procedure summary, propagated with depth, certainty, timing, and coverage | Path-conditional effects are a P0 non-goal; effect timing is the pack's declaration, not an inference about scheduling syntax |
| Annotation markers | The normalized `decorators` role | Matches the written annotation name, not a resolved annotation type |
| Negative claims | Absence requires exhaustive coverage; an unmet obligation is structured data on the run | An open effect set or an unresolved callee is exit 2, never exit 0 |
| Explanations | `explain_finding` over `match`, `assertion`, `flow`, `taint`, and `typestate` findings, `explain_candidate` over `match` and `assertion` policies, and `explain_flow_candidate` over `flow` and `taint` source and observation pairs, plus the MCP `explain_policy` tool and the CLI `--explain-finding`/`--explain-candidate`/`--explain-candidate-source` flags, each accepting an optional workspace-generation pin | A `why` answer projects retained evidence only, so it is exactly as complete as the report; an effect chain names the reviewed declaration, the retained call chain, and the timing, and publishes no hop the effect relation did not retain; a flow or taint `why-not` solves only the regions that bind both sites, is `failed` only over complete coverage, and refuses store-declaring policies with a typed `unsupported_flow` boundary; `typestate` `why-not` is refused rather than answered; a relational `why-not` replays each complete RQL binding query as one membership decision and reports the plan's joins, group keys, and aggregates as unreplayed |
| Near-miss ranking | `rank_near_misses` over `match` and `assertion` policies, published as `bifrost_policy_near_miss/v1`, plus the MCP `explain_policy` `near_misses` form and the CLI `--explain-near-misses N` flag | Distance is the count of unsatisfied declared predicates and nothing else; candidates are the caller's list or the policy's own seed scope, never a repository scan, and a seed with no kind union is refused; a relational subject that clears every row binding is `unknown`, because the joins, group keys, and aggregates are not replayed |
| Model activation | Two routes, above; the CLI policy runner activates both | A `review_required` workspace model stays inert without an `enable` entry, reported as a warning |

## Completeness, Findings, And Report Parity

A policy run is not just a list of findings:

- `complete` with zero findings is a clean result only for the analyzer,
  workspace, selector, and budgets used by that invocation. The policy report
  does not currently record the analyzer version, workspace root/revision, or
  configured budget maxima; preserve those separately as described in
  [Reproduce an Analysis](/reproduce-analysis/).
- `proven_subset` means every retained finding is proven, but the run
  searched only part of the program. Its findings gate normally. With zero
  gated findings the run exits 2, because a subset cannot prove absence. The
  completion carries the `codes` that limited the search.
- `proven_by_summary` means the result is precise, but it rests on authored
  external procedure summaries rather than on analyzed code. It can exit 0 or
  1. A clean result holds only as far as those summaries are correct.
- `inconclusive` (including cancellation or budget reasons), `unsupported`, or
  `failed` is non-clean even when zero findings were retained. Existing positive
  findings remain useful bounded evidence, but the run cannot support a complete
  negative claim.
- `not_run` means a selected policy lacked a required capability and made no
  absence claim. Pack, category, and default selections do not affect the exit
  status; an explicitly named policy ID exits 2.
- Query diagnostics carry typed impact. Capability or work omissions propagate
  into policy completion instead of being flattened into an empty match set.

Only `complete` is exhaustive. The [policy reference](/reference/policies/)
lists every completion state with its reasons, its exit effect, and its SARIF
notification ID.

### Declare What An Unknown Result Does

A policy declares how the gate should treat a verdict its evidence could not
reach:

```lisp
(analysis :type taint
  :on-unknown (on-unknown :verdict abstain|warn-unreliable|fail-closed|treat-may-as-finding)
  ...)
```

| Verdict | Findings and completion | Exit status |
| --- | --- | --- |
| `abstain` (default) | Retained; the run stays `inconclusive` with its typed reasons | `--on-inconclusive` decides: by default (`pass`) the findings alone; under `unreliable`, unreliable (2) |
| `warn-unreliable` | Retained unchanged; the run also carries `unknown_verdict` in its report JSON | Whatever the findings alone produce |
| `fail-closed` | Retained unchanged, plus an `unknown_verdict_fail_closed` diagnostic naming the reasons | As if a finding at the policy's severity were present |
| `treat-may-as-finding` | Explicit assertion may evidence is published as possible; coverage obligations remain inconclusive | As `abstain` if inconclusive; otherwise the findings determine the exit |

`treat-may-as-finding` publishes explicit may evidence from assertion rows as
findings with `certainty: possible`, retaining the reasons. Flow and taint
already publish possible findings under every verdict; this spelling does not
change their publication or hide findings under the other verdicts. Unsupported
relations, budget-truncated aggregates, and unmet absence obligations do not
become possible findings. Unmet coverage obligations still make the run
`inconclusive`, so under `--on-inconclusive unreliable` its exit status is
unreliable (2) even when findings are present.
Human and JSON output retain possible certainty and reasons; SARIF marks possible
findings as `review` results and retains `bifrost.certainty`.

Omitting the record is exactly `abstain`, so a policy written before this
vocabulary existed behaves identically and keeps its canonical semantic hash.
`warn-unreliable` and `fail-closed` apply only to an `inconclusive` run: an
`unsupported` or `failed` run is an engine outcome, not a policy verdict, and
still exits unreliable whatever the policy declared.

Every finding is built from one canonical typed model. Human, canonical JSON,
and SARIF 2.1.0 therefore retain the same rule and semantic hashes, finding ID,
location, severity, certainty, completion, endpoint/combination or terminal
identity, classifications, evidence, witnesses, and CVSS variants.

Strong finding IDs use semantic/source anchors and occurrence ordinals—not line
numbers or absolute native paths—so unrelated preceding-line changes do not
churn them unless they introduce an equal earlier anchor and therefore change
the ordinal. A weak ID is labeled inconclusive and is deliberately omitted
from SARIF `partialFingerprints`; it is not promoted into a fake stable
fingerprint.

## Review Findings With Exact Suppressions

Keep project-owned analysis inputs together and keep generated cache data
separate:

```text
.bifrost/
├── queries/                    # saved exploratory .rql
├── policies/                   # recurring .rqlp roots
├── suppressions.json           # exact review decisions
├── suppressions.private.json   # decisions on files this repository does not publish
├── suppressions.local.json     # one developer's decisions; not committed
├── policy-scope.json           # directory-level review decisions
├── baseline.json               # bulk-accepted findings from --accept-current
└── cache/                      # generated; safe to ignore
```

Bifrost reads all three suppression files, in that order, and merges them into
one record set. Each is optional: a repository that publishes everything needs
no private file, and the local file is absent on most machines. All three use
the identical schema below, so a record can be moved between them unchanged.

The split exists so every record can name the file its finding was reported
against. A repository that publishes a subset of its source publishes
`suppressions.json` with it, and a decision about an unpublished file would
otherwise have to omit that name -- leaving the record unreadable -- or
disclose it. `suppressions.private.json` holds those decisions instead. Add
`.bifrost/suppressions.local.json` to `.gitignore`; it is for decisions you are
still working out, and it is never published or shared.

Two files must not both claim the same finding. Bifrost rejects the run rather
than choosing a winner: a disagreement about one finding is a mistake in the
records, not an ordering question. Each source's state is reported separately,
so an absent local file is visibly absent rather than silently ignored.

`--suppressions-file PATH` replaces the whole convention with one named file,
including the private and local ones.

Version 1 contains accepted review decisions for exact strong findings:

```json
{
  "schema_version": 1,
  "suppressions": [
    {
      "policy_id": "bifrost.security.dynamic-eval",
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

`policy_id` and `finding_id` are the complete join key. Bifrost applies a
record only to a current finding whose identity is strong and exactly equal.
It never falls back to paths, lines, globs, regular expressions, messages,
similar code, or weak identities. Unrelated line insertions and policy
presentation changes can preserve the ID. Editing the selected source bytes,
moving the file, changing its semantic owner, or changing the duplicate
occurrence ordinal produces a different ID and leaves the old decision for
review.

`path` is optional and is never part of the join key. It records the
workspace-relative file the decision was made against, which is what lets a
run tell a record whose identity changed under an edit from a record whose
file that run does not contain at all. Record it: without it a decision that
silently stopped matching is indistinguishable from one this run cannot see,
and the run cannot gate on either. It follows the same portable path rules as
a scope entry -- forward slashes, no absolute paths, no `.` or `..`
components.

Recording it also makes the record readable. A finding identity is a hash and
cannot be reversed, so a record carrying only an identity can be traced back to
its code only by re-running the policy and matching the hash -- and once the
identity has rotated, not at all. The path is what keeps a decision auditable
after the code around it moves.

Use an explicit date for a reproducible accept-and-rerun cycle:

```bash
bifrost --root . \
  --policy-file .bifrost/policies/dynamic-eval.rqlp \
  --evaluation-date 2026-07-27 \
  --format json \
  --fail-on warning
```

Copy the reported strong finding ID, policy ID, and optional policy hash into
the suppression file, record a bounded reason and acceptance date, then run
the same command again. The second canonical report still contains the
finding and one suppression review, but an applied decision does not meet the
failure threshold. SARIF retains the result, its `bifrostFinding/v1`
fingerprint, and a standard external accepted suppression. Concise human
output hides the result from the active-finding list while counting it;
`--verbose` prints the reason and provenance.

The audit keeps independent states instead of collapsing review outcomes:

- A current exact strong match is `applied`. A changed `policy_hash` is also
  marked `drifted`, but hash drift alone does not reactivate the same finding.
- A record is `expired` only when the evaluation date is later than
  `expires_at`; it remains active on the expiration date itself.
- An unmatched record reports `finding_absent` only when the selected policy
  completed and proved that the finding is absent.
- An unselected, incomplete, failed, unsupported, or inconclusive policy
  cannot prove absence. A current weak finding also cannot prove the strong
  match required for suppression.
- A retention-limit failure is explicit as `result_omitted` and makes the
  report unreliable rather than claiming a clean result.

`finding_absent` alone does not say whether a decision went dead. A record
naming a file the run never analyzed reports `finding_absent` in every run
forever, and a document copied to a tree that does not contain every file it
names is full of those. The separate `orphan_state` answers the question the
gate needs:

- `orphaned`: the run analyzed the record's file and no finding carries its
  identity. The accepted decision no longer resolves to anything, either
  because an edit changed the identity or because the finding is genuinely
  gone. **This makes the run exit 1, even with `--fail-on never`.** A finding
  that was reviewed and accepted must
  not quietly return to the gate as new code, and a decision that covers
  nothing must not sit in the document unnoticed. Repair it by re-keying the
  record to the current identity or by deleting it; the review lists the
  policy's unclaimed identities in that same file as `rekey_candidates`.
- `path_not_analyzed`: the run did not analyze the record's file, or root
  exclusions removed possible calling contexts for that policy, so it says
  nothing about the record and never fails the run.
- `path_unrecorded`: the record names no `path`, so the two cases above
  cannot be told apart. It never fails the run. Adding `path` to the record
  is what makes it decidable.
- `resolved`: the record matched, or the policy did not run exhaustively.

A missing conventional or explicit suppression file means no suppressions.
Malformed, unsafe, oversized, escaping, duplicate, or conflicting input
produces a `suppression-load-failed` report diagnostic, applies none of that
document, and exits with status 2. Each file holds at most 512 records and
256 KiB; the [policy reference](/reference/policies/) lists every field, limit,
and review state. Use `--suppressions-file PATH` for one workspace-relative
override.
The CLI uses today's UTC date if `--evaluation-date` is omitted. MCP
`run_policy` requires `evaluation_date`, and library callers pass the date
explicitly.

## Scope Directories Out Of The Gate

An exact suppression accepts one finding of one rule version. Some
acceptances are instead standing statements about a directory: a checked-in
fixture corpus intentionally contains the code smells its tests assert, or a
test tree is not performance-sensitive, so performance review prompts there
are noise. Recording those per finding means every new fixture or test
re-dirties the gate. The conventional scope file `.bifrost/policy-scope.json`
records the directory-level decision once:

```json
{
  "schema_version": 1,
  "scopes": [
    {
      "path": "tests/fixtures",
      "reason": "Intentional smell corpus used as policy test fixtures.",
      "exclude_roots": true
    },
    {
      "path": "tests",
      "reason": "Test code is not performance-sensitive.",
      "policy_categories": ["performance"]
    }
  ]
}
```

Each entry names one workspace-relative directory with a mandatory reason.
`path` follows the portable path rules: forward slashes, no absolute paths,
no `.` or `..` components. Finding acceptance uses a component-wise directory
prefix on the finding's primary location, so `tests` covers `tests/app.py`
but never `tests_extra/app.py`. Entries have no expiry: a directory scope
describes what the directory is, not one review cycle.

Root exclusion is explicit and opt-in with `exclude_roots: true`. That flag
changes only policy-analysis starting roots; it does not change finding
acceptance. Omitting it (the default `false`) preserves the original scope
contract: every policy-analysis root remains eligible, while findings anchored
under the entry are accepted.

An entry without selectors applies to every policy. `policy_ids` and
`policy_categories` restrict it, as a union: the entry applies to a policy
whose stable id is listed or whose catalog category is listed. Categories
come from catalog pack policies, so an entry that should also cover a
repository `.rqlp` policy must list its id or omit selectors entirely. Two
entries may share a path when their selectors differ.

With `exclude_roots: true`, a matching entry has two distinct effects. First,
it excludes a matching file as a policy-analysis starting root. The rest of
the dependency workspace remains visible, so a retained root can still reach
code under a scoped directory. Second, after evaluation and suppressions, a
resulting finding whose primary anchor matches the entry is accepted. These
are root and finding contracts, not interchangeable labels: an anchor inside a
scope does not prove that every excluded calling context that can reach it was
analyzed.

A scoped finding stays in the canonical report with an attached `scope`
decision (path and reason) and stops counting toward the failure threshold,
exactly like a suppressed finding; a finding that already carries a
suppression is not claimed by scope. The report's top-level `scope` array
audits every entry, its `exclude_roots` coverage choice, its matched-finding
count, and its `excluded_root_files` count. The latter counts policy/file
exclusion pairs before policy language and query filters are applied; when
overlapping policies exclude the same file, each pair counts. It is not a
count of procedures or of files the policy would actually query. The human
summary sums entry/policy/file matches, so overlapping entries count separately. An entry is
applied when it did either kind of work, so an entry with no matched finding
but at least one excluded root remains visible rather than being reported as
dead. Concise human output hides scoped findings from the active list while
counting them in the summary.

Explicit root exclusion supports Match and Assertion policies whose file-backed
seed sources honor scope. Taint, flow, and typestate policies, and
configuration-fact seed sources, fail explicitly rather than silently
discarding roots; the run remains unreliable and no unscoped fallback is
presented as applied. Scoped executions bypass unit and subject-query caches
because those cache whole-workspace identities; whole-base identities that are
already scope-keyed remain reusable. An unsupported family or query source must
not publish root-exclusion work: its scope-review excluded-root count stays
zero, and the run remains explicitly unreliable. For a diff base, the head's
normalized scope is applied to both revisions.

This is deliberately not `.bifrostignore` for navigation, search, and usages:
the dependency workspace remains visible in those surfaces. For policy
evaluation, an opted-in scoped file is no longer used as an analysis starting
root.

A missing scope file means no scoping. A malformed one produces a
`scope-load-failed` report diagnostic, applies none of that document, and
exits with status 2, so a broken scope file can never silently accept
findings. A scope file holds at most 256 entries and 256 KiB, and each entry
lists at most 64 policy IDs and 64 categories. Use `--scope-file PATH` on the CLI or `scope_file` on the MCP
`run_policy` tool for one workspace-relative override; both default to
`.bifrost/policy-scope.json`.

## Gate Only On What The Change Introduced

A full policy run fails a repository for every finding, including debt that
predates the change under review. `--diff-base REV` turns the same run into a
changed-code gate: the identical policies also evaluate the committed content
of `REV`, findings are joined across the two revisions by `(policy_id,
finding_id)`, and the failure threshold counts only the findings whose
identity is absent from the base.

```bash
bifrost --root . \
  --policy-pack bifrost.code-smells \
  --format sarif --output out.sarif \
  --diff-base origin/main
```

The join works because a strong finding identity hashes only content-derived
facts: the workspace-relative path, either the analyzer `DeclarationId` or a
typed non-declaration semantic owner key, a digest of the matched source
bytes, and a small ordinal for identical slices under one owner.
Declaration-backed owners serialize `id` without a `derivation`; canonical
AST and semantic-wire owners serialize `derivation` plus `semantic_key`. The
identity contains no absolute path, revision, timestamp, or run-local
handle, so the same finding in unchanged content produces the same identity
at both revisions. The base revision is exported into a private temporary
directory and analyzed there; the checkout is never touched.

Each retained finding gains a `diff` decision (`new` or `persisting`, plus a
`weak_identity` marker), and the report gains one top-level `diff` review
with the requested revision, the resolved commit, the three counts, and the
fixed identities the head no longer produces. Weak identities are
snapshot-local by construction, so a weak finding never joins and always
classifies as new. Suppressions and scope still apply first: a suppressed or
scoped new finding does not gate, exactly as in a full run. SARIF results
carry the standard `baselineState` field (`new` or `unchanged`; fixed base
findings are not emitted as results), and concise human output hides
persisting findings while the summary reports all three counts.

The reliability contract is asymmetric on purpose. An unresolvable base -- a
workspace outside a git repository, or a revision `git rev-parse` cannot
resolve -- fails the run with status 2: an unresolvable base is an unreliable
diff request, never a silent full run. A base that resolves but whose
evaluation cannot prove its own completeness instead degrades to full gating:
every head finding gates as if `--diff-base` had not been given, the review
records `degraded: true`, and a `diff-base-unreliable` report diagnostic
states why, so a broken base can never hide new findings and can never be
mistaken for a clean diff run. That diagnostic, and the per-policy
`diff-base-policy-unqualified` diagnostic, have severity `error`, so such a run
exits 2 even though it still reports every head finding.

Two identity limitations are accepted rather than solved. A pure file rename
re-keys every finding in the file (the path is part of the identity), so a
rename reports one `fixed` plus one `new` pair. Identical source slices under
one owner are distinguished by an ordinal, so inserting an exact duplicate
above an existing one can shift the ordinals and misclassify one pair.

A typestate finding's identity follows the same rule as every other family: it
hashes only what the finding itself is. That is the policy id, the compiled
protocol, the tracked object's semantic identity, the violating site's
semantic identity, the solver root's semantic identity, and the violated event
or terminal expectation together with its observed and expected states. Two
violations under one root stay two findings because they differ in at least
one of those: the site, the expectation or event, the observed state, or the
tracked object. The policy's compiled binding plan -- a digest of every
declaration the policy binds anywhere in the workspace -- is not part of the
identity, so an edit that adds a tracked object in one file leaves every other
finding's identity where it was. Editing the policy document's automaton does
re-key the findings that policy reports, because a different protocol is a
different rule.

A tracked object's semantic identity names each declaration it was acquired
through -- the file, the type, the enclosing function -- by that declaration's
kind, name and ordinal among its same-kind siblings, never by a byte span of
the file or the type that contains it. An edit somewhere else in a file that
declares an acquisition callee therefore leaves the identity where it was.

The one byte span such an identity does carry is the span of the procedure or
call site the locator itself names, and it is measured from the start of the
declaration that contains it rather than from the start of the file. An edit
that makes a declaration longer moves every byte below it in that file, so a
file-relative span would re-key every locator under the edit; a span measured
from its own declaration does not move at all unless that declaration's own
text changes. A locator that names a class-level member from inside a method
is the exception, because the member is a sibling of the method rather than a
part of it; such a span is marked as such and stays file-relative.

What still re-keys a finding is an edit to the violating site's own source
slice, to the text of the declaration a locator sits in above that locator, or
to the declaration path any of these locators names.

### What a second run reuses

The base revision is exported and analyzed through the repository's shared
analyzer cache, the same cache every other Bifrost run reads and writes. Each
policy's result over the base is stored per evaluation unit -- a seed file, a
subject file, a row binding, or a solver root -- together with what that unit
read. A later run against the same base reuses the recorded base findings
without exporting or building the base again. It evaluates the working tree by
recomputing only the units whose recorded inputs changed. Every other unit is
reused after the run verifies that its recorded inputs still hold in the
working tree.

When a unit cannot be bounded, the policy that owns it is evaluated in full and
the report says why. Nothing is skipped silently. The report is identical to a
full evaluation except for the run's own measurements: the `work` counters and
the `incremental` section. Pass `--no-incremental` to force the full dual
evaluation, which is how to compare the two when you diagnose a difference.

A changed line is an input to this analysis, never a filter on where a finding
may appear. A unit is recomputed because something it read moved: a caller, an
import, a declaration a name resolves to, a semantic model, the policy text, or
the analyzer configuration. Its finding can therefore appear in a file the pull
request did not touch, and the gate counts it like any other new finding.

Every entry point evaluates policies the same way and shares one store. The
CLI, the GitHub action, an MCP session's `run_policy`, and an ordinary scan
without `--diff-base` all analyze the workspace under the same policy analyzer
configuration and activate the same semantic models: the shipped models, the
repository's reviewed models under `.bifrost/semantic-models/`, and the packs
its `.bifrost/packs.json` names. An MCP session builds this policy workspace
over its own files for each `run_policy` call instead of evaluating on the
analyzer that serves its other tools, so its policy findings match the CLI's.
Units are published to the repository's analyzer cache under keys that every
entry point computes identically, so a unit one entry point publishes is a unit
another can reuse. An ordinary scan reuses the units whose recorded inputs it
verifies against its own workspace, recomputes the rest, and publishes what
completes; a later `--diff-base` run whose base is that same revision
reuses those units for its base evaluation, and its head reuses the ones whose
inputs it verifies. Reuse is on by default everywhere; the full-evaluation
override is `--no-incremental` on the CLI, `incremental: false` for MCP
`run_policy`, and `full-evaluation: true` for the GitHub action.

A unit records the content identity of the workspace snapshot whose name
lookups it read. A recorded name lookup is verified by the set of names that
changed since that snapshot, so a run reuses a unit with such lookups only when
the unit's snapshot is the run's base or its head. A unit computed on any other
revision, such as an earlier push to the same pull request or a scan of a
different commit, is recomputed. A unit that read no name lookup is verified
against the working tree directly, wherever it was computed.

The `incremental` section reports what the run reused. `base` is `reused` when
the run served the base findings from a stored base evaluation, and `evaluated`
when the run evaluated the base itself. `policies` holds one entry per policy
that ran, with the policy's `mode` (`sliced` when it ran unit by unit, `full`
when it was evaluated whole) and five counts for the working tree:
`units_total`, `units_reused`, `units_recomputed`, `units_unbounded`, and
`lookups_replayed`. `lookups_replayed` is the number of distinct lookup
questions (callers, dispatch, declaration facts and the like) the run asked the
working tree again to check that a stored unit still holds. The run widens with
`verification_budget_exceeded` when that number would pass the policy's file
budget. Three more counts, `base_units_reused`, `base_units_recomputed`, and
`base_lookups_replayed`, describe the base evaluation of the same policy in the
same run, and `base_widen_reason` says why that evaluation ran in full when it
did. They are zero when the run evaluated no base.

A policy evaluated in full also carries `widen_reason`, one of these typed
reasons:

- `whole_policy_family`: the family has no per-unit result. Taint and flow
  policies are always evaluated whole in this version.
- `plan_crosses_seeds`: the query's rows are not the concatenation of its
  per-seed-file rows, so no per-file result exists.
- `workspace_preparation_required`: the query contains `class-set` or
  `absent-member`, which needs a workspace field index. The policy runs whole
  before any file units are attempted, avoiding repeated index preparation.
  These bindings forgo per-file reuse; recorded base findings can still be reused.
- `unit_unbounded`: a unit read something the run could not name, or its
  result depended on the state of the run rather than on the code alone: it
  was cancelled, it ran out of a budget shared with other work, the source
  changed while it ran, or a provider or the store failed. A later run could
  not verify its inputs, or could get a different answer from the same code.
- `unit_not_exhaustive`: a unit ran under a bounded budget or was truncated,
  so its result is not a complete answer for its own part.
- `unit_diagnostics`: a unit reported a diagnostic whose code can depend on the
  state of the run, such as cancellation, an exhausted budget or a provider
  failure. Diagnostics about the code itself, such as an unsupported
  construct, combine across units and do not widen the policy.
- `merged_limit_reached`: the merged result reached a cap that a whole
  evaluation applies globally, so the whole evaluation might have truncated
  somewhere else.
- `verification_budget_exceeded`: verifying the recorded inputs would have cost
  more than the evaluation it avoids.
- `reverse_dependency_evidence_missing`: the evidence needed to verify a
  recorded input is not available in this run.
- `product_load_failed`: a stored result could not be read back.
- `incremental_disabled`: the run was given `--no-incremental`.

For the GitHub Actions recipe that passes the pull request's base SHA, see
[CI Gating with GitHub Actions](/ci-github-actions/).

## Accept Today's Findings, Gate Tomorrow's

A repository adopting Bifrost can carry hundreds to thousands of pre-existing
findings. The suppression store is deliberately the wrong tool for that scale:
it caps at 512 identity-exact records and demands a reviewed reason for each,
which is right for governed waivers and wrong for onboarding. `--diff-base`
removes the pressure from pull-request gates, but scheduled full runs and
release gates still need "accept everything that exists today, gate everything
new." That is the baseline document:

```bash
bifrost --root . --policy-pack bifrost.code-smells --accept-current
```

`--accept-current` runs the selected policies and writes
`.bifrost/baseline.json` (override with `--baseline-file`) from the completed
run: per policy, the sorted strong finding-id hashes plus the policy's
semantic hash at acceptance, under one batch-level reason and acceptance date.
Entries are identity-only — no per-record prose — so the document holds up to
100,000 entries in at most 16 MiB, two decimal orders beyond the suppression
cap. Acceptance is written only by a clean run: an unreliable run refuses to
define a baseline and exits 2 without writing, because an identity the run
could not prove cannot be accepted. A successful acceptance run exits 0. Its
`reason` is always `Bulk baseline acceptance of existing findings via
--accept-current`, and its `accepted_at` is the evaluation date
(`--evaluation-date`, or today's UTC date). `--accept-current` cannot be
combined with `--fail-on` or `--diff-base`, and it replaces any existing
document at the target path. Weak-identity findings are never written
(their identities are snapshot-local), and their excluded count is reported.
Regeneration is always an explicit re-run; the baseline never refreshes
itself.

On every later run the document joins by `(policy_id, finding_id)` after
suppressions and directory scope claim their findings; a finding already
suppressed or scoped is not claimed by the baseline, and its entry is audited
as `finding_claimed`. Claimed findings stay in the report with a `baseline`
decision and stop counting toward `--fail-on`, in full and in `--diff-base`
runs alike: gating counts findings that are new and unclaimed by suppression,
scope, and baseline. The report gains one top-level `baseline` review with the
document path, the batch metadata, exact per-state counts, and a bounded
needs-attention entry list (anything other than applied-with-matching-hash;
the counts stay exact when the list truncates). SARIF renders each baselined
finding as an external accepted suppression entry whose property bag carries
`bifrost.decision: "baseline"`, and concise human output hides baselined
findings while the summary reports the counts.

The audit rules mirror suppressions. A malformed or oversized document is a
diagnostic and exit 2; a baseline never turns an unreliable run clean. Editing
a policy marks its entries drifted without reactivating them — a drifted entry
still applies, and the drift count in the review is the signal to re-review.
An entry is stale only when an exhaustive completed run proves the finding
absent; an incomplete run reports `policy_incomplete` instead of guessing. The
`--diff-base` identity limitations apply unchanged: a rename or an edited
source slice re-keys the finding, so the old entry goes stale and the re-keyed
finding gates until it is re-accepted or fixed.

The [policy reference](/reference/policies/) shows the document's fields and
the review's count fields. For the onboarding recipe that commits the baseline
once and keeps pull-request gates on `--diff-base`, see
[CI Gating with GitHub Actions](/ci-github-actions/).

## Classification And CVSS v4.0

A policy can declare one broad fallback taxonomy classification plus typed
refinements. Refinements add evidence-backed classifications; they do not erase
the fallback. A winning taint finding combination can also add classifications.

CVSS is reduced from typed evidence. Policy input never supplies or overrides a
numeric score. A scored CVSS v4 Base assessment requires all eleven Base metrics
with coherent metric/value/scope evidence and no Base `X`. Missing or conflicting
evidence remains an explicit unscored variant with reasons. Threat,
Environmental, and analyst overlays stay separate from static policy assertions;
incompatible records are not averaged, spliced, or resolved by provider order.
Organizational risk is reported separately from CVSS.

## Run Policies From The CLI

Pass every runnable root explicitly. File-backed selectors and endpoint
dependencies are resolved from their authored query-file, exact-endpoint, and
directory references:

```bash
bifrost --root docs/fixtures/ten-minute-evaluation \
  --policy-file policies/review-audit-call.rqlp \
  --format human \
  --fail-on never
```

This is the published, executable [ten-minute policy
example](/evaluate-bifrost/). Replace the root and
policy path with your project when authoring a rule of your own.

Repeat `--policy-file` to produce one deterministic combined report. Choose
`human`, `json`, or `sarif`; use `--output report.sarif` for synchronized,
same-directory atomic replacement instead of stdout.

`--sources PATH` restricts policy evaluation to the named files, directories,
or globs. It is repeatable and helps when you iterate on one rule against a
small part of a repository:

```bash
bifrost --root . --policy-file policies/security.rqlp --sources src/auth
```

`--policy-cost-hints <path>` reads a JSON object mapping non-empty policy IDs
to non-negative integer milliseconds. Parallel batches start unknown policies
first, then hinted policies from longest to shortest; hints never change the report.

`--policy-timings` adds each policy's elapsed evaluation time to its report
work metrics as `evaluation.elapsed_ms`. A policy that ran unit by unit also
gets four disjoint parts of that time: `units.prefetch_ms` (loading stored
units), `units.verify_ms` (checking their reads, without lookup replay),
`units.lookup_replay_ms` (asking lookups again), and `units.recompute_ms`
(evaluating units that could not be reused). `bifrost scan [PATH]` runs the selected external catalog's default
policies and prints the activated pack versions and catalog hash on
stderr before the report. [Scan a Codebase](/scan-a-codebase/) walks through a
first scan and explains why it can exit 2.

The one-shot CLI starts with empty catalog and endpoint registries. A workspace
semantic-pack policy uses the shared `.bifrost/packs.json` contract: an absent
document selects compatible dependency packs for languages present in the
workspace, a configured document selects its named ecosystems, and an empty
`ecosystems` array explicitly disables that route. A configured catalog is
workspace-relative; without one, activation is ephemeral. Activation never
downloads packs or dependencies, and compatibility and `review_required` gates
remain authoritative. A policy which names a machine catalog must be loaded
through an embedding that explicitly populated `TaintCatalogRegistry`. A
policy which uses only
`(match-endpoints :ids [...])` likewise needs an embedding to pre-register those
endpoint IDs. In an ordinary CLI run, the same policy can instead discover its
closed endpoint set through `(match-directory ...)` and then select exact IDs
from that set. The CLI does not guess paths or scan ambient directories beyond
this explicit workspace document. Reports expose the dependency activation mode
and the individual decisions, including missing, incompatible, disabled, or
incomplete activation.

| Status | Meaning |
| --- | --- |
| `0` | The run is reliable, no active finding met `--fail-on`, and no suppression record is orphaned. |
| `1` | The run is reliable, and at least one active finding met the threshold or at least one suppression record is orphaned. An orphaned record gives status 1 even with `--fail-on never`. |
| `2` | Policy, suppression, scope, or baseline loading, schema validation, composition, evaluation, completeness, serialization, or output was unreliable, or a `proven_subset` run had no gated finding. This takes precedence over status 1. |

`--fail-on` accepts `never`, `finding`, `note`, `warning` (the default), or
`error`; `finding` includes unrated findings. It changes only the complete-run
finding threshold. It cannot turn an invalid, incomplete, cancelled, or
unsupported run into status 0. Taint and typestate policies execute through the
production semantic engine; cancellation, budgets, incomplete selector
discovery, semantic uncertainty, unmodeled call boundaries, and witness
truncation remain visible in run/finding completeness instead of becoming clean
zero-results. Source-backed taint works without external models. An embedding
must explicitly supply and activate a semantic-model catalog when external
procedure summaries are required outside the shared workspace activation
contract.

See the [policy reference](/reference/policies/) for the exact exit-status
rules, the [CLI reference](/reference/cli/) for option syntax and
interactions, and [Reproduce an Analysis](/reproduce-analysis/) for the
artifacts to preserve.

## Author In VS Code

The Bifrost VS Code extension associates `.rqlp` files with the **Bifrost RQL
Policy** language. Diagnostics, hover, and the **Run RQL Policy** action need a
running language server. The language server is the separate `bifrost-lsp`
program, not the `bifrost` binary. See [LSP Server](/lsp/) for the versions
that serve it.

**Run RQL Policy** sends the current text, including unsaved edits, and
today's UTC date as the evaluation date. It does not name a suppression file.
Active findings appear under **Bifrost Policy Results**. Suppressed findings
move to its suppression audit. Policy findings never appear in **Bifrost Query
Results**. When the date or the suppression file must be fixed, run the policy
from the CLI. See [RQL in VS Code](/rql-vscode/).
