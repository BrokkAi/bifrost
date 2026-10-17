---
title: Languages
description: Every language Bifrost analyzes, with labels, file extensions, capabilities, project inputs, structural vocabulary, and semantic IR support.
---

This page lists every language that Bifrost analyzes and what each language
adapter supports. For a short overview of what the analysis can and cannot
prove, read [Language and Analysis Capabilities](/capabilities/).

Bifrost reports gaps at run time. Check the diagnostics in each result before
you rely on an empty answer:

- `unsupported_structural_feature` means a query used a kind, role, or pattern
  field that the language adapter does not support.
- `semantic_capability_unsupported` means a semantic step, such as
  `class_set`, is not available for the language.
- `topology_derivation_incomplete` means Bifrost could not read the whole
  build model.

`bifrost --list-row-schemas` prints the value domain of every row field. The
`language` field lists the language labels below, and the
`semantic_unsupported` field of `dispatch_outcome` and `receiver_outcome` rows
lists the semantic capability labels in
[Semantic IR capabilities](#semantic-ir-capabilities).

## Proof tiers apply to every language

Any language adapter can return an `unproven` reference or call edge. An
`unproven` edge is an explicit best-effort candidate. Bifrost returns it when
the receiver type is unknown or several targets remain possible, for example
an interface call with several implementations. This happens in statically
typed languages such as Java, Go, and Rust as well as in Python and Ruby.
Bifrost never reports an `unproven` edge as `proven`. Check the `proof` field
in every language. Filter to `proven` when an answer must contain only
analyzer-established identities.

## Labels and file extensions

Each analyzed file belongs to exactly one language label. Bifrost chooses the
label from the file extension. Extension matching ignores case.

| Label | Languages | Extra aliases | File extensions | Dialects |
| --- | --- | --- | --- | --- |
| `java` | Java | none | `.java` | none |
| `go` | Go | none | `.go` | none |
| `cpp` | C and C++ | `c++` | `.c`, `.cc`, `.cpp`, `.cxx`, `.h`, `.hin`, `.hpp`, `.hh`, `.hxx` | `cpp-c` for files with the lowercase `.c` extension; every other extension, including `.h` and `.C`, uses C++ rules |
| `javascript` | JavaScript and JSX | none | `.js`, `.mjs`, `.cjs`, `.jsx` | `javascript-jsx` for `.jsx` |
| `typescript` | TypeScript and TSX | none | `.ts`, `.tsx` | `typescript-tsx` for `.tsx` |
| `python` | Python | none | `.py` | none |
| `rust` | Rust | none | `.rs` | none |
| `php` | PHP | none | `.php` | none |
| `scala` | Scala | none | `.scala` | none |
| `csharp` | C# | `c#` | `.cs` | none |
| `ruby` | Ruby | none | `.rb` | none |
| `kotlin` | Kotlin, including Kotlin script | none | `.kt`, `.kts` | none |

Dialect labels appear in the `dialect` field of `procedure` rows. A `language`
row field can also hold `none` for a file that no analyzer owns.

### Language filters

The `languages` field of a JSON CodeQuery, the RQL `languages` scope, and the
`:languages` list of a policy all use the same label parser. Each entry can
be:

- a label from the table above;
- an extra alias: `c++` or `c#`;
- any file extension of a language, with or without the leading dot, for
  example `py`, `.kts`, `tsx`, or `h`; or
- a fixed family: `jvm` (`java`, `kotlin`, `scala`) or `js-ts` (`javascript`,
  `typescript`).

Labels, aliases, and extensions ignore case, surrounding spaces, `-`, and
`_`. Family names must be written exactly as `jvm` or `js-ts`. A CodeQuery
`languages` list can hold at most 32 entries. An unknown label is an error:
`unknown language label`.

An extension selects its whole label. `c` and `h` select every `cpp` file,
and `jsx` selects every `javascript` file. There is no C-only or JSX-only
filter. To restrict a query to C files, add a `where` glob such as `**/*.c`.

### Files that Bifrost does not analyze

Bifrost does not parse these template files: `.vue` and `.svelte` (JavaScript
and TypeScript) and `.razor` and `.cshtml` (C#). They can still reference
analyzed symbols. When the workspace contains such files, `scan_usages` adds a
note to the result: "workspace contains .vue files that may reference this
symbol but are not analyzed; inspect or analyze those files separately before
concluding absence".

Bifrost also does not analyze common extensions that are not in the table, for
example `.pyi`, `.pyw`, `.mts`, `.cts`, `.rake`, `.gemspec`, `.sc`, and
`.phtml`. A query over these files returns no results and no diagnostic.

One exception applies to C and C++. Bifrost analyzes a file whose extension
no language claims, such as `.inc`, `.inl`, `.ipp`, `.tpp`, or a file with
no extension, as C or C++ when a C or C++ file includes it with a quoted
`#include "..."`. This applies through chains of such includes. An
angle-bracket include (`#include <...>`) does not cause this. A quoted
include of `name.h` also matches a header template named `name.hin`.

## Capability matrix

Every label supports structural `query_code` matching, exact references and
calls, and the receiver steps `receiver_targets`, `points_to`, and
`member_targets`. The receiver steps return bounded outcomes; see
[Receiver Traversal](/code-query-tutorials/receiver-traversal/).

### Navigation and graph

| Language | Call and receiver precision | Named arguments (`kwargs`) | Import-file edges | Indexed hierarchy |
| --- | --- | --- | --- | --- |
| Python | Resolved functions, methods, and properties | Yes | Yes | Yes |
| Java | Receiver identity, overloads, constructors, fields, and types | No | Yes | Yes |
| JavaScript | Module and method identity; `this` references are separated by result surface | No | Yes | Yes |
| TypeScript | JavaScript forms plus typed declaration and module identity | No | Yes | Yes |
| Go | Package-scoped functions, methods, fields, and types | No | Yes | Yes, including indexed type relationships |
| C (`cpp`) | Functions, fields, and types; method receivers and class inheritance do not apply | No | Yes, from `#include` | Not applicable |
| C++ (`cpp`) | Functions, members, fields, types, includes, and structured receiver resolution | No | Yes, from `#include` | Yes |
| Rust | Functions, impl members, fields, types, and explicit `self` handling | No | Yes, including `pub use` re-exports | Yes |
| PHP | Namespaces, functions, methods, fields, types, static receivers, and `$this` ownership | Yes | Yes, from namespace imports and type references | Yes |
| Scala | Receiver and overload resolution across methods, fields, types, and inheritance | Yes | Yes | Yes |
| C# | Receiver and overload resolution across methods, constructors, fields, and types | Yes | Yes | Yes |
| Ruby | Resolved methods, fields, and constants | Yes | Yes, from literal require forms | Yes |
| Kotlin | Functions, methods, real constructors, properties, and types through inheritance, companion objects, extensions, and receiver chains | Yes | Yes | Yes |

Import-file edges are what `imports_of` and `importers_of` return.
These forms create an edge to a project file:

| Label | Forms that create an import-file edge |
| --- | --- |
| `python` | `import` and `from ... import` statements, for example `from target import target` |
| `java` | `import` declarations, for example `import example.Target;` |
| `javascript`, `typescript` | `import` declarations, `require("...")` calls, and source-bearing re-exports (`export { ... } from`, `export * from`, and `export * as name from`, including TypeScript type-only forms). The specifier can be a relative path, a `tsconfig.json` or `jsconfig.json` path alias, or the name of a workspace package. Each edge names the direct resolved source file, without following a barrel's re-exports transitively. Source-less exports create no edge. These structural dependencies do not assert runtime execution or add local symbol bindings |
| `go` | `import` paths that name a workspace package, for example `import "example.com/project/target"` |
| `cpp` | `#include` directives, for example `#include "target.h"` |
| `rust` | `use` declarations, for example `use crate::shared::target;`. The edge goes to the module file that the path names. When the path reaches the item through `pub use` re-exports, another edge goes to the file that defines the item. This covers single-name, chained, glob, and module re-exports, also across Cargo crates |
| `php` | `use` clauses, for example `use function Ex\target;`, and type references that name a class: `new`, static member access, parameter, return, and property types, `extends` and `implements`, `catch`, attributes, and `instanceof`. This includes fully qualified names and same-namespace names. `require` and `include` do not create edges. A same-namespace function call without a `use` clause does not create an edge |
| `scala` | `import` clauses, for example `import example.Target` |
| `csharp` | `using` directives, for example `using Example;` |
| `ruby` | `require`, `require_relative`, `load`, and `autoload` with a literal path, for example `require_relative 'target'` |
| `kotlin` | `import` directives, for example `import example.target` |

### Analysis

| Language | Semantic adapter: CFG, value flow, taint, typestate | Class-set type flow (`class_set`, `absent_member`) | Build topology (`target_of`, `source_set_of`, `topology_edges_of`) | Semantic-pack ecosystem |
| --- | --- | --- | --- | --- |
| Python | Yes | Yes | No | `python` |
| Java | Yes | No | Maven only | `jvm` |
| JavaScript | Yes | Yes | No | `npm` |
| TypeScript | Yes, shared with JavaScript | Yes | No | `npm` |
| Go | Yes | No | No | `go` |
| C and C++ | Yes, one shared C-family adapter | No | No | `cpp` |
| Rust | Yes | No | No | `cargo` |
| PHP | Yes | Yes | No | `composer` |
| Scala | Yes | No | Maven only | `jvm` |
| C# | Yes | No | No | `dotnet` |
| Ruby | Yes | Yes | No | `ruby` |
| Kotlin | Yes | No | Maven only | `jvm` |

Notes on the analysis table:

- Every semantic adapter supports registered value-flow plans, `.rqlp` taint
  policies, typestate protocols, and procedure-local CFG inspection.
  Precision depends on the adapter. See
  [Semantic IR capabilities](#semantic-ir-capabilities) and
  [Data Flow, Taint, and Typestate](/data-flow-and-typestate/).
- For a language without class-set type flow, `class_set` and
  `absent_member` return no rows and the diagnostic
  `semantic_capability_unsupported` with the message
  `class-set propagation is unsupported for <label>`.
- Build topology reads Maven `pom.xml` files only. See
  [Project and build inputs](#project-and-build-inputs). A workspace with
  only Gradle builds returns the diagnostic `topology_derivation_incomplete`.
  A file that no build file claims returns no row.
- The semantic-pack ecosystem names the dependency ecosystem whose packs
  describe external libraries for that language. Java, Kotlin, and Scala
  share one JVM classpath, so a JVM pack declared for any of them serves all
  three. TSX and JSX files use the `typescript` and `javascript` packs. See
  [Semantic packs](/reference/semantic-packs/).

## Project and build inputs

Bifrost reads these project files to assign identities and resolve imports.
It parses them and never runs a build tool or compiler while it indexes
source. Dependency discovery for semantic packs reads other files and, for
some ecosystems, can run a build tool; the next table lists those files.

| Label | Files read during analysis | What Bifrost uses them for |
| --- | --- | --- |
| `python` | `pyproject.toml` (`tool.setuptools.packages.find.where`); `setup.py`, parsed and never run (`packages`, a literal `package_dir`, and the `where` argument of `find_packages` or `find_namespace_packages`); `__init__.py` package layout | Module identity. Bifrost picks the nearest project and the deepest import root that contains the file. Without packaging evidence, the outermost `__init__.py` package sets the module path. See [Identity and Language Front Ends](/design/identity-and-language-frontends/) |
| `java`, `kotlin`, `scala` | `package` declarations in source; Maven `pom.xml` files | Package identity comes from source. `pom.xml` files define build targets, `main` and `test` source sets, and dependency edges between targets of the same workspace, with the Maven scope. Gradle build scripts are not read for topology |
| `go` | The nearest `go.mod` (`module` directive) | Package import paths, which are the qualified names of Go declarations. Without a `go.mod`, Bifrost uses the directory path |
| `rust` | `Cargo.toml`: `[package]`, `[lib]`, `[[bin]]`, `[[example]]`, `[[test]]`, `[[bench]]`, the conventional target paths such as `src/main.rs` and `src/bin/`, `build.rs`, `[workspace]`, path dependencies and `package` renames in `[dependencies]`, `[dev-dependencies]`, and `[build-dependencies]`, and `[features]` | Crate roots, module routes, and crate names used to resolve `use` paths and calls |
| `javascript`, `typescript` | The nearest `tsconfig.json` or `jsconfig.json` for each importing file (`extends`, `compilerOptions.baseUrl`, `compilerOptions.paths`); every `package.json` outside `node_modules` that has a `name` (`exports` entry for `.`, `main`, `module`) | Resolving non-relative import specifiers to project files: path aliases such as `@/lib/foo`, and bare specifiers that name a workspace package. Package entries that name source through the `source` or `development` condition are tried first |
| `php` | The root `composer.json` (`autoload` and `autoload-dev`, `psr-4` entries) | A declaration under a PSR-4 root is treated as visible from every PHP file when Bifrost searches for usages |
| `ruby` | The root `Gemfile` or `Gemfile.lock` | If either names the gem `rails` or `zeitwerk`, `.rb` files under `app/<dir>/` are visible to every Ruby file without a `require`. `app/assets`, `app/javascript`, and `app/views` are excluded |
| `cpp` | The root `compile_commands.json` (`directory`, `file`, and `arguments` or `command`) | Include search roots (`-I`, `/I`, `-iquote`, `-isystem`, `/external:I`, `/imsvc`), forced includes (`-include`), macro definitions (`-D`, `-U`), and the translation-unit language (`-x`, `/TC`, `/TP`, `-std`). Bifrost uses them for include resolution and semantic diagnostics. It never runs the recorded commands |
| `csharp` | Every `.csproj` file (`Compile` items with `Include` and `Remove`, `EnableDefaultItems`, `EnableDefaultCompileItems`) | Which `.cs` files form one compilation, so that a `global using` applies only to files of its own project. Without a `.csproj`, all `.cs` files form one compilation. MSBuild is not run. `Directory.Build.props` and `Directory.Build.targets` are not interpreted; their presence marks the membership as incomplete |

### Dependency discovery inputs

These files feed semantic-pack dependency discovery, not source indexing. The
[semantic packs reference](/reference/semantic-packs/) describes discovery
modes, configuration, and which modes run a tool.

| Ecosystem | Languages | Dependency input files |
| --- | --- | --- |
| `jvm` | Java, Kotlin, Scala | `pom.xml`, `settings.xml`, `build.gradle`, `build.gradle.kts`, `settings.gradle`, `settings.gradle.kts`, `gradle.properties`, `gradle.lockfile`, `libs.versions.toml`, `gradle-wrapper.properties` |
| `dotnet` | C# | `project.assets.json` |
| `npm` | JavaScript, TypeScript | `package.json`, `package-lock.json`, `npm-shrinkwrap.json` |
| `python` | Python | `METADATA`, `RECORD`, `top_level.txt`, `pyproject.toml`, `.python-version` |
| `go` | Go | `go.mod`, `go.sum`, `go.work`, `go.work.sum`, `vendor/modules.txt` |
| `cargo` | Rust | `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml` |
| `ruby` | Ruby | `Gemfile`, `Gemfile.lock`, `gems.locked` |
| `composer` | PHP | `composer.json`, `composer.lock`, `installed.json` |
| `cpp` | C, C++ | `compile_commands.json` |

JVM dependency discovery runs Maven and Gradle only in its offline
build-tools mode, which only a Rust embedding selects. Go dependency discovery
runs `go list`. It is off by default; a CLI policy run (`bifrost scan` or the
policy flags) turns it on. The other ecosystems only read files. The JVM toolchain selection file
`.bifrost/jvm-toolchains.json` is listed in
[Configuration files](/reference/configuration-files/).

### Static JavaScript/TypeScript dependency evidence

The Rust preparation API
`analyzer::dependency_evidence::discover_js_ts_dependency_file_evidence`
accepts bounded, caller-supplied workspace snapshot bytes and returns the shared
dependency file-fact contract. It performs no file-system discovery, package
installation, runtime inspection, lifecycle execution, or semantic-pack
activation. JavaScript and TypeScript analyzers publish these facts through the
shared revision-selected SQLite store before queries run. The canonical
`dependency_evidence` / `(dependency-evidence ...)` seed reads those stored rows
with `ecosystems: ["npm"]`; selected overlays use private SQL publication leases.
Queries do not launch discovery or reread disk for their citations.

| Input | Supported interpretation |
| --- | --- |
| Root/member `package.json` | Workspace patterns and membership; dependency, development, optional and peer categories; npm aliases and source specifiers; declared engines, `packageManager` and `devEngines`. Overrides/resolutions are retained with an unsupported-selection diagnostic |
| `package-lock.json`, `npm-shrinkwrap.json` | Versions 2 and 3 with an exact `packages` table. Installation locators, duplicate versions, aliases, workspace links, source/integrity, peer requirements and platform/optional conditions remain distinct |
| `pnpm-lock.yaml` | Version 9.0 importer, package and snapshot tables. Peer-qualified snapshot keys retain their identity. Importer specifier/version pairs establish direct consuming-package edges; package-only candidates remain unowned |
| `yarn.lock` (Classic) | Standard generated two-comment header with `# yarn lockfile v1`, decoded by maintained `yarn-lock-parser` 0.14.0 and checked against released `tree-sitter-yarnlock` 0.2.0. Separate or combined selectors, quoted scoped names, npm aliases, duplicate versions, resolved sources/integrity and dependency/optional-dependency references retain distinct descriptor-group identity and exact entry spans |
| `yarn.lock` (Berry) | YAML metadata versions 4, 6 and 8. Resolution keys, including virtual and workspace locators, retain identity. A workspace resolution and dependency descriptor must establish each consumer edge |

Other lock versions, malformed inputs, missing
members, unresolved edges, competing lockfiles, cancellation and exhausted
limits produce explicit gaps. Competing locks are not selected by input order.
Authored non-peer requirements omitted from an exact importer remain unresolved.
Berry entries for the same resolution must agree on metadata; disagreement retains
partial source-backed alternatives and cannot establish a consuming-package edge.
Peer constraints do not establish installed peers. Engine requirements do not
establish the installed runtime. Development dependencies retain their category;
their purpose is unknown rather than assumed to be testing.

Declared requirements, unassociated locked candidates and locked candidates with
proven direct consumers are separate rows. Source references are not semantic
versions. Each row retains its snapshot hash and exact source range; owner rows
use the build-project identity of the consuming manifest. Files in a different
workspace member cannot supply that ownership. Configuration mitigation requires
the separate typed configuration-correlation contract.

Classic has no importer table or workspace/peer/platform selection records.
Its candidates remain unowned even when a manifest has a matching requirement;
workspace declarations remain separate, and ownership and conditional
applicability produce an unresolved gap. Dependency references retain their
category, alias, raw requirement and target instance IDs only within the same
lock snapshot. Missing or competing descriptor targets remain diagnostic.
File/link/git descriptors retain authored references; they do not prove a local
workspace member or installation. Classic does not supply Berry virtual locators.
When `resolved` is absent, a unique descriptor source retains its authored
coordinate with descriptor provenance. Competing descriptor sources stay
unselected, with their alternatives retained and an unresolved-source gap.

The Classic syntax boundary is the upstream grammar, not a fallback scanner.
Recovered trees and duplicate fields/references are rejected with diagnostics.
The upstream grammar can misclassify optional sections as dependency entries.
Structured values are preserved by the value decoder, while disagreements
between decoder reference spans and syntax nodes mark that record partial with
an unsupported-validation gap. Unknown lines cannot certify complete validation.
Valid Yarn syntax outside that grammar (including unquoted scoped selectors,
quoted ranges containing spaces, escaped selector strings, and empty locks) is
currently unsupported and also yields a recovery diagnostic. Grammar extensions
must be released upstream or in a separate maintained grammar project.

The reusable Rust `NpmVersionRange` matcher uses the maintained `js-semver`
parser for npm comparator sets, `||` unions, caret/tilde, partial and wildcard
versions, and hyphen ranges. A prerelease matches only when its comparator set
explicitly admits a prerelease with the same major/minor/patch tuple. Build
metadata does not change version precedence. The parser supports surrounding
whitespace and a leading `v`; Bifrost adds no version coercion or tag resolution.
Range input is limited to 16 KiB and full version input to the parser's 256-byte
limit. Invalid ranges, aliases, dist-tags and git/path/link/workspace references
return errors when supplied as semver input.

`analyzer::dependency_evidence::npm_dependency_version_matches` evaluates one
complete npm locked/installed row's `exact_version`, returning `Some(true)` or
`Some(false)` for valid comparisons, `None` for missing/non-exact evidence, and
an error for invalid versions. It never substitutes `version_requirement`.
Consumers must retain acquisition gaps and apply package, source, locator and
owner filters to that same row. This matcher does not yet expose an RQL
predicate; canonical query integration remains separate work.

## Structural vocabulary by language

`query_code` matches normalized kinds. A kind also matches its subkinds:
`declaration` covers `callable`, `class`, `import`, `parameter`, and `module`;
`callable` covers `function`, `method`, `constructor`, and `lambda`;
`literal` covers the five literal kinds; and `loop` covers `for_loop` and
`while_loop`. A parent kind is supported when the language supports any of
its subkinds.

When a query uses a kind that a language does not support, Bifrost returns no
match for that language and the diagnostic `unsupported_structural_feature`,
for example `structural adapter for go does not support kind(s): for_loop`.

### Kinds

| Kind | Meaning | Labels without support |
| --- | --- | --- |
| `declaration` | Any declaration, including callable, class, and import declarations | none |
| `callable` | Any callable declaration: functions, methods, constructors, and lambdas | none |
| `function` | A named free-standing function declaration | `java` |
| `method` | A method declared on a class or similar container | none |
| `constructor` | A constructor declaration | `go`, `python`, `rust`, `scala`, `ruby` |
| `lambda` | An anonymous function or lambda expression | none |
| `class` | A class-like declaration | none |
| `import` | An import declaration | none |
| `parameter` | A formal parameter declaration | `go`, `cpp`, `python`, `rust`, `php`, `scala`, `csharp`, `ruby`, `kotlin`, `javascript`. A rest parameter (`...args`) does not match in `javascript` |
| `module` | A module or namespace declaration | `java`, `go`, `javascript`, `typescript`, `python`, `scala`, `kotlin` |
| `call` | A call of a function, method, or constructor | none |
| `concurrent_spawn` | An operation that starts a callable in a separate concurrent task | every label except `go` |
| `resource_release` | A construct that releases a resource when it exits, such as Java try-with-resources or a Python `with` statement | every label except `java` and `python` |
| `assignment` | An assignment expression or statement | none |
| `field_access` | A member or field access | none |
| `identifier` | An identifier reference | none |
| `literal` | Any literal value | none |
| `string_literal` | A string literal | none |
| `numeric_literal` | A numeric literal | none |
| `boolean_literal` | A boolean literal | none |
| `null_literal` | A null-like literal | `rust` |
| `collection_literal` | An array, list, set, dictionary, or tuple literal | `go`, `cpp`, `php`, `scala`, `csharp`, `ruby`, `kotlin` |
| `jsx_element` | A JSX element, including a self-closing element | every label except `javascript` and `typescript` |
| `jsx_attribute` | A named JSX attribute | every label except `javascript` and `typescript` |
| `jsx_spread_attribute` | A JSX spread attribute | every label except `javascript` and `typescript` |
| `object_property` | A named property pair in an object literal | every label except `javascript` and `typescript` |
| `computed_property` | A computed object-property key | every label except `javascript` and `typescript` |
| `spread_element` | A spread expression in an object, array, or argument list | every label except `javascript` and `typescript` |
| `return` | A return statement | none |
| `throw` | A throw or raise statement | `go`, `rust`, `ruby` |
| `catch` | A catch clause or exception handler | `go`, `rust` |
| `if` | A conditional statement or expression | none |
| `loop` | Any loop | none |
| `for_loop` | A loop over a collection, iterator, or range (the for-each family) | `go`, `cpp` |
| `while_loop` | A condition-controlled loop: while, do-while, or until | `go` |
| `decorator` | A decorator or annotation | `go`, `cpp`, `ruby` |
| `block` | A statement list that forms its own lexical scope, such as a method body, a bare block, or a switch body | `php`, `ruby` |
| `yield` | A Python yield expression that suspends generator execution | every label except `python` |

### Roles

A role constrains a sub-node of a match. Each role applies only to certain
kinds.

| Role | Applies to kinds | Labels without support |
| --- | --- | --- |
| `callee` | `call`, `concurrent_spawn` | none |
| `receiver` | `call`, `concurrent_spawn` | none |
| `args` | `call`, `concurrent_spawn` | none |
| `kwargs` | `call`, `concurrent_spawn` | `java`, `go`, `cpp`, `javascript`, `typescript`, `rust` |
| `left` | `assignment` | none |
| `right` | `assignment` | none |
| `operator` | `assignment` | none |
| `module` | `import`, `declaration` | none |
| `decorators` | `function`, `method`, `constructor`, `lambda`, `callable`, `class`, `parameter`, `declaration` | `go`, `cpp`, `ruby` |
| `object` | `field_access` | none |
| `field` | `field_access` | none |
| `iterable` | `for_loop` | `go`, `cpp`, `php`, `scala`, `csharp`, `ruby`, `kotlin` |
| `elements` | `collection_literal` | `go`, `cpp`, `php`, `scala`, `csharp`, `ruby`, `kotlin` |
| `tag` | `jsx_element` | none; the kind exists only in `javascript` and `typescript` |
| `attributes` | `jsx_element` | none; the kind exists only in `javascript` and `typescript` |
| `children` | `jsx_element` | none; the kind exists only in `javascript` and `typescript` |
| `value` | `jsx_attribute`, `jsx_spread_attribute`, `object_property`, `computed_property`, `spread_element`, `return`, `throw` | every label except `python` for `return` and `throw`; the JSX and property kinds exist only in `javascript` and `typescript` |
| `key` | `object_property` | none; the kind exists only in `javascript` and `typescript` |
| `test` | `assertion`, `if` | every label except `python` |

The pattern field `boolean_value`, which matches the exact value of a
`boolean_literal`, is supported by every label except `php`.

The full pattern and step vocabulary is in the
[CodeQuery reference](/reference/code-query/).

## Semantic IR capabilities

Each semantic adapter declares, for every semantic capability, one of three
support levels:

- **C** (complete): the adapter models the feature for every construct it
  reaches.
- **P** (partial): the adapter models the feature, but some constructs
  produce an explicit semantic gap.
- **-** (unsupported): the adapter does not model the feature. An analysis
  that needs it reports a gap or a `semantic_unsupported` value instead of an
  empty answer.

TypeScript and JavaScript share the `js-ts` adapter. C and C++ share the
`cpp` adapter.

| Capability | Meaning | java | kotlin | scala | csharp | cpp | go | js-ts | python | rust | php | ruby |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `procedures` | Lists the procedures in a file: functions, methods, lambdas, and similar bodies | C | C | C | C | C | C | C | C | C | C | C |
| `entry_boundary` | Models the entry of each procedure | C | C | C | C | C | C | C | C | C | C | C |
| `normal_exit_boundary` | Models normal exit from a procedure | C | C | C | C | C | C | C | C | C | C | C |
| `exceptional_exit_boundary` | Models exit from a procedure by an exception or panic | C | C | C | C | C | C | C | C | C | C | C |
| `basic_blocks` | Groups statements into basic blocks | C | C | C | C | C | C | C | C | C | C | C |
| `program_points` | Assigns program points to statements and expressions | C | C | C | C | C | C | C | C | C | C | C |
| `normal_control_flow` | Models ordinary control-flow edges: branches, loops, and jumps | P | P | P | P | P | P | P | P | P | P | P |
| `exceptional_control_flow` | Models edges taken when an exception is raised or handled | P | P | P | P | P | P | P | P | P | P | P |
| `cleanup_control_flow` | Models cleanup paths such as `finally`, `defer`, or `ensure` | P | P | P | P | P | P | P | P | P | P | P |
| `assignments` | Models assignments | P | P | P | P | P | P | P | P | P | P | P |
| `values` | Models expression values | P | P | P | P | P | P | P | P | P | P | P |
| `allocations` | Models sites that create objects or values | P | P | P | P | P | P | P | P | P | P | P |
| `local_flow` | Models value flow between locals in one procedure | P | P | P | P | P | P | P | P | P | P | P |
| `parameter_flow` | Models value flow from arguments to parameters | P | P | P | P | P | P | P | P | P | P | P |
| `receiver_flow` | Models flow of the receiver, such as `this` or `self`, into a method | P | P | P | P | P | P | P | P | P | P | P |
| `return_flow` | Models flow of returned values to the caller | C | C | C | C | C | P | C | C | C | C | C |
| `field_memory` | Models reads and writes of object fields | P | P | P | P | P | P | P | P | P | P | P |
| `static_memory` | Models reads and writes of static or global storage | - | P | P | P | P | P | - | - | - | - | - |
| `index_memory` | Models reads and writes through an index, such as an array or map element | P | P | P | P | P | P | P | P | P | P | P |
| `calls` | Models call sites | P | P | P | P | P | P | P | P | P | P | P |
| `dynamic_dispatch` | Models calls whose target depends on the run-time receiver | P | P | P | P | P | P | P | P | P | P | P |
| `normal_call_continuation` | Models control returning normally from a call | C | C | C | C | C | C | C | C | C | C | C |
| `exceptional_call_continuation` | Models control leaving a call by an exception | C | C | C | C | C | C | C | C | C | C | C |
| `captures` | Models variables that closures and lambdas capture | P | P | P | P | P | P | P | P | P | P | P |
| `callable_references` | Models callables used as values, such as method references | P | P | P | P | P | P | P | P | P | P | P |
| `async_suspend_resume` | Models suspension and resumption at `await` | - | - | - | P | P | - | P | P | P | - | - |
| `generator_suspension` | Models suspension at `yield` in generators | - | - | - | P | P | - | P | P | P | P | P |
| `deferred_execution` | Models code that is scheduled to run later than it appears, such as initializers or deferred calls | P | P | P | P | P | P | P | P | P | P | P |
| `concurrent_spawn` | Models starting a callable in a separate concurrent task | - | - | P | - | P | P | - | - | - | - | P |
| `synchronization` | Models synchronization between concurrent tasks | - | - | - | - | - | P | - | - | - | - | - |
| `non_local_control` | Models control transfers that leave structured blocks, such as labeled `break` and `continue` | P | P | P | P | P | P | P | - | P | P | P |
| `resource_management` | Models resource acquisition and release, such as try-with-resources or `with` | P | - | P | P | P | - | P | P | P | P | P |
| `guard_facts` | Records normalized branch conditions | P | P | P | P | P | P | P | P | P | P | P |
| `switch_facts` | Records normalized switch conditions | - | - | - | - | - | C | - | - | - | - | - |

## Language-specific behavior

### C and C++

- The `cpp` label covers both languages. Only files with the lowercase `.c`
  extension use C scoping rules. All other extensions, including `.h` and
  `.C`, use C++ rules. A `.h` file is never treated as Objective-C.
- `.hin` header templates are parsed and indexed like any other header.
- Files with an unclaimed extension are adopted through quoted includes. See
  [Files that Bifrost does not analyze](#files-that-bifrost-does-not-analyze).

### C#

- Bifrost hides preprocessor directive lines from the parser. In each `#if`,
  `#elif`, `#else` chain, the first branch is active, unless its condition is
  the literal `false`; then the next branch is tried.
- Bifrost does not model defined symbols. It does not read `DefineConstants`
  or `#define`. Declarations in the inactive branches are not indexed, so
  code that differs by target framework (`#if NET...`) can lose
  declarations.
- Semantic diagnostics for a file with inactive branches are marked
  incomplete with the detail
  `conditional compilation: inactive branches excluded from the index`.
- `global using` directives apply only to the files of the same `.csproj`
  compilation. See [Project and build inputs](#project-and-build-inputs).

### Go

- Bifrost does not evaluate build constraints. It indexes every `.go` file,
  including files with `//go:build` or `// +build` lines and files whose
  names end in a `_GOOS` or `_GOARCH` suffix such as `_linux.go`. Package
  context for a package that contains such files is marked incomplete.
- Go 1.26 `new(expr)` calls are parsed correctly. The bundled grammar
  rejects them, so Bifrost parses the file again around that form.

The Rust API `analyzer::collect_go_build_evidence` reads caller-selected
`GoBuildSnapshot` inputs without filesystem fallback or Go execution. Shared
file, byte and row limits and cancellation bound each acquisition.

- `go.mod` and `go.work` retain requirements, indirect annotations,
  replacements, exclusions, declared language/toolchain requirements and
  module/workspace ownership. Local replacements keep their path and an
  unknown version. Missing members and conflicting snapshots remain diagnostic.
- `go.sum` and `go.work.sum` retain checksum observations, including historical
  versions and separate module versus manifest checksums. They do not establish
  selection or installation.
- `vendor/modules.txt` supplies locked evidence only within a validated
  single-module snapshot. Unused replacement headers remain constraints.
  Workspace vendor selection remains partial and uses workspace ownership.

Facts retain exact build-file byte ranges and snapshot digests. Semantic import
paths, pseudo-versions and replacement source identity are preserved. Root
requirements do not establish the MVS-selected graph; toolchain declarations
do not identify an installed toolchain. These acquisition APIs do not yet
publish facts to canonical RQL/CodeQuery or policy execution. Configuration
applicability requires an established relation to the same module.

### JavaScript and TypeScript

- `.js`, `.mjs`, and `.cjs` files use a repaired JavaScript grammar that
  accepts reserved words as JSX attribute names.
- `.jsx` and `.tsx` files use the TSX grammar.
- In `javascript`, `parameter` matches formal parameters in `.js`, `.mjs`,
  `.cjs`, and `.jsx` files when the parameter is a bare identifier, a default
  value (`a = 1`), or a destructuring pattern. A rest parameter (`...args`) and
  a single unparenthesized arrow parameter (`x => x`) do not match.

### Python

- Module identity follows the import-root rules in
  [Project and build inputs](#project-and-build-inputs). The design chapter
  [Identity and Language Front Ends](/design/identity-and-language-frontends/)
  gives the full rules and an example.

The Rust analysis API `analyzer::python_packaging` acquires distribution evidence
from caller-selected project snapshots without starting an interpreter or package
manager. Distribution names use Python packaging normalization; they do not
identify import modules.

- `pyproject.toml` supports project identity, PEP 508 dependencies, optional
  dependencies, PEP 735 groups and `requires-python`. Dynamic metadata stays
  unresolved. Literal setuptools declarations in `setup.py`, structured
  `setup.cfg` declarations, and supported Poetry/uv declaration tables are
  also read without executing project code.
- Requirements roots explicitly request or constrain packages. Local `-r` and
  `-c` includes share file, byte, depth and evidence limits, with cycle and
  unsafe-path diagnostics. Constraints do not establish installation. Unsupported
  options remain diagnostic evidence.
- `uv.lock` version 1 (absent revision or revisions 1–3) and `poetry.lock`
  versions 1.1, 2.0 and 2.1 retain exact PEP 440 versions, sources and conditional
  alternatives. uv direct references to local project entries establish ownership;
  unassociated candidates retain no owner. `associate_python_poetry_lock`
  accepts a caller-established manifest/lock pairing and proves direct
  associations through declaration, source and version agreement. It retains
  the original candidates and cites the declaration snapshot and range.
- Explicitly selected `METADATA` supplies separate installed evidence. It does
  not replace declarations or lock candidates or prove code loading.

Each fact retains its build-file range and snapshot digest. Marker and
extra/group evaluation requires an explicitly supplied target; unsupported
selection, including Poetry group-keyed marker tables and configured-index
selection, remains unknown. Poetry source tables are retained as project
evidence; unresolved index selection cannot establish lock ownership.
`python_version_evidence_disagrees` compares facts only for an explicitly shared
owner with known applicability; it does not infer an installed environment from
lock alternatives. Existing symlink escapes are rejected before snapshot reads.
These acquisition APIs do not yet publish facts to
the canonical RQL/store surface. Configuration applicability requires an
established component relation.

### Ruby

- `raise` is a method call in Ruby, so it does not match the `throw` kind.
  Use a `call` pattern with the callee `raise`.
- Import-file edges come from `require`, `require_relative`, `load`, and
  `autoload` calls with a literal path.

### Rust

- Bifrost indexes items under every `#[cfg(...)]` condition.
- When resolution must decide whether a cfg-gated item is active, it uses
  the host that runs Bifrost: `test`, `debug_assertions`, `unix` or
  `windows`, and the host values of `target_os`, `target_arch`,
  `target_family`, `target_pointer_width`, and `target_endian`. A Cargo
  feature counts as enabled when the package's `default` feature enables it,
  directly or through other features. Bifrost treats any other condition
  as unknown.
