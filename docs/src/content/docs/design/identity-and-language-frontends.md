---
title: Identity and Language Front Ends
description: How Bifrost turns partial multi-language source into structured declarations, resolvable identities, and explicit uncertainty.
---

Bifrost uses one analysis vocabulary across languages, while each front end
retains its own rules for names, calls, and types. Tree-sitter provides the
common syntax foundation; language front ends translate that syntax into shared
structural records.

Structured identity connects the shared syntax model to language-specific
resolution. Exact analysis follows declarations, import binders, ownership, and
resolver evidence. Human-readable names and source snippets support presentation
and candidate discovery. Structured resolution supplies proof of which
declaration a program uses.

![A possibly incomplete source file passes through a Tree-sitter grammar and a language adapter into structured declarations and relationships. Resolver outcomes retain proof, ambiguity, incompleteness, and unsupported states.](../../../assets/design-identity-resolution.svg)

## Shared syntax, language-specific semantics

Tree-sitter gives each front end an incremental, error-tolerant concrete syntax
tree with named fields and byte ranges. These properties suit interactive
source: the file may be unsaved, mid-edit, generated in an unfamiliar style, or
valid only under a particular dialect. Bifrost can extract the structure that
remains even when a compiler invocation would fail.

The parser API supplies common tree access. A language adapter retains semantic
ownership: it selects the grammar and dialect, recognizes source files, reads
AST fields, extracts declarations and structured imports, normalizes source
coordinates, and reports parser recovery. Language modules add the rules that
differ: namespaces and packages, visibility, receiver lookup, inheritance,
overload applicability, export and re-export behavior, macro-derived shapes,
and dynamic dispatch boundaries.

Related languages can share a module where their semantics overlap. Current
front ends include families for C and C++, C#, Go, JavaScript and TypeScript,
JVM languages, PHP, Python, Ruby, and Rust. Shared result types let the rest of
the system ask comparable questions. Capability reporting distinguishes an
unsupported relation from an empty one.

## Front-end pipeline

A source file moves through a series of explicit contracts:

1. **Select language and dialect.** File classification chooses the adapter and
   parser configuration. Dialects such as C versus C++, TypeScript versus TSX,
   or JavaScript versus JSX, remain visible to storage and semantic validity
   keys. A dialect is derived from the path alone, because the storage key it
   selects is needed before any source is read.
2. **Parse the exact bytes.** Disk content or an editor overlay is paired with
   its content identity and parsed under a cancellation budget.
3. **Extract structured facts.** The adapter walks tree nodes and fields to
   produce declarations, imports, containment, source ranges, raw hierarchy
   inputs, signatures, and other supported relations.
4. **Assign source identities.** Declarations receive structured names and
   stable source-facing identities; coordinates refer back to the exact file
   snapshot.
5. **Resolve with language rules.** Imports, lexical scopes, owner chains,
   hierarchy, receiver evidence, and callable applicability narrow candidates.
6. **Report an outcome.** A result carries the selected identities, supporting
   evidence, and whether the relevant search was exhaustive, ambiguous,
   incomplete, unsupported, stopped at a budget limit, or cancelled.

The persistent store records extracted relational facts. The parser's in-memory
object graph ends at the front-end boundary. Higher semantic representations
are built as immutable artifacts under their own complete validity keys. See
[Storage and Cache Strategy](/design/storage-and-cache/) for that lifetime split.

## Python hostname-like regex values

Python's `regex_risk_hostname` classifies a decoded pattern value selected from
a recognized `re` call. It identifies hostname-like expressions; it does not
prove that the caller validates a hostname or that the subject came from a URL.
For example, `package.module.py` also has this shape.

The supported shape has at least two ASCII labels with alphanumeric endpoints
and optional interior hyphens. The terminal label consists of at least two ASCII
letters. A host may have a literal `http://` or `https://` prefix, a terminal
slash, and boundary anchors (`^`, `$`, `\A`, `\Z`, or `\z`). Capturing and
noncapturing groups and literal alternatives preserve the shape. Each
alternative must supply its own hostname context; one branch cannot borrow
another branch's terminal label. No TLD registry is consulted.

Every wildcard dot in a separator position produces its own risk fact,
including the separator before the terminal label. Escaped dots and singleton
dot classes such as `[.]` are separators without risks. Thus
`trusted.example.com` produces two facts, `trusted\.example.com` produces one,
and `trusted[.]example[.]com` produces none. Facts retain the exact source spans
after Python string decoding, including escapes and adjacent literals.

Unicode/IDNA processing, IP addresses, ports, trailing root dots, lookarounds,
and quantified expressions are outside this heuristic. In particular, the old
slash-based classifier's acceptance of `trusted.*example.com/` does not extend
the supported shape to quantified wildcard separators. An absence of findings
for a pattern outside the shape does not establish safety. Dynamic or
unsupported patterns retain their separate `regex_incomplete` facts.

## Shared declaration model

The cross-language unit of declared structure is a `CodeUnit`. Its broad kind
can be a class-like declaration, function, field, module, macro, or file scope.
It also carries:

- the normalized workspace-relative source file;
- a structured fully qualified name whose segments retain their roles;
- the boundary between package or namespace and nested ownership;
- an optional signature when the language needs it to distinguish declarations;
- source ranges and containment relationships; and
- whether the declaration is source-written or synthesized.

`CodeUnit` captures distinctions used across queries while leaving specialized
facts in language or semantic layers. A Java overload signature, Rust module
path, C++ qualified owner, and Python nested function share the identity
machinery. Their language-specific resolvers still decide what each name means.

Rendered qualified names serve people and protocols. Resolvers use the
underlying package, type, member, local, and other segments. Reconstructing those
segments from display text discards structure that the front end already knows.

### C++ out-of-line member identities

A file-local extraction can provisionally assign an out-of-line member to a
namespace introduced by `using namespace`. Public symbol reads reconcile the
structured written owner against the classes visible through the source file's
include closure. One shared canonical `CodeUnit` view serves symbol search,
usage scans, definitions, summaries, source labels, and the declaration census.
It preserves the physical source, signature, synthetic status, and structured
segment roles. Range and signature reads follow the canonical-to-physical
mapping back to the immutable extraction facts.

Literal namespace heads can survive parser recovery inside a damaged
function-like wrapper. Their namespace and name ranges remain anchored to the
written keyword and name tokens. Namespace lifetime follows the existing real
brace evidence, rather than the damaged wrapper's body extent. This structural
recovery does not expand opaque macros or remove parser-recovery diagnostics.

For a member written with one class owner, reconciliation validates the exact
physical declaration and name against prepared syntax. Agreeing source records
establish its lexical namespace independently of the provisional identity.
Relative owners try enclosing namespace tiers from inner to outer before the
existing global and using-namespace candidates; an explicit global qualifier
uses only the global scope. Missing or conflicting proof cannot authorize a
new owner. Multi-owner and template reconciliation retain their existing rules.

A class-template member and its out-of-line definition need not spell their
template heads alike. Callable comparison reads each declaration's template
levels from syntax: every enclosing class with the head that introduces its
parameters and the written arguments that select it, then the declaration's
own head. Two levels agree when their heads match position by position in
arity, parameter kind, pack-ness, non-type parameter type and requires-clause,
and their owner arguments match once each side's parameter names are bound
to the other's. Parameter types are then compared under that binding. A
qualifier whose arguments are not the head's own parameters selects a
specialization, a different owner from the primary template. A shape the
comparison cannot align, such as a qualifier spelled through an alias, keeps
the declarations separate.

A class defined identically in two headers is one class, but a shared name
does not prove that. Two complete definitions are one class only when their
template levels agree, their base specifiers agree, and they declare the same
members with the same signatures. A translation unit that includes one copy
then relates to the other copy's member declarations, so definition lookup
from either copy reaches the body, and inverse usages of the body find
references made through either copy. Each source declaration keeps its own
identity: declaration navigation still answers with the copy the reference
can reach.

A qualified member such as `Owner<int>::Alias` belongs to the class its
qualifier selects, not to the primary template the bare spelling `Owner`
names. The qualifier's template arguments select the specialization the same
way an unqualified `Owner<int>` does, including a partial specialization. An
alias qualifier denotes the class its alias declaration names. When the alias
is defined in several conditional arms, only the arms the reference's guards
admit count, and they must agree. Arguments that cannot be bound, an ambiguous
specialization, or alias arms that disagree leave the member undecided:
definition lookup reports it as ambiguous, and inverse usages report the
reference as unproven, never as a proven use of the primary template's member.

Ordinary structured receiver types use lookup at the declaration site and
preserve a selected alias. An ambiguous or missing lexical result cannot fall
back to a pool of unrelated types with the same terminal name. Navigation of
a standalone, non-template global declaration type also preserves its explicit
global qualifier.

The stored blob facts remain independent of the workspace's include graph.
Reconciliation uses byte-bounded identifier and owner cohorts on the immutable
analyzer snapshot; an update or persistent reopening constructs new caches.
Warm identity and physical-provenance reads record the attested C++ scope
(including configuration) for dependency replay. This conservatively invalidates
cached caller results when that scope changes, even when ownership was already
memoized. Only complete results enter those caches. Missing or ambiguous owner
evidence keeps the provisional identity, while cancellation or failed reads retain their
typed incomplete outcome.

Search discovers a superset of potentially canonical names from relational
written-owner and class facts before applying the requested pattern. Include
visibility and ownership are proved by the shared reconciler after candidate
hydration, and the pattern is then checked against the canonical structural
unit. Re-labeling matches selected only by provisional names would lose exact
canonical searches and make the census/scan/search round trip inconsistent.

### JavaScript and TypeScript local declarations

In JavaScript and TypeScript, one declaration is one binding scope plus one
name and kind. Sites that share all three, such as TypeScript overload
signatures with their implementation, an ambient declaration with its
implementation, merged interface or namespace declarations, and repeated `var`
declarations in one function, are several sites of one declaration. Sites
whose binding scopes differ are different declarations, even when their
rendered names match.

A local object created in a function, such as `const options = { ... }`, owns
its properties, so their identities are scoped to that binding: the enclosing
indexed declaration's name, one segment for each enclosing anonymous function
or block that binds the object, and then the local name. `let` and `const`
bind to their block; `var` binds to the function, so `var` sites in separate
blocks stay one declaration. A function's own body adds no segment.
Properties assigned through a parameter or through a local that holds an
object from elsewhere keep a file-scoped name, because that object can be
shared with other functions.

A bound CommonJS-shaped receiver (`exports` or `module.exports`) in a bundled
module factory belongs to its lexical binding. Its members include that binding's
structured scope segments, so independent factories assigning `exports.default`
produce independent declarations. A closure using the same outer binding does
not introduce another identity. Repeated assignments to the same member of that
binding remain multiple sites of one declaration.

The free `exports` object and the free `module.exports` object expose this file's
exports. A factory parameter has that role only when direct argument-to-parameter
evidence connects it to one of those objects. This includes a UMD callback passed
to an immediately invoked wrapper, whose body calls that exact callback with the
free exports object. Other UMD branches may call the same factory with a global
object; they do not erase its CommonJS export surface. Shadowed, reassigned,
spread, defaulted or otherwise unproved inputs do not establish this provenance.
The extractor follows immutable local aliases and direct calls; it does not
interpret arbitrary JavaScript. Unproved bound receivers retain lexical identity
rather than claiming the file export surface.

These distinctions use the existing structured qualified-name inputs to
`DeclarationId` v1. They change extracted facts and therefore advance both
language extraction epochs; they do not change the `decl:v1` digest recipe.

### Module and package source anchors

A source-declared module uses its declaration item as its primary range.
Rust's `pub mod m;` anchors in the declaring file, whether its contents live in
`m.rs` or `m/mod.rs`; its signature is the declaration's source text. Inline
Rust modules keep the range of their `mod m { ... }` item. Java packages likewise
retain their `package` declaration ranges. Navigation selects the name token
inside that item, as it does for other source declarations.

A file-backed module with no declaration token, such as a Python package's
`__init__.py`, navigates to the start of its backing file. A same-named class or
reference inside that file is not a declaration of the module. Go records
package membership and package-owned declarations rather than manufacturing a
single package declaration spanning all its files.

Rust crate roots reached through Cargo have a file-scope unit covering the root
source file, starting at byte zero (line 1, column 1 for clients). In the absence
of a `mod` item, Bifrost does not invent a module declaration or a `mod` signature
for that directory. A namespace-only lookup can therefore report no single
indexed declaration. The file-scope anchor remains available without choosing
an unrelated declaration as the crate's definition.

## Identity vocabulary

Different representations have different identity lifetimes. Treating all of
them as a "symbol ID" risks reuse outside the boundary where an ID is valid.

| Identity | What it contains | Valid use | Important limit |
| --- | --- | --- | --- |
| `DeclarationId` | A versioned digest of language, normalized relative path, declaration kind, structured qualified-name segments, package boundary, signature, and synthetic status | Referring to the same extracted declaration across processes that implement the same identity recipe | A move, rename, signature change, or identity-version change can produce a new ID |
| Declaration site ID | One `DeclarationId` plus an exact half-open byte span | Referring to one source site of an extracted declaration | The span changes when that declaration site moves or changes extent |
| Semantic locator | Logical workspace mount, relative path, language, lexical declaration segments, semantic role, and source anchor | Finding or remapping source-facing semantic entities and explaining their origin | Requires a separate cache-validity key |
| Stable locator digest | The stable source-facing portion of a semantic locator, excluding the absolute checkout mount | Comparing equivalent source identities across checkout locations | Artifact inputs and dependencies still need independent validation |
| Semantic artifact key | The source revision or overlay content, logical mount and relative path, language, adapter and IR versions, configuration, and dependency fingerprints | Reusing one exact immutable semantic artifact | It contains more validity inputs than a locator |
| Dense procedure, block, value, or call-site ID | A compact index owned by one immutable artifact or graph | Fast graph construction and analysis within that owner | It has no meaning without the exact artifact or graph that owns it |
| Display name and source range | Human-readable rendering and coordinates | Diagnostics, navigation, and candidate discovery | Neither is exact declaration identity |

`DeclarationId` excludes an absolute checkout root and process-local interner
numbers, so byte-equivalent checkouts with the same relative structure can
produce the same ID. Moves, renames, signature changes, and identity-recipe
changes can still mint a different ID. A semantic locator provides a remappable
source-facing address. Artifact reuse is governed by the larger cache key.

Grammar upgrades must invalidate every affected representation. The analysis
epoch fingerprints the live grammar's ABI, node kinds and field names; it does
not hash the generated parse tables. A parser correction can therefore leave
that fingerprint unchanged. When it does, rotate the language epoch salt for
every affected dialect, including dialects that share another language's
parser. Semantic artifacts have a separate validity key: rotate their adapter
version when the changed parse can change those artifacts. Validate upgrades
against an existing persisted store as well as a fresh one.

Every public RQL row field that names an indexed declaration uses the same
`decl:v1:<hex>` `DeclarationId`, including role-specific aliases such as
`target_id`, `procedure_id`, and `declaration_id`. A full-detail declaration
also carries `site_id`; it is the declaration ID plus that row's exact byte
span. Display names, line/column ranges, and semantic-model wire IDs are not
inputs to either identity. Semantic-wire and canonical-AST owners remain
separate identity domains and retain an explicit derivation.

Dense IDs are artifact-local and interpreted with the immutable artifact or
graph that assigned them. A bare value ID in storage, or a call-site comparison
across artifacts, has lost that required owner.

## Structured resolution

Resolution applies language-defined transformations to structured facts.
Candidate selection follows resolver evidence; unresolved ties remain
ambiguous.

### Imports, packages, and lexical ownership

Import extraction preserves parser-derived path segments, import kind, lexical
scope, aliases or binders, and declaration position. A resolver can therefore
distinguish a namespace import from a static member import, or a local alias
from a declaration that merely has the same spelling.

Language rules decide which prefixes are absolute, package-relative,
module-relative, nested-owner, exported, or otherwise visible. The shared
layer carries the paths and candidate identities; the language front end owns
the interpretation. Parsing import text with delimiters would lose exactly the
grammar distinctions the resolver needs.

### Python import roots

Each language front end reads its own project files to assign identities. For
example, Go import paths come from the nearest `go.mod`, and JavaScript and
TypeScript path aliases come from `tsconfig.json`. The
[Languages reference](/reference/languages/#project-and-build-inputs) lists
the project files for every language. This section describes the Python rules
in detail.

Python module identities start at a supported packaging import root when one
contains the source file. Bifrost searches ancestor directories, preferring the
nearest project and the deepest containing root. It reads
`tool.setuptools.packages.find.where` from `pyproject.toml`.

Packaging declarations and `__init__.py` membership come from the selected
project snapshot, including unsaved overlays. They determine mounted names;
content-addressed declaration names retain only their tails. A change to these
inputs reprojects package placement, while older snapshots keep their names.
Retained naming and binding read the selected revision's configuration bytes
from SQLite, including the absence of a manifest or marker. Later disk edits
cannot change an older snapshot's exact lookup names; an explicit new logical
project selects its own inputs when rebuilding.

Legacy `setup.py` files can also establish a root. Bifrost parses the
Python syntax without executing the script and recognizes a direct call to an
imported setuptools or distutils `setup` function with a `packages` argument:
a literal `package_dir` mapping (`{}` or `{"": "source"}`) establishes the root
regardless of the packages expression and takes precedence over discovery.
Without `package_dir`, a nonempty literal package collection uses the script
directory, while calls to imported setuptools `find_packages` or
`find_namespace_packages` (including aliases) use their literal `where` argument
or the script directory when omitted; dynamic roots and argument expansions do
not establish a root. The selected directory is the import root even if it
contains `__init__.py`. For example, Wirecloud's
`src/setup.py` declares `packages=('wirecloud',)`, so
`src/wirecloud/commons/utils/testcases.py` has module identity
`wirecloud.commons.utils.testcases`.

A filename such as `src`, an empty `__init__.py`, or the presence of `manage.py`
alone does not establish a root. Unsupported dynamic packaging arguments do not
supply a default root. Without supported packaging evidence, the existing
outermost `__init__.py` package convention remains in effect; namespace paths
without such a package retain their workspace-relative components. Import
resolution and workspace-boundary checks use these same indexed identities.
They do not search for matching suffixes or add alternate module names.

### Aliases

Definition navigation answers with what the selected token binds. A C or C++
`typedef` or `using` alias name therefore navigates to the alias declaration,
not to the type the alias names. Type lookup (`get_type_by_location`),
receiver typing, and member lookup follow the alias to that type. An alias
template applied to arguments, such as `Node<Item>`, is the exception: it
navigates to the class specialization its arguments select. An alias
redefined in the branches of one `#if`/`#elif`/`#else` chain is one
declaration, so navigation answers with one branch rather than an ambiguity.
When identical aliases are copied into several headers, navigation selects the
copy the reference can reach through its include closure.

### Hierarchy and members

Adapters extract declared supertypes and owner relationships from AST fields.
Language-specific hierarchy resolution then connects those references to
declaration identities under the relevant package, import, generic, and
visibility rules. Member search follows resolved owners and hierarchy evidence.
Equal short display names leave type identity unresolved.

An unresolved supertype remains an unresolved edge. The raw structured
reference stays available for later resolution and retains its unresolved
status until new evidence proves the relationship.

### Calls, receivers, and argument binding

Call extraction records a typed call kind, receiver shape, ordered argument
groups, and whether that shape was extracted completely. Resolver evidence
narrows possible callees using the language's dispatch and applicability rules.
Actual-to-formal binding requires structured rows joined to stable call and
declaration identities.

Python's call syntax does not distinguish a function from a class invocation.
RQL call-shape rows refine a Python call to `constructor` only when the
production definition resolver selects exactly one workspace or active
semantic-model class declaration; unresolved or ambiguous callees keep their
syntax-derived kind.

The result can distinguish:

- one applicable target with exact binding;
- multiple applicable targets that remain ambiguous;
- a useful candidate set from partial receiver or argument evidence;
- an unresolved name after an exhaustive supported search;
- a dynamic or macro-derived call whose shape is unknown; and
- a language feature for which the front end has no supported resolver.

The binder accepts the resolver's selection. If several overloads survive,
binding remains ambiguous.

## Partial source and parser recovery

Interactive source is often temporarily invalid. Tree-sitter can recover a
tree containing `ERROR` or missing nodes, and Bifrost retains those recovery
regions. Structure outside them can remain useful: a declaration that parsed
cleanly may still be navigable even when a neighboring expression is
unfinished.

Parser and semantic status are tracked separately:

- **parse job complete** means extraction finished for the exact input bytes and
  the resulting fact set can be published atomically;
- **syntax clean** means no relevant parser recovery was required; and
- **semantic analysis complete** means the requested capability covered its
  declared scope without encountering an unsupported construct, cancellation,
  or exhausted budget.

A fact set for a file with parser errors can still be published once extraction
finishes for the exact bytes. Publication says that extraction completed; the
syntax and semantic-recovery statuses remain separate. A query whose proof
crosses a damaged region retains that limitation.

Structural facts record each recovery region as a row: an outermost `ERROR`
node, or a zero-width missing token. A node inside an `ERROR` region may have
produced no structural fact, so a structural selection that finds nothing in
that file is not an authoritative absence. The selected kind decides which
regions count. Statement-level kinds (conditionals, loops, returns, throws,
handlers, and resource releases) occur only in executable code, so only a
region inside a callable leaves their selection incomplete. Every other kind
can also occur in an initializer, an annotation, or a declaration list, so any
region in the file leaves its selection incomplete. The store answers whether a
callable contains a region from the persisted facts. Rows found elsewhere in
the file remain valid positive evidence.

Parser timeout or cancellation leaves the extraction job unfinished, so
publication is refused under the shared
[complete-value cache contract](/design/storage-and-cache/).

## Proof, ambiguity, and completeness

Bifrost treats candidate discovery and proof as separate stages. A structural
match can remain useful when the resolver cannot prove a unique binding. The
result identifies which kind of evidence it contains.

The exact outcome vocabulary varies by capability. These distinctions stay
stable:

- **proven** means the language resolver supplied the required relationship;
- **ambiguous** means structured evidence supports more than one surviving
  identity;
- **incomplete** means some relevant search space was not examined or could not
  be constructed;
- **unsupported** means the requested relationship is outside the front end's
  declared capability; and
- **budget exhausted or cancelled** means the request stopped before reaching
  its normal semantic boundary.

Proof and completeness are independent. One proven edge can be returned from a
partial search; the response cannot claim that no other edge exists. An
empty result is authoritative only when the applicable resolver completed an
exhaustive supported search in the stated snapshot and scope. The
[Evidence and Result Contract](/design/evidence-and-results/) develops this rule at
the API boundary.

## Exact-claim discipline

Several guardrails follow from the identity model:

- use AST fields, structured name segments, import binders, declaration IDs,
  semantic locators, and resolver evidence for exact claims;
- use source text or textual search for candidate discovery; proof requires
  structured resolver evidence;
- do not recover a structured path by splitting its rendered display name;
- do not select one declaration only because it is the first or nearest item
  with the requested short name;
- retain all supported candidates when evidence is ambiguous; and
- return typed incomplete or unsupported outcomes when the front end lacks the
  structure needed to decide.

Protocol strings are presentation data. Exact results still carry the identity
and provenance behind them.

## Adding or extending a language front end

A front-end contract covers grammar registration and the following boundaries:

1. file and dialect classification;
2. declaration, qualified-name, signature, and containment extraction;
3. structured import and scope representation;
4. hierarchy, receiver, callable, and reference capabilities;
5. source recovery, generated-code, and macro behavior;
6. identity and semantic-version inputs used by persistent and in-memory
   artifacts; and
7. the outcome returned for constructs it cannot resolve exactly.

Tests should pair realistic positive cases with near misses: same short name in
another owner, shadowed binders, ambiguous overloads, unresolved imports,
partial source, and unsupported dynamic shapes. The common contract requires
truthful coverage: every supported result says what evidence established it,
and every gap remains visible.

## Coverage by capability

A language can support syntax search before it supports exact calls or dataflow.
Each exact capability ships with its corresponding identity and resolver
contracts. Coverage still differs by language adapter. The
[Languages reference](/reference/languages/) lists the current coverage for
each language: file extensions, graph and analysis capabilities, structural
kinds and roles, and semantic IR features.
