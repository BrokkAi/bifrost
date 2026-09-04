# CSMI C and C++ interoperability profile 0.1.0

This document defines a C/C++ profile family for CSMI 0.1. It is normative.
The authoritative payload schema is `profiles/cpp/0.1/schema.json`.

| Identifier | Version | Language boundary | Purpose |
| --- | --- | --- | --- |
| `csmi.c-cpp-resolution` | `0.1.0` | C and C++ | Translation-unit arguments, directly reached exact headers, and complete header-closure applicability. |
| `csmi.cpp` | `0.1.0` | C++ only | Structured alias and exact special-member facts. |
| `csmi.cpp.declaration` | `0.1.0` | C++ only | Portable resolver-proven C++ declaration identity scheme. |

The profile is deliberately narrow. It standardizes only the structured
identity and applicability evidence needed to carry the C++ `std::string`
alias, its exact `std::basic_string<char, std::char_traits<char>,
std::allocator<char>>` target, and the target's copy constructor, copy
assignment, and move-constructor declaration identities. It does not standardize a general C++ ABI,
overload resolver, template instantiator, standard-library inventory, or
source parser.

## 1. Support and requiredness

A producer or consumer claiming support MUST implement the exact identifier
and version it declares, this document, the profile schema, the `cppsig-0.1`
construction below, and the applicable normative cases in
`conformance/cpp-profile.md`. Schema validation alone is not semantic support.

Every use that affects identity, alias resolution, applicability, operation
selection, a `csmi.value-transfer` fact, or completeness MUST be `required`.
A consumer that does not support the exact required identifier and version
treats dependent facts as uninterpretable. It MUST NOT recover them from a
rendered name, signature, source fragment, native declaration id, or
producer-local handle.

## 2. Artifact applicability and resolution context

C and C++ declarations have portable meaning only inside exact artifact and
resolver evidence. Every artifact selector embedded by this profile therefore
has at least one SHA-256 digest. A coordinate without exact bytes is
insufficient for system headers, locally installed libraries, generated
headers, or implementation-selected standard libraries.

A `csmi.c-cpp-resolution` `resolution-context` compatibility value records the
SHA-256 digest of its ordered compiler argument vector, every directly reached
header used by a covered fact, and a `complete` header closure. The argument
digest is over RFC 8785 canonical JSON for the ordered vector; arguments retain
order. A `contextDigest` is lowercase hexadecimal SHA-256 over RFC 8785
canonical JSON of the complete `resolution-context` value. The context is
`compatible` only when the candidate translation unit,
ordered arguments, direct-header selectors and digests, and complete closure
are all established and equal. A comparable mismatch is `incompatible`.
Missing inputs or an incomplete header closure are `indeterminate`; an
unsupported required profile is `uninterpretable`. All non-compatible results
fail closed.

This context vocabulary is shared by C and C++. It makes no claim that C has
C++ aliases, templates, constructors, assignment operators, or value-category
rules. `type-alias` and `special-member` payloads belong exclusively to
`csmi.cpp`; each carries language `c++` and an exact required reference to a
compatible `csmi.c-cpp-resolution` context. Applying either payload to C, to a
different context, or to a partial header closure is non-conforming.

The core artifact selector is evaluated independently and first. A favorable
compilation context never repairs a non-matching or indeterminate artifact.
Paths and include spellings are evidence for the resolver result, not artifact
or declaration identity.

## 3. Portable declaration identity

A portable C++ declaration uses scheme `csmi.cpp.declaration`, scheme version
`0.1.0`, stability `portable`, and exact-content artifact selectors. Its
descriptor sequence is built from resolver ownership, not textual spelling:

- a namespace descriptor has role `namespace` and disambiguator `namespace`;
- a class-template primary has role `type` and disambiguator
  `template-primary:<arity>`;
- a type alias has role `type` and disambiguator `type-alias`; and
- a covered callable has role `callable` and disambiguator
  `cppsig-0.1:<digest>`.

The `std::basic_string`, `std::char_traits`, and `std::allocator` primaries in
the canonical positive case are distinct declarations under the resolver-proven
`std` namespace. Their terminal descriptors are respectively
`template-primary:3`, `template-primary:1`, and `template-primary:1`.
`std::string` is a distinct `type-alias` declaration. Equal terminal names,
equal arity, an enclosing namespace spelled `std`, or equal generated native
ids do not prove any of these identities.

Template specializations are canonical type expressions, not new declaration
keys in this version. A `template-specialization` names its primary by its full
portable symbol key and retains its ordered arguments. `char` is the fundamental
type `{ "kind": "fundamental", "name": "char" }`. This version defines no
fallback for typedef expansion, canonical type printing, mangled names, or
unrepresentable template arguments.

## 4. Exact alias relation

A `type-alias` fact relates an alias symbol handle to one canonical target type
and to the exact resolution context that proved it. For the canonical
`std::string` case the target MUST be exactly:

1. the resolver-proven `std::basic_string` primary;
2. fundamental `char`;
3. `std::char_traits<char>` using its resolver-proven primary; and
4. `std::allocator<char>` using its resolver-proven primary.

The alias remains a declaration distinct from its target. Consumers use the
relation when selecting type-wide value semantics; they do not replace the
alias symbol's identity. A same-named `custom::basic_string`, an alias with a
different traits or allocator argument, an unresolved primary, or a target
derived from display text does not acquire the standard target.

## 5. Exact special-member declaration identities

The only callable identities standardized by version `0.1.0` are the exact
copy constructor, copy assignment, and move constructor of the resolved
`basic_string` primary.
Their terminal disambiguator is `cppsig-0.1:<digest>`, where `digest` is
lowercase hexadecimal SHA-256 over RFC 8785 canonical JSON of the complete
`callableSignature` object.

The canonical type tree is closed: `fundamental`, `declared`,
`template-specialization`, `qualified`, and `reference`. A `declared` node
contains the complete portable symbol key. Qualifiers are a set ordered
lexicographically before hashing. Parameter order and template argument order
are semantic and retained.

The copy-constructor fact MUST have operation `copy-constructor`; its signature
has callable kind `constructor`, no receiver or result field, and one
lvalue-reference parameter to const owner. The copy-assignment fact MUST have
operation `copy-assignment`; its signature has callable kind `method`, an lvalue-reference
receiver to the owner, one lvalue-reference parameter to const owner, and an
lvalue-reference result to the owner. The referenced owner key MUST equal the
owner key in every position.

Native evidence through Bifrost commit
`8a724c2d2e9975831519b6cdbda0d38ee00dd203` proves an exact move constructor
for a non-const by-value `basic_string` parameter returned by value. Its fact
has operation `move-constructor`; its signature has callable kind
`constructor`, no receiver or result field, and one rvalue-reference parameter
to the unqualified owner. The same evidence declines named-local return when
NRVO makes transfer identity conditional and preserves typed incompleteness
for a const by-value parameter that cannot select the move.

The operation classification does not participate in the declaration digest;
it is checked against the canonical signature. No rendered signature, method
name, overload ordinal, parameter count alone,
source location, mangled name, compiler AST id, generated pack id, or
producer-local symbol handle participates in the digest. If exact resolution
finds zero or multiple candidates, the operation is unresolved. The producer
MUST preserve incomplete or conflicting coverage and MUST NOT emit an exact
operation identity.

The operation identity proves only which declaration was selected. Whether a
value transfer is a copy or move, whether its source value is preserved,
whether destination storage is distinct, and whether a move invalidates a
source are language-neutral facts in `csmi.value-transfer`, not CSMI core and
not facts inferred by this profile. This profile neither infers those facts
from a callable name nor converts pointer or reference aliasing into a value
copy.

## 6. Family keys, conflicts, and completeness

`type-alias` facts are keyed by alias symbol; `special-member` facts are keyed
by owner symbol and operation. Equal keys with unequal targets, signatures,
digests, or resolution contexts conflict. Consumers preserve the conflict and
do not choose by input order.

Completeness is scoped to one exact artifact selector set, resolution context,
owner declaration, fact family, and this exact profile version. A complete
header closure plus one exact operation is not evidence that every overload,
special member, template specialization, or standard-library declaration was
modeled. Unresolved declarations, ambiguous provenance, unsupported type
shapes, cancellation, or exhausted bounds prohibit a complete claim for the
affected scope.

## 7. Bounds

The executable reference for this profile boundary is Bifrost commit
`8a724c2d2e9975831519b6cdbda0d38ee00dd203`. The profile standardizes only the
portable evidence visible at that checkpoint; Bifrost pack ids, generated
declaration ids, and semantic IR handles remain producer-local.

Producers MUST apply finite limits to header traversal, declarations,
specializations, canonical type depth, and diagnostic retention. Crossing a
limit yields a typed partial, unknown, cancelled, or budget-exhausted outcome.
It never yields a complete-empty result. The profile does not prescribe numeric
limits because they are producer capabilities; producers record the applicable
core completeness limitation and provenance.
