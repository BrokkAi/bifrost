# CSMI value-transfer profile 0.1.0

This document defines `csmi.value-transfer` version `0.1.0`. The normative
schema is `profiles/value-transfer/0.1/schema.json`, identified by
`https://csmi.brokk.ai/schema/profiles/value-transfer/0.1/schema.json`.

The profile says how a core procedure-summary transfer crosses into a distinct
destination value and storage identity. It adds no second endpoint model and
no occurrence identifier. Core `source` and `destination` locations remain the
only portable endpoints.

## Transfer attachment

A `transfer` payload attaches directly to one core `procedureSummaries[]`
`transfers[]` entry at attachment point `procedure-summary-transfer`. The
required vocabulary use MUST declare that attachment point with target
`{ "callable": <enclosing summary callable> }`.

The structured `transferKind` is one of:

- `copy`, `aggregate-copy`, `boxing`, or `unboxing`;
- `move` with source `invalidation` of `invalidated` or `unknown`; or
- `conversion` with `preservation` of `identity`, `preserving`, `changing`, or
  `unknown`.

The transfer itself asserts identity separation. References, pointer aliases,
and shared backing-store relations MUST NOT carry this attachment. A copy
followed by source mutation remains a copy of the value at the transfer point;
the attachment does not make later source state part of the destination.

`operation` is `none`, `unknown` with a typed limitation, or `implicit` with an
exact local callable symbol. An implicit symbol MUST resolve to exactly one
matching fact in the `implicit-operations` family. Names, rendered signatures,
source text, regexes, and producer-local database identity are not substitutes.

## Type value semantics

`type-value-semantics` is split into independent, single-valued aspects. Its
scope is exactly `{ "type": <local type symbol>, "aspect": "copy" }` or the
same shape with `move`. The payload repeats that type and aspect.

Copy semantics are `trivial`, `via-member`, `unknown`, or `unsupported`. Move
semantics are `invalidating`, `unknown`, or `unsupported`. A copy `via-member`
symbol MUST be owned by the scoped type and have the copy-constructor
implicit-operation role. Exact move-constructor identity remains an independent
implicit-operation fact; type-wide invalidation does not claim that every move
uses one member. Assignment members remain exact operations, but do not satisfy
type-wide construction semantics.

Absence is open-world. `unknown` and `unsupported` preserve inability to state
the behavior and are not negative facts.

## Exact implicit operations

`implicit-operations` is set-valued at exact scope
`{ "owner": <type>, "operation": <role> }`. Conversion-operator scopes also
include `target`. Each fact supplies one exact local callable `symbol`; multiple
facts in the same scope remain multiple candidates until complete coverage and
consumer rules establish otherwise. The symbol declaration owner MUST equal
the scoped owner. Conversion targets MUST resolve to local type declarations.

Fact equality includes exact vocabulary version, family, scope, and payload.
Conflicting or ambiguous sets remain observable; consumers MUST NOT select by
input order.

## Completeness and support

Every affected attachment and fact scope MUST be declared by one required
vocabulary use. Complete type-aspect coverage cannot contain `unknown` or
`unsupported` semantics. A transfer with unknown operation, move invalidation,
or conversion preservation remains usable positive evidence, but no consumer
may strengthen the unknown field.

Core `procedure-summaries` completeness closes only the set of core
may-transfers. It does not prove that every transfer has been classified by
this profile or that an attached operation, invalidation, or preservation is
exact. The profile family `identity-separating-transfers`, scoped by callable,
closes only that classification. It cannot be complete when an attachment in
the scope retains an unknown field. Type-value, implicit-operation,
identity-separating-transfer, and core procedure-summary completeness remain
independent. Unsupported required profile semantics are uninterpretable, never
a complete empty result.

## Initial executable evidence

The canonical C++ fixture is grounded in Bifrost issue #2846 at native commit
`8a724c2d2e9975831519b6cdbda0d38ee00dd203`. It demonstrates resolver-proven
`std::basic_string` copy construction, an exact member role, independent
destination identity, and reference/pointer/custom-type near misses. Reserved
move and conversion forms do not claim implemented adapter support for C++ or
for C#, Go, Rust, Java, Kotlin, or Scala.
