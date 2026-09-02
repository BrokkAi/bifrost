# `ai.brokk.csmi.jvm-symbol` identity profile 0.1

This analyzer-neutral CSMI identity profile identifies JVM binary declarations.
Its scheme identifier is `ai.brokk.csmi.jvm-symbol` and its scheme version is
`0.1`.

## Artifact scope

The enclosing CSMI semantic model supplies one exact Maven PURL and an exact
whole-artifact SHA-256 digest. Package coordinates, versions, and digests never
appear in descriptor paths.

## Descriptor construction

A binary type name is split on JVM package separators. Each package component
is a `namespace` descriptor followed by one `type` descriptor containing the
binary type name component. Names compare as exact Unicode scalar sequences;
the profile performs no case folding or Unicode normalization.

A supported callable appends one `callable` descriptor to its owner type path.
The descriptor name is the JVM member name. Its disambiguator is:

```text
(parameter-type-1,parameter-type-2)->result-type
```

The empty parameter list is `()`. A missing result is `void`. Named types use
their binary names. Generic arguments are enclosed in `<` and `>` and retain
order. Arrays append `[]`, and by-reference types append `&`. Type-parameter
names are exact. Constructors use their analyzer-provided JVM member name;
methods, static methods, and functions use their JVM member name. Bifrost
export rejects properties, fields, constants, macros, events, unnamed
declarations, and type forms outside this list instead of inventing portable
identity.

The portable identity is the enclosing artifact scope, this exact scheme and
version, the ordered descriptor path, and the `portable` stability class.
CSMI local `id` handles and any hashes used to construct them are not semantic
identity.

## Generics, generated declarations, and artifact-local identity

Generic callables are distinguished by their fully expanded ordered parameter
and result type expressions. This version does not separately identify generic
arity, operators, extension members, generated or synthetic declarations,
unnamed declarations, or artifact-local entities. A producer encountering one
of those cases must reject export or use a different identity profile.

## Consumer obligations

A consumer supports this profile only if it constructs and compares every
supported descriptor exactly as above. Unsupported versions are
uninterpretable; a consumer must not compare their descriptor payloads as
opaque strings or fall back to display names.
