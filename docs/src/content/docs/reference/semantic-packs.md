---
title: Semantic Pack Reference
description: Every field of the semantic-model pack format, the .bifrost/packs.json document, the shipped packs, and the pack commands.
---

This page lists every part of the semantic-model pack format and the tools that
work with it. For an explanation of how packs are authored, activated, and used,
read [Semantic-Model Packs](/semantic-model-packs/).

The sources of truth are the Rust types that the JSON schema is generated from,
the pack validator, the embedded pack registry, and the command-line parsers.
You can print some of these lists from a binary:

| Command | Prints |
| --- | --- |
| `bifrost pack-engine-profile` | The pack schema versions this build reads and writes, as JSON. |
| `bifrost-semantic-pack` with no arguments | The usage text for every authoring subcommand. |
| `bifrost-semantic-pack list CATALOG --format json` | Every pack installed in a catalog. |

## Schema versions

Every authored pack declares `schema_version`. This build reads versions `2`
through `18`, inclusive. Its newest version is `18`. Version `1` and
any other value fail with `schema.unsupported_version`. The field is
required; there is no default.

`bifrost-semantic-pack generate` writes each pack produced from a pinned
artifact at the lowest version its content needs: the highest version gate in
the table below that the content meets, and never below `8`. A pack that uses
no field newer than version 8 is written as version 8, so a reader that predates
later fields still accepts it. A pack loaded from an `authored_semantic_model`
spec keeps the version its author declared.

A field is accepted only in a pack whose `schema_version` is at least the
version that introduced it. A pack that declares an earlier version and uses
the field fails validation with the code in the table. This rule lets a reader
of an older version parse every pack that it accepts by number.

| Version | Adds | Validation code when used below this version |
| --- | --- | --- |
| 2 | The base format: envelope, shards, and the three payload kinds. Every field not listed below. | None |
| 3 | `ambient_use` on `TypeFact` and `MemberFact`. | `schema.ambient_use_requires_version` |
| 4 | The `runtime_contracts` shard companion (CSMI runtime-values 0.2). | `runtime_contracts.schema_version` |
| 5 | `result_use_obligations` on procedure summaries. | `summary.result_use_obligations_schema` |
| 6 | `callable_surface_complete: true` on `TypeFact`. | `schema.callable_surface_version` |
| 7 | `no_concurrency_effects: true` on procedure summaries. | `summary.no_concurrency_effects_schema_version` |
| 8 | Removes `compatibility.bifrost`. A version-8 pack must omit it. See [Compatibility](#compatibility). | Not a field gate. `compatibility.bifrost` is required below version 8 and forbidden at version 8 (`compatibility.schema_shape`). |
| 9 | `kind: unknown` for a parameter or result type port whose type is unavailable. The port remains present with an unresolved type. | `schema.unknown_type_version` |
| 10 | Native callable-values facts and scoped coverage on authored shards. | `schema.callable_values_version` |
| 11 | Structured procedure-formal names, passing modes, and default-presence facts for call binding; channel-close effects and returned-callable models. | `summary.formals_schema_version`, `summary.channel_close_schema_version` |
| 12, 13 | Merged contract revisions. No additional field-version gate. | None |
| 14 | Directional variadic kinds on structured procedure formals. | `summary.formals_schema_version`, `summary.variadic_formals_schema_version` |
| 15 | Typed module values (`value_type`, `proxied_type`) and callable parameter roles. | `declaration.module_value_type_schema_version`, `parameter.role_schema_version` |
| 16 | Non-empty `exact_return_classes` on members. | `declaration.exact_return_classes_schema_version` |
| 17 | Ordered, exhaustive `runtime_bases` on Python class facts. | `declaration.runtime_bases_schema_version` |
| 18 | Rust generic defaults, implemented-trait facts and associated bindings, generic forwarding impls, self forms, and associated-type projections. | `declaration.rust_contract_schema_version` |

### JSON schema files

The generated JSON schema is
[`schemas/semantic-model-pack-v18.schema.json`](https://github.com/BrokkAi/bifrost/blob/master/schemas/semantic-model-pack-v18.schema.json).
`cargo run --example generate_semantic_model_schema` writes it from the Rust
type `AuthoredSemanticModelPack`, and a repository test requires the
checked-in file to match the generated schema exactly. The file describes
every field of every supported version, and it accepts `schema_version` from
`2` through `18`. It requires `compatibility.bifrost` for versions `2` through
`7` and forbids it for versions `8` and newer. It does not express the other
per-field version gates in the table above; the validator enforces them.

The schema files for earlier versions remain checked in; there is no v7 file.
The v8 file accepts versions `2` through `8`, requires `compatibility.bifrost`
through version `7`, and forbids it for version `8`.

## Pack envelope

An authored pack is one YAML or JSON document. Every object rejects unknown
fields. Every variant is tagged by a `kind` (or `op`) field.

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `schema_version` | integer, 2 to 18 | yes | The pack format version. See [Schema versions](#schema-versions). |
| `pack_id` | stable ID | yes | The pack identity. |
| `version` | SemVer version | yes | The pack version. |
| `producer` | `{name, version}` | yes | The tool that produced the pack. `name` is non-empty text; `version` is a SemVer version. |
| `language` | stable ID | yes | The language the pack describes, for example `java`, `go`, or `python`. Activation evidence must name the same language. |
| `ecosystem` | stable ID | yes | The ecosystem label, for example `maven`, `npm`, `pypi`, `go`, `go-module`, or `jdk`. Activation evidence must name the same ecosystem. |
| `compatibility` | object | yes | See [Compatibility](#compatibility). |
| `provenance` | `{source, revision?}` | yes | Where the facts came from. Both are non-empty text. `revision` is optional. |
| `license` | text | yes | An SPDX license expression. An invalid expression fails with `license.invalid_spdx`. |
| `completeness` | `partial` or `complete` | yes | Whether the pack claims to cover its whole scope. A `partial` pack cannot contain a `complete` procedure summary. |
| `safety` | object | yes | See [Safety](#safety). |
| `carried_sources` | list of relative paths | no (default empty) | The source paths the producer read and parsed from a sources artifact. Paths must be unique and sorted in ascending order (`carried_sources.unsorted`). A consumer uses this list to tell a source path that the pack carries from an upstream path that it only names. |
| `cpp_portability` | object | no | Exact C and C++ resolver evidence imported from CSMI. See [C++ portability evidence](#c-portability-evidence). |
| `python_correspondence` | object | no | Python declaration-to-runtime correspondence imported from CSMI. See [Python correspondence evidence](#python-correspondence-evidence). |
| `shards` | list of shards | yes | At least one shard (`pack.no_shards`), at most 4,096. See [Shards](#shards). |

A **stable ID** is 1 to 256 bytes of lowercase ASCII letters, digits, `.`,
`-`, and `_`. It must start and end with a letter or digit. Pack IDs, shard
IDs, and fact IDs use this grammar. Language-facing names such as type and
member names keep their ordinary spelling.

### Compatibility

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `bifrost` | SemVer requirement | Required in versions 2 to 7. Forbidden in version 8 and newer. | The engine versions that may activate a version 2 to 7 pack. An engine outside the range reports the pack as `incompatible`. A missing or blank value in versions 2 to 7, or any value in version 8 and newer, fails with `compatibility.schema_shape`. A value that is not a SemVer requirement fails with `version.invalid_requirement`. A `null` value fails to parse. |
| `toolchains` | list of `{name, requirement}` | no (default empty) | Toolchains the pack is compatible with. `name` is a stable ID. `requirement` is a SemVer requirement. A shard selector may name a toolchain only if this list declares it (`selector.incompatible`). |

`validate` accepts an open requirement such as `>=21.0.0` in an authored pack.
Only pinned release specs require an upper bound; see
[Pinned pack specs](#pinned-pack-specs).

### Safety

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `generated_code_only` | boolean | `false` | The pack describes only code that a generator produces, such as accessors. |
| `review_required` | boolean | `false` | The pack stays inactive until an activation control with action `enable` names its `pack_id`. The `enable` list in `.bifrost/packs.json` supplies such controls. |

## Shards

A shard is the unit of activation and loading.

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `id` | stable ID | yes | The shard identity. |
| `activation` | list of activation selectors | yes, at least one | The shard is eligible when any selector matches one activation evidence row. See [Activation selectors](#activation-selectors). |
| `payload` | object | yes | One payload, tagged by `kind`. See [Payload kinds](#payload-kinds). |
| `runtime_values` | object | no | CSMI runtime-values 0.1 companion. See [Shard companions](#shard-companions). |
| `runtime_contracts` | object | no, version 4 or later | CSMI runtime-values 0.2 companion. |
| `collection_flows` | object | no | CSMI collection-flow 0.1 companion. |
| `deferred_yields` | object | no | CSMI deferred-yield 0.1 companion. |
| `conditional_type_refinements` | object | no | CSMI conditional-type-refinement companion. |

A shard must contain at least one record across its payload and companions
(`shard.empty_payload`). A shard may hold at most 250,000 records and a pack at
most 2,000,000.

### Activation selectors

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `package` | `{name, version?}` | absent | Requires an evidence row with a package of this exact name. When `version` is present, it is a SemVer requirement that the evidence version must satisfy. |
| `module` | `{name, version?}` | absent | The same rule for a module coordinate, such as a Go module path. |
| `toolchain` | `{name, version?}` | absent | The same rule for a toolchain, such as `jdk`. The name must appear in `compatibility.toolchains`. |
| `targets` | list of stable IDs | `[]` | When not empty, the evidence `target` must equal one entry. |
| `configurations` | list of text | `[]` | When not empty, the evidence `configuration` must equal one entry. Entries are stable IDs, except that entries starting with `typescript-lib:` may be any non-empty text. |
| `artifact_sha256` | 64 lowercase hex characters | absent | Requires an evidence row with exactly this artifact digest (`selector.invalid_digest` for a bad value). |

A selector with no coordinates is a language selector. It matches any evidence
row with the pack's language and ecosystem. Missing evidence never satisfies a
populated field. All populated fields must match the same evidence row.

Each selector has a rank: an `artifact_sha256` selector is an exact-artifact
match; otherwise a selector with any coordinate `version` is a versioned
coordinate; otherwise a selector with any coordinate is a named coordinate;
otherwise it is a language selector. See
[Discovery and precedence](#discovery-and-precedence).

## Payload kinds

| `kind` | Fields | Contents |
| --- | --- | --- |
| `declaration_facts` | `types`, `members`, `relations` (each default `[]`) | Declarations of external types and members. |
| `generator_rules` | `rules` (required) | Rules that add declarations for generated code at matching source sites. |
| `procedure_summaries` | `summaries` (required) | Reviewed behavior of external procedures. |

## Declaration facts

### TypeFact

| Field | Type | Default | Version | Meaning |
| --- | --- | --- | --- | --- |
| `id` | stable ID | required | 2 | The fact identity. Unique across the pack. |
| `name` | qualified name | required | 2 | The language spelling, for example `com.acme.Widget`. No whitespace. |
| `type_kind` | [`TypeKind`](#declaration-enumerations) | required | 2 | The kind of type. |
| `visibility` | [`Visibility`](#declaration-enumerations) | required | 2 | Declared visibility. |
| `locator` | [`Locator`](#locator) | required | 2 | Where the declaration lives. |
| `is_abstract` | boolean | `false` | 2 | The type is abstract. |
| `is_sealed` | boolean | `false` | 2 | The type is sealed or final. |
| `callable_surface_complete` | boolean | `false` | 6 | Every directly declared, externally visible callable and every direct hierarchy edge of this type is in the pack. It does not cover inherited members, fields, effects, or overload applicability. `false` means not reviewed. |
| `has_explicit_type_terms` | boolean | `false` | 2 | The type is a Go interface that lists explicit type terms (a type-set constraint). |
| `type_parameters` | list of names | `[]` | 2 | Generic parameter names, in order. Names must be unique. |
| `type_parameter_defaults` | list of optional defaults | `[]` | 18 | Rust defaults parallel to `type_parameters`, excluding lifetimes. A default is `{kind: type, type: TypeRef}` or `{kind: const, value: text}`; null means no default, and an empty list means unreviewed. |
| `implemented_traits` | list of implemented-trait facts | `[]` | 18 | Rust trait identities and structured associated-type bindings, retained even when no method is overridden. Negative impls contribute nothing. |
| `generic_trait_impls` | list of generic impl facts | `[]` | 18 | Rust forwarding rules owned by the implemented trait: `type_parameters`, structured `self_pattern`, `bounds`, and `implementation`. |
| `type_parameter_constraints` | list of [`TypeParameterConstraint`](#small-declaration-types) | `[]` | 2 | Constraints on the type parameters. One per parameter at most. |
| `underlying_type` | [`StructuredTypeExpression`](#small-declaration-types) | absent | 2 | The underlying type of a defined type, such as a Go named type. |
| `value_semantics` | [`TypeValueSemantics`](#value-semantics) | absent | 2 | Reviewed copy and move behavior. Absence means not reviewed, not "no operations". |
| `ambient_use` | `not_ambient`, `implicit`, or `given` | absent | 3 | See [Ambient use](#ambient-use). |
| `embedded_types` | list of [`EmbeddedTypeFact`](#small-declaration-types) | `[]` | 2 | Embedded types, such as Go struct embedding. |
| `hierarchy` | list of [`HierarchyFact`](#small-declaration-types) | `[]` | 2 | Direct supertypes and mixins. |
| `aliases` | list of names | `[]` | 2 | Other names for the same type. |
| `extension_surfaces` | list of names | `[]` | 2 | Names of declarations that add extension members to this type. |
| `guard` | [`DeclarationGuard`](#declarationguard) | absent | 2 | The toolchain and target condition under which the type exists. |

An implemented-trait fact has `trait_type: TypeRef` and `associated_types`, a list of
`{name, type: TypeRef}` bindings. A generic impl bound has `subject: TypeRef`,
`bound` (an implemented-trait fact), and `maybe` (for `?Sized`). Subjects may be
associated projections such as `P::Target`. A self pattern is a `parameter`
with `name`, a `reference` with `mutable` and `inner`, or a `constructor` with
`owner: TypeRef` and nested `arguments`. These facts retain declarations; they
do not assert that a bound has been solved for an arbitrary receiver.

### MemberFact

| Field | Type | Default | Version | Meaning |
| --- | --- | --- | --- | --- |
| `id` | stable ID | required | 2 | The fact identity. |
| `owner` | stable ID | required | 2 | The `id` of the owning `TypeFact`. The owner must exist (`reference.missing_owner`). |
| `name` | language name | required | 2 | The member name. No whitespace or control characters, except inside Scala backticks. |
| `member_kind` | [`MemberKind`](#declaration-enumerations) | required | 2 | The kind of member. |
| `visibility` | [`Visibility`](#declaration-enumerations) | required | 2 | Declared visibility. |
| `locator` | [`Locator`](#locator) | required | 2 | Where the declaration lives. |
| `is_static` | boolean | `false` | 2 | The member is static. |
| `is_abstract` | boolean | `false` | 2 | The member is abstract. |
| `is_virtual` | boolean | `false` | 2 | The member is virtual. `false` is not evidence that the member cannot be overridden. |
| `implemented_trait` | `TypeRef` | absent | 18 | The Rust trait implemented by this impl member. |
| `self_form` | tagged object | absent | 18 | Rust receiver form: `value`, `shared`, `mutable`, or `other` with a structured `pattern`. |
| `non_overridable` | `java_final_method` | absent | 2 | Evidence that the member cannot be overridden. A producer sets it only after it reads an exact Java `final` method. |
| `implicit_operation` | [`ImplicitOperation`](#value-semantics) | absent | 2 | The member's role in an implicit value operation. |
| `explicit_operation` | [`ExplicitValueOperation`](#value-semantics) | absent | 2 | The member's role in a value operation that the call site writes out. |
| `ambient_use` | `not_ambient`, `implicit`, or `given` | absent | 3 | See [Ambient use](#ambient-use). |
| `callable_family_complete` | boolean | `false` | 2 | The pack contains every callable with this member's exact owner, name, receiver form, and declared arity; variadic signatures retain their fixed prefix and repeated final parameter. Rejected on a non-callable or on a member without a signature. |
| `value_type` | [`TypeRef`](#typeref) | absent | 15 | Declared class of a modeled field value; requires a non-null nominal type without type arguments. |
| `proxied_type` | [`TypeRef`](#typeref) | absent | 15 | Class used for member dispatch on a proxy field value. Requires `value_type` and the same nominal type shape. |
| `exact_return_classes` | list of [`TypeRef`](#typeref) | `[]` | 16 | Exhaustive runtime classes returned by this member. Requires a signature and a constructor, method, function, static, or property member. Entries must be unique, non-null `named` or `declared` type references; declared IDs must name a type in this pack. |
| `signature` | [`Signature`](#signature-and-parameter) | absent | 2 | Parameters, return type, and generic parameters. |
| `receiver` | `{pointer}` | absent | 2 | Receiver form. `pointer` (default `false`) marks a pointer receiver, as in Go. |
| `extension_receiver` | [`TypeRef`](#typeref) | absent | 2 | The receiver type of an extension member. |
| `extension_receiver_constraints` | list of `TypeRef` | `[]` | 2 | Constraints on the extension receiver. |
| `aliases` | list of names | `[]` | 2 | Other names for the same member. |
| `guard` | [`DeclarationGuard`](#declarationguard) | absent | 2 | The toolchain and target condition under which the member exists. |

`exact_return_classes` records a stronger claim than `signature.returns`: it
names every runtime class the callable can return. The schema-16 gate applies
to non-empty lists. An absent or empty list makes no exhaustive runtime-class
claim. CSMI callable `returnClasses` imports
into this field. Return-class identity does not describe the callable's runtime
effects; those require separate behavior evidence.

### RelationFact

| Field | Type | Meaning |
| --- | --- | --- |
| `id` | stable ID | The relation identity. |
| `relation_kind` | `navigates_to` or `references` | `navigates_to` makes definition and declaration navigation follow `from` to `to`. `references` records that `from` refers to `to`. |
| `from` | stable ID | A declared type or member ID. |
| `to` | stable ID | A declared type or member ID. |

### Signature and Parameter

`Signature`:

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `parameters` | list of `Parameter` | `[]` | Formal parameters, in order. Order is significant. |
| `returns` | [`TypeRef`](#typeref) | absent | The return type. Absent means no return type is recorded. |
| `type_parameters` | list of names | `[]` | Generic parameters of the member. |

`Parameter`:

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `name` | language name | absent | The parameter name. Producers omit it when the artifact does not record it. |
| `type` | [`TypeRef`](#typeref) | required | The parameter type. |
| `optional` | boolean | `false` | The argument may be omitted. |
| `variadic` | boolean | `false` | The parameter accepts zero or more arguments. |
| `passing_mode` | `positional_only`, `positional_or_named`, or `named_only` | `positional_or_named` | Which argument forms may bind the parameter. Python stub producers set the other values from `/`, `*`, `*args`, and `**kwargs`. |

### TypeRef

A `TypeRef` is tagged by `kind`. Type nesting is limited to depth 64.

| `kind` | Fields | Meaning |
| --- | --- | --- |
| `unknown` | none | The type is not known. This preserves a present parameter or result port without asserting a concrete type or that every type is allowed. Added in schema version 9. |
| `named` | `name`, `arguments` (default `[]`), `nullable` (default `false`) | A type named by its qualified spelling. |
| `declared` | `id`, `arguments` (default `[]`), `nullable` (default `false`) | A type declared in this pack, by stable ID. |
| `projection` | `owner`, optional `trait_type`, `name`, `arguments` (default `[]`) | A Rust associated type such as `<I as Iterator>::Item`. Schema 18 retains its structure while leaving the projected result unresolved. |
| `type_parameter` | `name` | A generic parameter in scope. Unknown names fail with `type.unknown_parameter`. |
| `array` | `element` | An array of `element`. |
| `by_ref` | `element`, `reference_kind` (`lvalue` or `rvalue`, default `lvalue`) | A by-reference type. |
| `pointer` | `element` | A pointer to `element`. |
| `slice` | `element` | A slice of `element`, as in Go. |
| `fixed_array` | `element`, `length` (text) | A fixed-length array. |
| `map` | `key`, `value` | A map type. |
| `channel` | `element`, `direction` (`bidirectional`, `receive`, or `send`) | A Go channel. |
| `wildcard` | `variance` (`any`, `extends`, or `super`), `bound` | A wildcard. `extends` and `super` require `bound`; `any` forbids it. |
| `tuple` | `elements` | A tuple type. Empty elements represent Rust unit `()` at schema 18; other languages require at least one element. |
| `function` | `parameters` (list of `Parameter`), `result` (optional `TypeRef`) | A function type. |

### Locator

A `Locator` is tagged by `kind`. Paths are canonical relative paths with `/`
separators.

| `kind` | Fields | Meaning |
| --- | --- | --- |
| `source` | `path`, `symbol` (optional) | A source file path and, optionally, the symbol in it. |
| `artifact` | `path`, `symbol` | An entry in a binary or packaged artifact, such as `com/acme/Widget.class`. |
| `interchange` | `path`, `symbol`, `identity`, `callable_shape_evidence` (optional), `profile_evidence` (optional) | A declaration imported from CSMI. `identity` is a [CSMI portable symbol identity](#csmi-identity-types). The two evidence fields carry validated CSMI core and Python profile data for the exact imported artifact. |

### DeclarationGuard

Each recorded constraint is a necessary condition for the record to exist.

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `min_toolchain_version` | `{major, minor, patch}` | absent | The lowest toolchain version that declares the record, inclusive. |
| `max_toolchain_version_exclusive` | `{major, minor, patch}` | absent | The lowest toolchain version that no longer declares the record. |
| `required_targets` | list of text | `[]` | Activation targets that declare the record. Empty places no requirement. |
| `excluded_targets` | list of text | `[]` | Activation targets that do not declare the record. |
| `uninterpreted` | boolean | `false` | The producer read part of the condition that it could not express. Such a record is never dropped for lack of a constraint. |

Guard versions compare only the three release components. A shorter source
version such as `(3, 14)` is padded with zeros. Activation drops a guarded
record only when the pinned toolchain version or target provably fails a
recorded constraint.

### Value semantics

`TypeValueSemantics` on a type:

| Field | Values | Meaning |
| --- | --- | --- |
| `copy` | `{kind: trivial}` or `{kind: via_member, member}` | How the type copies. `member` is the stable ID of the copy operation. |
| `move_semantics` | `invalidating` | A move leaves the source invalid. |

The validator rejects an empty `value_semantics` object
(`declaration.empty_value_semantics`).

`ImplicitOperation` on a member (tagged by `kind`):

| `kind` | Fields | Allowed on | Meaning |
| --- | --- | --- | --- |
| `copy_constructor` | none | constructor | Implicit copy construction. |
| `move_constructor` | none | constructor | Implicit move construction. |
| `value_preserving_constructor` | none | constructor | Construction that preserves the logical value of one source argument. |
| `copy_assignment` | none | method | Implicit copy assignment. |
| `move_assignment` | none | method | Implicit move assignment. |
| `conversion_operator` | `target` (`TypeRef`) | method | Implicit conversion to `target`. |

`ExplicitValueOperation` on a member (tagged by `kind`). The member must be a
method with a signature:

| `kind` | Meaning |
| --- | --- |
| `receiver_assign` | The receiver's value becomes the first argument's value. The receiver keeps its storage identity. |
| `receiver_extend` | The first argument's value is added to the receiver's value. |
| `receiver_projection` | The normal result is a view of the receiver's storage. Writing through it writes the receiver. |
| `argument_expiring_cast` | The normal result is the single argument's own object, as an expiring value. No operation runs. |

### Ambient use

`ambient_use` states whether importing the declaration can make it usable
without the importing file spelling its name.

| Value | Meaning |
| --- | --- |
| `not_ambient` | Every use spells the imported name. This is the only value that proves a negative. |
| `implicit` | A Scala 2 `implicit` definition, selected by type from the imported scope. |
| `given` | A Scala 3 `given` definition, selected by type from the imported scope. |

Absence means the producer did not review the declaration. A consumer must
treat it as unknown.

### Small declaration types

| Type | Fields | Meaning |
| --- | --- | --- |
| `HierarchyFact` | `hierarchy_kind`, `target` (`TypeRef`), `declaration_ordinal` (optional integer) | One supertype or mixin edge. `declaration_ordinal` keeps source order where order matters. |
| `EmbeddedTypeFact` | `target` (`TypeRef`), `pointer` (default `false`) | One embedded type. `pointer` marks an embedded pointer. |
| `TypeParameterConstraint` | `parameter` (name), `constraint` (`StructuredTypeExpression`) | A constraint on one type parameter. |
| `StructuredTypeExpression` | `display` (non-empty text), `referenced_types` (list of `TypeRef`, default `[]`) | A type expression kept as display text plus the structured types it references. |

### Declaration enumerations

| Enumeration | Values |
| --- | --- |
| `TypeKind` | `class`, `annotation`, `delegate`, `interface`, `trait`, `struct`, `union`, `enum`, `record`, `module`, `type_alias` |
| `MemberKind` | `constructor`, `method`, `function`, `field`, `property`, `constant`, `static`, `macro`, `event` |
| `Visibility` | `public`, `protected`, `internal`, `protected_internal`, `package`, `private` |
| `HierarchyKind` | `extends`, `implements`, `uses_trait`, `mixin_include`, `mixin_prepend`, `mixin_extend` |
| `RelationKind` | `navigates_to`, `references` |
| `ParameterPassingMode` | `positional_only`, `positional_or_named`, `named_only` |
| `ChannelDirection` | `bidirectional`, `receive`, `send` |
| `WildcardVariance` | `any`, `extends`, `super` |

## Generator rules

### GeneratorRule

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `id` | stable ID | required | The rule identity. |
| `trigger` | [`RuleTrigger`](#rule-triggers) | required | The source site that the rule matches. |
| `captures` | list of [`CaptureDeclaration`](#captures) | `[]` | Values read from the matched site. Names must be unique. |
| `emissions` | list of [`RuleEmission`](#emissions) | required, at least one | What the rule adds (`rule.no_emissions`). |

### Rule triggers

A trigger is tagged by `kind`. Two kinds are accepted by the schema but never
match in this build.

| `kind` | Fields | Matches | Evaluated |
| --- | --- | --- | --- |
| `language_construct` | `construct` | A normalized source node whose construct label or normalized kind label equals `construct`. Construct labels are `java_method_reference`, `java_object_creation`, `scala_case_class`, and `rust_macro_invocation`. Normalized kind labels are the structural kinds listed in the [CodeQuery reference](/reference/code-query/). | yes |
| `annotation` | `name` | A decorator or annotation node. See [Annotation name matching](#annotation-name-matching). | yes |
| `annotated_field` | `annotation`, `value` (optional), `excluded_annotations` (default `[]`), `owner_annotation_path` (at least one entry) | A named field declaration that carries `annotation` (with argument `value`, if given), carries none of `excluded_annotations`, and whose owning class carries the annotations in `owner_annotation_path`. | yes |
| `macro_invocation` | `name` | A call node with a matching name. In Rust files the call must be a macro invocation. | yes |
| `generator_invocation` | `name` | A call node with a matching name. | yes |
| `resolved_owner` | `owner` | Never matches. Bifrost does not yet supply the resolver evidence. | no |
| `resolved_call` | `owner`, `name` | Never matches, for the same reason. | no |

#### Annotation name matching

- A trigger name with no `.` or `::` matches the last segment of the node's
  name. A trailing `!` on the node's name is ignored.
- A qualified trigger name such as `com.acme.GenerateBuilder` matches a node
  whose name is exactly that string, or whose decorator source is that string
  followed by nothing or by `(`.
- A qualified trigger name also matches an unqualified annotation, such as
  `@GenerateBuilder`, when exactly one non-wildcard import in scope at that
  site binds the local name to the qualified name.

### Captures

`CaptureDeclaration`:

| Field | Type | Meaning |
| --- | --- | --- |
| `name` | text | The capture name used by templates. |
| `binding` | `{source, projection}` | Where the value comes from and which part of it to read. |
| `value_kind` | `identifier`, `stable_id`, `type`, `string`, or `path` | The declared value kind. It must equal the kind that the projection produces. |
| `cardinality` | `one`, `optional`, `many`, or `group` | How many values the capture produces. It must equal the cardinality that the source requires. |

Capture sources (`binding.source`, tagged by `kind`):

| `kind` | Fields | Required cardinality | Valid triggers | Value |
| --- | --- | --- | --- | --- |
| `matched_node` | none | `one` | all | The matched node. |
| `enclosing_declaration` | none | `one` | all | The declaration that encloses the matched node. |
| `owning_type` | none | `one` | all | The type that owns the matched declaration. |
| `owned_fields` | none | `many` | all | The direct fields that supply generated members. A field-level annotation yields that field; a type-level annotation yields the type's direct fields. |
| `owned_mutable_fields` | none | `many` | all | The same fields as `owned_fields`, without final fields. |
| `owned_uninitialized_final_fields` | none | `group` | all | The same fields as `owned_fields`, limited to non-static final fields without an initializer, in declaration order. |
| `resolved_owner` | none | `one` | `resolved_owner`, `resolved_call` | The resolved owner. These triggers never match in this build. |
| `argument` | `index` | `optional` | `language_construct`, `macro_invocation`, `generator_invocation`, `resolved_call` | One argument by zero-based index. |
| `arguments` | `from` | `many` | `language_construct`, `macro_invocation`, `generator_invocation`, `resolved_call` | The arguments from index `from` to the end. |
| `annotation_argument` | `name` | `optional` | `annotation` | One named annotation argument. |

Projections (`binding.projection`) and the value kind each one produces:

| Projection | Value kind |
| --- | --- |
| `name` | `identifier` |
| `stable_id` | `stable_id` |
| `type` | `type` |
| `text` | `string` |
| `path` | `path` |

Cardinalities:

| Cardinality | Effect at a match |
| --- | --- |
| `one` | Exactly one value. No value fails the match with `capture.unbound`. |
| `optional` | Zero or one value. A template cannot reference an `optional` capture (`capture.cardinality`). |
| `many` | One emission row per value. Zero values produce no emissions. When a rule has several `many` captures, they must produce the same number of values, or the match fails with `capture.repeated_length`. |
| `group` | All values stay together in one emission. `TemplateSignature.repeated_parameters` renders once per value. |

### Template expressions

Templates build text from literals and captures. A `TemplateExpression` is
tagged by `op`. Nesting is limited to depth 64.

| `op` | Fields | Result |
| --- | --- | --- |
| `literal` | `value` | The literal text. |
| `capture` | `name` | The capture's value. The capture must exist and must not be `optional`. |
| `concat` | `values` (at least one) | The values joined in order. |
| `transform` | `transform`, `value` | `value` with an ASCII case transform applied. |
| `conditional` | `condition`, `then`, `else` | `then` when the condition holds, otherwise `else`. |

Conditions (`TemplateCondition`, tagged by `op`):

| `op` | Fields | Holds when |
| --- | --- | --- |
| `equals` | `left`, `right` | The two expressions produce equal text. |
| `starts_with` | `value`, `prefix` | `value` starts with `prefix`. |

Transforms: `lowercase`, `uppercase`, `snake_case`, `kebab_case`,
`pascal_case`, `camel_case`. In a stable-ID position, `uppercase`,
`pascal_case`, and `camel_case` are rejected (`template.unsupported_transform`).

Position rules:

- A stable-ID position (an emitted `id`, an alias or relation endpoint, a
  member `owner`) accepts only `stable_id` captures. Literal fragments may
  contain only lowercase letters, digits, `.`, `-`, and `_`.
- A language-name position (a `name`, a parameter name, a type parameter)
  accepts `identifier` or `stable_id` captures. Literal fragments must be
  printable and contain no whitespace.
- A type position accepts only `type` captures.

### Emissions

`RuleEmission` is tagged by `kind`.

| `kind` | Fields | Adds |
| --- | --- | --- |
| `declaration` | `id`, `name`, `declaration`, `anchor` (optional) | One declaration. `anchor` must be a `capture` expression; it names an authored location. Without an exact anchor, the declaration gets a `bifrost-model://` location. |
| `alias` | `id`, `from`, `to` | An alias from one ID to another. |
| `relation` | `id`, `from`, `to`, `relation_kind` | A relation, as in `RelationFact`. |

`EmittedDeclaration` (the `declaration` field) is tagged by `kind`:

| `kind` | Fields |
| --- | --- |
| `type` | `type_kind`, `visibility`, `is_abstract` (default `false`), `is_sealed` (default `false`), `type_parameters` (templates, default `[]`), `hierarchy` (list of `{hierarchy_kind, target}` with a template type, default `[]`), `extension_surfaces` (templates, default `[]`) |
| `member` | `member_kind`, `visibility`, `owner` (optional template), `signature` (optional `TemplateSignature`), `is_static`, `is_abstract`, `is_virtual` (each default `false`) |

`TemplateSignature`:

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `type_parameters` | list of templates | `[]` | Generic parameters. |
| `parameters` | list of `TemplateParameter` | `[]` | Fixed parameters. |
| `repeated_parameters` | list of `TemplateParameter` | `[]` | Parameters rendered once for each value of the rule's `group` capture. |
| `returns` | `TemplateTypeRef` | absent | The return type. |

`TemplateParameter` has `name` (template), `type` (`TemplateTypeRef`),
`optional` (default `false`), and `variadic` (default `false`).

`TemplateTypeRef` is tagged by `kind`: `named` (`name` template, `arguments`
default `[]`, `nullable` default `false`), `capture` (`name` of a `type`
capture), `array` (`element`), and `by_ref` (`element`).

## Procedure summaries

### Summary fields

Omitted list fields default to empty. "Version" is the lowest
`schema_version` that accepts the field.

| Field | Type | Version | Meaning |
| --- | --- | --- | --- |
| `id` | stable ID | 2 | The summary identity. `pack_id`, one byte, and `id` together may not exceed 512 bytes. |
| `target` | [`AuthoredProcedureTarget`](#target) | 2 | The exact procedure. Two summaries in a pack may not share `path` and `symbol` (`summary.duplicate_target`). |
| `completeness` | `partial` or `complete` | 2 | Whether the summary covers the procedure's whole transfer scope. |
| `locations` | list of `{id, location_kind}` | 2 | Declared locations. `location_kind` is `capture` or `heap`. At most 65,536. |
| `transfers` | list of [transfers](#transfers) | 2 | Value flows. Required field; may be an empty list. At most 65,536. |
| `effects` | list of [effects](#effects) | 2 | Allocations, calls, escapes, unknown calls, and sanitizers. At most 65,536. |
| `concurrency_effects` | list of [concurrency effects](#concurrency-effects) | 2 | Synchronization behavior at the call. At most 65,536. |
| `no_concurrency_effects` | boolean, default `false` | 7 | The procedure neither synchronizes with caller-visible memory nor retains it for concurrent work. Requires `completeness: complete` and an empty `concurrency_effects`. |
| `ordinary_heap_unchanged` | boolean, default `false` | 2 | The procedure and its transitive behavior do not write, publish, or escape ordinary program storage, and do not call an unaccounted callback. Requires `completeness: complete`. Conflicts with allocations, calls, escapes, unknown or ambiguous calls, conditional indirect writes, and transfers into heap or capture locations. |
| `declared_effects` | list of [declared effects](#declared-effects) | 2 | Namespaced effect identifiers. At most 64. |
| `normal_continuation_absent` | boolean | 2 | The procedure never returns normally. Omitted or `false` makes no claim. |
| `normal_result_count` | integer, at most 65,536 | 2 | The number of normal results. Required when `result_contracts`, `result_use_obligations`, `conditional_result_refinements`, or an `indexed_normal_return` output is present. |
| `preconditions` | list of [operation preconditions](#preconditions-and-refinements), or absent | 2 | Absent: not reviewed. Empty list: reviewed, none required. Populated: the predicates required at the call. |
| `result_contracts` | list of [result contracts](#result-contracts) | 2 | When a normal result is valid to use. At most 64. |
| `result_use_obligations` | list of [result-use obligations](#result-use-obligations) | 5 | Whether a discarded result matters. At most 64. |
| `conditional_result_refinements` | list | 2 | What a boolean result outcome proves about a parameter. At most 64. |
| `conditional_indirect_writes` | list | 2 | Writes through a pointer parameter that depend on a boolean result. At most 64. |
| `normal_return_refinements` | list | 2 | Predicates that hold for parameters whenever the procedure returns normally. At most 64. |
| `normal_return_type_refinements` | list | 2 | Class assertions that hold for a parameter whenever the procedure returns normally. At most 64. |
| `transfer_partitions` | list of [transfer partitions](#transfer-partitions) | 2 | Coverage of one input universe into one normal result. |
| `covers_overrides` | boolean | 2 | Every implementation of this member outside the workspace conforms to this summary. Requires `completeness: complete` and `target.has_receiver: true`. |
| `class_decorator_identity` | [class decorator identity](#class-decorator-identity) | 2 | The decorator preserves class identity. |

A `partial` summary must contain at least one of: a transfer, a `complete`
transfer partition, an effect, a concurrency effect, a `preconditions` value
(even an empty list), a result contract, a result-use obligation, a
conditional result refinement, a conditional indirect write, a normal-return
refinement, a normal-return type refinement, a class decorator identity, or
`normal_continuation_absent: true`. Otherwise it fails with `summary.empty`.
`declared_effects` alone do not count. A `complete` summary may be empty; it
then claims that the procedure has no transfers.

When `normal_continuation_absent` is `true`, the summary cannot contain a
normal transfer, an allocation or sanitize effect whose output is a normal
return, result contracts, result-use obligations, conditional result
refinements, conditional indirect writes, normal-return refinements,
normal-return type refinements, or a class decorator identity
(`summary.normal_continuation_conflict`).

### Target

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `path` | relative path | required | The artifact-relative path. For a qualified `symbol` it is provenance; for a bare `symbol` it names the owning module. |
| `symbol` | text | required | The declaration's symbol. A qualified symbol such as `Acme.run` names its owner. A bare symbol names a module-level declaration whose owner is the module at `path` without its extension. |
| `has_receiver` | boolean | `false` | The call has a semantic receiver. A static call through a type qualifier has no receiver. |
| `parameter_count` | integer, at most 65,536 | required | The number of declared formals, including any rest formals. |
| `variadic` | boolean | `false` | The target declares one or more rest formals and can accept varying actual counts. Requires at least one formal. Claims may reference only fixed parameters (`summary.unsupported_variadic_tail_reference`). |
| `formals` | list of structured formals | empty | Schema 11 for fixed signatures; schema 14 adds directional rest formals. When present, describes every formal in declaration order. Exact applicability binds each direct actual by position or keyword; omitted fixed formals are accepted only when `optional: true`, and an unfilled rest formal denotes an empty collection. Empty retains legacy behavior. |

Each structured formal has a unique `name`, an optional `passing_mode` (`positional_only`,
`positional_or_named`, or `named_only`, default `positional_or_named`), and an
`optional` boolean (default `false`) that records whether the declaration has
a default value. Schema 14 adds optional `variadic_kind` values `positional`,
`keyword`, and `both`. A signature may have one rest formal for each argument
domain. Call-site spreads and unmatched keywords without a keyword-rest formal
do not bind exactly. Summary claims cannot reference a rest formal itself.

### Ports

`AuthoredSummaryInput` (tagged by `kind`):

| `kind` | Fields | Meaning |
| --- | --- | --- |
| `receiver` | none | The receiver. The target must have `has_receiver: true`. |
| `parameter` | `ordinal` (0 to 65,535) | A zero-based parameter. The ordinal must be less than `parameter_count`. |

`AuthoredSummaryOutput` (tagged by `kind`):

| `kind` | Fields | Meaning |
| --- | --- | --- |
| `normal_return` | none | The normal return value. |
| `indexed_normal_return` | `ordinal` | One normal result of a multi-result procedure. Requires `normal_result_count`, and `ordinal` must be less than it. |
| `receiver` | none | The receiver. |
| `capture` | `location` | A declared `capture` location. |
| `heap` | `location` | A declared `heap` location. |
| `exceptional_return` | none | The exceptional exit. |

### Transfers

| Field | Type | Meaning |
| --- | --- | --- |
| `input` | input port | The source of the value. |
| `exit_kind` | `normal` or `exceptional` | The exit on which the flow happens. Must agree with the output port. |
| `output` | output port | Where the value goes. |
| `value_transfer` | `{kind, operation}` | Optional. Classifies how value and identity relate. Absent means not reviewed. |

`value_transfer.kind` (tagged by `kind`): `copy`, `aggregate_copy`, `move`
(with `invalidation`: `invalidated` or `unknown`), `conversion` (with
`preservation`: `identity`, `preserving`, `changing`, or `unknown`), `boxing`,
`unboxing`.

`value_transfer.operation` (tagged by `kind`): `none`; `implicit` with
`member` (the stable ID of a declared member); or `unknown` with `limitation`
`{kind, message?}`. Limitation kinds are `budget_exhausted`, `cancelled`,
`unsupported`, `unresolved_identity`, `ambiguous_identity`, `incomplete_input`,
and `other`. `other` requires `message`.

### Effects

Each effect is tagged by `kind`. `event` is a stable ID that names the effect.

| `kind` | Fields | Meaning |
| --- | --- | --- |
| `allocation` | `event`, `output` | The procedure allocates a new object into `output`. |
| `call` | `event`, `callee` | The procedure calls another summary in the same pack. `callee` is that summary's `id` (`summary.unbound_callee`). |
| `escape` | `event`, `input` | The input escapes to storage that the summary does not model. |
| `unknown_call` | `event`, `input` | The procedure passes the input to code that the summary does not model. |
| `unknown_call_boundary` | `event` | The procedure calls code that the summary does not model. |
| `ambiguous_call` | `event`, `input`, `candidates` | The procedure calls one of the named summaries. At least one, at most 4,096 candidates. |
| `sanitize` | `input`, `output`, `removes` | The named taint labels are removed on a declared transfer from `input` to `output`. `removes` has 1 to 64 unique labels. A matching transfer must exist (`summary.sanitize_without_transfer`). |

The total number of callee references across `call` and `ambiguous_call`
effects is at most 65,536.

### Concurrency effects

Concurrency effects are tagged by `kind`. They name receiver or parameter
ports and do not add value-flow edges.

| `kind` | Fields | Meaning |
| --- | --- | --- |
| `unsupported` | `protocol` | The call takes part in a concurrency protocol that Bifrost does not model. |
| `task_spawn` | `callable`, `group` (optional), `condition` (optional `call_result_true`), `timer` (optional output) | Starts `callable` as a task. With `condition: call_result_true`, the task starts only when the call returns `true`. `timer` names the returned timer for a cancellable callback. |
| `task_join` | `group` | Waits for the tasks in `group`. |
| `once_do` | `once`, `callable` | Runs `callable` at most once per `once` object. |
| `lock_acquire` | `lock`, `mode` (`shared` or `exclusive`), `condition` (optional `call_result_true`) | Acquires `lock`. With `condition`, the lock is held only when the call returns `true`. |
| `lock_release` | `lock`, `mode` | Releases `lock`. |
| `wait_group_add` | `group`, `delta` | Adds `delta` to a wait group. |
| `wait_group_done` | `group` | Marks one wait-group task done. |
| `wait_group_wait` | `group` | Waits for a wait group. |
| `atomic` | `location`, `operation` (`load`, `store`, or `read_modify_write`) | An atomic access. |
| `cond_bind` | `condition` (output), `lock` | Binds a new condition variable to its locker. |
| `cond_wait` | `condition` | Releases the bound locker, waits, and re-acquires it. |
| `cond_notify` | `condition`, `waiters` (`one` or `all`) | Wakes one or every waiter. |
| `sync_map` | `map`, `operation`, `key` (optional) | One `sync.Map` entry operation. `key` is absent only for `clear`. |
| `timer_stop` | `timer` | Stops a timer. A `true` result proves that the timer's callback did not and will not run. |
| `timer_reset` | `timer` | Re-arms a timer. It voids an earlier stop. |
| `subtest_run` | `callable`, `group` | Runs a subtest callback under the parent test `group`. |
| `subtest_parallel` | `receiver` | Marks the test node as parallel. |
| `subtest_cleanup` | `callable`, `group` | Registers a cleanup that runs after the test and its subtests. |

`sync_map` operations: `store`, `delete`, `clear`, `load`, `range`,
`load_or_store`, `load_and_delete`, `swap`, `compare_and_swap`,
`compare_and_delete`.

### Declared effects

| Field | Type | Meaning |
| --- | --- | --- |
| `id` | stable ID with at least one `.` | A namespaced effect name, such as `acme.network_io` (`summary.effect_namespace`). Unique within one summary. |
| `timing` | `immediate`, `deferred`, or `unknown` | Before the call returns, scheduled by the call, or not stated. |
| `certainty` | `definite` or `possible` | Every execution, or some execution. |

### Preconditions and refinements

Result predicates are `null`, `non_null`, `true`, and `false`.

| Record | Fields | Meaning |
| --- | --- | --- |
| Operation precondition | `input`, `predicate` | The predicate must hold for the input at the call. One predicate per input. |
| `conditional_result_refinements[]` | `result_ordinal`, `outcome` (boolean), `parameter_ordinal`, `predicate`, `proof_effect` (`establishes` or `does_not_establish`) | When the boolean result equals `outcome`, the parameter predicate is established, or explicitly not established. |
| `conditional_indirect_writes[]` | `result_ordinal`, `outcome` (boolean), `parameter_ordinal`, `target` (`pointee`) | When the boolean result equals `outcome`, the procedure writes through the pointer parameter. |
| `normal_return_refinements[]` | `parameter_ordinal`, `predicate` | The predicate holds for the parameter after a normal return. |
| `normal_return_type_refinements[]` | `parameter_ordinal`, `class_parameter_ordinal`, `required_receiver_members` (default `[]`, at most 64) | After a normal return, the subject parameter is an instance of the class passed at `class_parameter_ordinal`. `required_receiver_members` names receiver members that must stay bound to the modeled owner. The two ordinals must differ. |

### Result contracts

| Field | Type | Meaning |
| --- | --- | --- |
| `result_ordinal` | integer | The protected normal result. |
| `condition_result_ordinal` | integer, optional | A separate result whose predicate makes the protected result valid, as in a Go `(value, error)` pair. Present together with `predicate`. Must differ from `result_ordinal`. |
| `predicate` | result predicate, optional | The predicate required of the condition result. |
| `result_success_predicate` | result predicate, optional | The predicate that makes the protected result valid. Required when there is no condition result. |
| `member_contracts` | list, at most 64 | Operations on the protected result. |

A member contract has `member` (name), `parameter_count`, `completeness`,
`declared_effects` (default `[]`), and `preconditions` (absent, empty, or
populated, with the same three meanings as on the summary).

### Result-use obligations

| Field | Type | Meaning |
| --- | --- | --- |
| `result_ordinal` | integer | The normal result. One obligation per result. |
| `kind` | `pure_transformation_value` or `fallible_status` | A pure value has no effect when discarded. A status reports a fallible outcome that needs inspection. |
| `failure_predicate` | result predicate | Required for `fallible_status`; forbidden for `pure_transformation_value`. |

A `pure_transformation_value` obligation requires
`ordinary_heap_unchanged: true` on the summary.

### Transfer partitions

| Field | Type | Meaning |
| --- | --- | --- |
| `normal_result` | integer | The normal result covered. |
| `source` | `all_inputs`, `input_receiver`, `input_parameter` (`ordinal`), or `input_capture` (`symbol`) | The input universe, tagged by `kind`. |
| `status` | `unknown`, `partial`, or `complete` | Coverage. `complete` forbids limitations; `partial` requires at least one. |
| `limitations` | list of `{kind, diagnostic_code?, diagnostic_message?}` | Why coverage is not complete. |
| `provenance` | list of text | Provenance references. |

A partition never closes effects, exceptions, heap state, or the whole
procedure.

### Class decorator identity

| Field | Type | Meaning |
| --- | --- | --- |
| `direct` | boolean | The decorator, applied directly to a class, returns the same class. The target must accept exactly the class argument. |
| `factory_keywords` | list of `{name, allowed_values}`, optional | The decorator factory preserves class identity when called with only these keyword arguments, each with a literal boolean from `allowed_values`. At most 64 keywords. |

The claim requires a `complete` summary, a target without a receiver, and no
`covers_overrides`. At least one of `direct: true` or `factory_keywords` must
be present.

## Shard companions

Companions carry facts from CSMI vocabularies. Their field names follow the
[CSMI specification](http://csmi.brokk.ai/), including its camel-case
spelling. Bifrost validates them against the profile schema and its own
semantic checks.

| Companion | CSMI vocabulary | Lowest version | Contents |
| --- | --- | --- | --- |
| `runtime_values` | `csmi.runtime-values` 0.1.0 | 2 | Runtime global exposures and keyed-read behaviors, such as `process.env`. |
| `runtime_contracts` | `csmi.runtime-values` 0.2 | 4 | Portable runtime contracts in five fact families. |
| `collection_flows` | `csmi.collection-flow` 0.1.0 | 2 | Flows through collection operations. |
| `deferred_yields` | `csmi.deferred-yield` 0.1.0 | 2 | Values that a factory yields later through a resume operation. |
| `conditional_type_refinements` | `csmi.conditional-type-refinement` | 2 | Type refinements that a predicate call establishes, such as Python `TypeIs` and `TypeGuard`. |

### runtime_values

`RuntimeValuesPayload` has four lists, each default empty: `exposures`,
`behaviors`, `binding_evidence`, and `observations`. The schema accepts the
last two for CSMI round trips. The production evaluator does not read them; it
derives binding and observation facts from the analyzed workspace.

`exposures[]` (`RuntimeGlobalExposure`):

| Field | Meaning |
| --- | --- |
| `exposureId` | The exposure identity. |
| `bindingName` | The global name, such as `process`. |
| `members` | The exposed members, such as `env` and `argv`. |
| `languages` | Languages the exposure applies to. |
| `rootIdentity` | `{scheme, schemeVersion, descriptors: [{name, role}]}`. `role` is `runtime` or `global`. |
| `runtime` | Applicability: `runtimeFamily`, `realm`, `initializationBoundary`, and optional `platform`, `architecture`, `moduleMode`, `runtimeArtifact`, `runtimeArtifactDigest`, `hostAssumptions`. |
| `runtimeProfileDigest` | The reviewed runtime profile digest. |
| `activation` | `enabled`, `disabled`, or `review-required`. `enabled` does not bypass pack activation or `safety.review_required`. |
| `coverage` | `{status, limitations}`. |
| `evidence` | `{producer, method, inputsDigest}`. |
| `provenance`, `extensions` | Optional lists. An extension is `{vocabulary, version, payload}`. |

`behaviors[]` (`KeyedReadBehavior`):

| Field | Values |
| --- | --- |
| `behaviorId`, `exposureId`, `containerMember` | Identities. `containerMember` must be one of the exposure's `members`. |
| `acceptedKeys` | `static-property` or `static-index` |
| `normalResult` | `value-or-undefined` or `value` |
| `exceptionBehavior` | `nonthrowing`, `may-throw`, or `unknown` |
| `materialization` | `eager`, `lazy`, `host-defined`, or `unknown` |
| `mutationModel` | `pristine-input-until-write`, `ordinary-mutable`, or `unknown` |
| `coverage`, `evidence`, `provenance`, `extensions` | As for exposures. |

`binding_evidence[]` (`RuntimeGlobalBindingEvidence`) has
`bindingEvidenceId`, `exposureId`, `language`, `dialect`, `scopeIdentity`,
`rootOccurrence`, `lexicalBinding` (`absent`, `present`, `indeterminate`),
`rebinding` (`excluded`, `present`, `indeterminate`), `activation`
(`activationSource`, `activeExposureIds`, `activeSetDigest`, `exposureId`,
`modelDigest`, `runtimeProfileDigest`, `outcome`: `matched`, `not-matched`,
`indeterminate`, `conflict`, `unsupported`), `coverage`, `evidence`,
`provenance`, and `extensions`.

`observations[]` (`KeyedReadObservation`) has `observationId`, `behaviorId`,
`bindingEvidenceId`, `expression`, `baseValue`, `loadOperation`,
`observationPoint`, `resultValue`, `key` (`property` with text or `index` with
an integer), `sourceForm` (`dot`, `bracket-string`, `bracket-number`),
`phase` (`before-effects`, `after-effects`, `exceptional`), `sourceOrigin`
(`pristine-runtime-input`, `mutated`, `indeterminate`, `not-applicable`),
`normalOutcome` (`exact`, `partial`, `unsupported`, `indeterminate`),
`exceptionOutcome` (`excluded`, `possible`, `unsupported`, `indeterminate`),
`coverage`, `evidence`, `provenance`, and `extensions`.

Shared shapes: a scoped identity is `{kind, ownerDigest, locatorDigest}` with
`kind` one of `scope`, `value`, `operation`, `point`. A source range is
`{resource, resourceDigest, startByte, endByte}`. Coverage `status` is
`complete`, `partial`, or `unknown`. Coverage limitations are
`activation-missing`, `activation-conflict`, `activation-unsupported`,
`lexical-binding-indeterminate`, `rebinding-indeterminate`,
`mutation-incomplete`, `accessor-or-proxy-incomplete`,
`materialization-incomplete`, `exception-behavior-indeterminate`,
`dynamic-key`, `unsupported-index`, `cancelled`, `budget-exhausted`,
`stale-evidence`, `ambiguous-owner`, and `coverage-limited`. Incomplete
coverage requires at least one limitation.

### runtime_contracts

`runtime_contracts` has a required `payload` and an optional `envelope`. The
envelope keeps the original CSMI document envelope for lossless re-export. The
payload has five lists, each default empty, in this order:

| List | Record fields |
| --- | --- |
| `targets` | `targetId`, `targetDigest`, `definition` (`basis`: `declared-target`, `deployment-observation`, `unknown`; `context`: exact `realm`, `platform`, `architecture`, `moduleMode`, `launchMode`, `initializationBoundary`, `scheme`; `partition`; `resources`: `[{resource, resourceDigest}]`; `runtime`: optional selector; `assumptions`; `coverage`; `evidence`) |
| `contracts` | `contractId`, `contractDigest`, `evidence`, `definition` (`identifier`, `version`, `languages`, `surface` `{root, container}`, `applicability` (`basis`: `portable` or `artifact-specific`; `selectors`), `context` (sets per dimension plus `scheme`), `assumptions`, `behavior`) |
| `activations` | `activationId`, `activationDigest`, `targetId`, `surface`, `candidateIds`, `selectedIds`, `disabledIds`, `candidateCoverage`, `policy` (`identifier`, `version`, `purpose`, `inputsDigest`, `trustedReviewers`), `reviews` (`contractDigest`, `targetDigest`, `reviewer`, `purpose`, `decision`: `approved`, `denied`, `unknown`; `evidence`), `outcome` (`matched`, `not-matched`, `indeterminate`, `conflict`, `unsupported`, `review-required`, `disabled`) |
| `bindings` | `bindingId`, `activationId`, `activationDigest`, `contractId`, `language`, `source`, `scope`, `root`, `container`, `lexicalBinding`, `rebinding`, `outcome` (`exact`, `excluded`, `indeterminate`, `unsupported`), `coverage`, `evidence` |
| `observations` | `observationId`, `bindingId`, `source`, `sourceForm` (`dot`, `bracket-string`, `bracket-number`, `mapping`, `unsupported`), `key`, `storageKey` (optional), `baseValue`, `loadOperation`, `point`, `resultValue`, `phase`, `origin` (`initial-if-present`, `written`, `deleted`, `absent`, `unknown`), `store`, `proof`, `coverage` |

`behavior` fields: `keyDomain` (`static-property`, `static-index`),
`keyEquality` (scheme), `lookup` (`own-value`, `mapping-entry`),
`presentValue` (`string`), `absent` (`undefined`, `exception`), `read`
(`materialization`; `exceptions`: `nonthrowing`, `may-throw`, `unknown`),
`write` (`normal`: `store-converted-value`, `unknown`; `exceptional`:
`unchanged`, `may-mutate`, `unknown`; `conversion`: `identity`,
`string-conversion`, `requires-contract`, `unknown`), `delete` (`normal`:
`remove-entry`, `unknown`; `exceptional`: `unchanged`, `may-mutate`,
`unknown`), `initialOrigins` (`[{origin, keys}]`; `origin` is
`external-environment`, `application-argument`, `executable-path`,
`entry-path`, or `unknown`; `keys` is `all-properties` or `index-range` with
`minimum` and `maximum`), and `coverage`.

`store` fields: `realm`, `invocation`, `container`, `backing`, `relationship`
(`isolated`, `copied`, `shared`, `unknown`), `copiedFrom`, `copyPoint`, and
`evidence`.

`proof` fields: `closureDigest`, `initialization` and `dependencies`
(`closed`, `open`, `unknown`), `keyNormalization` (`exact`, `unknown`),
`lookup` (`own-present`, `absent-no-fallback`, `mapping-present`,
`mapping-absent`, `inherited`, `accessor`, `proxy`, `unknown`),
`materialization` (`resolved`, `unresolved`), `mutation` (`pristine`,
`written`, `deleted`, `unknown`), `normal` (`exact`, `indeterminate`,
`unreachable`), `exceptional` (`excluded`, `modeled`, `unknown`), and
`evidence`.

Shared shapes: an identity is `{kind, scheme, ownerDigest, locatorDigest}`
with `kind` one of `scope`, `value`, `operation`, `point`, `invocation`,
`realm`, `store`. A scheme is `{identifier, version}`. A range is `{resource,
resourceDigest, startByte, endByte}`. A key is `property` (text), `index`
(integer), `dynamic`, or `unsupported`. A selector is `{purl, versionRange?,
digests?}`; a digest is `{algorithm, value, coverage, canonicalization?}` with
algorithm `sha-256`, `sha-384`, or `sha-512`. Coverage limitations add
`target-unknown`, `review-missing`, `inventory-incomplete`,
`lookup-incomplete`, `initialization-incomplete`, `unsupported-key`,
`equality-unknown`, and `sharing-unknown` to the 0.1 list, and drop
`accessor-or-proxy-incomplete`, `unsupported-index`, and `ambiguous-owner`.

### collection_flows, deferred_yields, conditional_type_refinements

| Companion | List | Record fields |
| --- | --- | --- |
| `collection_flows` | `flows` | `callable` (a declared member ID), `payload` (CSMI collection-flow fact), `coverage` (`partial` or `complete`, optional), `provenance` |
| `deferred_yields` | `yields` | `factory`, `resume`, `handleType` (declared IDs), `payload` (CSMI deferred-yield fact), `coverage` (optional), `provenance` |
| `conditional_type_refinements` | `refinements` | `payload` (CSMI conditional-type-refinement fact), `coverage` (`unknown`, `partial`, or `complete`, optional), `provenance` |

## Pack-level evidence

### C++ portability evidence

`cpp_portability` must contain at least one resolution context and one symbol.

| List | Record fields |
| --- | --- |
| `resolution_contexts` | `context_digest` (lowercase SHA-256 of the RFC 8785 context), `compile_arguments_digest`, `language` (`c` or `cpp`), `translation_unit`, `direct_headers` (`[{include_name, artifact}]`, at least one), `header_closure` (`complete`) |
| `symbols` | `native_id` (a declared fact ID), `key` (`scheme`, `scheme_version`, `stability`: `portable`, `artifact_selectors`, `descriptors`: `[{name, role, disambiguator}]` with role `namespace`, `type`, or `callable`) |
| `type_aliases` | `alias` (a declared ID), `target` (a C++ canonical type), `resolution_context` |
| `special_members` | `owner`, `member`, `member_disambiguator`, `operation` (`copy_constructor`, `copy_assignment`, `move_constructor`), `signature`, `resolution_context` |

A C++ artifact selector is `{purl, digests: [{algorithm: sha256, value,
coverage, canonicalization?}]}`. A resolution-context reference is
`{vocabulary, version, context_digest, language, header_closure}`. A callable
signature is `{callable_kind (constructor or method), owner, parameters,
receiver?, result?}`. A C++ canonical type is tagged by `kind`: `fundamental`
(`name`: `char`), `declared` (`symbol`), `template_specialization` (`primary`,
`arguments`), `qualified` (`qualifiers`: `const`, `volatile`; `type`), or
`reference` (`reference_kind`: `lvalue`, `rvalue`; `referent`).

### Python correspondence evidence

| Field | Meaning |
| --- | --- |
| `native_sha256` | SHA-256 of the normalized full pack, with this field blanked. |
| `declaration_artifact` | The CSMI artifact selector of the declaration artifact. |
| `symbols` | `[{local_id, identity, provenance}]`. |
| `mappings` | `[{declaration, runtime, relation, conditions?}]`. `relation` is `describes`, `augments`, or `replaces-for-type-checking`. |
| `vocabulary_uses`, `extension_facts`, `completeness_statements`, `core_completeness_statements`, `provenance_records` | CSMI records kept as JSON for re-export. |
| `default_provenance` | Optional local provenance ID. |

### CSMI identity types

A CSMI portable symbol identity is `{scheme, schemeVersion, artifactSelectors,
descriptors}`. An artifact selector is `{purl, versionRange?, digests?}`. A
digest is `{algorithm (sha-256, sha-384, sha-512), value, coverage,
canonicalization?}`. A descriptor is `{role, name?, disambiguator?}` with role
`namespace`, `type`, `term`, `callable`, `type-parameter`, `value-parameter`,
or `meta`.

## Limits

Compilation and decoding use the same defaults. A caller can lower them.

| Limit | Default | Validation code |
| --- | --- | --- |
| Source document | 64 MiB | `limit.source_bytes` |
| Readable manifest | 16 MiB | |
| Each raw shard | 64 MiB | |
| Each stored shard | 64 MiB | |
| Total raw pack | 1 GiB | |
| Shards per pack | 4,096 | `limit.shards` |
| Records per shard | 250,000 | `limit.shard_records` |
| Records per pack | 2,000,000 | `limit.pack_records` |
| Text value | 16 KiB | `limit.text_bytes` |
| Type and template nesting | 64 | `limit.type_depth`, `limit.template_depth`, `limit.template_type_depth` |

YAML input allows one document and rejects duplicate keys, aliases, anchors,
merge keys, includes, legacy boolean spellings, and excessive nesting.

## Compiled manifest

`compile` writes `manifest.json` and one file per shard in `shards/`, named
`<shard_id>.json` (raw) or `<shard_id>.deflate` (raw DEFLATE). The manifest
repeats the envelope fields and adds:

| Field | Meaning |
| --- | --- |
| `semantic_sha256` | Digest of the ordered shard semantic identities. |
| `content_sha256` | SHA-256 of the manifest view without this field. |
| `shards[].shard_id`, `payload_kind` | The shard and its payload kind. |
| `shards[].routing_keys` | Sorted keys derived from selectors and triggers, such as `trigger:language_construct`. |
| `shards[].encoding` | `raw` or `deflate`. |
| `shards[].raw_size`, `stored_size`, `record_count` | Sizes and count. |
| `shards[].defined_ids`, `referenced_ids` | Declaration IDs that the shard defines and references. |
| `shards[].semantic_sha256`, `content_sha256`, `stored_sha256` | The three shard digests. |

The digest definitions are in
[Canonical artifacts and digests](/semantic-model-packs/).

## Workspace pack document

`.bifrost/packs.json` is optional. When present it must be valid JSON of at
most 256 KiB. Every object rejects unknown fields. The machine-readable schema
is
[`schemas/workspace-packs-v1.schema.json`](https://github.com/BrokkAi/bifrost/blob/master/schemas/workspace-packs-v1.schema.json).

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `schema_version` | integer | yes | Must be `1`. |
| `ecosystems` | list of labels | yes | The dependency ecosystems to discover. Labels must be unique and from the [ecosystem table](#dependency-ecosystems). An unknown or duplicate label is an error. `[]` turns off dependency-pack discovery. |
| `catalog` | text, 1 to 1,024 bytes | no | A workspace-relative catalog directory. Absolute paths, `..` components, and platform prefixes are rejected. When omitted, see [Catalog location](#catalog-location). |
| `enable` | list of pack IDs | no | Pack IDs that satisfy `safety.review_required`. Each becomes a workspace `enable` control. It cannot bypass compatibility. |
| `python_runtime_environments` | list | no | Explicit bindings from a source tree to installed Python wheels. See below. |

When the document is absent, hosts select every ecosystem that serves a
language present in the workspace.

### python_runtime_environments

Each entry binds one workspace source tree to installed wheel contents. Bifrost
verifies each installed tree against its original wheel without running
Python. Entries are added to the Python runtime-environment configuration for
activation. All paths are workspace-relative and are validated the same way as
`catalog`.

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `source_root` | path | yes | The source tree bound to this environment. `.` binds the whole workspace. |
| `artifacts` | list of `{archive_path, installed_root}` | yes | `archive_path` is the original wheel. `installed_root` is the directory that holds its installed contents. |
| `declared_environment` | object or `null` | no | A declared filesystem-import environment. It describes the declared launch configuration, not a running interpreter. |

`declared_environment` fields, all required:

| Field | Type | Meaning |
| --- | --- | --- |
| `producer_version` | text | Version of the producer that wrote the descriptor. |
| `resolver_version` | text | Version of the declared resolver semantics. |
| `interpreter` | object | `path` (workspace-relative interpreter file), `sha256`, `implementation`, `python_version`, `abi`, `platform`. |
| `launch` | object | `isolation` (`isolated`, `environment_sensitive`), `site_startup` (`disabled`, `enabled`), `environment` (`cleared`, `explicit_inputs`, `ambient`), `import_path` (`declared_roots_only`, `environment_augmented`), `finder` (`standard_filesystem`, `custom_hooks`), `editable_installs` (`disabled`, `enabled`), `native_extensions` (`disabled`, `enabled`). |
| `entry_point` | object | `mode` (`script`, `module`, `command_string`), `root_slot_id`, `relative_path`, `working_directory_root_slot_id`, `working_directory`. Paths are relative to their root slot. |
| `extras` | list of text | Enabled extras, in order. |
| `config_inputs` | list | `[{ordinal, input_id, role, path, sha256}]`. `role` is `resolver_configuration`, `startup_configuration`, `environment_configuration`, `extras_configuration`, or `entry_configuration`. |
| `root_slots` | list | `[{ordinal, slot_id, role, path, artifact_index?}]` in resolver order. `role` is `source`, `standard_library`, or `installed_distribution`. `artifact_index` points into `artifacts`. |

### Catalog location

| Situation | Catalog |
| --- | --- |
| `catalog` is set | That directory under the workspace root, opened read-write. |
| `catalog` is omitted, and the analyzer is persisted or `BIFROST_SEMANTIC_PACK_CACHE_ROOT`, `BIFROST_CACHE_DIR`, or `BIFROST_CACHE_ROOT` is set | `semantic-pack-catalog.v11` under `BIFROST_SEMANTIC_PACK_CACHE_ROOT` if set, otherwise under the repository's Bifrost cache directory. |
| `catalog` is omitted, and the analyzer uses ephemeral storage with none of those variables set | An in-memory catalog that is deleted when the session ends. |

When `BIFROST_SEMANTIC_PACK_CACHE_ROOT` is not set, the default catalog also
reuses exact generated packs through `generated-semantic-packs.v10` in the
machine cache. See the [environment reference](/reference/environment/) for
the cache variables.

## Workspace semantic models

`.bifrost/semantic-models/` holds reviewed models that a repository checks in.
Each file is one pack source, the same input that `bifrost-semantic-pack validate`
and `compile` read.

| Rule | Value |
| --- | --- |
| Files read | Direct children with the extension `.json`, `.yaml`, or `.yml`. Discovery does not recurse. Other files are ignored without a diagnostic. |
| Rejected entries | Symbolic links, entries that are not files, and paths outside the canonical workspace. |
| Directory entries | At most 1,024 (`limit.workspace_files`). |
| File size | At most 64 MiB per file (`limit.source_bytes`). |
| Source kind | `ephemeral_workspace`. Workspace models outrank installed and shipped packs. |
| Review | A model with `safety.review_required: true` stays inert until `.bifrost/packs.json` `enable` names its pack ID. |
| Check | `bifrost-semantic-pack workspace-check WORKSPACE` reports each file's source SHA-256 and compiled semantic digest. |

A CLI policy run without `--sources` loads this directory whenever it exists. A
`SearchToolsService` session loads it only when
`BIFROST_WORKSPACE_SEMANTIC_MODELS` is on. See
[Semantic-Model Packs](/semantic-model-packs/) for the failure behavior of each
host.

## JVM toolchain document

`.bifrost/jvm-toolchains.json` binds workspace source roots to JDK
installations. Reviewed JDK models apply to a call only when its source root
has a binding. `JAVA_HOME` alone does not create a binding.

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `schema_version` | integer | yes | Must be `1`. |
| `source_toolchains` | list of `{source_root, jdk_home}` | yes | At most 128 bindings. |
| `source_root` | text | yes | A workspace-relative path. `.` binds the whole workspace. |
| `jdk_home` | path | yes | The JDK installation. Absolute or relative to the workspace. Must not be empty. |

The document is at most 256 KiB, and every object rejects unknown fields. The
deepest matching source root wins. Two equally specific bindings to different
JDK homes are ambiguous, and the reviewed obligations stay incomplete. Bifrost
reads the document when it builds the workspace, so restart a running host
after a change. An invalid document makes the workspace build fail.

## Activation evidence

Activation matches shard selectors against evidence rows. A row has
`language`, `ecosystem`, and optional `package`, `module`, and `toolchain`
(`{name, version?}` with an exact SemVer version), `target`, `configuration`,
and `artifact_sha256`.

Hosts mint these rows for a workspace:

| Row | When | Fields |
| --- | --- | --- |
| Intrinsic language row | One per language present | `language` and the intrinsic ecosystem below. No other fields. |
| Node runtime row | One per present JavaScript or TypeScript language, when the root `package.json` (`engines.node` or `volta.node`), `.nvmrc`, or `.node-version` names exactly `22.11.0` (an optional leading `v` is allowed) | `package` `pkg:generic/nodejs.org/node@22.11.0`, the reviewed Node archive digest as `artifact_sha256`, and the reviewed profile digest as `configuration`. |
| Python process-input row | When Python is present | Ecosystem `pypi` and the reviewed process-input profile digest as `configuration`. |
| Dependency rows | For each selected ecosystem | Rows from the ecosystem's dependency discovery. |
| Workspace model rows | For each model in `.bifrost/semantic-models/` | Rows returned by registration. |

Intrinsic ecosystems:

| Language | Ecosystem |
| --- | --- |
| Java, Scala, Kotlin | `maven` |
| Rust | `cargo` |
| Go | `go` |
| Python | `pypi` |
| Ruby | `rubygems` |
| JavaScript, TypeScript | `npm` |
| C# | `nuget` |
| C++, PHP | `language` |

The `bifrost-semantic-pack list` command reads evidence from an activation
file. See [Activation input file](#activation-input-file).

## Dependency ecosystems

These are the labels accepted in `.bifrost/packs.json` `ecosystems`. Each
label selects one dependency resolver and one pack adapter. The input files
are the files whose change makes a host invalidate the ecosystem's packs.

| Label | Languages | Input files | What discovery reads |
| --- | --- | --- | --- |
| `jvm` | Java, Kotlin, Scala | `pom.xml`, `settings.xml`, `build.gradle`, `build.gradle.kts`, `settings.gradle`, `settings.gradle.kts`, `gradle.properties`, `gradle.lockfile`, `libs.versions.toml`, `gradle-wrapper.properties` | Exact Maven coordinates from reports, repositories, Gradle caches, and explicit paths. The default mode, `Metadata`, reads files only. Maven or Gradle runs only when a library host sets `JvmDependencyDiscoveryMode::OfflineBuildTools`. |
| `dotnet` | C# | `project.assets.json` | NuGet package, version, target framework, and asset role. |
| `npm` | JavaScript, TypeScript | `package.json`, `package-lock.json`, `npm-shrinkwrap.json` | Lockfiles and locally installed package manifests, to find declaration entry points. Lockfiles are limited to 32 MiB and package manifests to 1 MiB. |
| `python` | Python | `METADATA`, `RECORD`, `top_level.txt`, `pyproject.toml`, `.python-version` | A host-declared environment (standard library, bundled stubs, distributions), or the workspace-declared toolchain for standard-library packs. Never starts Python. |
| `go` | Go | `go.mod`, `go.sum`, `go.work`, `go.work.sum`, `modules.txt` | `go env` and `go list` metadata from the configured `go` executable, offline. A CLI policy run turns this on to select installed packs. Other hosts leave it off unless a library host sets `AnalyzerConfig.go.dependency_discovery.mode`. |
| `cargo` | Rust | `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml` | A host-supplied bundle of Cargo metadata and rustdoc JSON. Never runs Cargo. |
| `ruby` | Ruby | `Gemfile`, `Gemfile.lock`, `gems.locked` | A host-supplied lockfile and `.gem` archives. Never runs Ruby or Bundler. |
| `composer` | PHP | `composer.json`, `composer.lock`, `installed.json` | `composer.lock`, `vendor/composer/installed.json`, and installed package trees under approved vendor roots. At most 64 autoload rules per package and 8,192 directories per package walk. Never runs Composer. |
| `cpp` | C++ | `compile_commands.json` | Compile commands and the headers reachable from include roots outside the workspace. At most 10,000 headers and 32 MiB per header closure. |

None of these resolvers downloads anything.

## Discovery and precedence

### Sources

| Source kind | Storage | Origin |
| --- | --- | --- |
| `ephemeral_workspace` | Session memory | Models registered from `.bifrost/semantic-models/` for one session. |
| `workspace_produced` | Durable catalog | Packs produced by the workspace. |
| `generated` | Durable catalog | Packs generated locally from exact dependency artifacts. |
| `installed` | Durable catalog | Packs installed from a release bundle. |
| `pre_shipped` | Durable catalog | Packs that a host image installs in advance. |
| `embedded` | Session memory | The packs compiled into the engine. See [Shipped packs](#shipped-packs). |

### Selection order

1. Discovery narrows candidates by language, ecosystem, and the populated
   package, module, toolchain, or artifact index, without reading payloads.
2. Each candidate must be compatible. For a version 2 to 7 pack,
   `compatibility.bifrost` must match the engine version. A version 8 or later
   pack has no engine range; this build accepts it when it reads that
   version. Each populated selector field must match one evidence row.
3. Controls apply. A workspace control outranks a user control. Within a scope,
   a control that names `manifest_digest` outranks one that names `version`,
   which outranks one that names only `pack_id`. Equally ranked controls with
   different actions are an error. A `review_required` pack needs an `enable`
   control. A control cannot make an incompatible pack active.
4. When candidates overlap, the higher evidence rank wins: exact artifact, then
   versioned coordinate, then named coordinate, then language. Ties go to the
   higher source kind: ephemeral workspace, workspace-produced, generated,
   installed, pre-shipped, then embedded.
5. Equal-rank candidates with different facts stay a conflict.

Activation statuses are `active`, `disabled`, `incompatible`,
`review_required`, `shadowed`, `conflict`, and `unavailable`.

Authored workspace source and exact navigable artifact declarations outrank
model-only facts after activation.

## Shipped packs

The engine embeds these packs. Hosts register them when they bootstrap the
catalog. When `BIFROST_OPEN_SEMANTIC_PACK_BUNDLE` is set, the bundle replaces
this whole set; the two are not merged.

"Review" means the pack sets `safety.review_required`, so it also needs an
`enable` entry. "Ver." is the pack `schema_version`.

| Pack ID | Version | Language / ecosystem | Ver. | Payload | Completeness | Review | Models | Activation requires |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `bifrost.scala.case-class` | 1.0.0 | scala / maven | 2 | generator rules | partial | no | Generated `copy` and parameter accessors of case classes. | Scala present. |
| `bifrost.java.lombok` | 1.0.0 | java / maven | 2 | generator rules | partial | no | Accessors and constructors generated by Lombok 1.18.42 `@Data`, `@Getter`, `@Setter`, `@Value`, `@NoArgsConstructor`, `@RequiredArgsConstructor`. | Package `org.projectlombok:lombok` `=1.18.42`. |
| `bifrost.rust.getset` | 1.0.0 | rust / cargo | 2 | generator rules | partial | no | Getters generated by getset 0.1.7 `#[get = "pub"]`. | Package `getset` `=0.1.7`. |
| `bifrost.jdk21.result-use-obligations` | 1.0.0 | java / jdk | 5 | summaries | complete | no | `String.trim()` as a pure value; `Files.deleteIfExists(Path)` as a status result. | Toolchain `jdk` `>=21.0.0, <22.0.0`, target `jvm`. |
| `bifrost.node-runtime-values-javascript` | 0.1.0 | javascript / npm | 4 | `runtime_values` companion | partial | yes | `process.env` and `process.argv` keyed reads. | The Node runtime row for 22.11.0. |
| `bifrost.node-runtime-values-typescript` | 0.1.0 | typescript / npm | 4 | `runtime_values` companion | partial | yes | The same, for TypeScript. | The Node runtime row for 22.11.0. |
| `bifrost.node-child-process-javascript-declarations` | 0.2.0 | javascript / npm | 2 | declarations | partial | yes | The `child_process` module and `execSync`. | JavaScript present. |
| `bifrost.node-child-process-typescript-declarations` | 0.2.0 | typescript / npm | 2 | declarations | partial | yes | The same, for TypeScript. | TypeScript present. |
| `bifrost.node-child-process-javascript-summaries` | 0.1.0 | javascript / npm | 4 | summaries | complete | yes | `child_process.execSync`. | JavaScript present. |
| `bifrost.node-child-process-typescript-summaries` | 0.1.0 | typescript / npm | 4 | summaries | complete | yes | The same, for TypeScript. | TypeScript present. |
| `bifrost.node-buffer-javascript-declarations` | 0.1.0 | javascript / npm | 2 | declarations | partial | yes | The `Buffer` type and four members. | JavaScript present. |
| `bifrost.node-buffer-typescript-declarations` | 0.1.0 | typescript / npm | 2 | declarations | partial | yes | The same, for TypeScript. | TypeScript present. |
| `bifrost.python-process-inputs` | 0.1.0 | python / pypi | 4 | `runtime_values` companion | partial | no | `os.environ` and `sys.argv` keyed reads. | The Python process-input row. |
| `bifrost.python-os-command-declarations` | 0.2.0 | python / pypi | 2 | declarations | partial | no | The `os` module and `os.system/chmod/open/mkdir/makedirs`. | Python present. |
| `bifrost.python-os-command-summaries` | 0.1.0 | python / pypi | 4 | summaries | complete | no | `os.system(command)`. | Python present. |
| `bifrost.python-security-sink-declarations` | 0.1.0 | python / python | 2 | declarations | partial | no | `socket.socket.bind` and three XML parser entry points. | CPython `3.13.5`. |
| `bifrost.python-security-sink-summaries` | 0.2.0 | python / python | 14 | summaries | complete | no | Socket bind, XML parser, and regex execution input flows. | CPython `3.13.5`. |
| `bifrost.python-stdlib-api-declarations` | 0.2.0 | python / python | 2 | declarations | partial | no | `hmac.new`, `hashlib.md5/sha1/sha256`, `re` execution APIs and `Pattern.search`, `textwrap.shorten`, `pathlib.Path.chmod`, and legacy `ssl.wrap_socket`. | CPython `>=3.10, <3.15`; SSL shard `>=3.10, <3.12`. |
| `bifrost.go.stdlib.os` | 1.0.0 | go / go | 2 | summaries | complete | no | Result contracts for `os.Open`, `os.Create`, `os.CreateTemp`, `os.OpenFile`, `os.Stat`, `os.Lstat`, `os.File.Stat`, `os.IsNotExist`, `os.Exit`, and `os/exec.ExitError.ExitCode`. | Go present. |
| `bifrost.go.stdlib.os-declarations` | 1.0.0 | go / go | 2 | declarations | partial | no | Declarations for the `os` summaries. | Go present. |
| `bifrost.go.stdlib.errors` | 1.1.0 | go / go | 7 | summaries | complete | no | `errors.Is`, `errors.As`, `errors.New`. | Go present. |
| `bifrost.go.stdlib.errors-declarations` | 1.0.0 | go / go | 2 | declarations | partial | no | Declarations for `errors`. | Go present. |
| `bifrost.go.stdlib.log` | 1.0.0 | go / go | 2 | summaries | partial | no | No normal return for `log.Fatal*`, `log.Panic*`, and the `log.Logger` methods of the same names. | Go present. |
| `bifrost.go.stdlib.log-declarations` | 1.0.0 | go / go | 2 | declarations | partial | no | Declarations for `log`. | Go present. |
| `bifrost.go.stdlib.net` | 1.1.0 | go / go | 2 | summaries | complete | no | Result contracts for `net.Dial`, `net.DialTimeout`, `net.Listen`. | Go present. |
| `bifrost.go.stdlib.net-declarations` | 1.1.0 | go / go | 2 | declarations | partial | no | `net`, `net.Conn`, `net.Listener`, `net.Addr`. | Go present. |
| `bifrost.go.stdlib.net-url` | 1.0.0 | go / go | 2 | summaries | complete | no | Result contracts for `url.Parse` and `url.ParseRequestURI`. | Go present. |
| `bifrost.go.stdlib.net-url-declarations` | 1.0.0 | go / go | 2 | declarations | partial | no | `net/url` and `url.URL`. | Go present. |
| `bifrost.go.stdlib.net-http` | 1.2.0 | go / go | 2 | summaries | complete | no | Handler registration and serving: `http.Handle`, `HandleFunc`, `Serve`, `ListenAndServe`, `NewServeMux`, `ServeMux.Handle`, `ServeMux.HandleFunc`, and `http.Get`. | Go present. |
| `bifrost.go.stdlib.net-http-declarations` | 1.2.0 | go / go | 2 | declarations | partial | no | `net/http`, `Handler`, `HandlerFunc`, `ServeMux`. | Go present. |
| `bifrost.go.stdlib.bytes-declarations` | 1.0.0 | go / go | 2 | declarations | partial | no | The `bytes` package and one member. | Go present. |
| `bifrost.go.stdlib.encoding-pem` | 1.0.0 | go / go | 2 | summaries | complete | no | Result contract for `pem.Decode`. | Go present. |
| `bifrost.go.stdlib.encoding-pem-declarations` | 1.0.0 | go / go | 2 | declarations | partial | no | `encoding/pem` and `pem.Block`. | Go present. |
| `bifrost.go.stdlib.crypto-x509` | 1.0.0 | go / go | 2 | summaries | complete | no | Parameter preconditions for `x509.IsEncryptedPEMBlock`. | Go present. |
| `bifrost.go.stdlib.crypto-x509-declarations` | 1.0.0 | go / go | 2 | declarations | partial | no | `crypto/x509` and one member. | Go present. |
| `bifrost.go.stdlib.path-filepath` | 1.0.0 | go / go | 2 | declarations | partial | no | The `path/filepath` module and the variadic `Join(...string) string`. | Go present. |
| `bifrost.go.stdlib.testing` | 1.1.0 | go / go | 2 | declarations, summaries | partial | no | `testing.T`, `testing.B`, `testing.F` receivers, and no normal return for their `FailNow`, `Fatal*`, and `Skip*` methods. | Go present. |
| `bifrost.go.stdlib.sync-atomic` | 1.0.0 | go / go | 2 | summaries | complete | no | Concurrency effects of the `sync/atomic` functions and typed atomics. | Go present. |
| `bifrost.go.stdlib.sync-atomic-declarations` | 1.0.0 | go / go | 2 | declarations | partial | no | Declarations for `sync/atomic`. | Go present. |
| `bifrost.go.concurrency` | 1.6.0 | go / go | 12 | summaries | complete | no | Concurrency effects for `sync` (mutexes, `Once`, `WaitGroup`, `Cond`, `Map`), `context.Context.Done` and cancellation, `time` timers and tickers, `testing.T.Run`, `Parallel`, `Cleanup`, and `errgroup`. | Go present. The `errgroup` shard also requires module `golang.org/x/sync` `>=0.1.0, <1.0.0` in ecosystem `go`. |
| `bifrost.go.concurrency-declarations` | 1.2.0 | go / go | 2 | declarations | partial | no | Declarations for the concurrency summaries. | Go present. The `errgroup` shard has the same module requirement. |
| `bifrost.go.testify.require` | 1.0.0 | go / go-module | 2 | summaries | complete | no | Normal-return refinement for `require.NoError`. | Module `github.com/stretchr/testify` `=1.11.1`. |
| `bifrost.go.testify.require-declarations` | 1.0.0 | go / go-module | 2 | declarations | partial | no | `require` and `require.TestingT`. | The same module. |
| `bifrost.go.testify.assert` | 1.0.0 | go / go-module | 2 | summaries | complete | no | Conditional result refinement for `assert.NoError`. | The same module. |
| `bifrost.go.testify.assert-declarations` | 1.0.0 | go / go-module | 2 | declarations | partial | no | `assert` and `assert.TestingT`. | The same module. |

"Present" means that the workspace contains files of that language, which
mints the intrinsic language row. The source files for open packs and their
release recipes are published in
[Bifrost-packs](https://github.com/BrokkAi/bifrost-packs).

## bifrost-semantic-pack

The `bifrost-semantic-pack` binary is in the `brokk-bifrost-semantic-packs`
crate. Build it with the `release-tooling` feature:

```bash
cargo run -p brokk-bifrost-semantic-packs --features release-tooling \
  --bin bifrost-semantic-pack -- validate model.yaml
```

`--format human` (default) or `--format json` may appear anywhere in the
arguments. Source files must end in `.json`, `.yaml`, or `.yml`.

| Command | Arguments | `--format json` | Purpose |
| --- | --- | --- | --- |
| `validate` | `SOURCE` | yes | Parse, validate, and compile one source with the production compiler. |
| `lint` | `SOURCE` | yes | `validate`, plus authoring warnings: duplicate IDs, unreachable or shadowed rules, ambiguous selectors, unused captures, broad wildcard selectors, and conflicting emissions. |
| `csmi-check` | `FILE` | yes | Validate a CSMI semantic document or pack manifest. A manifest (`documentType: pack-manifest`) also has its resources checked, relative to the manifest's directory. |
| `compile` | `SOURCE OUTPUT` | yes | Write `manifest.json` and `shards/` to `OUTPUT`. Identical existing files are accepted; different existing files are an error. |
| `list` | `CATALOG [ACTIVATION.json]` | yes | Open a catalog read-only and list installed packs. With an activation file, also resolve and list active packs and explanations. |
| `workspace-check` | `WORKSPACE` | yes | Discover and lint the files in `WORKSPACE/.bifrost/semantic-models/`. |
| `generate` | `OUTPUT SPEC ARTIFACT [SPEC ARTIFACT ...]` | no | Build a release bundle from pinned specs and their artifacts. |
| `merge` | `OUTPUT INPUT...` | no | Merge release bundles into `OUTPUT`. |
| `verify` | `OUTPUT` | no | Verify a release bundle. |
| `install` | `BUNDLE CATALOG` | no | Install a release bundle into the catalog directory `CATALOG`. |
| `summary-corpus-join` | `PINS CODEQL_MODELS JOERN_SOURCE REPORT.json [JVM_SOURCES]` | no | Translate two pinned third-party summary corpora, round-trip them through the pack format, join them, and write the report to `REPORT.json`. |
| `sanitizer-pack` | `CANDIDATES_DIR OUTPUT_ROOT` | no | Convert sanitizer candidates into procedure-summary packs and an audit report. |
| `framework-decl-pack` | `CANDIDATES_DIR OUTPUT_ROOT` | no | Convert framework declaration candidates into declaration packs and an audit report. |
| `golden-summary-pack` | `CANDIDATES_DIR OUTPUT_ROOT REALM` | no | Convert one realm's flow-through candidates into a procedure-summary pack. `REALM` is `jdk`, `python`, `rust`, `javascript`, or `typescript`. |

The last nine commands are release tooling. They print human-readable text
only, and `--format json` makes them fail with status 2.

### Exit status

| Command | 0 | 1 | 2 |
| --- | --- | --- | --- |
| `validate`, `lint` | Valid, with no diagnostics. | Invalid, or `lint` reported a warning. | Bad arguments or unreadable input. |
| `csmi-check` | Valid. | Invalid. | Bad arguments or unreadable input. |
| `compile` | Written. | The source is invalid; the validation report is printed. | Bad arguments, unreadable input, or a write conflict. |
| `list` | Complete inventory. | | Incomplete inventory, activation that did not produce a complete active set, bad activation file, or catalog error. |
| `workspace-check` | Complete and every file valid. | A file is invalid. | Discovery is incomplete (limits, links, unreadable entries) while every discovered file is valid. |
| `summary-corpus-join` | Round trip clean. | Round trip not clean. | Error. |
| Other release commands | Success. | | Error. |

Any command fails with status 2 for an unknown command, a missing argument, or
an unknown `--format` value. With `--format json`, a failure prints
`{"format": "bifrost_semantic_model_cli_error/v1", "code": "command.failed",
"exit_status": N, "error": "..."}` on standard output.

### Report formats

| Command | `format` value | Fields |
| --- | --- | --- |
| `validate` | `bifrost_semantic_model_validate/v1` | `source_sha256`, `valid`, `pack_id`, `pack_version`, `manifest_content_sha256`, `manifest_semantic_sha256`, `diagnostics` |
| `lint` | `bifrost_semantic_model_lint/v1` | The same fields as `validate`. |
| `compile` | `bifrost_semantic_model_write/v1` | `manifest_path`, `manifest_content_sha256`, `shard_paths` |
| `list` | `bifrost_semantic_model_inventory/v1` | `complete`, `installed`, `active`, `activation_explanations` |
| `workspace-check` | `bifrost_semantic_model_workspace/v1` | `directory`, `enabled`, `complete`, `files` (`path`, `source_sha256`, `source_format`, `valid`, `pack_id`, `manifest_semantic_sha256`, `diagnostics`), `diagnostics` |
| `csmi-check` | `bifrost_csmi_check/v2` | `input_kind` (`pack` or `document`), `structural_valid`, `semantic_valid`, `integrity_valid` (`null` for a document), `interpretable`, `valid`, `profiles` (`identifier`, `version`, `schema`, `schema_recognized`, `structural_valid`, `semantically_supported`), `diagnostics` |

A diagnostic has `severity` (`error` or `warning`), `code`, `path`, and
`message`. Fields with no value are omitted.

`workspace-check` reads direct children of `.bifrost/semantic-models/` with
the extension `.json`, `.yaml`, or `.yml`. It ignores other files without a
diagnostic. It allows at most 1,024 directory entries (`limit.workspace_files`)
and 64 MiB per file (`limit.source_bytes`). It rejects symbolic links,
non-files, and paths that resolve outside the workspace.

### Activation input file

The optional `ACTIVATION.json` argument of `list`:

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `schema_version` | integer | yes | Must be `1`. |
| `bifrost_version` | SemVer version | yes | The engine version to check against `compatibility.bifrost` in version 2 to 7 packs. |
| `evidence` | list | yes | Evidence rows: `language`, `ecosystem`, and optional `package`, `module`, `toolchain` (`{name, version?}`), `target`, `configuration`, `artifact_sha256`. |
| `controls` | list | no | `[{scope, action, pack_id, version?, manifest_digest?}]`. `scope` is `user` or `workspace`. `action` is `enable` or `disable`. `version` is a SemVer requirement. |

### Pinned pack specs

`generate` reads one pinned spec per artifact. A spec is JSON with
`schema_version` `1` or `2` and rejects unknown fields. Version `1` is the
legacy pinned input schema. Version `2` adds optional per-shard activation
pins for authored semantic models.

| Field | Meaning |
| --- | --- |
| `schema_version` | Must be `1` or `2`. Version `1` does not accept `shard_activation_pins`. |
| `pack_id`, `pack_version`, `ecosystem` | The pack identity. |
| `kind` | The producer family, tagged by `artifact_kind` (table below). |
| `artifact` | `{file_name, sha256, url?, container?}`. `container` is `{file_name, sha256, url, artifact_path}` when the artifact is inside another archive. |
| `compatibility` | As in the pack envelope. Generated packs are written at schema version 8 or later, so every spec except `authored_semantic_model` must omit `bifrost`. `generate` rejects a generated spec that sets it. |
| `activation` | Required, bounded activation selectors. Generated shards use these selectors. Authored shards without per-shard pins must repeat this selector vector exactly. When pins are present, they state the authored shards' exact selectors. |
| `provenance`, `license`, `safety` | As in the pack envelope. |
| `notices` | Notice files to include. |
| `measurement_activation` | One activation selector used for measurement. |
| `measurement_queries` | Lookups used to measure the result: `type` (`name`), `member` (`owner`, `name`), or `procedure` (`language`, `owner`, `name`, `has_receiver`, `parameter_count`). |

Every version requirement in `compatibility.toolchains` and in activation
selector coordinates must have an upper bound. `generate` rejects an open
requirement such as `>=21.0.0`. This check applies only to pinned specs. It
does not apply to authored packs checked with `validate`.

Version `2` authored specs may add `kind.shard_activation_pins`, a nonempty
array of closed `{shard_id, activation}` entries. The IDs must be nonempty,
unique, and cover the authored pack's complete shard set exactly. Each entry
must have at least one selector, and each shard's selector vector must equal
its pin exactly, including selector order, coordinates, targets,
configurations, and artifact digest. Every version requirement in these
selectors must also have an upper bound. A missing field keeps the legacy
rule: every authored shard repeats the spec's global `activation` vector
exactly. A `null` or empty pin array is invalid; pins in a version `1` spec
are rejected. The global activation remains required for version `2` specs.
The exact pin comparison checks the authored input before compilation. The
compiler then applies its existing canonical ordering of selectors, targets
and configurations to the compiled output; this does not relax input matching.

| `artifact_kind` | Extra fields | Input |
| --- | --- | --- |
| `jdk_source_zip` | `layout` (`module_prefixed` or `flat`) | A JDK `src.zip`. |
| `kotlin_source_jar` | none | A Kotlin source JAR. |
| `scala_source_jar` | none | A Scala source JAR. |
| `java_source_jar` | none | A Java source JAR. |
| `java_class_jar` | none | A Java class JAR. |
| `type_script_declaration_file` | none | One `.d.ts` file. |
| `type_script_library_set` | `manifest`, `libraries` (`[{name, path}]`) | A set of TypeScript library files. |
| `dot_net_assembly` | none | A .NET assembly. |
| `rustdoc_json` | none | One rustdoc JSON file. |
| `rustdoc_json_set` | `crates` (`[{name, path}]`) | Several rustdoc JSON files. |
| `python_stub` | `stubs` (relative seed `.pyi` paths) | A pinned stub tree; local imports determine the loaded closure. |
| `authored_semantic_model` | `shard_activation_pins` (optional in spec version `2`; exact complete per-shard selector list) | An authored pack source, compiled directly. |
| `npm_package` | `manifest`, `declarations` (`[{module, path}]`) | An npm package manifest and its declaration files. |
| `go_module` | `packages` (`[{import_path, name, files}]`) | A Go module source set. |
| `ruby_gem_archive` | none | A `.gem` archive. |
| `composer_package` | `rules` (tagged by `rule`: `psr4` with `namespace_prefix` and `files`; `classmap` with `files`; `files` with `files`) | A Composer package source set. |
| `php_declaration_stub` | `stubs` (relative `.php` paths) | A tree of PHP declaration stubs. |

For `python_stub`, the artifact directory is an import root, such as a pinned
typeshed `stdlib` tree. Generation follows AST imports, including module aliases,
relative imports, package initializers and available imported child modules,
until no new stubs remain. Seeds are order independent and duplicates are
ignored. Resolution reads only this local tree; absent modules remain unresolved.
The existing source-file, path-depth, byte and symlink bounds apply to the full
closure. No Python code executes.

`artifact.sha256` pins the canonical exact source set over the computed closure,
including every relative path and its exact bytes. The compiled manifest's
`source_inputs` records that digest and the sorted loaded `files`, each with
`path`, `sha256` and `bytes`. A transitive input edit changes the input identity
even if it leaves the declarations unchanged. This inventory records generation
provenance; it does not claim that those files are available for navigation.

A release bundle has `index.json` (bundle index schema version `3`),
`rejects.json`, `measurements.json`, `SHA256SUMS`, and the pack assets.
`verify` and `merge` reject a bundle whose index names a different generator
than the running build (`brokk-bifrost-semantic-packs` at the same version),
because publishing a bundle must not mix generators. `install` and
`bifrost install-semantic-packs` accept a bundle from any generator: each
curated pack installs when this build reads its schema version. Installation
skips, without reporting it, a generated production whose schema or cache
version is not current for this build; the engine builds that production on
demand instead.

## bifrost pack commands

The main `bifrost` binary has two pack commands. They run before any analyzer
starts. The full CLI is in the [CLI reference](/reference/cli/).

### bifrost pack-engine-profile

Takes no arguments. Prints one JSON object that describes the pack formats
this build supports. A host passes it to pack selection tools.

| Field | Meaning |
| --- | --- |
| `engine_version` | The `bifrost` package version. |
| `build_identity` | The exact source revision of this build. |
| `model_set_sha256` | SHA-256 over the embedded pack registry: each pack's source ID and manifest bytes, length-prefixed. |
| `capability_contract_version` | `1`. |
| `schemas.policy_document` | Supported policy document versions. |
| `schemas.rql` | Supported RQL schema versions. |
| `schemas.builtin_catalog` | Supported built-in policy catalog versions. |
| `schemas.semantic_model_read` | `[2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17]`. |
| `schemas.semantic_model_write` | `[17]`, the newest version. Generated packs may declare a lower one. |
| `schemas.release_index` | `[3]`, the release bundle index version. |
| `schemas.policy_bundle`, `schemas.semantic_spec`, `schemas.runtime` | Empty lists. |
| `capabilities` | Always an empty list. This build advertises no pack capability requirements. |

Exit status is 0 on success and 1 when arguments are given.

### bifrost install-semantic-packs

```bash
bifrost install-semantic-packs BUNDLE_DIR CACHE_ROOT
```

Verifies an extracted release bundle and installs it into
`CACHE_ROOT/semantic-pack-catalog.v11`. A relative `CACHE_ROOT` is resolved
against the current directory. This is the catalog that
`BIFROST_SEMANTIC_PACK_CACHE_ROOT=CACHE_ROOT` selects. On success it prints
`{"catalog_root": ..., "installed": [{"pack_id", "pack_version",
"manifest_digest"}]}` and exits 0. It exits 1 on a usage error, a catalog or
bundle error, or when the bundle installs no compatible pack.

`bifrost-semantic-pack install` differs: it installs into the `CATALOG`
directory exactly as given, without adding the versioned subdirectory.

## Environment variables

These variables change pack behavior. The
[environment reference](/reference/environment/) lists every variable.

| Variable | Effect |
| --- | --- |
| `BIFROST_SEMANTIC_PACK_CACHE_ROOT` | Root of the default catalog and of the shared generated-pack cache. |
| `BIFROST_OPEN_SEMANTIC_PACK_BUNDLE` | An extracted release bundle that replaces the embedded packs. Bifrost installs it when it opens a catalog for activation. An empty value, a malformed bundle, or a bundle with no compatible pack makes that activation fail. A policy report then carries `pack-activation-failed` and the run exits 2. |
| `BIFROST_POLICY_PACK_ROOT` | An extracted policy rules directory that replaces the embedded policy catalog. See the [policy reference](/reference/policies/). |
| `BIFROST_WORKSPACE_SEMANTIC_MODELS` | Read by every `SearchToolsService` session: the MCP server, one-shot `--tool` and `--query-file` runs, a policy run with `--sources`, and the Rust and Python libraries. `on`, `1`, or `enabled` registers `.bifrost/semantic-models/` when the session activates packs; `off`, `0`, or `disabled` (the default) does not. Any other value is an error. A CLI policy run without `--sources` reads the directory whether or not this variable is set. |
| `BIFROST_SEMANTIC_PACK_CATALOG`, `BIFROST_SEMANTIC_PACK_EVIDENCE` | Legacy. Read by every `SearchToolsService` session. Set both or neither. The catalog is opened read-only. The evidence is a non-empty JSON array of rows with `language`, `ecosystem`, and optional `package`, `module`, `toolchain` (`{name, version?}`), `target`, `configuration`, and `artifactSha256`. This route supplies no `enable` controls, and it fails when `.bifrost/packs.json` exists. |
