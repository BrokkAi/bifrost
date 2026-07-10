# Issue 581: synthetic constructor and source round-trip policy

## Decision

Bifrost does not model compiler-provided default constructors as synthetic
`CodeUnit`s merely to give constructor calls a `Function` target. When no
user-authored constructor exists, definition and usage resolution should use the
declaring type. This is already the structured fallback used by the current Java,
C#, JavaScript/TypeScript, and similar resolver paths.

Synthetic identities remain appropriate when they preserve real,
constructor-specific source semantics. They must carry a source range if they are
advertised by `search_symbols`. `search_symbols` therefore omits internal graph
identities that have no unique source range; an advertised selector must be
re-queryable by source and location tools without a language-specific invented
source fallback.

## Language audit

| Language | Policy | Source and analysis behavior |
| --- | --- | --- |
| Java | No synthetic implicit constructor. Explicit constructors remain normal function units. | `new Type()` resolves to an explicit constructor when one matches, otherwise to the class. Removing the implicit unit also removes a false callable/dead-code candidate and the `Type` versus `Type.Type` search ambiguity. |
| C# | No synthetic implicit constructor. | Explicit `constructor_declaration` units round-trip normally; construction without one resolves to the class. |
| Python | No synthetic implicit constructor. | Explicit `__init__` methods round-trip normally. A class with no `__init__` advertises only the class. |
| Scala | Keep the synthetic primary-constructor unit when class parameters provide constructor-specific identity/signature information. | The unit is backed by the class node range, so `search_symbols` -> `get_symbol_sources` returns the class declaration. Secondary constructors are explicit source-backed functions. A parameterless class does not need a synthetic constructor unit. |
| JavaScript / TypeScript | No synthetic implicit constructor. | Explicit `constructor` methods round-trip normally; a class without one advertises only the class. |
| C++ | No synthetic implicit constructor is created. Keep the existing synthetic marker on real in-class function declarations. | Those declaration identities have exact ranges and round-trip normally. The marker distinguishes declaration-side identities from out-of-line definitions and is not a compiler-generated constructor model. |
| Go | Constructors do not apply. Keep range-less replicated inline-member identities for graph/owner resolution, but do not advertise them through `search_symbols`. | The first member with a real syntax range remains searchable and source-retrievable. Replicas created for grouped anonymous struct/interface fields remain internal. |
| PHP | No synthetic implicit constructor. | Explicit `__construct` methods round-trip normally. |
| Ruby | No synthetic implicit constructor. | Explicit `initialize` methods round-trip normally. |

## Tool invariant

`search_symbols` is an implicit offer of a selector for follow-up source and
location calls. It must only advertise declarations with a concrete source range.
Internal range-less identities may remain available to structured resolvers, but
must not appear as user-retrievable source symbols.
