# Structurally valid semantic near misses

Every JSON document in this directory must pass `spec/0.1/schema.json`. Each
then fails a semantic rule that JSON Schema cannot establish:

| Fixture | Semantic violation |
| --- | --- |
| `unresolved-symbol.json` | A declaration references a local symbol handle that is not defined. |
| `noncontiguous-parameters.json` | Callable parameter positions are not contiguous from zero. |
| `missing-provenance.json` | The default provenance handle does not resolve. |
| `undeclared-vocabulary.json` | An extension fact has no corresponding exact vocabulary-use declaration. |
| `duplicate-completeness-scope.json` | One model assigns two statements to the same family and equivalent scope. |
| `missing-declaration-dependency.json` | A procedure summary needs a callable shape that is neither embedded nor declared as consumer-resolved. |
| `python-runtime-overload-identity.json` | A declaration-only Python typing overload is given a runtime procedure summary. |
| `javascript-identity-profile-optional.json` | The standard JavaScript/TypeScript identity profile is declared optional. |
| `javascript-module-binding-mismatch.json` | Module-binding evidence contradicts the attached symbol identity. |
| `javascript-profile-payload-undeclared.json` | A known profile payload and identity scheme omit the exact vocabulary-use declaration. |
| `javascript-runtime-binding-scope-mismatch.json` | A runtime/declaration fact's scope and payload name different runtime symbols. |
| `node-mutually-exclusive-conditions.json` | One Node resolution activates mutually exclusive `import` and `require` conditions. |
| `rust-name-only-trait-binding.json` | A Rust implementation uses name-only trait and self-type references instead of defined resolver-proven symbols. |
| `rust-complete-with-unsupported-expansion.json` | Rust generation coverage is claimed complete although the producer marks the relevant expansion unavailable. |
| `rust-sysroot-selector-mismatch.json` | A Rust sysroot payload points at a different exact sysroot artifact than the enclosing semantic model. |
| `rust-invalid-identity-normalization.json` | Rust source keys use a lowercase percent escape, retain a raw-identifier prefix, and name a generic parameter instead of using its position. |

These fixtures are expected to remain structurally valid. A validator that
rejects them through undocumented heuristics is not a conforming substitute for
the semantic checks in the specification.
