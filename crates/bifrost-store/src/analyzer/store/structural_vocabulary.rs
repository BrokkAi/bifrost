use brokk_bifrost_core::analyzer::structural::facts::AssignmentShape;
use brokk_bifrost_core::analyzer::structural::facts::IntegerLiteralValue;

/// Semantic contract for persisted structural facts.
///
/// Increment this whenever normalization semantics or the persisted row shape changes,
/// even when older rows would still hydrate. The version is stored in the
/// SQLite manifest so incompatible facts are treated as ordinary cache misses.
/// Version 2 was claimed twice on divergent branches (loop-kind refinement and
/// the #1473 per-node occurrence-role rows), so their merge is version 3.
/// Version 4 was also claimed twice (the #1474 `Block` kind, which makes
/// scope-forming statement lists facts, and the #1603 generated behavior
/// models), so their merge is version 5.
/// Version 6 adds source-backed facts parsed from opaque regions, initially
/// Python deferred annotation strings (#1570).
/// Version 7 adds the per-call-site classification a language spec reads from
/// its own grammar node: refined call kind, argument-shape coverage, and
/// whether the site continues its callee's argument-list sequence (#1478).
/// Version 8 makes TypeScript's bodiless callable declarations facts:
/// `function_signature`, `method_signature`, and `abstract_method_signature`
/// normalize as callables, so declaration-only stubs are addressable (#1658).
/// Version 9 records the exact language-neutral value of normalized boolean
/// literals for the RQL `boolean_value` predicate (#2623).
/// Version 10 makes collection display literals facts (`collection_literal`,
/// a `literal` subtype) and adds the `iterable` role edge from a for-each
/// loop to its iterated expression and the `elements` role edges from a
/// collection literal to its elements (#2647).
/// Version 11 adds TypeScript formal parameter facts (`parameter`, a
/// `declaration` subtype) and parameter decorator role edges (#2644).
/// Version 12 adds JSX element/attribute facts, object-property facts, and
/// structured tag, attribute, child, key, and value role edges (#2645).
/// Version 13 adds Rust `decorators` role edges from a declaration to the
/// outer attributes written above it (#2518).
/// Version 14 makes module and namespace declarations facts (`module`, a
/// `declaration` subtype) in Rust, C#, C++, PHP, and Ruby, which also makes
/// them containment parents of everything they enclose (#2518).
/// Version 15 gives Scala occurrence-role classification, so Scala facts now
/// carry per-node occurrence roles where version 14 carried none (#1597).
/// Version 16 makes a Scala `type_definition` a class-kind fact, so a type
/// alias's declaration name reports the type namespace instead of the value
/// namespace it reported when the alias had no declaring fact (#2878).
/// Version 17 does the same for Kotlin: a `type_alias` is a class-kind fact,
/// and every Kotlin declaration name now carries the `declaration_name`
/// occurrence role. The role was decided by a `name` AST field this grammar
/// never spells, so version 16 reported every Kotlin class, object and function
/// name as a plain value reference (#2892).
/// Version 18 finishes the set for Rust and TypeScript: a `type_item` and a
/// `type_alias_declaration` are class-kind facts, so an alias name reports the
/// type namespace instead of the value namespace it reported while the alias
/// normalized as a bare `declaration` (#2911).
/// Version 19 gives Scala a scope tree: `block`, `indented_block` and
/// `case_clause` are block-kind facts and `package_object` is a class-kind
/// fact, so Scala facts carry scope-forming nodes that version 18 did not
/// (#1597).
/// Version 20 completes that scope tree: a Scala `given_definition` is a
/// callable-kind fact and an `extension_definition` is a block-kind fact, so
/// the parameters written in either are scoped by the definition instead of
/// sitting in the enclosing template's scope, where the shared class-scope
/// rule excluded them as members (#2925).
/// Version 21 gives Ruby a lexical environment: `singleton_class` is a
/// class-kind fact, and every `identifier`, `constant`, `instance_variable`,
/// `class_variable` and `global_variable` token now carries an occurrence role
/// where only receiver-call member positions did before (#2962).
/// The same version gives PHP one: every `name` and `variable_name` token now
/// carries an occurrence role -- binder, import alias, import target, type
/// operand, path segment, receiver, declaration name or value reference --
/// where only member positions did before (#2962).
/// Version 24 adds Java formal and spread parameter facts and their annotation
/// role edges (#3714). Old arenas cannot supply these source identities.
/// Version 25 stops classifying Kotlin reads inside `for` and `catch` bodies,
/// parameter default values and `for` iterables as binders (#3551).
/// Version 26 classifies C# binders and adds C# block and implicit lambda
/// parameter facts (#3546).
/// Version 27 classifies Go binders and adds Go block, case and switch
/// scope facts (#3547).
/// Version 28 classifies C and C++ binders and adds their block, switch and
/// range-`for` scope facts (#3544, #3545).
/// Version 29 records decoded values for normalized string literals.
/// Version 29 records the regions tree-sitter error recovery produced, each
/// outermost `ERROR` node and `MISSING` token, as recovered-region rows
/// (#3777). Older facts cannot say whether recovery removed a node.
/// Version 30 stores nested Python regex facts and recovery-derived comments/errors.
/// Version 31 adds Python comparison/binary facts and string parenthesization.
/// Version 32 adds Python parameter/directive kinds and paired assignment shapes.
/// Version 33 adds canonical integer-literal values.
/// Version 34 bounds decimal spellings and stores integer permission bits.
/// Version 35 records duplicate-key status on Python dictionary entries.
/// Version 36 adds tuple-literal facts alongside the Python literal facts.
/// Version 37 seals the combined 2026-10-03 structural-facts generation.
/// Version 38 adds decoded Python strings and the distinct list-literal kind.
/// Version 39 adds origin vocabulary and polynomial Python regex-risk facts.
/// Version 40 combines those with local facts and vocabulary.
/// Version 41 combines local version-40 facts with origin async-callable and await-node facts.
/// Version 42 adds Python module roots to normalized declaration facts.
/// Version 43 combines version 42 with C# field modifiers and initializers,
/// integer and string literal values, the distinct character-literal kind,
/// and assignment-operator and element-access roles (#4380, #4382).
/// Version 44 publishes Java underscore patterns and exact Rust macro-derived
/// call-shape coverage for selectors (#4366).
/// Version 45 adds JS/TS decoded string and template literals, constructor
/// call kinds, named function binders, object-method properties, and
/// collection and parameter positions (#4386, #4387, #4388).
/// Version 47 combines the signed integer literal values for repeated-literal
/// aggregation with Java enhanced-for binder classification. These changes
/// diverged as version 46 on the two branches.
/// Version 49 stores Rust callee provenance, supplier, type shape and bounds
/// and Rust call unsafe context as trailing structural node-array positions (#6217).
#[doc(hidden)]
pub const STRUCTURAL_FACTS_VERSION: i64 = 49;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub struct PersistedSpan {
    #[doc(hidden)]
    pub start: u32,
    #[doc(hidden)]
    pub end: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedStructuralNode {
    pub node_id: u32,
    /// `NormalizedKind::code()`, decoded in `from_persisted_rows`.
    pub kind: u8,
    pub boolean_value: Option<bool>,
    pub parenthesized: Option<bool>,
    pub assignment_shape: Option<AssignmentShape>,
    pub integer_literal_value: Option<IntegerLiteralValue>,
    pub duplicate_key: Option<bool>,
    pub is_async: Option<bool>,
    /// Rust call-site unsafe context; absent on other kinds and languages.
    pub unsafe_context: Option<bool>,
    pub string_value: Option<String>,
    pub construct: Option<String>,
    pub span: PersistedSpan,
    pub parent: Option<u32>,
    pub name: Option<PersistedSpan>,
    pub subtree_end: u32,
    pub call_site: Option<PersistedCallSite>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedCallSite {
    pub callee_provenance:
        Option<brokk_bifrost_core::analyzer::structural::callable::CalleeProvenanceFact>,
    pub call_kind: Option<u8>,
    pub coverage: u8,
    pub continues_callee_groups: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedStructuralRole {
    pub source_node_id: u32,
    pub ordinal: u32,
    /// `Role::code()`, decoded in `from_persisted_rows`.
    pub role: u8,
    pub spread: bool,
    pub keyword: Option<PersistedSpan>,
    pub node: Option<u32>,
    pub span: PersistedSpan,
    pub name: Option<PersistedSpan>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedOccurrenceRole {
    pub node_id: u32,
    pub ordinal: u32,
    /// `OccurrenceRole::code()`, decoded in `from_persisted_rows`.
    pub role: u8,
}

/// One `source_structural_recovered_regions` row with the store's answer to
/// whether a callable fact contains it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub struct PersistedRecoveredRegion {
    #[doc(hidden)]
    pub span: PersistedSpan,
    pub inside_callable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct PersistedStructuralFacts {
    pub source_bytes: u32,
    pub nodes: Vec<PersistedStructuralNode>,
    pub roles: Vec<PersistedStructuralRole>,
    pub occurrence_roles: Vec<PersistedOccurrenceRole>,
    #[doc(hidden)]
    pub recovered_regions: Vec<PersistedRecoveredRegion>,
}
