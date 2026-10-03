//! Canonical Rust item/type publication through the real producer and store.

use super::tests::{oid_for, parse_state};
use super::*;
use crate::analyzer::rust::RustAdapter;
use crate::inline_project::InlineTestProject;
use brokk_bifrost_core::analyzer::rust_facts::{
    RustItemMacroExpansion, RustItemMacroSourcePosition, RustItemSourceFacts, RustTypeSourceFact,
};
use brokk_bifrost_rust::hierarchy::RustHierarchySourceFacts;

const ITEM_SOURCE: &str = concat!(
    "struct Caf\u{e9}; type Unicode = Caf\u{e9};\n",
    r#"
struct Item;
struct Fields<T> { value: Option<Result<T, Error>> }
union GenericUnion<T> { value: T }
type GenericAlias<T> = Option<T>;
const VALUE: Item = Item;
static STATIC_VALUE: Item = Item;
enum Variants<T> { Unit, Tuple(T), Named { value: T } }
fn annotated<T>() -> Result<Option<T>, Error> { todo!() }
trait Trait<T> {
    type Required<'a>;
    type Defaulted = Item;
    fn required(&self, r#type: u8);
    members!{}
}
impl<'a, T: Bound, const N: usize> Trait<T> for Item {
    fn required(&self, r#type: u8) {}
    type Value = &[Outer<Item>];
}
impl !Trait<Item> for Missing {}
type Unsupported = (Item, Item);
extern "C" { fn variadic(value: u8, /* parameter trivia */ ...); }
mod outer {
    use crate::{Item as Alias, Trait};
    wrap! {
        impl Trait<Item> for Alias { fn embedded(&self) -> Option<Self> { todo!() } }
        struct Embedded<T> { value: Result<T, Error> }
    }
    helper::wrap! { use crate::Hidden; type RawAlias = Outer<Item>::Assoc; }
    broken! { impl Trait<Item> for Missing { fn bad(&self, value: ); } }
    empty!{}
}
"#
);

fn canonical_order(items: &mut RustItemSourceFacts, types: &mut [RustTypeSourceFact]) {
    // Family roots are sets keyed by source identity. Context and nested-child
    // vector order is part of the publication contract and is not normalized.
    items.syntax.sort_by_key(|row| row.occurrence.get());
    items.impls.sort_by_key(|row| row.declaration.get());
    items.traits.sort_by_key(|row| row.declaration.get());
    items.aliases.sort_by_key(|row| row.declaration.get());
    items.callables.sort_by_key(|row| row.declaration.get());
    items.values.sort_by_key(|row| row.declaration.get());
    items.generics.sort_by_key(|row| row.declaration.get());
    items.macros.sort_by_key(|row| row.invocation.get());
    items
        .import_contexts
        .sort_by_key(|row| row.declaration.get());
    types.sort_by_key(|row| row.occurrence.get());
}

#[test]
fn rust_primary_query_occurrences_reopen_without_equal_range_provenance_aliasing() {
    use brokk_bifrost_core::analyzer::source_facts::{
        SourceFactRows, SourceOccurrence, SourceOccurrenceId, SourceOccurrenceProvenance,
    };

    let fixture = InlineTestProject::new()
        .file("src/lib.rs", ITEM_SOURCE)
        .build();
    let file = fixture.file("src/lib.rs");
    let mut state = parse_state(&RustAdapter, &file);
    let facts = state.source_facts.as_mut().unwrap();
    let alias = &facts.rust_items.aliases[0];
    let selected = facts.occurrences.declaration(alias.declaration).occurrence;
    let range = facts.occurrences.occurrence(selected).range;
    assert_eq!(
        facts.occurrences.occurrence(selected).provenance,
        SourceOccurrenceProvenance::PrimaryNode
    );
    let expected = facts
        .occurrences
        .occurrences()
        .iter()
        .enumerate()
        .filter(|(_, row)| {
            row.range.start_byte == range.start_byte
                && row.range.end_byte == range.end_byte
                && row.provenance == SourceOccurrenceProvenance::PrimaryNode
        })
        .map(|(index, _)| SourceOccurrenceId::try_from_index(index).unwrap())
        .collect::<HashSet<_>>();
    // Exact equal spans are legal for distinct provenance. Publish the extra
    // source-only rows through the normal writer to exercise that boundary.
    let mut occurrences = facts.occurrences.occurrences().to_vec();
    for provenance in [
        SourceOccurrenceProvenance::ExplicitSubspan,
        SourceOccurrenceProvenance::Embedded,
    ] {
        occurrences.push(SourceOccurrence { range, provenance });
    }
    facts.occurrences = SourceFactRows::new(occurrences, facts.occurrences.declarations().to_vec());
    let oid = oid_for(ITEM_SOURCE.as_bytes());
    let path = fixture.root().join("primary-query-source.db");
    let store = AnalyzerStore::open_persistent(&path).unwrap();
    store
        .write_parsed_blob(oid, "rust", &RustAdapter, &state)
        .unwrap();
    let generation = store.current_generation("rust").unwrap();
    drop(state);
    drop(store);
    std::fs::remove_file(file.abs_path()).unwrap();
    let store = AnalyzerStore::open_persistent(&path).unwrap();
    let query_range = range.start_byte..range.end_byte;
    assert!(
        store
            .rust_primary_occurrences_at(oid, generation, query_range.clone(), &|| false)
            .unwrap()
            .is_none()
    );
    let actual = store
        .rust_primary_occurrences_at(oid, generation, query_range.clone(), &|| true)
        .unwrap()
        .unwrap()
        .into_iter()
        .collect::<HashSet<_>>();
    assert_eq!(actual, expected);
    assert!(
        store
            .rust_primary_occurrences_at(
                oid,
                generation,
                ITEM_SOURCE.len() + 1..ITEM_SOURCE.len() + 2,
                &|| true
            )
            .unwrap()
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .rust_primary_occurrences_at(
                oid_for(b"unpublished query"),
                generation,
                query_range.clone(),
                &|| true
            )
            .is_err()
    );
    store.drop_rust_modules_table_for_test();
    assert!(
        store
            .rust_primary_occurrences_at(oid, generation, query_range, &|| true)
            .is_err()
    );
}

#[test]
fn rust_item_type_source_inventory_reopens_with_exact_ids_and_ordered_children() {
    let fixture = InlineTestProject::new()
        .file("src/lib.rs", ITEM_SOURCE)
        .file("other/lib.rs", ITEM_SOURCE)
        .build();
    let state = parse_state(&RustAdapter, &fixture.file("src/lib.rs"));
    let source = state.source_facts.as_ref().expect("Rust source facts");
    let mut expected_items = source.rust_items.clone();
    let mut expected_types = source.rust_types.clone();
    let expected_declarations = source.occurrences.declarations().to_vec();
    let expected_imports = source.imports.clone();
    let expected_modules: HashMap<_, _> = source
        .rust_modules
        .as_ref()
        .unwrap()
        .declarations
        .iter()
        .map(|module| (module.declaration, module.name.clone()))
        .collect();
    canonical_order(&mut expected_items, &mut expected_types);
    assert!(expected_items.syntax.iter().any(|row| row.has_error));
    assert!(expected_items.syntax.iter().any(|row| !row.has_error));
    assert!(
        expected_items
            .impls
            .iter()
            .any(|row| row.negation.is_some())
    );
    assert!(
        expected_items
            .aliases
            .iter()
            .any(|row| row.target_type.is_none())
    );
    assert!(!expected_items.import_contexts.is_empty());
    assert!(
        expected_items
            .callables
            .iter()
            .any(|row| row.return_type.is_some())
    );
    assert!(
        expected_items
            .callables
            .iter()
            .any(|row| row.return_type.is_none())
    );
    assert!(
        expected_items
            .values
            .iter()
            .any(|row| row.declared_type.is_some())
    );
    assert!(
        expected_items
            .values
            .iter()
            .any(|row| row.declared_type.is_none())
    );
    let type_ids: HashSet<_> = expected_types.iter().map(|ty| ty.occurrence).collect();
    for group in &expected_items.generics {
        assert!(!group.parameters.is_empty());
        assert!(
            expected_items
                .contexts
                .iter()
                .any(|context| context.owner == Some(group.declaration)),
            "generic owner lacks a source context: {group:?}"
        );
    }
    assert!(
        expected_items.contexts.iter().any(|context| {
            context.kind == brokk_bifrost_core::analyzer::rust_facts::RustSourceContextKind::Type
                && expected_items
                    .values
                    .iter()
                    .any(|value| value.context == context.context)
                && expected_items
                    .generics
                    .iter()
                    .any(|group| Some(group.declaration) == context.owner)
        }),
        "generic fields must retain their type-owner context"
    );
    for ty in &expected_types {
        if let brokk_bifrost_core::analyzer::rust_facts::RustTypeSourceShape::Path {
            segments,
            ..
        } = &ty.shape
        {
            for argument in segments
                .iter()
                .filter_map(|segment| segment.generic_arguments.as_ref())
                .flat_map(|arguments| &arguments.arguments)
            {
                assert!(type_ids.contains(argument), "missing nested type: {ty:?}");
            }
        }
    }
    let expected_usage = state.rust_usage_facts.clone();
    let expected_links: HashSet<_> = state.source_declaration_units.iter().cloned().collect();
    let oid = oid_for(ITEM_SOURCE.as_bytes());
    let path = fixture.root().join("rust-item-source.db");
    let store = AnalyzerStore::open_persistent(&path).unwrap();
    store
        .write_parsed_blob(oid, "rust", &RustAdapter, &state)
        .unwrap();
    let generation = store.current_generation("rust").unwrap();
    drop(state);
    drop(store);

    // Readback must depend only on the sealed publication and mounted path,
    // even when the temporary project's original source is no longer readable.
    std::fs::remove_file(fixture.file("src/lib.rs").abs_path()).unwrap();

    let reopened = AnalyzerStore::open_persistent(&path).unwrap();
    let actual = reopened
        .rust_hierarchy_source_facts(
            oid,
            generation,
            &RustAdapter,
            &fixture.file("src/lib.rs"),
            &|| true,
        )
        .unwrap()
        .unwrap();
    assert_eq!(actual.items, expected_items);
    assert_eq!(actual.types, expected_types);
    assert_eq!(actual.declarations, expected_declarations);
    assert_eq!(actual.imports, expected_imports);
    assert_eq!(actual.module_names, expected_modules);
    assert!(!actual.declaration_units.is_empty());
    assert_eq!(
        actual
            .declaration_units
            .iter()
            .cloned()
            .collect::<HashSet<_>>(),
        expected_links
    );
    for (declaration, unit) in &actual.declaration_units {
        assert!(actual.declarations.get(declaration.index()).is_some());
        assert_eq!(unit.source(), &fixture.file("src/lib.rs"));
    }
    let other = reopened
        .rust_hierarchy_source_facts(
            oid,
            generation,
            &RustAdapter,
            &fixture.file("other/lib.rs"),
            &|| true,
        )
        .unwrap()
        .unwrap();
    assert_eq!(other.items, actual.items);
    assert_eq!(other.types, actual.types);
    assert_eq!(other.declarations, actual.declarations);
    assert_eq!(other.imports, actual.imports);
    assert_eq!(other.module_names, actual.module_names);
    assert_eq!(
        other.declaration_units.len(),
        actual.declaration_units.len()
    );
    for (_, unit) in &other.declaration_units {
        assert_eq!(unit.source(), &fixture.file("other/lib.rs"));
    }
    let checks = std::cell::Cell::new(0usize);
    let completed = reopened
        .rust_hierarchy_source_facts(
            oid,
            generation,
            &RustAdapter,
            &fixture.file("src/lib.rs"),
            &|| {
                checks.set(checks.get() + 1);
                true
            },
        )
        .unwrap()
        .unwrap();
    assert_eq!(completed, actual);
    let final_checks = checks.get();
    for stop_at in [final_checks / 2, final_checks - 2, final_checks] {
        checks.set(0);
        let cancelled = reopened
            .rust_hierarchy_source_facts(
                oid,
                generation,
                &RustAdapter,
                &fixture.file("src/lib.rs"),
                &|| {
                    checks.set(checks.get() + 1);
                    checks.get() < stop_at
                },
            )
            .unwrap();
        assert!(
            cancelled.is_none(),
            "no partial hierarchy bundle at check {stop_at}"
        );
    }
    assert_eq!(
        reopened.rust_usage_facts(oid, "rust").unwrap(),
        expected_usage,
        "source item publication does not change current Rust projection membership"
    );
}

#[test]
fn rust_item_macro_descriptors_reopen_with_source_positions_and_outcomes() {
    let source = r#"
direct! { struct Embedded; }
statement!();
empty!{}
fn nested() { qualified::nested!(); }
<unrequested!()>::invoke!{}
"#;
    let fixture = InlineTestProject::new().file("src/lib.rs", source).build();
    let state = parse_state(&RustAdapter, &fixture.file("src/lib.rs"));
    let source_facts = state.source_facts.as_ref().expect("Rust source facts");
    let text = |occurrence| {
        let range = source_facts.occurrences.occurrence(occurrence).range;
        &source[range.start_byte..range.end_byte]
    };
    let expected = source_facts.rust_items.macros.clone();
    let descriptor = |prefix: &str| {
        expected
            .iter()
            .find(|macro_fact| text(macro_fact.invocation).starts_with(prefix))
            .unwrap_or_else(|| panic!("missing macro descriptor {prefix:?}: {expected:?}"))
    };
    assert_eq!(
        descriptor("direct!").position,
        RustItemMacroSourcePosition::DirectItem
    );
    assert!(matches!(
        descriptor("direct!").expansion,
        RustItemMacroExpansion::Parsed(_)
    ));
    assert_eq!(
        descriptor("statement!").position,
        RustItemMacroSourcePosition::ItemStatement
    );
    assert_eq!(
        descriptor("statement!").expansion,
        RustItemMacroExpansion::EmptyInterior
    );
    assert_eq!(
        descriptor("empty!").position,
        RustItemMacroSourcePosition::DirectItem
    );
    assert_eq!(
        descriptor("empty!").expansion,
        RustItemMacroExpansion::EmptyInterior
    );
    assert_eq!(
        descriptor("qualified::nested!").position,
        RustItemMacroSourcePosition::Other
    );
    assert_eq!(
        descriptor("qualified::nested!").expansion,
        RustItemMacroExpansion::EmptyInterior
    );
    assert_eq!(
        descriptor("unrequested!").position,
        RustItemMacroSourcePosition::Other
    );
    assert_eq!(
        descriptor("unrequested!").expansion,
        RustItemMacroExpansion::NotRequested
    );

    let oid = oid_for(source.as_bytes());
    let path = fixture.root().join("rust-item-macro-source.db");
    let store = AnalyzerStore::open_persistent(&path).unwrap();
    store
        .write_parsed_blob(oid, "rust", &RustAdapter, &state)
        .unwrap();
    let generation = store.current_generation("rust").unwrap();
    drop(state);
    drop(store);
    std::fs::remove_file(fixture.file("src/lib.rs").abs_path()).unwrap();

    let reopened = AnalyzerStore::open_persistent(&path).unwrap();
    let actual = reopened
        .rust_hierarchy_source_facts(
            oid,
            generation,
            &RustAdapter,
            &fixture.file("src/lib.rs"),
            &|| true,
        )
        .unwrap()
        .unwrap();
    assert_eq!(actual.items.macros, expected);
}

#[test]
fn rust_macro_source_definitions_reopen_with_exact_nested_rows() {
    let source = r#"
macro_rules! evaluate {
    ($expression:expr) => { $expression };
    ($name:ident, $value:literal) => { $name = $value };
    ($( [$nested:ident] ),*) => { $($nested);* };
}
fn use_macro() { evaluate!(answer, 42); }
"#;
    let fixture = InlineTestProject::new().file("src/lib.rs", source).build();
    let file = fixture.file("src/lib.rs");
    let state = parse_state(&RustAdapter, &file);
    let expected = state
        .source_facts
        .as_ref()
        .expect("Rust source facts")
        .rust_items
        .macro_definitions
        .clone();
    assert_eq!(expected.len(), 1, "macro source facts={expected:?}");
    assert_eq!(expected[0].arms.len(), 3, "macro source facts={expected:?}");
    assert!(
        expected
            .iter()
            .flat_map(|definition| &definition.arms)
            .any(|arm| { !arm.patterns.is_empty() && !arm.ident_roles.is_empty() })
    );

    let oid = oid_for(source.as_bytes());
    let path = fixture.root().join("rust-macro-source-facts.db");
    let store = AnalyzerStore::open_persistent(&path).unwrap();
    store
        .write_parsed_blob(oid, "rust", &RustAdapter, &state)
        .unwrap();
    let generation = store.current_generation("rust").unwrap();
    drop(state);
    drop(store);
    std::fs::remove_file(file.abs_path()).unwrap();

    let reopened = AnalyzerStore::open_persistent(&path).unwrap();
    let actual = reopened
        .rust_hierarchy_source_facts(oid, generation, &RustAdapter, &file, &|| true)
        .unwrap()
        .unwrap();
    assert_eq!(actual.items.macro_definitions, expected);
}

#[test]
fn rust_macro_source_marker_is_required_and_fresh_empty_family_is_readable() {
    let fixture = InlineTestProject::new().file("src/lib.rs", "").build();
    let file = fixture.file("src/lib.rs");
    let state = parse_state(&RustAdapter, &file);
    let oid = oid_for(b"");
    let store = AnalyzerStore::open_ephemeral().unwrap();
    store
        .write_parsed_blob(oid, "rust", &RustAdapter, &state)
        .unwrap();
    let generation = store.current_generation("rust").unwrap();
    let fresh = store
        .rust_hierarchy_source_facts(oid, generation, &RustAdapter, &file, &|| true)
        .unwrap()
        .unwrap();
    assert!(fresh.items.macro_definitions.is_empty());

    store.conn.execute(|conn| {
        conn.execute_batch(
            "DROP TRIGGER source_fact_manifests_no_reopen;
             UPDATE source_fact_manifests SET publication_state = 'building';
             UPDATE source_rust_item_manifests SET macro_facts_version = NULL;
             UPDATE source_fact_manifests SET publication_state = 'complete';",
        )
        .unwrap();
    });
    assert!(
        store
            .rust_hierarchy_source_facts(oid, generation, &RustAdapter, &file, &|| true)
            .is_err()
    );

    store
        .write_parsed_blob(oid, "rust", &RustAdapter, &state)
        .unwrap();
    let repaired = store
        .rust_hierarchy_source_facts(oid, generation, &RustAdapter, &file, &|| true)
        .unwrap()
        .unwrap();
    assert!(repaired.items.macro_definitions.is_empty());
}

#[test]
fn rust_macro_source_read_cancellation_retries_after_all_rows() {
    let source = r#"
macro_rules! many {
    ($a:ident) => { $a };
    ($b:ident) => { $b };
    ($c:ident) => { $c };
    ($d:ident) => { $d };
    ($e:ident) => { $e };
    ($f:ident) => { $f };
}
fn invoke() { many!(value); }
"#;
    let fixture = InlineTestProject::new().file("src/lib.rs", source).build();
    let file = fixture.file("src/lib.rs");
    let state = parse_state(&RustAdapter, &file);
    let oid = oid_for(source.as_bytes());
    let store = AnalyzerStore::open_ephemeral().unwrap();
    store
        .write_parsed_blob(oid, "rust", &RustAdapter, &state)
        .unwrap();
    let generation = store.current_generation("rust").unwrap();
    let checks = std::cell::Cell::new(0usize);
    let complete = store
        .rust_hierarchy_source_facts(oid, generation, &RustAdapter, &file, &|| {
            checks.set(checks.get() + 1);
            true
        })
        .unwrap()
        .unwrap();
    assert!(complete.items.macro_definitions.len() == 1);
    assert!(complete.items.macro_definitions[0].arms.len() >= 6);
    let total_checks = checks.get();
    assert!(
        total_checks > 20,
        "macro fixture had too few read checkpoints"
    );

    let cancelled_checks = std::cell::Cell::new(0usize);
    assert!(
        store
            .rust_hierarchy_source_facts(oid, generation, &RustAdapter, &file, &|| {
                cancelled_checks.set(cancelled_checks.get() + 1);
                cancelled_checks.get() < total_checks
            })
            .unwrap()
            .is_none()
    );
    assert!(cancelled_checks.get() >= total_checks);
    let retried = store
        .rust_hierarchy_source_facts(oid, generation, &RustAdapter, &file, &|| true)
        .unwrap()
        .unwrap();
    assert_eq!(
        retried.items.macro_definitions,
        complete.items.macro_definitions
    );
}

#[test]
fn repeated_embedded_macro_definitions_keep_exact_source_unit_bridges() {
    let source = r#"
macro_rules! passthrough { ($($item:item)*) => { $($item)* }; }
passthrough! { macro_rules! first { ($name:ident) => {}; } }
passthrough! { macro_rules! second { ($name:ident) => {}; } }
"#;
    let fixture = InlineTestProject::new().file("src/lib.rs", source).build();
    let file = fixture.file("src/lib.rs");
    let state = parse_state(&RustAdapter, &file);
    let parsed = state.source_facts.as_ref().expect("Rust source facts");
    let definitions = &parsed.rust_items.macro_definitions;
    let embedded_definitions = definitions
        .iter()
        .filter(|definition| {
            let occurrence = parsed
                .occurrences
                .declaration(definition.declaration)
                .occurrence;
            parsed.occurrences.occurrence(occurrence).provenance
                == brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceProvenance::Embedded
        })
        .collect::<Vec<_>>();
    assert_eq!(
        embedded_definitions.len(),
        2,
        "embedded definitions={definitions:?}"
    );
    let expected_definitions = definitions.clone();
    let definition_ids: HashSet<_> = embedded_definitions
        .iter()
        .map(|definition| definition.declaration)
        .collect();
    assert_eq!(definition_ids.len(), embedded_definitions.len());
    for definition in embedded_definitions {
        let occurrence = parsed
            .occurrences
            .declaration(definition.declaration)
            .occurrence;
        assert_eq!(
            parsed.occurrences.occurrence(occurrence).provenance,
            brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceProvenance::Embedded
        );
    }
    let expected_links: HashSet<_> = state
        .source_declaration_units
        .iter()
        .filter(|(declaration, _)| definition_ids.contains(declaration))
        .cloned()
        .collect();
    for declaration in &definition_ids {
        assert!(
            expected_links
                .iter()
                .any(|(linked_declaration, _)| linked_declaration == declaration),
            "embedded macro definition has no source-unit bridge: {declaration:?}"
        );
    }

    let oid = oid_for(source.as_bytes());
    let store =
        AnalyzerStore::open_persistent(&fixture.root().join("embedded-macro-source.db")).unwrap();
    store
        .write_parsed_blob(oid, "rust", &RustAdapter, &state)
        .unwrap();
    let generation = store.current_generation("rust").unwrap();
    drop(state);
    drop(store);
    std::fs::remove_file(file.abs_path()).unwrap();
    let reopened =
        AnalyzerStore::open_persistent(&fixture.root().join("embedded-macro-source.db")).unwrap();
    let actual = reopened
        .rust_hierarchy_source_facts(oid, generation, &RustAdapter, &file, &|| true)
        .unwrap()
        .unwrap();
    assert_eq!(actual.items.macro_definitions, expected_definitions);
    assert_eq!(
        actual
            .declaration_units
            .iter()
            .filter(|(declaration, _)| definition_ids.contains(declaration))
            .cloned()
            .collect::<HashSet<_>>(),
        expected_links
    );
}

#[test]
fn unknown_embedded_macro_definition_remains_source_only() {
    let source = "outer! { macro_rules! source_only { ($name:ident) => {}; } }";
    let fixture = InlineTestProject::new().file("src/lib.rs", source).build();
    let state = parse_state(&RustAdapter, &fixture.file("src/lib.rs"));
    let parsed = state.source_facts.as_ref().expect("Rust source facts");
    assert_eq!(parsed.rust_items.macro_definitions.len(), 1);
    let definition = &parsed.rust_items.macro_definitions[0];
    let occurrence = parsed
        .occurrences
        .declaration(definition.declaration)
        .occurrence;
    assert_eq!(
        parsed.occurrences.occurrence(occurrence).provenance,
        brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceProvenance::Embedded
    );
    assert!(
        !state
            .source_declaration_units
            .iter()
            .any(|(declaration, _)| *declaration == definition.declaration)
    );
}

#[test]
fn declaration_annotations_cannot_cross_source_owners_when_sealing() {
    let fixture = InlineTestProject::new()
        .file("src/lib.rs", ITEM_SOURCE)
        .build();
    let file = fixture.file("src/lib.rs");
    let state = parse_state(&RustAdapter, &file);
    let oid = oid_for(ITEM_SOURCE.as_bytes());
    let store = AnalyzerStore::open_ephemeral().unwrap();
    store
        .write_parsed_blob(oid, "rust", &RustAdapter, &state)
        .unwrap();
    let generation = store.current_generation("rust").unwrap();
    let before = store
        .rust_hierarchy_source_facts(oid, generation, &RustAdapter, &file, &|| true)
        .unwrap()
        .unwrap();
    for (table, column) in [
        ("source_rust_callable_items", "return_type_occurrence_id"),
        ("source_rust_value_items", "declared_type_occurrence_id"),
    ] {
        store.conn.execute(move |conn| {
            conn.execute_batch(
                "SAVEPOINT annotation_fault;
                 DROP TRIGGER source_fact_manifests_no_reopen;
                 UPDATE source_fact_manifests SET publication_state = 'building';",
            )
            .unwrap();
            let changed = conn
                .execute(
                    &format!(
                        "UPDATE {table} SET {column} = (
                   SELECT target_type_occurrence_id FROM source_rust_alias_items
                   WHERE target_type_occurrence_id IS NOT NULL ORDER BY declaration_id LIMIT 1
                 ) WHERE {column} IS NOT NULL"
                    ),
                    [],
                )
                .unwrap();
            assert!(changed > 0, "annotation fixture has no {table} rows");
            let error = conn
                .execute(
                    "UPDATE source_fact_manifests SET publication_state = 'complete'",
                    [],
                )
                .expect_err("annotation from another source owner cannot seal");
            assert!(
                error
                    .to_string()
                    .contains("canonical Rust declaration annotations are inconsistent"),
                "{error}"
            );
            conn.execute_batch("ROLLBACK TO annotation_fault; RELEASE annotation_fault;")
                .unwrap();
        });
        assert_eq!(
            store
                .rust_hierarchy_source_facts(oid, generation, &RustAdapter, &file, &|| true)
                .unwrap()
                .unwrap(),
            before
        );
    }
}

#[test]
fn malformed_macro_descriptor_shape_cannot_seal_or_change_the_publication() {
    let source = r#"
direct! { struct Embedded; }
statement!();
empty!{}
fn nested() { qualified::nested!(); }
"#;
    let fixture = InlineTestProject::new().file("src/lib.rs", source).build();
    let state = parse_state(&RustAdapter, &fixture.file("src/lib.rs"));
    let oid = oid_for(source.as_bytes());
    let store = AnalyzerStore::open_ephemeral().unwrap();
    store
        .write_parsed_blob(oid, "rust", &RustAdapter, &state)
        .unwrap();
    let generation = store.current_generation("rust").unwrap();
    let before = store
        .rust_hierarchy_source_facts(
            oid,
            generation,
            &RustAdapter,
            &fixture.file("src/lib.rs"),
            &|| true,
        )
        .unwrap()
        .unwrap();

    for (label, mutation) in [
        (
            "missing source position",
            "UPDATE source_rust_item_macro_expansions
             SET source_position = NULL
             WHERE blob_id = ?1 AND source_position = 0",
        ),
        (
            "direct item without replay outcome",
            "UPDATE source_rust_item_macro_expansions
             SET expansion_kind = 4, root_occurrence_id = NULL
             WHERE blob_id = ?1 AND source_position = 0",
        ),
    ] {
        let label = label.to_owned();
        let mutation = mutation.to_owned();
        store.conn.execute(move |conn| {
            let id: i64 = conn
                .query_row(
                    "SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'rust'",
                    [oid.to_string()],
                    |row| row.get(0),
                )
                .unwrap();
            conn.execute_batch(
                "SAVEPOINT rust_macro_descriptor_fault;
                 DROP TRIGGER source_fact_manifests_no_reopen;",
            )
            .unwrap();
            conn.execute(
                "UPDATE source_fact_manifests
                 SET publication_state = 'building'
                 WHERE blob_id = ?1",
                [id],
            )
            .unwrap();
            let changed = conn.execute(mutation.as_str(), [id]).unwrap();
            assert!(changed > 0, "{label} fixture mutation changed no rows");
            let error = conn
                .execute(
                    "UPDATE source_fact_manifests
                     SET publication_state = 'complete'
                     WHERE blob_id = ?1",
                    [id],
                )
                .expect_err("incomplete macro descriptors must not seal");
            // Removing a parsed root also leaves its embedded context without
            // expansion evidence. Both sealing constraints reject that state;
            // their execution order is not part of the schema contract.
            let message = error.to_string();
            assert!(
                message.contains("canonical Rust macro position is incomplete")
                    || message.contains("canonical Rust item or type facts are inconsistent"),
                "{label}: {error}"
            );
            conn.execute_batch(
                "ROLLBACK TO rust_macro_descriptor_fault;
                 RELEASE rust_macro_descriptor_fault;",
            )
            .unwrap();
        });
        assert_eq!(
            store
                .rust_hierarchy_source_facts(
                    oid,
                    generation,
                    &RustAdapter,
                    &fixture.file("src/lib.rs"),
                    &|| true,
                )
                .unwrap()
                .unwrap(),
            before,
            "failed descriptor seal changed the published facts"
        );
    }
}

#[test]
fn empty_rust_item_inventory_is_complete_but_cancellation_and_stale_generation_are_not() {
    let fixture = InlineTestProject::new().file("src/lib.rs", "").build();
    let state = parse_state(&RustAdapter, &fixture.file("src/lib.rs"));
    let oid = oid_for(b"");
    let store = AnalyzerStore::open_ephemeral().unwrap();
    store
        .write_parsed_blob(oid, "rust", &RustAdapter, &state)
        .unwrap();
    let generation = store.current_generation("rust").unwrap();
    let RustHierarchySourceFacts { items, types, .. } = store
        .rust_hierarchy_source_facts(
            oid,
            generation,
            &RustAdapter,
            &fixture.file("src/lib.rs"),
            &|| true,
        )
        .unwrap()
        .unwrap();
    assert_eq!(items.contexts.len(), 1);
    assert_eq!(items.syntax.len(), 1);
    assert!(!items.syntax[0].has_error);
    assert!(items.impls.is_empty() && items.traits.is_empty() && types.is_empty());
    assert!(
        store
            .rust_hierarchy_source_facts(
                oid,
                generation,
                &RustAdapter,
                &fixture.file("src/lib.rs"),
                &|| false
            )
            .unwrap()
            .is_none()
    );
    let checks = std::cell::Cell::new(0);
    assert!(
        store
            .rust_hierarchy_source_facts(
                oid,
                generation,
                &RustAdapter,
                &fixture.file("src/lib.rs"),
                &|| {
                    checks.set(checks.get() + 1);
                    checks.get() < 4
                }
            )
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .rust_hierarchy_source_facts(
                oid,
                generation,
                &RustAdapter,
                &fixture.file("src/lib.rs"),
                &|| true
            )
            .unwrap()
            .is_some()
    );
    store
        .ensure_language_epoch_value("rust", "item-source-stale-generation")
        .unwrap();
    assert!(
        store
            .rust_hierarchy_source_facts(
                oid,
                generation,
                &RustAdapter,
                &fixture.file("src/lib.rs"),
                &|| true
            )
            .is_err()
    );
}

#[test]
fn unpublished_rust_item_inventory_is_not_a_valid_empty_result() {
    let fixture = InlineTestProject::new()
        .file("src/lib.rs", "struct Pending;")
        .build();
    let store = AnalyzerStore::open_ephemeral().unwrap();
    let generation = store
        .ensure_language_epoch_value("rust", "item-source-unpublished")
        .unwrap();
    let oid = oid_for(b"struct Pending;");
    store.register_blobs(&[oid], "rust", generation).unwrap();
    assert!(
        store
            .rust_hierarchy_source_facts(
                oid,
                generation,
                &RustAdapter,
                &fixture.file("src/lib.rs"),
                &|| true
            )
            .is_err()
    );
}

#[test]
fn empty_import_groups_publish_contexts_without_import_leaf_rows() {
    let source = "use crate::{}; helper::wrap! { use crate::{}; }";
    let fixture = InlineTestProject::new().file("src/lib.rs", source).build();
    let state = parse_state(&RustAdapter, &fixture.file("src/lib.rs"));
    assert!(state.source_facts.as_ref().unwrap().imports.is_empty());
    let oid = oid_for(source.as_bytes());
    let store = AnalyzerStore::open_ephemeral().unwrap();
    store
        .write_parsed_blob(oid, "rust", &RustAdapter, &state)
        .unwrap();
    let generation = store.current_generation("rust").unwrap();
    let RustHierarchySourceFacts { items, types, .. } = store
        .rust_hierarchy_source_facts(
            oid,
            generation,
            &RustAdapter,
            &fixture.file("src/lib.rs"),
            &|| true,
        )
        .unwrap()
        .unwrap();
    assert_eq!(items.import_contexts.len(), 2);
    assert_eq!(items.contexts.len(), 2);
    assert!(types.is_empty());
    assert!(
        store
            .rust_usage_facts(oid, "rust")
            .unwrap()
            .import_targets
            .is_empty()
    );
}

#[test]
fn invalid_item_source_replacement_rolls_back_to_the_old_publication() {
    let fixture = InlineTestProject::new()
        .file("src/lib.rs", ITEM_SOURCE)
        .build();
    let state = parse_state(&RustAdapter, &fixture.file("src/lib.rs"));
    let oid = oid_for(ITEM_SOURCE.as_bytes());
    let store = AnalyzerStore::open_ephemeral().unwrap();
    store
        .write_parsed_blob(oid, "rust", &RustAdapter, &state)
        .unwrap();
    let generation = store.current_generation("rust").unwrap();
    let before = store
        .rust_hierarchy_source_facts(
            oid,
            generation,
            &RustAdapter,
            &fixture.file("src/lib.rs"),
            &|| true,
        )
        .unwrap()
        .unwrap();

    let mut missing_syntax = state.clone();
    missing_syntax
        .source_facts
        .as_mut()
        .unwrap()
        .rust_items
        .syntax
        .clear();
    assert!(
        store
            .write_parsed_blob(oid, "rust", &RustAdapter, &missing_syntax)
            .is_err()
    );
    assert_eq!(
        store
            .rust_hierarchy_source_facts(
                oid,
                generation,
                &RustAdapter,
                &fixture.file("src/lib.rs"),
                &|| true
            )
            .unwrap()
            .unwrap(),
        before
    );

    let mut cycle = state.clone();
    let context = &mut cycle.source_facts.as_mut().unwrap().rust_items.contexts[1];
    context.parent = Some(context.context);
    assert!(
        store
            .write_parsed_blob(oid, "rust", &RustAdapter, &cycle)
            .is_err()
    );
    assert_eq!(
        store
            .rust_hierarchy_source_facts(
                oid,
                generation,
                &RustAdapter,
                &fixture.file("src/lib.rs"),
                &|| true
            )
            .unwrap()
            .unwrap(),
        before
    );

    let mut wrong_owner = state.clone();
    let items = &mut wrong_owner.source_facts.as_mut().unwrap().rust_items;
    let replacement = items.traits[0].declaration;
    items.callables[0].declaration = replacement;
    assert!(
        store
            .write_parsed_blob(oid, "rust", &RustAdapter, &wrong_owner)
            .is_err()
    );
    assert_eq!(
        store
            .rust_hierarchy_source_facts(
                oid,
                generation,
                &RustAdapter,
                &fixture.file("src/lib.rs"),
                &|| true
            )
            .unwrap()
            .unwrap(),
        before
    );
}

#[test]
fn macro_definition_replay_contexts_publish_with_source_identity() {
    let source = r#"
macro_rules! evaluate { ($expression:expr) => { $expression }; }
const EXACT: usize = 1;
struct Other;
impl Other { const EXACT: usize = 2; }
fn module_reference() -> usize { evaluate!(EXACT) + evaluate!(EXACT | 8) }
fn associated_decoy() -> usize { evaluate!(Other::EXACT) }
fn lexical_decoy() -> usize { let EXACT = 3; evaluate!(EXACT) }
fn local_item_decoy() -> usize { const EXACT: usize = 4; evaluate!(EXACT) }
"#;
    let fixture = InlineTestProject::new().file("src/lib.rs", source).build();
    let state = parse_state(&RustAdapter, &fixture.file("src/lib.rs"));
    let oid = oid_for(source.as_bytes());
    let store = AnalyzerStore::open_ephemeral().unwrap();
    store
        .write_parsed_blob(oid, "rust", &RustAdapter, &state)
        .unwrap_or_else(|error| {
            panic!(
                "{error}; items={:?}",
                state.source_facts.as_ref().unwrap().rust_items
            )
        });
    let generation = store.current_generation("rust").unwrap();
    let RustHierarchySourceFacts { items, .. } = store
        .rust_hierarchy_source_facts(
            oid,
            generation,
            &RustAdapter,
            &fixture.file("src/lib.rs"),
            &|| true,
        )
        .unwrap()
        .unwrap();
    let expected = &state.source_facts.as_ref().unwrap().rust_items;
    assert_eq!(items.contexts, expected.contexts);
    assert_eq!(items.macros, expected.macros);
    assert!(items.syntax.iter().any(|row| row.has_error));
}

#[test]
fn cancelled_item_replacement_preserves_the_complete_inventory() {
    let fixture = InlineTestProject::new()
        .file("src/lib.rs", ITEM_SOURCE)
        .build();
    let state = Arc::new(parse_state(&RustAdapter, &fixture.file("src/lib.rs")));
    let oid = oid_for(ITEM_SOURCE.as_bytes());
    let store = AnalyzerStore::open_ephemeral().unwrap();
    store
        .write_parsed_blob(oid, "rust", &RustAdapter, &state)
        .unwrap();
    let generation = store.current_generation("rust").unwrap();
    let before = store
        .rust_hierarchy_source_facts(
            oid,
            generation,
            &RustAdapter,
            &fixture.file("src/lib.rs"),
            &|| true,
        )
        .unwrap()
        .unwrap();
    for checks in [4, 40, 200] {
        let prepared = AnalyzerStore::prepare_parsed_blob(
            oid,
            "rust",
            generation,
            &RustAdapter,
            Arc::clone(&state),
        )
        .unwrap();
        let cancellation = CancellationToken::cancel_after_checks_for_test(checks);
        let (outcomes, stats) = store.persist_prepared_blobs_with_cancellation(
            vec![prepared],
            &cancellation,
            PersistBatchTargets::PRODUCTION,
        );
        assert!(
            cancellation.is_cancelled(),
            "cancellation checkpoint {checks}"
        );
        assert!(
            outcomes[0].error.is_some(),
            "cancellation checkpoint {checks}"
        );
        assert_eq!(stats.failed_blobs, 1);
        assert_eq!(
            store
                .rust_hierarchy_source_facts(
                    oid,
                    generation,
                    &RustAdapter,
                    &fixture.file("src/lib.rs"),
                    &|| true
                )
                .unwrap()
                .unwrap(),
            before
        );
    }
}

#[test]
fn damaged_item_publication_is_rejected_and_repaired_by_normal_replacement() {
    for table in ["source_rust_item_manifests", "source_rust_type_segments"] {
        let fixture = InlineTestProject::new()
            .file("src/lib.rs", ITEM_SOURCE)
            .build();
        let state = parse_state(&RustAdapter, &fixture.file("src/lib.rs"));
        let oid = oid_for(ITEM_SOURCE.as_bytes());
        let store = AnalyzerStore::open_ephemeral().unwrap();
        store
            .write_parsed_blob(oid, "rust", &RustAdapter, &state)
            .unwrap();
        let generation = store.current_generation("rust").unwrap();
        let before = store
            .rust_hierarchy_source_facts(
                oid,
                generation,
                &RustAdapter,
                &fixture.file("src/lib.rs"),
                &|| true,
            )
            .unwrap()
            .unwrap();
        store.conn.execute(move |conn| {
            // Fault injection deliberately bypasses sealing and FK protection.
            // Normal publication must still reject a missing witness or child.
            conn.execute_batch(&format!(
                "PRAGMA foreign_keys = OFF;
                 DROP TRIGGER {table}_no_delete_after_seal;
                 DELETE FROM {table};
                 PRAGMA foreign_keys = ON;"
            ))
            .unwrap();
        });
        assert!(
            store
                .rust_hierarchy_source_facts(
                    oid,
                    generation,
                    &RustAdapter,
                    &fixture.file("src/lib.rs"),
                    &|| true
                )
                .is_err(),
            "{table}"
        );
        store
            .write_parsed_blob(oid, "rust", &RustAdapter, &state)
            .unwrap();
        assert_eq!(
            store
                .rust_hierarchy_source_facts(
                    oid,
                    generation,
                    &RustAdapter,
                    &fixture.file("src/lib.rs"),
                    &|| true
                )
                .unwrap()
                .unwrap(),
            before,
            "{table}"
        );
        store.conn.execute(|conn| {
            let violations: i64 = conn
                .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(violations, 0);
        });
    }
}

#[test]
fn sealed_item_rows_are_immutable_and_sparse_child_ordinals_cannot_reseal() {
    let fixture = InlineTestProject::new()
        .file("src/lib.rs", ITEM_SOURCE)
        .build();
    let state = parse_state(&RustAdapter, &fixture.file("src/lib.rs"));
    let oid = oid_for(ITEM_SOURCE.as_bytes());
    let store = AnalyzerStore::open_ephemeral().unwrap();
    store
        .write_parsed_blob(oid, "rust", &RustAdapter, &state)
        .unwrap();
    store.conn.execute(|conn| {
        for (table, column) in [
            ("source_rust_item_manifests", "facts_version"),
            ("source_rust_item_syntax", "has_error"),
            ("source_rust_item_contexts", "context_kind"),
            ("source_rust_types", "path_kind"),
            ("source_rust_type_segments", "name"),
            ("source_rust_callable_items", "return_type_occurrence_id"),
            ("source_rust_value_items", "declared_type_occurrence_id"),
            ("source_rust_item_macro_expansions", "expansion_kind"),
            ("source_rust_item_macro_expansions", "source_position"),
        ] {
            for sql in [format!("UPDATE {table} SET {column} = {column}"), format!("DELETE FROM {table}")] {
                let error = conn.execute(&sql, []).expect_err("sealed item mutation must fail");
                assert!(error.to_string().contains("immutable"), "{sql}: {error}");
            }
        }
        for table in ["source_rust_item_generic_parameters", "source_rust_item_body_children", "source_rust_callable_parameters", "source_rust_type_wrappers", "source_rust_type_segments", "source_rust_type_generic_arguments"] {
            conn.execute_batch("SAVEPOINT item_shape_fault; DROP TRIGGER source_fact_manifests_no_reopen; UPDATE source_fact_manifests SET publication_state = 'building';").unwrap();
            // Preserve row/payload accounting while making the last child sparse.
            let changed = conn.execute(&format!("UPDATE {table} SET ordinal = ordinal + 1 WHERE ordinal = (SELECT MAX(ordinal) FROM {table})"), []).unwrap();
            assert!(changed > 0, "fixture must populate {table}");
            let error = conn.execute("UPDATE source_fact_manifests SET publication_state = 'complete'", []).expect_err("sparse ordinals must fail sealing");
            assert!(error.to_string().contains("canonical Rust item or type"), "{table}: {error}");
            conn.execute_batch("ROLLBACK TO item_shape_fault; RELEASE item_shape_fault;").unwrap();
        }
    });
}
