//! Canonical compound Rust type-form publication through the real producer and store.

use super::tests::{oid_for, parse_state};
use super::*;
use crate::analyzer::rust::RustAdapter;
use crate::inline_project::InlineTestProject;
use brokk_bifrost_core::analyzer::rust_facts::{
    RustTypeCompoundSourceKind, RustTypeSourceFact, RustTypeSourceShape,
};
use brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceProvenance;

const TYPE_FORM_SOURCE: &str = r#"
trait Trait<'a> {}
fn abstract_factory() -> impl Trait<'static> { todo!() }
fn quantified_factory() -> impl for<'a> Trait<'a> { todo!() }
fn dynamic_factory() -> dyn Trait<'static> { todo!() }
fn bounded_factory() -> impl Trait<'static> + Send { todo!() }
fn higher_ranked_factory() -> dyn for<'a> Trait<'a> { todo!() }
fn wrapped_factory() -> Option<Box<&'static dyn Trait<'static>>> { todo!() }
macro_rules! passthrough { ($($item:item)*) => { $($item)* }; }
passthrough! {
    fn embedded_factory() -> impl Trait<'static> { todo!() }
}
"#;

fn compound_types(types: &[RustTypeSourceFact]) -> Vec<RustTypeSourceFact> {
    types
        .iter()
        .filter(|fact| matches!(&fact.shape, RustTypeSourceShape::Compound { .. }))
        .cloned()
        .collect()
}

fn assert_compound_rows_are_structured(
    source: &str,
    parsed: &brokk_bifrost_core::analyzer::parsed_file::ParsedSourceFacts,
) -> Vec<RustTypeSourceFact> {
    let compounds = compound_types(&parsed.rust_types);
    assert!(!compounds.is_empty(), "type facts={:?}", parsed.rust_types);
    let type_ids = parsed
        .rust_types
        .iter()
        .map(|fact| fact.occurrence)
        .collect::<std::collections::HashSet<_>>();
    for fact in &compounds {
        let RustTypeSourceShape::Compound {
            occurrence,
            kind,
            children,
            type_parameters,
        } = &fact.shape
        else {
            unreachable!("compound_types filters compound rows");
        };
        if fact.wrappers.is_empty() {
            assert_eq!(*occurrence, fact.occurrence);
        } else {
            assert_ne!(*occurrence, fact.occurrence);
        }
        assert!(!children.is_empty(), "compound={fact:?}");
        assert!(children.iter().all(|child| type_ids.contains(child)));
        match kind {
            RustTypeCompoundSourceKind::HigherRanked => {
                assert!(type_parameters.is_some(), "higher-ranked row={fact:?}");
            }
            RustTypeCompoundSourceKind::Abstract => {}
            RustTypeCompoundSourceKind::Dynamic | RustTypeCompoundSourceKind::Bounded => {
                assert!(type_parameters.is_none(), "non-HRTB row={fact:?}");
            }
        }
        let root_range = parsed.occurrences.occurrence(fact.occurrence).range;
        let form_range = parsed.occurrences.occurrence(*occurrence).range;
        assert!(form_range.start_byte >= root_range.start_byte);
        assert!(form_range.end_byte <= root_range.end_byte);
        assert_eq!(
            parsed.occurrences.occurrence(fact.occurrence).provenance,
            parsed.occurrences.occurrence(*occurrence).provenance
        );
        for child in children {
            let child_range = parsed.occurrences.occurrence(*child).range;
            assert!(child_range.start_byte >= form_range.start_byte);
            assert!(child_range.end_byte <= form_range.end_byte);
            assert_eq!(
                parsed.occurrences.occurrence(*child).provenance,
                parsed.occurrences.occurrence(*occurrence).provenance
            );
            assert!(!source[child_range.start_byte..child_range.end_byte].is_empty());
        }
    }
    compounds
}

#[test]
fn compound_type_forms_reopen_with_exact_children_and_embedded_occurrences() {
    let fixture = InlineTestProject::new()
        .file("src/lib.rs", TYPE_FORM_SOURCE)
        .build();
    let file = fixture.file("src/lib.rs");
    let state = parse_state(&RustAdapter, &file);
    let parsed = state.source_facts.as_ref().expect("Rust source facts");
    let mut expected = parsed.rust_types.clone();
    expected.sort_by_key(|fact| fact.occurrence.get());
    let compounds = assert_compound_rows_are_structured(TYPE_FORM_SOURCE, parsed);
    assert!(
        compounds.iter().any(|fact| !fact.wrappers.is_empty()),
        "nested generic arguments retain wrapped compound types: {compounds:?}"
    );
    assert!(
        compounds.iter().any(|fact| matches!(
            &fact.shape,
            RustTypeSourceShape::Compound {
                kind: RustTypeCompoundSourceKind::Abstract,
                ..
            }
        )),
        "missing abstract type form: {compounds:?}"
    );
    assert!(
        compounds.iter().any(|fact| matches!(
            &fact.shape,
            RustTypeSourceShape::Compound {
                kind: RustTypeCompoundSourceKind::Dynamic,
                ..
            }
        )),
        "missing dynamic type form: {compounds:?}"
    );
    let embedded = compounds
        .iter()
        .filter(|fact| {
            parsed.occurrences.occurrence(fact.occurrence).provenance
                == SourceOccurrenceProvenance::Embedded
        })
        .collect::<Vec<_>>();
    assert!(!embedded.is_empty(), "embedded compound rows={compounds:?}");
    assert!(compounds.iter().any(|fact| matches!(
        &fact.shape,
        RustTypeSourceShape::Compound {
            kind: RustTypeCompoundSourceKind::Bounded,
            ..
        }
    )));
    assert!(compounds.iter().any(|fact| matches!(
        &fact.shape,
        RustTypeSourceShape::Compound {
            kind: RustTypeCompoundSourceKind::HigherRanked,
            ..
        }
    )));

    let oid = oid_for(TYPE_FORM_SOURCE.as_bytes());
    let path = fixture.root().join("rust-type-forms.db");
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
    assert_eq!(actual.types, expected);
    let actual_compounds = actual
        .types
        .iter()
        .filter(|fact| matches!(&fact.shape, RustTypeSourceShape::Compound { .. }))
        .collect::<Vec<_>>();
    assert_eq!(actual_compounds.len(), compounds.len());
    assert!(
        actual_compounds
            .iter()
            .any(|fact| { fact.occurrence == embedded[0].occurrence })
    );
}

#[test]
fn missing_type_forms_marker_fails_before_hydration_and_repairs() {
    let fixture = InlineTestProject::new()
        .file("src/lib.rs", TYPE_FORM_SOURCE)
        .build();
    let file = fixture.file("src/lib.rs");
    let state = parse_state(&RustAdapter, &file);
    let parsed = state.source_facts.as_ref().expect("Rust source facts");
    let mut expected = parsed.rust_types.clone();
    expected.sort_by_key(|fact| fact.occurrence.get());
    assert!(!expected.is_empty());
    let oid = oid_for(TYPE_FORM_SOURCE.as_bytes());
    let store = AnalyzerStore::open_ephemeral().unwrap();
    store
        .write_parsed_blob(oid, "rust", &RustAdapter, &state)
        .unwrap();
    let generation = store.current_generation("rust").unwrap();
    store.conn.execute(|conn| {
        conn.execute_batch(
            "DROP TRIGGER source_fact_manifests_no_reopen;
             DROP TRIGGER source_fact_manifests_validate_rust_type_forms;
             UPDATE source_fact_manifests SET publication_state = 'building';
             UPDATE source_rust_item_manifests SET type_forms_version = NULL;
             UPDATE source_fact_manifests SET publication_state = 'complete';",
        )
        .unwrap();
    });
    assert!(
        store
            .rust_hierarchy_source_facts(oid, generation, &RustAdapter, &file, &|| true)
            .is_err(),
        "stale type-form publication must not hydrate"
    );

    store
        .write_parsed_blob(oid, "rust", &RustAdapter, &state)
        .unwrap();
    let repaired = store
        .rust_hierarchy_source_facts(oid, generation, &RustAdapter, &file, &|| true)
        .unwrap()
        .unwrap();
    assert_eq!(repaired.types, expected);
}

#[test]
fn compound_type_read_cancellation_retries_without_partial_rows() {
    let fixture = InlineTestProject::new()
        .file("src/lib.rs", TYPE_FORM_SOURCE)
        .build();
    let file = fixture.file("src/lib.rs");
    let state = parse_state(&RustAdapter, &file);
    let oid = oid_for(TYPE_FORM_SOURCE.as_bytes());
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
    let total_checks = checks.get();
    assert!(total_checks > 12, "type read had too few checkpoints");
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
    assert_eq!(retried.types, complete.types);
}
