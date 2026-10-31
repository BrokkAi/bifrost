pub use super::test_blob_oid as oid_for;

use super::*;

use crate::analyzer::model::StructuredTypeIdentityBuilder;
use crate::analyzer::model::StructuredTypeName;

#[doc(hidden)]
pub fn blob_id(conn: &Connection, oid: Oid) -> i64 {
    conn.query_row(
        "SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = 'rust'",
        [oid.to_string()],
        |row| row.get(0),
    )
    .expect("published Rust blob id")
}

/// One `SignatureMetadata` with every field carrying a non-default value.
///
/// The round-trip test below is only as strong as this value is complete:
/// a field that stays at its default here would round-trip through a
/// column that the encoder never writes and the decoder never reads.
#[doc(hidden)]
pub fn fully_populated_signature_metadata() -> SignatureMetadata {
    let named = |path: &str| {
        StructuredTypeName::new(vec![path.to_string()], vec!["outer".to_string()], true)
            .expect("structured type name")
    };
    let mut builder = StructuredTypeIdentityBuilder::default();
    let key = builder.named(named("String")).unwrap();
    let value = builder.named(named("Widget")).unwrap();
    let map = builder.map(key, value).unwrap();
    let base = builder.named(named("Registry")).unwrap();
    let generic = builder.generic(base, vec![map]).unwrap();
    let return_type_identity = builder.finish(generic).expect("return identity");

    let mut underlying = StructuredTypeIdentityBuilder::default();
    let element = underlying.named(named("Operation")).unwrap();
    let pointer = underlying.pointer(element).unwrap();
    let array = underlying.array(pointer).unwrap();
    let underlying_type_identity = underlying.finish(array).expect("underlying identity");

    let mut receiver = StructuredTypeIdentityBuilder::default();
    let receiver_named = receiver.named(named("Receiver")).unwrap();
    let receiver_slice = receiver.slice(receiver_named).unwrap();
    let extension_receiver_type_identity = receiver.finish(receiver_slice).expect("receiver");

    // Two declared results, so the round trip pins the positional column
    // rather than only the single `return_type_identity` beside it. A
    // reader that dropped this column would still decode every other
    // field, which is exactly how it went unnoticed the first time.
    let mut first_result = StructuredTypeIdentityBuilder::default();
    let first_named = first_result.named(named("Tx")).unwrap();
    let first_pointer = first_result.pointer(first_named).unwrap();
    let first_result_identity = first_result.finish(first_pointer).expect("first result");
    let mut second_result = StructuredTypeIdentityBuilder::default();
    let second_named = second_result.named(named("error")).unwrap();
    let second_result_identity = second_result.finish(second_named).expect("second result");

    SignatureMetadata::new(
        "fn build(first: String, second: Widget) -> Registry<Map<String, Widget>>",
        vec![
            ParameterMetadata::new("first: String", 9, 22).with_name("first"),
            ParameterMetadata::new("second: Widget", 24, 38).with_name("second"),
        ],
    )
    .with_return_type_text(Some("Registry<Map<String, Widget>>"))
    .with_return_type_identity(Some(return_type_identity))
    .with_parameter_type_identities(vec![Some(first_result_identity.clone()), None])
    .with_result_type_identities(vec![first_result_identity, second_result_identity])
    .with_callable_override_modifier(CallableOverrideModifier::Override)
    .with_underlying_type_identity(Some(underlying_type_identity))
    .with_declaration_only(true)
    .with_callable_arity(CallableArity::new(2, 3, true))
    // The recorded builder, so the round trip pins the flag column beside
    // the list. `bare` beside this row is the unrecorded reading, which is
    // what a row written before #1651 reads back as.
    .with_recorded_type_parameters(vec!["T".to_string(), "U".to_string()])
    .with_bare_return_type_parameter(Some("T"))
    .with_callable_linkage(CallableLinkage::External)
    .with_dispatch_extensibility(DispatchExtensibility::Closed)
    .with_extension_receiver_type(Some("Receiver"))
    .with_extension_receiver_type_identity(Some(extension_receiver_type_identity))
    .with_extension_receiver_is_unconstrained_type_parameter(true)
    .with_field_modifiers(true, true)
    .with_field_initializer(true)
    .with_cpp_field_linkage(CppFieldLinkage::InternalUnlessExternalPeer)
    .with_companion_object(true)
    .with_callable_modifiers(true, true, DeclaredVisibility::PackagePrivate)
    .with_overload_discriminator(Some([0x75; 32]))
    .with_callable_parameter_types(vec!["String".to_string(), "Widget".to_string()])
    .with_callable_native(true)
    .with_class_like_kind(brokk_bifrost_core::analyzer::model::ClassLikeKind::Interface)
    .with_class_like_static(true)
}

#[doc(hidden)]
pub fn replace_test_metadata_bridges(state: &mut FileState, target: &CodeUnit, count: usize) {
    let original = state
        .source_declaration_metadata
        .iter()
        .filter(|link| link.unit == *target && link.metadata_ordinal == 0)
        .cloned()
        .collect::<Vec<_>>();
    assert!(
        !original.is_empty(),
        "fixture metadata needs source declarations"
    );
    state
        .source_declaration_metadata
        .retain(|link| link.unit != *target);
    for link in original {
        state
            .source_declaration_metadata
            .extend((0..count).map(|metadata_ordinal| {
                let mut alternative = link.clone();
                alternative.metadata_ordinal = metadata_ordinal;
                alternative
            }));
    }
}

#[doc(hidden)]
pub fn assert_file_state_equivalent(expected: &FileState, actual: &FileState) {
    assert_eq!(actual.package_name, expected.package_name);
    assert_eq!(actual.completeness, expected.completeness);
    assert_eq!(
        actual.top_level_declarations,
        expected.top_level_declarations
    );
    assert_eq!(actual.declarations, expected.declarations);
    assert_eq!(actual.scala_exports, expected.scala_exports);
    assert_eq!(
        actual.definition_lookup_units,
        expected.definition_lookup_units
    );
    assert_eq!(actual.imports, expected.imports);
    assert_eq!(
        non_empty_vec_entries(&actual.raw_supertypes),
        non_empty_vec_entries(&expected.raw_supertypes)
    );
    assert_eq!(
        non_empty_vec_entries(&actual.supertype_lookup_paths),
        non_empty_vec_entries(&expected.supertype_lookup_paths)
    );
    assert_eq!(actual.type_identifiers, expected.type_identifiers);
    assert_eq!(actual.signatures, expected.signatures);
    assert_eq!(actual.signature_metadata, expected.signature_metadata);
    assert_eq!(
        actual.signature_metadata_signature_ordinals,
        expected.signature_metadata_signature_ordinals
    );
    assert_eq!(
        actual.materialization_records,
        expected.materialization_records
    );
    assert_eq!(actual.cpp_template_metadata, expected.cpp_template_metadata);
    assert_eq!(actual.ranges, expected.ranges);
    assert_eq!(
        non_empty_vec_entries(&actual.children),
        non_empty_vec_entries(&expected.children)
    );
    assert_eq!(actual.type_aliases, expected.type_aliases);
    assert_eq!(
        actual.ruby_method_dispatch_modes,
        expected.ruby_method_dispatch_modes
    );
    assert_eq!(actual.scala_traits, expected.scala_traits);
    assert_eq!(actual.contains_tests, expected.contains_tests);
    assert_eq!(actual.test_region_units, expected.test_region_units);
    assert!(actual.source.is_empty());
    assert!(actual.parse_errors.is_none());
}

#[doc(hidden)]
pub fn non_empty_vec_entries<T: Clone>(
    map: &HashMap<CodeUnit, Vec<T>>,
) -> HashMap<CodeUnit, Vec<T>> {
    map.iter()
        .filter(|(_, values)| !values.is_empty())
        .map(|(unit, values)| (unit.clone(), values.clone()))
        .collect()
}

#[doc(hidden)]
pub fn assert_rust_source_read_cancellation_retries<T>(
    mut read: impl FnMut(&dyn Fn() -> bool) -> Option<T>,
    minimum_checkpoints: usize,
    check_retry: impl FnOnce(&T, &T),
) {
    let checks = std::cell::Cell::new(0usize);
    let complete = read(&|| {
        checks.set(checks.get() + 1);
        true
    })
    .expect("complete Rust source-fact read");
    let total_checks = checks.get();
    assert!(
        total_checks > minimum_checkpoints,
        "Rust source-fact read had too few checkpoints: {total_checks}"
    );

    let cancelled_checks = std::cell::Cell::new(0usize);
    assert!(
        read(&|| {
            cancelled_checks.set(cancelled_checks.get() + 1);
            cancelled_checks.get() < total_checks
        })
        .is_none(),
        "cancelled Rust source-fact read returned partial rows"
    );
    assert!(
        cancelled_checks.get() >= total_checks,
        "cancelled Rust source-fact read skipped checkpoints"
    );

    let retried = read(&|| true).expect("retry Rust source-fact read");
    check_retry(&complete, &retried);
}
