//! Inheritance metadata for exact selected JVM declarations, read per demand.

use super::*;
use crate::analyzer::CodeUnitType;
use crate::analyzer::resolution::{
    JavaInheritanceDeclaration, JavaInheritanceDeclarationKind, language_has_jvm_semantics,
};

// Requests carry selected mount/semantic keys. Every subsequent join is keyed
// by the selected blob and its source declaration; no workspace scan or live
// filesystem metadata supplies an inheritance decision.
pub(in crate::analyzer::store) const DECLARATIONS: &str = r#"
SELECT json_extract(request.value, '$[0]'), json_extract(request.value, '$[1]'), units.kind, meta.content_package,
       metadata.class_like_is_interface, metadata.callable_override_modifier,
       metadata.callable_is_static, metadata.callable_declared_visibility,
       metadata.callable_modifiers_recorded, units.identifier,
       EXISTS (SELECT 1 FROM main.code_unit_fq_segments AS segment
               WHERE segment.blob_id=units.blob_id AND segment.unit_key=units.unit_key
                 AND segment.seg_ordinal=units.fq_segment_count-1
                 AND segment.seg_kind='companion')
FROM json_each(?1) AS request
CROSS JOIN temp.selected_resolution_mounts AS mount
  ON mount.mount_ordinal=json_extract(request.value, '$[0]')
CROSS JOIN main.resolution_fragment_interiors AS interior
  ON interior.blob_id=mount.blob_id AND interior.lang=mount.storage_language
 AND interior.semantic_language=mount.semantic_language
 AND interior.producer_epoch=mount.producer_epoch AND interior.interior_digest=mount.interior_digest
 AND interior.publication_state='complete'
CROSS JOIN main.resolution_semantic_sites AS semantic
  ON semantic.blob_id=interior.blob_id AND semantic.semantic_role='definition'
 AND semantic.semantic_key=json_extract(request.value, '$[1]')
CROSS JOIN main.source_fact_manifests AS source
  ON source.blob_id=semantic.blob_id AND source.publication_state='complete'
CROSS JOIN main.source_native_declaration_bridges AS bridge
  ON bridge.blob_id=semantic.blob_id AND bridge.source_site=semantic.source_site
CROSS JOIN main.source_declaration_metadata_bridges AS link
  ON link.blob_id=bridge.blob_id AND link.declaration_id=bridge.declaration_id
CROSS JOIN main.code_units AS units
  ON units.blob_id=link.blob_id AND units.unit_key=link.unit_key AND units.in_declarations=1
CROSS JOIN main.unit_signature_metadata_values AS metadata
  ON metadata.blob_id=link.blob_id AND metadata.unit_key=link.unit_key
 AND metadata.ordinal=link.metadata_ordinal AND metadata.metadata_available=1
CROSS JOIN main.blob_meta AS meta ON meta.blob_id=units.blob_id AND meta.is_complete=1
"#;

// Generated JVM type owners need no authored signature metadata. Java's
// anonymous/enum-constant bodies retain their existing source-bridge proof.
// A Scala companion's primary Value binding, explicit term-type proof,
// singleton relation and owned type body prove its module class. An indexed
// definition unit, when present, must be the synthetic class; local companions
// can have a lexical declaration without a parser unit.
pub(in crate::analyzer::store) const SYNTHETIC_TYPE_BODIES: &str = r#"
SELECT json_extract(request.value, '$[0]'), json_extract(request.value, '$[1]'), meta.content_package,
       CASE WHEN mount.semantic_language='scala' THEN COALESCE(units.identifier, '') ELSE '' END,
       mount.semantic_language='scala'
FROM json_each(?1) AS request
CROSS JOIN temp.selected_resolution_mounts AS mount
  ON mount.mount_ordinal=json_extract(request.value, '$[0]')
CROSS JOIN main.resolution_fragment_interiors AS interior
  ON interior.blob_id=mount.blob_id AND interior.lang=mount.storage_language
 AND interior.semantic_language=mount.semantic_language
 AND interior.producer_epoch=mount.producer_epoch AND interior.interior_digest=mount.interior_digest
 AND interior.publication_state='complete'
CROSS JOIN main.resolution_semantic_sites AS semantic
  ON semantic.blob_id=interior.blob_id AND semantic.semantic_role='definition'
 AND semantic.semantic_key=json_extract(request.value, '$[1]')
CROSS JOIN main.resolution_member_scope_properties AS scope
  ON scope.blob_id=semantic.blob_id AND scope.definition_semantic_key=semantic.semantic_key AND scope.scope_kind='type_body'
CROSS JOIN main.source_fact_manifests AS source
  ON source.blob_id=semantic.blob_id AND source.publication_state='complete'
CROSS JOIN main.blob_meta AS meta ON meta.blob_id=semantic.blob_id AND meta.is_complete=1
LEFT JOIN main.resolution_definition_unit_crosswalks AS crosswalk
  ON crosswalk.blob_id=semantic.blob_id
 AND crosswalk.definition_semantic_key=semantic.semantic_key
LEFT JOIN main.code_units AS units
  ON units.blob_id=crosswalk.blob_id AND units.unit_key=crosswalk.unit_key
WHERE (mount.semantic_language='java' AND NOT EXISTS (
  SELECT 1 FROM main.source_native_declaration_bridges AS bridge
  WHERE bridge.blob_id=semantic.blob_id AND bridge.source_site=semantic.source_site))
   OR (mount.semantic_language='scala' AND semantic.namespace='value'
       AND (units.unit_key IS NULL OR (units.kind=?2 AND units.synthetic=1))
       AND EXISTS (
         SELECT 1 FROM main.resolution_additional_definition_namespaces AS term_type
         WHERE term_type.blob_id=semantic.blob_id
           AND term_type.definition_semantic_key=semantic.semantic_key
           AND term_type.namespace='value')
       AND EXISTS (
         SELECT 1 FROM main.resolution_singleton_relations AS singleton
         WHERE singleton.blob_id=semantic.blob_id
           AND singleton.declaration_site=semantic.source_site
           AND singleton.kind='companion'))
"#;

pub(super) fn read(
    source: &SelectedResolutionTypedSource<'_, '_>,
    definitions: &[SemanticId],
    cancellation: &CancellationToken,
) -> StoreResult<Option<Vec<JavaInheritanceDeclaration>>> {
    let selection = source.selection;
    let authority = &source.authority;
    let mut result = std::collections::BTreeMap::new();
    for chunk in definitions.chunks(crate::analyzer::resolution::MAX_TYPED_FACT_REQUESTS_PER_BATCH)
    {
        let mut coordinates = std::collections::BTreeMap::new();
        for &definition in chunk {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let Some(ordinal) = definition.ordinal() else {
                continue;
            };
            let language = selection
                .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?
                .semantic_language();
            if !language_has_jvm_semantics(language) {
                continue;
            }
            let Some(provenance) =
                authority.semantic_catalog_provenance(definition, cancellation)?
            else {
                return Ok(None);
            };
            let Some(SelectedSemanticProvenance::FragmentLocal(local)) = provenance else {
                continue;
            };
            let coordinate = (local.mount().ordinal(), local.local_key().get());
            coordinates.insert(coordinate, definition);
        }
        if coordinates.is_empty() {
            continue;
        }
        let requests = json_pair_array(
            coordinates
                .keys()
                .map(|(mount, key)| (i64::from(mount.get()), *key)),
        );
        let rows = source.read_statement(cancellation, |connection| {
            let mut statement = connection.prepare_cached(DECLARATIONS)?;
            let mut rows = statement.query([&requests])?;
            let mut found = Vec::new();
            while let Some(row) = rows.next()? {
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                let coordinate = (
                    SelectedResolutionMountOrdinal::new(row.get(0)?),
                    row.get::<_, i64>(1)?,
                );
                let definition = coordinates[&coordinate];
                let kind = super::super::code_unit_kind_from_i64(row.get(2)?)?;
                let kind = match kind {
                    CodeUnitType::Class => JavaInheritanceDeclarationKind::Type {
                        is_interface: row.get(4)?,
                        is_singleton: row.get(10)?,
                    },
                    CodeUnitType::Function if row.get::<_, bool>(8)? => {
                        let modifier: Option<String> = row.get(5)?;
                        let is_abstract = match modifier.as_deref() {
                            Some("abstract") => Some(true),
                            Some("not_declared") => Some(false),
                            _ => None,
                        };
                        let visibility: Option<String> = row.get(7)?;
                        let visibility = visibility
                            .as_deref()
                            .and_then(DeclaredVisibility::from_label)
                            .ok_or_else(|| {
                                StoreError::corrupt("recorded Java callable lacks visibility")
                            })?;
                        JavaInheritanceDeclarationKind::Method {
                            is_abstract,
                            is_static: row.get(6)?,
                            visibility,
                        }
                    }
                    _ => continue,
                };
                found.push(JavaInheritanceDeclaration {
                    definition,
                    name: row.get(9)?,
                    package: crate::analyzer::resolution::fact_source::JvmDeclarationPackage::Known(
                        row.get(3)?,
                    ),
                    kind,
                });
            }
            Ok(Some(found))
        })?;
        let Some(rows) = rows else {
            return Ok(None);
        };
        for row in rows {
            if let Some(previous) = result.insert(row.definition, row.clone())
                && previous != row
            {
                return Err(StoreError::corrupt(
                    "one Java source declaration has conflicting inheritance metadata",
                ));
            }
        }
        // Only requests without authored inheritance metadata need the
        // generated-owner proof. The query retains each language's admission.
        let unsourced = coordinates
            .iter()
            .filter(|(_, definition)| !result.contains_key(definition))
            .map(|(&coordinate, _)| coordinate)
            .collect::<Vec<_>>();
        if unsourced.is_empty() {
            continue;
        }
        let requests = json_pair_array(
            unsourced
                .into_iter()
                .map(|(mount, key)| (i64::from(mount.get()), key)),
        );
        let synthetic = source.read_statement(cancellation, |connection| {
            let mut statement = connection.prepare_cached(SYNTHETIC_TYPE_BODIES)?;
            let mut rows = statement.query(rusqlite::params![
                requests,
                super::super::code_unit_kind_to_i64(CodeUnitType::Class)
            ])?;
            let mut found = Vec::new();
            while let Some(row) = rows.next()? {
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                let coordinate = (
                    SelectedResolutionMountOrdinal::new(row.get(0)?),
                    row.get::<_, i64>(1)?,
                );
                found.push(JavaInheritanceDeclaration {
                    definition: coordinates[&coordinate],
                    name: row.get(3)?,
                    package: crate::analyzer::resolution::fact_source::JvmDeclarationPackage::Known(
                        row.get(2)?,
                    ),
                    kind: JavaInheritanceDeclarationKind::Type {
                        is_interface: false,
                        is_singleton: row.get(4)?,
                    },
                });
            }
            Ok(Some(found))
        })?;
        let Some(synthetic) = synthetic else {
            return Ok(None);
        };
        for row in synthetic {
            assert!(
                result.insert(row.definition, row).is_none(),
                "a generated JVM type has no source-declared inheritance row"
            );
        }
    }
    Ok((!cancellation.is_cancelled()).then(|| result.into_values().collect()))
}
