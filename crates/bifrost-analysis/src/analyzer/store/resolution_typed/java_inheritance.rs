//! Inheritance metadata for exact selected Java declarations, read per demand.

use super::*;
use crate::analyzer::CodeUnitType;
use crate::analyzer::resolution::{JavaInheritanceDeclaration, JavaInheritanceDeclarationKind};

// Requests carry selected mount/semantic keys. Every subsequent join is keyed
// by the selected blob and its source declaration; no workspace scan or live
// filesystem metadata supplies an inheritance decision.
pub(in crate::analyzer::store) const DECLARATIONS: &str = r#"
SELECT request.mount_ordinal, request.key0, units.kind, meta.content_package,
       metadata.class_like_is_interface, metadata.callable_override_modifier,
       metadata.callable_is_static, metadata.callable_declared_visibility,
       metadata.callable_modifiers_recorded
FROM temp.selected_resolution_typed_requests_1 AS request
CROSS JOIN temp.selected_resolution_mounts AS mount
  ON mount.mount_ordinal=request.mount_ordinal AND mount.semantic_language='java'
CROSS JOIN main.resolution_fragment_interiors AS interior
  ON interior.blob_id=mount.blob_id AND interior.lang=mount.storage_language
 AND interior.semantic_language=mount.semantic_language
 AND interior.producer_epoch=mount.producer_epoch AND interior.interior_digest=mount.interior_digest
 AND interior.publication_state='complete'
CROSS JOIN main.resolution_semantic_sites AS semantic
  ON semantic.blob_id=interior.blob_id AND semantic.semantic_role='definition'
 AND semantic.semantic_key=request.key0
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
            if selection
                .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?
                .semantic_language()
                != Language::Java
            {
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
            coordinates.insert(
                (local.mount().ordinal(), local.local_key().get()),
                definition,
            );
        }
        if coordinates.is_empty() {
            continue;
        }
        if !selection.replace_resolution_requests_1(coordinates.keys().copied(), cancellation)? {
            return Ok(None);
        }
        let rows = source.read_statement(cancellation, |connection| {
            let mut statement = connection.prepare_cached(DECLARATIONS)?;
            let mut rows = statement.query([])?;
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
                    package: row.get(3)?,
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
    }
    Ok((!cancellation.is_cancelled()).then(|| result.into_values().collect()))
}
