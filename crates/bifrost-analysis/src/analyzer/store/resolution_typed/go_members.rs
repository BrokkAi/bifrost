//! Go embedding and receiver metadata for exact selected declarations.

use super::*;
use crate::analyzer::resolution::{GoMemberDeclaration, GoMemberDeclarationKind, GoStructField};
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;

// Left joins retain known-empty structs and source embeddings whose native
// bridge is unavailable. Neither case may disappear into an apparent absence.
pub(in crate::analyzer::store) const DECLARATIONS: &str = r#"
SELECT request.mount_ordinal, request.key0, owner_type.kind,
       callable.is_method, receiver.kind, field.declaration_id,
       field_semantic.semantic_key, value.slot, field.name, field.embedded
FROM temp.selected_resolution_typed_requests_1 AS request
CROSS JOIN temp.selected_resolution_mounts AS mount
  ON mount.mount_ordinal=request.mount_ordinal AND mount.semantic_language='go'
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
CROSS JOIN main.source_go_manifests AS go_source ON go_source.blob_id=source.blob_id
CROSS JOIN main.source_native_declaration_bridges AS bridge
  ON bridge.blob_id=semantic.blob_id AND bridge.source_site=semantic.source_site
LEFT JOIN main.source_go_type_declarations AS declaration
  ON declaration.blob_id=bridge.blob_id AND declaration.declaration_id=bridge.declaration_id
LEFT JOIN main.source_go_types AS owner_type
  ON owner_type.blob_id=declaration.blob_id AND owner_type.type_id=declaration.type_id
LEFT JOIN main.source_go_fields AS field INDEXED BY source_go_fields_by_owner
  ON field.blob_id=declaration.blob_id AND field.owner_type_id=declaration.type_id
 AND owner_type.kind=12
LEFT JOIN main.source_native_declaration_bridges AS field_bridge
  ON field_bridge.blob_id=field.blob_id AND field_bridge.declaration_id=field.declaration_id
LEFT JOIN main.resolution_semantic_sites AS field_semantic
  ON field_semantic.blob_id=field_bridge.blob_id
 AND field_semantic.source_site=field_bridge.source_site AND field_semantic.semantic_role='definition'
LEFT JOIN main.resolution_declaration_types AS value
  ON value.blob_id=field_semantic.blob_id AND value.definition=field_semantic.semantic_key AND value.role=0
LEFT JOIN main.source_go_callables AS callable
  ON callable.blob_id=bridge.blob_id AND callable.declaration_id=bridge.declaration_id
LEFT JOIN main.source_go_types AS receiver
  ON receiver.blob_id=callable.blob_id AND receiver.type_id=callable.receiver_type_id
"#;

pub(super) fn read(
    source: &SelectedResolutionTypedSource<'_, '_>,
    definitions: &[SemanticId],
    cancellation: &CancellationToken,
) -> StoreResult<Option<Vec<GoMemberDeclaration>>> {
    let selection = source.selection;
    let mut result = std::collections::BTreeMap::<SemanticId, GoMemberDeclaration>::new();
    let definitions = definitions
        .iter()
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
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
                != Language::Go
            {
                continue;
            }
            let Some(provenance) = source
                .authority
                .semantic_catalog_provenance(definition, cancellation)?
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
            let names = selection.shared_name_table().interner(connection);
            let mut statement = connection.prepare_cached(DECLARATIONS)?;
            let mut rows = statement.query([])?;
            let mut found = Vec::new();
            while let Some(row) = rows.next()? {
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                let ordinal = SelectedResolutionMountOrdinal::new(row.get(0)?);
                let definition = coordinates[&(ordinal, row.get::<_, i64>(1)?)];
                let owner_kind: Option<i64> = row.get(2)?;
                let method: Option<bool> = row.get(3)?;
                let kind = if owner_kind == Some(12) {
                    let field_declaration: Option<i64> = row.get(5)?;
                    let field_key: Option<u32> = row.get(6)?;
                    let value_key: Option<u32> = row.get(7)?;
                    let mut fields = Vec::new();
                    if field_declaration.is_some() {
                        let name: String = row.get(8)?;
                        let recipe =
                            crate::analyzer::resolution::ResolutionLookupSemanticRecipe::new(
                                Language::Go,
                                ResolutionNamespace::Callable,
                                &name,
                            );
                        fields.push(GoStructField {
                            callable_lookup: recipe.semantic(&names),
                            embedded: row.get(9)?,
                            field: field_key.map(|key| SemanticId::local(ordinal.get(), key)),
                            value_type: value_key.map(|key| SemanticId::local(ordinal.get(), key)),
                        });
                    }
                    GoMemberDeclarationKind::Struct { fields }
                } else if owner_kind == Some(13) {
                    GoMemberDeclarationKind::Interface
                } else if method == Some(true) {
                    let receiver_kind: Option<i64> = row.get(4)?;
                    GoMemberDeclarationKind::Method {
                        pointer_receiver: match receiver_kind {
                            Some(0) => Some(false),
                            Some(1) => Some(true),
                            _ => None,
                        },
                    }
                } else {
                    continue;
                };
                found.push(GoMemberDeclaration { definition, kind });
            }
            Ok(Some(found))
        })?;
        let Some(rows) = rows else { return Ok(None) };
        for row in rows {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            use std::collections::btree_map::Entry;
            match result.entry(row.definition) {
                Entry::Vacant(entry) => {
                    entry.insert(row);
                }
                Entry::Occupied(mut entry) => match (&mut entry.get_mut().kind, row.kind) {
                    (
                        GoMemberDeclarationKind::Struct { fields },
                        GoMemberDeclarationKind::Struct { fields: more },
                    ) => {
                        fields.extend(more);
                    }
                    (previous, kind) if *previous == kind => {}
                    _ => {
                        return Err(StoreError::corrupt(
                            "conflicting Go member declaration metadata",
                        ));
                    }
                },
            }
        }
    }
    Ok((!cancellation.is_cancelled()).then(|| result.into_values().collect()))
}
