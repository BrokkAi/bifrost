//! Exact selected Java ownership for declaration-access decisions.

use super::*;
use crate::analyzer::resolution::JavaAccessEndpoint;

// Each seed and parent lookup is keyed by one selected blob and semantic. UNION
// also bounds malformed cyclic ownership without recursive Rust traversal.
pub(in crate::analyzer::store) const ENDPOINTS: &str = r#"
WITH RECURSIVE seeds(mount_ordinal, semantic_key, blob_id, package, owner) AS (
 SELECT request.mount_ordinal, request.key0, mount.blob_id, meta.content_package,
        CASE semantic.semantic_role WHEN 'definition' THEN request.key0 ELSE site.owner END
 FROM temp.selected_resolution_typed_requests_1 AS request
 CROSS JOIN temp.selected_resolution_mounts AS mount
   ON mount.mount_ordinal=request.mount_ordinal AND mount.semantic_language='java'
 CROSS JOIN main.resolution_fragment_interiors AS interior
   ON interior.blob_id=mount.blob_id AND interior.lang=mount.storage_language
  AND interior.semantic_language=mount.semantic_language
  AND interior.producer_epoch=mount.producer_epoch AND interior.interior_digest=mount.interior_digest
  AND interior.publication_state='complete'
 CROSS JOIN main.resolution_sites AS site
   ON site.blob_id=mount.blob_id AND site.site=request.key0
 CROSS JOIN main.resolution_semantic_sites AS semantic
   ON semantic.blob_id=mount.blob_id AND semantic.semantic_key=request.key0
  AND semantic.semantic_role=CASE site.role WHEN 0 THEN 'reference' ELSE 'definition' END
 CROSS JOIN main.blob_meta AS meta ON meta.blob_id=mount.blob_id AND meta.is_complete=1
), owners(mount_ordinal, semantic_key, blob_id, package, owner) AS (
 SELECT mount_ordinal, semantic_key, blob_id, package, owner FROM seeds
 UNION
 SELECT owners.mount_ordinal, owners.semantic_key, owners.blob_id, owners.package,
        parent.owner_definition_semantic_key
 FROM owners
 CROSS JOIN main.resolution_member_owner_properties AS parent
   ON parent.blob_id=owners.blob_id AND parent.definition_semantic_key=owners.owner
)
SELECT owners.mount_ordinal, owners.semantic_key, owners.package, owners.owner,
       CASE WHEN parent.definition_semantic_key IS NULL
                 AND scope.definition_semantic_key IS NOT NULL THEN owners.owner END
FROM owners
LEFT JOIN main.resolution_member_owner_properties AS parent
  ON parent.blob_id=owners.blob_id AND parent.definition_semantic_key=owners.owner
LEFT JOIN main.resolution_member_scope_properties AS scope
  ON scope.blob_id=owners.blob_id AND scope.definition_semantic_key=owners.owner
"#;

pub(super) fn read(
    source: &SelectedResolutionTypedSource<'_, '_>,
    semantics: &[SemanticId],
    cancellation: &CancellationToken,
) -> StoreResult<Option<Vec<JavaAccessEndpoint>>> {
    let mut result = std::collections::BTreeMap::new();
    for chunk in semantics.chunks(crate::analyzer::resolution::MAX_TYPED_FACT_REQUESTS_PER_BATCH) {
        let mut coordinates = std::collections::BTreeMap::new();
        for &semantic in chunk {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let Some(ordinal) = semantic.ordinal() else {
                continue;
            };
            if source
                .selection
                .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?
                .semantic_language()
                != Language::Java
            {
                continue;
            }
            let Some(provenance) = source
                .authority
                .semantic_catalog_provenance(semantic, cancellation)?
            else {
                return Ok(None);
            };
            let Some(SelectedSemanticProvenance::FragmentLocal(local)) = provenance else {
                continue;
            };
            coordinates.insert((local.mount().ordinal(), local.local_key().get()), semantic);
        }
        if coordinates.is_empty() {
            continue;
        }
        if !source
            .selection
            .replace_resolution_requests_1(coordinates.keys().copied(), cancellation)?
        {
            return Ok(None);
        }
        let rows = source.read_statement(cancellation, |connection| {
            let mut statement = connection.prepare_cached(ENDPOINTS)?;
            let mut rows = statement.query([])?;
            let mut found = Vec::new();
            while let Some(row) = rows.next()? {
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                let ordinal = SelectedResolutionMountOrdinal::new(row.get(0)?);
                let semantic = coordinates[&(ordinal, row.get::<_, i64>(1)?)];
                let root: Option<u32> = row.get(4)?;
                found.push((
                    semantic,
                    row.get::<_, Option<String>>(2)?,
                    root.map(|key| SemanticId::local(ordinal.get(), key)),
                ));
            }
            Ok(Some(found))
        })?;
        let Some(rows) = rows else { return Ok(None) };
        for (semantic, package, root) in rows {
            let endpoint = result
                .entry(semantic)
                .or_insert_with(|| JavaAccessEndpoint {
                    semantic,
                    package: package.clone(),
                    outermost_type: None,
                });
            assert_eq!(endpoint.package, package);
            if let Some(root) = root {
                assert!(
                    endpoint
                        .outermost_type
                        .is_none_or(|previous| previous == root)
                );
                endpoint.outermost_type = Some(root);
            }
        }
    }
    Ok((!cancellation.is_cancelled()).then(|| result.into_values().collect()))
}
