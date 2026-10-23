//! Go embedding and receiver metadata for exact selected declarations.

use super::*;
use crate::analyzer::resolution::{
    GoMemberDeclaration, GoMemberDeclarationKind, GoStructField, MAX_TYPED_FACT_REQUESTS_PER_BATCH,
};
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;

// Left joins retain known-empty structs and source embeddings whose native
// bridge is unavailable. Neither case may disappear into an apparent absence.
pub(in crate::analyzer::store) const DECLARATIONS: &str = r#"
SELECT request.mount_ordinal, request.key0, owner_type.kind,
       callable.is_method, receiver.kind, field.declaration_id,
       field_semantic.semantic_key, value.slot, field.name, field.embedded,
       interface_method.name, interface_method_semantic.semantic_key
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
LEFT JOIN main.source_go_callables AS interface_method
  ON interface_method.blob_id=owner_type.blob_id
 AND interface_method.owner_type_id=owner_type.type_id AND interface_method.is_method=1
LEFT JOIN main.source_native_declaration_bridges AS interface_method_bridge
  ON interface_method_bridge.blob_id=interface_method.blob_id
 AND interface_method_bridge.declaration_id=interface_method.declaration_id
LEFT JOIN main.resolution_semantic_sites AS interface_method_semantic
  ON interface_method_semantic.blob_id=interface_method_bridge.blob_id
 AND interface_method_semantic.source_site=interface_method_bridge.source_site
 AND interface_method_semantic.semantic_role='definition'
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
                    let mut methods = Vec::new();
                    if let Some(name) = row.get::<_, Option<String>>(10)? {
                        let recipe =
                            crate::analyzer::resolution::ResolutionLookupSemanticRecipe::new(
                                Language::Go,
                                ResolutionNamespace::Callable,
                                &name,
                            );
                        methods.push(crate::analyzer::resolution::GoInterfaceMethod {
                            callable_lookup: recipe.semantic(&names),
                            definition: row
                                .get::<_, Option<u32>>(11)?
                                .map(|key| SemanticId::local(ordinal.get(), key)),
                        });
                    }
                    GoMemberDeclarationKind::Interface { methods }
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
                    (
                        GoMemberDeclarationKind::Interface { methods },
                        GoMemberDeclarationKind::Interface { methods: more },
                    ) => {
                        methods.extend(more);
                        methods.sort_unstable_by_key(|method| {
                            (method.callable_lookup, method.definition)
                        });
                        methods.dedup();
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

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) struct OwnerProofReadKey {
    selected: [u8; 32],
    scope: [u8; 32],
    stage: (u64, u64),
    candidate: (SemanticId, SemanticId),
}

#[derive(Default)]
pub(super) struct OwnerProofMemo {
    stamp: Option<SelectedResolutionReadStamp>,
    reads: super::super::selected_read_memo::ExactReadMemo<OwnerProofReadKey, Option<SemanticId>>,
}

// Drive exact candidate coordinates, not all callables sharing a spelling.
// Seek package peers from each candidate's file version, then selected
// versions. Materializing every workspace placement once per forward group
// erases the saving from excluding unrelated receiver frontiers. The explicit
// version checks preserve go_context_source_files' source/revision visibility.
// Both package members and source/native identities belong to this selection.
pub(crate) const OWNER_PROOFS: &str = r#"
/* selected_go_deferred_member_owner_proofs */
WITH candidates AS (
  SELECT request.key AS candidate, mount.workspace_id,mount.generation,mount.revision,
         package.package_id,method_file.source_role,
         CASE WHEN callable.receiver_type_id IS NULL THEN interface_declaration.name ELSE name.name END AS receiver_name
  FROM json_each(?1) request
  CROSS JOIN temp.selected_resolution_mounts mount
    ON mount.mount_ordinal=json_extract(request.value,'$[0]')
   AND mount.semantic_language='go'
  CROSS JOIN temp.selected_resolution_scope_mounts scope
    ON scope.mount_ordinal=mount.mount_ordinal
  CROSS JOIN main.resolution_fragment_interiors interior
    ON interior.blob_id=mount.blob_id AND interior.lang=mount.storage_language
   AND interior.semantic_language=mount.semantic_language
   AND interior.producer_epoch=mount.producer_epoch AND interior.interior_digest=mount.interior_digest
   AND interior.publication_state='complete'
  CROSS JOIN main.source_fact_manifests source
    ON source.blob_id=interior.blob_id AND source.publication_state='complete'
  CROSS JOIN main.source_go_manifests go_source ON go_source.blob_id=source.blob_id
  CROSS JOIN main.resolution_semantic_sites semantic
    ON semantic.blob_id=mount.blob_id AND semantic.semantic_role='definition'
   AND semantic.semantic_key=json_extract(request.value,'$[1]')
  CROSS JOIN main.resolution_deferred_member_owners deferred
    ON deferred.blob_id=semantic.blob_id AND deferred.definition=semantic.semantic_key
   AND json_extract(deferred.body,'$[0]')=json_extract(request.value,'$[2]')
  CROSS JOIN main.source_native_declaration_bridges bridge
    ON bridge.blob_id=semantic.blob_id AND bridge.source_site=semantic.source_site
  CROSS JOIN main.source_go_callables callable
    ON callable.blob_id=bridge.blob_id AND callable.declaration_id=bridge.declaration_id
   AND callable.is_method=1
  LEFT JOIN main.source_go_types receiver
    ON receiver.blob_id=callable.blob_id AND receiver.type_id=callable.receiver_type_id
   AND receiver.kind IN (0,1)
  LEFT JOIN main.source_go_types base
    ON base.blob_id=receiver.blob_id
   AND base.type_id=CASE WHEN receiver.kind=1 THEN receiver.child1 ELSE receiver.type_id END
   AND base.kind=0
  LEFT JOIN main.source_go_type_names name
    ON name.blob_id=base.blob_id AND name.type_id=base.type_id AND name.ordinal=0
  LEFT JOIN main.source_go_types interface_owner
    ON interface_owner.blob_id=callable.blob_id AND interface_owner.type_id=callable.owner_type_id
   AND interface_owner.kind=13 AND callable.receiver_type_id IS NULL
  LEFT JOIN main.source_go_type_declarations interface_declaration
    ON interface_declaration.blob_id=interface_owner.blob_id
   AND interface_declaration.type_id=interface_owner.type_id AND interface_declaration.file_scope=1
  LEFT JOIN temp.selected_go_transient_placements placed ON placed.mount_ordinal=mount.mount_ordinal
  CROSS JOIN main.workspace_file_versions method_version
    ON method_version.file_version_id=coalesce(mount.file_version_id,placed.file_version_id)
   AND method_version.workspace_id=mount.workspace_id AND method_version.lang=mount.storage_language
   AND method_version.generation=mount.generation AND method_version.input_kind='source'
   AND method_version.valid_from<=mount.revision
   AND (method_version.valid_until IS NULL OR mount.revision<method_version.valid_until)
  CROSS JOIN main.go_package_files method_file
    ON method_file.rel_path=method_version.rel_path AND method_file.source_role<>'ignored'
  CROSS JOIN main.go_package_instances package
    ON package.package_id=method_file.package_id AND package.complete=1
  CROSS JOIN main.go_context_publications publication ON publication.context_id=package.context_id
  CROSS JOIN main.go_context_selections selected_context
    ON selected_context.selection_id=publication.selection_id
   AND selected_context.workspace_id=mount.workspace_id AND selected_context.lang=mount.storage_language
   AND selected_context.generation=mount.generation
   AND publication.valid_from<=mount.revision AND (publication.valid_until IS NULL OR mount.revision<publication.valid_until)
  WHERE (name.name IS NOT NULL OR interface_declaration.name IS NOT NULL)
  AND NOT EXISTS (
    SELECT 1 FROM main.source_go_type_names extra
    WHERE extra.blob_id=base.blob_id AND extra.type_id=base.type_id AND extra.ordinal<>0
  ) AND NOT EXISTS (
    SELECT 1 FROM temp.selected_resolution_stage_package_members staged
    WHERE staged.host_ordinal=mount.mount_ordinal
  ) AND NOT EXISTS (
    SELECT 1 FROM temp.selected_resolution_stage_package_references staged
    WHERE staged.host_ordinal=mount.mount_ordinal
  )
), package_files AS (
  SELECT candidate.candidate,candidate.receiver_name,candidate.workspace_id,candidate.generation,
         candidate.revision,peer.file_version_id
  FROM candidates candidate
  CROSS JOIN temp.selected_go_context_source_files peer
    ON peer.package_id=candidate.package_id AND peer.source_role IN ('go',candidate.source_role)
  CROSS JOIN main.workspace_file_versions peer_version
    ON peer_version.file_version_id=peer.file_version_id
   AND peer_version.workspace_id=candidate.workspace_id AND peer_version.lang='go'
   AND peer_version.generation=candidate.generation AND peer_version.input_kind='source'
   AND peer_version.valid_from<=candidate.revision
   AND (peer_version.valid_until IS NULL OR candidate.revision<peer_version.valid_until)
), owner_mounts AS (
  SELECT peer.candidate,peer.receiver_name,owner.mount_ordinal,owner.blob_id,owner.storage_language,
         owner.semantic_language,owner.producer_epoch,owner.interior_digest
  FROM package_files peer
  CROSS JOIN temp.selected_resolution_mounts owner ON owner.file_version_id=peer.file_version_id
   AND owner.workspace_id=peer.workspace_id AND owner.generation=peer.generation
   AND owner.revision=peer.revision AND owner.semantic_language='go'
  UNION ALL
  SELECT peer.candidate,peer.receiver_name,owner.mount_ordinal,owner.blob_id,owner.storage_language,
         owner.semantic_language,owner.producer_epoch,owner.interior_digest
  FROM package_files peer
  CROSS JOIN temp.selected_go_transient_placements placed ON placed.file_version_id=peer.file_version_id
  CROSS JOIN temp.selected_resolution_mounts owner ON owner.mount_ordinal=placed.mount_ordinal
   AND owner.workspace_id=peer.workspace_id AND owner.generation=peer.generation
   AND owner.revision=peer.revision AND owner.semantic_language='go'
)
SELECT DISTINCT owner.candidate,owner.mount_ordinal,owner_semantic.semantic_key
FROM owner_mounts owner
CROSS JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=owner.mount_ordinal
CROSS JOIN main.resolution_fragment_interiors interior
  ON interior.blob_id=owner.blob_id AND interior.lang=owner.storage_language
 AND interior.semantic_language=owner.semantic_language
 AND interior.producer_epoch=owner.producer_epoch AND interior.interior_digest=owner.interior_digest
 AND interior.publication_state='complete'
CROSS JOIN main.source_fact_manifests source
  ON source.blob_id=interior.blob_id AND source.publication_state='complete'
CROSS JOIN main.source_go_manifests go_source ON go_source.blob_id=source.blob_id
CROSS JOIN main.source_go_type_declarations nominal
  ON nominal.blob_id=owner.blob_id AND nominal.name=owner.receiver_name AND nominal.file_scope=1
CROSS JOIN main.source_native_declaration_bridges owner_bridge
  ON owner_bridge.blob_id=nominal.blob_id AND owner_bridge.declaration_id=nominal.declaration_id
CROSS JOIN main.resolution_semantic_sites owner_semantic
  ON owner_semantic.blob_id=owner_bridge.blob_id AND owner_semantic.source_site=owner_bridge.source_site
 AND owner_semantic.semantic_role='definition'
WHERE NOT EXISTS (
  SELECT 1 FROM temp.selected_resolution_stage_package_members staged
  WHERE staged.host_ordinal=owner.mount_ordinal
) AND NOT EXISTS (
  SELECT 1 FROM temp.selected_resolution_stage_package_references staged
  WHERE staged.host_ordinal=owner.mount_ordinal
)
"#;

pub(super) fn owner_proofs(
    source: &SelectedResolutionTypedSource<'_, '_>,
    owners: &[SemanticId],
    candidates: &[(SemanticId, SemanticId)],
    cancellation: &CancellationToken,
) -> StoreResult<Option<Vec<crate::analyzer::resolution::DeferredMemberOwnerProof>>> {
    use crate::analyzer::resolution::DeferredMemberOwnerProof;
    let selection = source.selection;
    let proof_stamp = selection.read_change_stamp()?;
    if cancellation.is_cancelled() || !source.validate_selected_interiors(cancellation)? {
        return Ok(None);
    }
    let selected = selection.candidate_coverage_fingerprint();
    let scope = selection.scope_identity();
    let stage = selection.staged_read_epoch();
    let keys = candidates
        .iter()
        .copied()
        .map(|candidate| OwnerProofReadKey {
            selected,
            scope,
            stage,
            candidate,
        })
        .collect::<Vec<_>>();
    let mut nominal = vec![BTreeSet::new(); candidates.len()];
    let mut missing = Vec::new();
    {
        let mut memo = source.go_owner_proofs.borrow_mut();
        // Keep the validated pre-read stamp, as the other selected readers do.
        // A concurrent publication makes the next boundary invalidate this
        // memo rather than attributing an older answer to the newer stamp.
        let stamp = Some(proof_stamp);
        if memo.stamp != stamp {
            memo.reads = Default::default();
            memo.stamp = stamp;
        }
        for (index, key) in keys.iter().enumerate() {
            if let Some(owner) = memo.reads.get(key) {
                nominal[index].extend(*owner);
            } else {
                missing.push(index);
            }
        }
    }
    let mut requests = Vec::new();
    let mut request_indices = Vec::new();
    for &index in &missing {
        let (definition, frontier) = candidates[index];
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let Some(definition) = source
            .authority
            .semantic_catalog_provenance(definition, cancellation)?
        else {
            return Ok(None);
        };
        let Some(frontier) = source
            .authority
            .semantic_catalog_provenance(frontier, cancellation)?
        else {
            return Ok(None);
        };
        let (
            Some(SelectedSemanticProvenance::FragmentLocal(definition)),
            Some(SelectedSemanticProvenance::FragmentLocal(frontier)),
        ) = (definition, frontier)
        else {
            continue;
        };
        if definition.mount().ordinal() != frontier.mount().ordinal() {
            continue;
        }
        requests.push([
            i64::from(definition.mount().ordinal().get()),
            definition.local_key().get(),
            frontier.local_key().get(),
        ]);
        request_indices.push(index);
    }
    if !requests.is_empty() {
        let requests = serde_json::to_string(&requests).expect("integer coordinates serialize");
        let Some(rows) = source.read_statement(cancellation, |connection| {
            let mut statement = connection.prepare_cached(OWNER_PROOFS)?;
            let mut rows = statement.query([requests])?;
            let mut found = Vec::new();
            while let Some(row) = rows.next()? {
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                found.push((
                    row.get::<_, usize>(0)?,
                    SemanticId::local(row.get(1)?, row.get(2)?),
                ));
            }
            Ok(Some(found))
        })?
        else {
            return Ok(None);
        };
        for (request, owner) in rows {
            nominal[request_indices[request]].insert(owner);
        }
    }
    if cancellation.is_cancelled() {
        return Ok(None);
    }
    // Cache source ownership, not receiver comparisons or forward answers.
    // Another receiver can reuse the same selected declaration read.
    if stage == selection.staged_read_epoch()
        && scope == selection.scope_identity()
        && selected == selection.candidate_coverage_fingerprint()
    {
        let mut memo = source.go_owner_proofs.borrow_mut();
        for index in missing {
            let owner = (nominal[index].len() == 1)
                .then(|| *nominal[index].first().expect("one nominal owner"));
            memo.reads.insert(keys[index].clone(), owner);
        }
    }
    let proofs = nominal
        .into_iter()
        .map(|nominal| {
            if nominal.len() != 1 {
                DeferredMemberOwnerProof::Unknown
            } else if owners.contains(nominal.first().expect("one proven nominal owner")) {
                DeferredMemberOwnerProof::Matches
            } else {
                DeferredMemberOwnerProof::DoesNotMatch
            }
        })
        .collect::<Vec<_>>();
    Ok(Some(proofs))
}

// Exact selected publication, including transient files whose package placement
// is proven unchanged. Incompleteness is not exclusion: only an explicit ignored
// role removes a candidate, without requiring its package to be complete.
pub(in crate::analyzer::store) const NONPARTICIPATING: &str = r#"
/* selected_go_deferred_member_participation */
SELECT request.key
FROM json_each(?1) request
JOIN temp.selected_resolution_mounts mount
  ON mount.mount_ordinal=request.value AND mount.semantic_language='go'
LEFT JOIN temp.selected_go_transient_placements placed
  ON placed.mount_ordinal=mount.mount_ordinal
JOIN main.go_context_source_files source
  ON source.context_id=?2
 AND source.file_version_id=coalesce(mount.file_version_id,placed.file_version_id)
 AND source.source_role='ignored'
 AND source.valid_from<=?3 AND (source.valid_until IS NULL OR ?3<source.valid_until)
 AND source.publication_valid_from<=?3
 AND (source.publication_valid_until IS NULL OR ?3<source.publication_valid_until)
"#;

pub(super) fn participation(
    source: &SelectedResolutionTypedSource<'_, '_>,
    definitions: &[SemanticId],
    cancellation: &CancellationToken,
) -> StoreResult<Option<Vec<bool>>> {
    if cancellation.is_cancelled() {
        return Ok(None);
    }
    let mut participation = vec![true; definitions.len()];
    let Some(binder) = &source.go_context_binder else {
        return Ok(Some(participation));
    };
    let mut groups = std::collections::BTreeMap::<(i64, i64), Vec<(usize, i64)>>::new();
    for (index, definition) in definitions.iter().enumerate() {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let Some(ordinal) = definition.ordinal() else {
            continue;
        };
        let mount = source.mount(SelectedResolutionMountOrdinal::new(ordinal))?;
        if mount.semantic_language != crate::analyzer::Language::Go {
            continue;
        }
        if let Some(context) = binder.bind_context(&mount.persisted_relative_path)? {
            groups
                .entry((context.context_id, context.revision))
                .or_default()
                .push((index, i64::from(ordinal)));
        }
    }
    for ((context_id, revision), group) in groups {
        for chunk in group.chunks(MAX_TYPED_FACT_REQUESTS_PER_BATCH) {
            let ordinals = chunk
                .iter()
                .map(|(_, ordinal)| *ordinal)
                .collect::<Vec<_>>();
            let requests = serde_json::to_string(&ordinals).expect("mount ordinals serialize");
            let Some(excluded) = source.read_statement(cancellation, |connection| {
                let mut statement = connection.prepare_cached(NONPARTICIPATING)?;
                let mut rows =
                    statement.query(rusqlite::params![requests, context_id, revision])?;
                let mut excluded = Vec::new();
                while let Some(row) = rows.next()? {
                    if cancellation.is_cancelled() {
                        return Ok(None);
                    }
                    excluded.push(row.get::<_, usize>(0)?);
                }
                Ok(Some(excluded))
            })?
            else {
                return Ok(None);
            };
            for index in excluded {
                participation[chunk[index].0] = false;
            }
        }
    }
    Ok(Some(participation))
}
