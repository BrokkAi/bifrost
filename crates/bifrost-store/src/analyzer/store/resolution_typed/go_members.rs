//! Go embedding and receiver metadata for exact selected declarations.

use super::*;
use crate::analyzer::resolution::{
    GoMemberDeclaration, GoMemberDeclarationKind, GoStructField, MAX_TYPED_FACT_REQUESTS_PER_BATCH,
};
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;

// Left joins retain known-empty structs and source embeddings whose native
// bridge is unavailable. Neither case may disappear into an apparent absence.
pub(in crate::analyzer::store) const DECLARATIONS: &str = r#"
SELECT json_extract(request.value, '$[0]'), json_extract(request.value, '$[1]'), owner_type.kind,
       callable.is_method, receiver.kind, field.declaration_id,
       field_semantic.semantic_key, value.slot, field.name, field.embedded,
       interface_method.name, interface_method_semantic.semantic_key
FROM json_each(?1) AS request
CROSS JOIN temp.selected_resolution_mounts AS mount
  ON mount.mount_ordinal=json_extract(request.value, '$[0]') AND mount.semantic_language='go'
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
        let requests = json_pair_array(
            coordinates
                .keys()
                .map(|(mount, key)| (i64::from(mount.get()), *key)),
        );
        let rows = source.read_statement(cancellation, |connection| {
            let names = selection.shared_name_table().interner(connection);
            let mut statement = connection.prepare_cached(DECLARATIONS)?;
            let mut rows = statement.query([&requests])?;
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
                } else if owner_kind.is_some() {
                    GoMemberDeclarationKind::Defined
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
  -- Source inventory cannot authorize a build-constrained method. Its owner
  -- frontier must retain that uncertainty until a Go-tool profile selects it.
  AND (package.provider_provenance='go_tool'
       OR (go_source.has_build_constraints=0 AND go_source.build_selection_facts_version=1))
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
pub(in crate::analyzer::store) static SOURCE_PARTICIPATION: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| {
        format!(
            r#"
/* selected_go_deferred_member_participation */
WITH probe AS (
  SELECT request.key AS request_key, mount.blob_id, mount.persisted_relative_path,
         coalesce(mount.file_version_id,placed.file_version_id) AS file_version_id,
         ?2 AS context_id, ?3 AS revision
  FROM json_each(?1) request
  CROSS JOIN temp.selected_resolution_mounts mount
    ON mount.mount_ordinal=request.value AND mount.semantic_language='go'
  LEFT JOIN temp.selected_go_transient_placements placed
    ON placed.mount_ordinal=mount.mount_ordinal
)
SELECT probe.request_key, source.source_role, package.provider_provenance,
       probe.persisted_relative_path, facts.has_build_constraints,
       facts.build_selection_facts_version,
       EXISTS(SELECT 1 FROM json_each(package.gaps) gap
              WHERE json_extract(gap.value,'$.code')='source_cgo_build_selection_unavailable'
                AND json_extract(gap.value,'$.evidence.path')=probe.persisted_relative_path)
FROM probe
{}
LEFT JOIN main.source_go_manifests facts ON facts.blob_id=probe.blob_id
WHERE versions.file_version_id=probe.file_version_id AND package.context_id=probe.context_id
"#,
            super::super::resolution_operation::go_context::GO_CONTEXT_SOURCE_FILE_BY_VERSION_JOIN
        )
    });

pub(super) fn source_participation(
    source: &SelectedResolutionTypedSource<'_, '_>,
    definitions: &[SemanticId],
    cancellation: &CancellationToken,
) -> StoreResult<Option<Vec<Option<String>>>> {
    if cancellation.is_cancelled() {
        return Ok(None);
    }
    let mut participation = vec![None; definitions.len()];
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
        if let Some(context) = binder.bind_context(
            SelectedResolutionMountOrdinal::new(ordinal),
            &mount.persisted_relative_path,
            definitions,
        )? {
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
            let Some(selected) = source.read_statement(cancellation, |connection| {
                source_participation_in_context(
                    connection,
                    &requests,
                    context_id,
                    revision,
                    cancellation,
                )
            })?
            else {
                return Ok(None);
            };
            for (index, role) in selected {
                let selected_role = &mut participation[chunk[index].0];
                // Preserve the existing rule: any explicit ignored membership
                // excludes a deferred candidate, regardless of row order.
                if selected_role.as_deref() != Some("ignored") {
                    *selected_role = Some(role);
                }
            }
        }
    }
    Ok(Some(participation))
}

// Keep ignored files in the inventory: their selected role proves exclusion,
// while a saved source-inventory sibling still needs its own placement proof.
pub(crate) const PACKAGE_MEMBER_SOURCES: &str = r#"
WITH probe AS (
 SELECT ?1 AS revision
), caller AS (
 SELECT package.package_id, package.for_test, versions.workspace_id,
        versions.generation
 FROM probe
 JOIN temp.selected_resolution_mounts mount ON mount.mount_ordinal=?2
 LEFT JOIN temp.selected_go_transient_placements placed ON placed.mount_ordinal=mount.mount_ordinal
 JOIN main.workspace_file_versions versions
   ON versions.file_version_id=coalesce(mount.file_version_id,placed.file_version_id)
  AND versions.valid_from<=probe.revision
  AND (versions.valid_until IS NULL OR probe.revision<versions.valid_until)
 JOIN main.go_package_files source ON source.rel_path=versions.rel_path
 JOIN main.go_package_instances package ON package.package_id=source.package_id AND package.context_id=?3
 -- Same-package callers retain their selected variant. An external test's
 -- import binds the package under test with its internal test files included.
 AND (package.package_id=?4 OR (NOT EXISTS (
   SELECT 1 FROM main.go_package_files active
   WHERE active.package_id=?4 AND active.rel_path=versions.rel_path
 ) AND (
   (?5='xtest' AND EXISTS (
     SELECT 1 FROM main.go_package_imports imported
     WHERE imported.importer_package_id=?4 AND imported.import_role='xtest'
       AND imported.target_package_id=package.package_id
   )) OR (package.for_test='' AND NOT EXISTS (
     SELECT 1 FROM main.go_package_imports imported
     JOIN main.go_package_files selected ON selected.package_id=imported.target_package_id
       AND selected.rel_path=versions.rel_path
     WHERE ?5='xtest' AND imported.importer_package_id=?4 AND imported.import_role='xtest'
   ))
 )))
 JOIN main.go_context_publications publication ON publication.context_id=package.context_id
  AND publication.workspace_id=versions.workspace_id AND publication.generation=versions.generation
  AND publication.lang=versions.lang AND publication.valid_from<=probe.revision
  AND (publication.valid_until IS NULL OR probe.revision<publication.valid_until)
)
SELECT coalesce(mount.mount_ordinal,placed.mount_ordinal)
FROM caller
JOIN main.go_package_files member ON member.package_id=caller.package_id
 -- For a same-package go-role caller, choosing the production variant is a
 -- single-build-configuration policy, not a Go rule: go test includes test files.
 AND (member.source_role NOT IN ('test','xtest')
      OR (member.source_role='test' AND ?5 IN ('test','xtest')
          AND (caller.package_id=?4 OR caller.for_test<>''))
      OR (member.source_role='xtest' AND caller.package_id=?4 AND ?5='xtest'))
LEFT JOIN main.workspace_file_versions version ON version.rel_path=member.rel_path
 AND version.workspace_id=caller.workspace_id AND version.generation=caller.generation
 AND version.lang='go' AND version.input_kind='source' AND version.valid_from<=?1
 AND (version.valid_until IS NULL OR ?1<version.valid_until)
LEFT JOIN temp.selected_resolution_mounts mount ON mount.file_version_id=version.file_version_id
LEFT JOIN temp.selected_go_transient_placements placed ON placed.file_version_id=version.file_version_id
"#;

pub(super) fn package_member_sources(
    source: &SelectedResolutionTypedSource<'_, '_>,
    definitions: &[SemanticId],
    cancellation: &CancellationToken,
) -> StoreResult<Option<Vec<Option<Vec<SemanticId>>>>> {
    let mut packages = vec![None; definitions.len()];
    let Some(binder) = &source.go_context_binder else {
        return Ok(Some(packages));
    };
    for (index, definition) in definitions.iter().enumerate() {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let Some(ordinal) = definition.ordinal() else {
            continue;
        };
        let ordinal = SelectedResolutionMountOrdinal::new(ordinal);
        let mount = source.mount(ordinal)?;
        let Some(context) =
            binder.bind_context(ordinal, &mount.persisted_relative_path, definitions)?
        else {
            continue;
        };
        let Some(members) = source.read_statement(cancellation, |connection| {
            package_member_sources_in_context(
                connection,
                context.revision,
                ordinal,
                context.context_id,
                binder.active_package(),
                &mount.persisted_relative_path,
                cancellation,
            )
        })?
        else {
            return Ok(None);
        };
        if !members.is_empty() {
            packages[index] = members.into_iter().collect();
        }
    }
    Ok(Some(packages))
}

// Participation is evaluated in an exact selected publication. Definition
// queries bind that publication through caller ownership; demand providers
// already have it, including target-only vendor and dependency packages.
fn source_participation_in_context(
    connection: &rusqlite::Connection,
    requests: &str,
    context_id: i64,
    revision: i64,
    cancellation: &CancellationToken,
) -> StoreResult<Option<Vec<(usize, String)>>> {
    let mut statement = connection.prepare_cached(&SOURCE_PARTICIPATION)?;
    let mut rows = statement.query(rusqlite::params![requests, context_id, revision])?;
    let mut selected = Vec::new();
    while let Some(row) = rows.next()? {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let role: String = row.get(1)?;
        let provenance: String = row.get(2)?;
        if provenance == "source_inventory" && role != "ignored" {
            let path: String = row.get(3)?;
            let directive: Option<bool> = row.get(4)?;
            let version: Option<i64> = row.get(5)?;
            let cgo_unselected: bool = row.get(6)?;
            // Source inventory lists constrained and cgo files without
            // selecting them. Only discovery proves their participation.
            if cgo_unselected
                || version
                    != Some(
                        brokk_bifrost_core::analyzer::go_facts::GO_BUILD_SELECTION_FACTS_VERSION,
                    )
                || directive.is_none_or(|directive| {
                    brokk_bifrost_go::packages::source_path_has_build_constraints(
                        std::path::Path::new(&path),
                        directive,
                    )
                })
            {
                continue;
            }
        }
        selected.push((row.get::<_, usize>(0)?, role));
    }
    Ok(Some(selected))
}

pub(in crate::analyzer::store) fn package_member_sources_in_context(
    connection: &rusqlite::Connection,
    revision: i64,
    ordinal: SelectedResolutionMountOrdinal,
    context_id: i64,
    active_package: Option<(i64, Option<&str>)>,
    caller_path: &str,
    cancellation: &CancellationToken,
) -> StoreResult<Option<Vec<Option<SemanticId>>>> {
    let mut statement = connection.prepare_cached(PACKAGE_MEMBER_SOURCES)?;
    let mut rows = statement.query(rusqlite::params![
        revision,
        ordinal.get(),
        context_id,
        active_package.map(|(package, _)| package),
        active_package.and_then(|(_, role)| role)
    ])?;
    let mut members = Vec::new();
    while let Some(row) = rows.next()? {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        members.push(
            row.get::<_, Option<u32>>(0)?
                .map(|ordinal| SemanticId::local(ordinal, 0)),
        );
    }
    drop(rows);
    // New or membership-changing overlays may not have a package row
    // yet. Keep those same-directory sources in the proof request too;
    // the role reader will leave their placement unproven.
    let mut unplaced = connection.prepare_cached(
        "SELECT unknown.mount_ordinal, unknown.persisted_relative_path
                 FROM temp.selected_resolution_mounts unknown
                 JOIN temp.selected_resolution_mounts caller ON caller.mount_ordinal=?1
                 WHERE unknown.storage_language='go' AND unknown.file_version_id IS NULL
                   AND unknown.workspace_id=caller.workspace_id
                   AND unknown.generation=caller.generation
                   AND NOT EXISTS(SELECT 1 FROM temp.selected_go_transient_placements placed
                                  WHERE placed.mount_ordinal=unknown.mount_ordinal)",
    )?;
    let mut rows = unplaced.query([ordinal.get()])?;
    while let Some(row) = rows.next()? {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let path: String = row.get(1)?;
        if std::path::Path::new(&path).parent() == std::path::Path::new(&caller_path).parent() {
            members.push(Some(SemanticId::local(row.get(0)?, 0)));
        }
    }
    Ok(Some(members))
}

/// A context publication must not close an uncertain package frontier. Reuse
/// the ordinary source inventory and participation reads with the provider's
/// selected publication, without requiring its targets to own a caller unit.
/// `members` is the package's `package_member_sources_in_context` answer.
pub(in crate::analyzer::store) fn package_placement_is_proven(
    connection: &rusqlite::Connection,
    context: &crate::analyzer::store::GoContextIdentity,
    members: &[Option<SemanticId>],
    cancellation: &CancellationToken,
) -> StoreResult<Option<bool>> {
    if members.is_empty() || members.iter().any(Option::is_none) {
        return Ok(Some(false));
    }
    for chunk in members.chunks(MAX_TYPED_FACT_REQUESTS_PER_BATCH) {
        let ordinals = chunk
            .iter()
            .map(|source| {
                i64::from(
                    source
                        .expect("package members are all mounted")
                        .ordinal()
                        .expect("a mounted source has an ordinal"),
                )
            })
            .collect::<Vec<_>>();
        let requests = serde_json::to_string(&ordinals).expect("mount ordinals serialize");
        let Some(roles) = source_participation_in_context(
            connection,
            &requests,
            context.context_id,
            context.revision,
            cancellation,
        )?
        else {
            return Ok(None);
        };
        let mut proven = vec![false; chunk.len()];
        for (index, _) in roles {
            proven[index] = true;
        }
        if !proven.into_iter().all(|proven| proven) {
            return Ok(Some(false));
        }
    }
    Ok(Some(true))
}
