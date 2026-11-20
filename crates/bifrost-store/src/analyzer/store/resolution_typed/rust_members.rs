//! Receiver evidence for admission of deferred Rust inherent members.

use super::*;
use crate::analyzer::resolution::MAX_TYPED_FACT_REQUESTS_PER_BATCH;
use crate::analyzer::resolution::fact_source::DeferredMemberReceiverType;
use brokk_bifrost_core::analyzer::resolution_facts::IntrinsicTypeKind;

// The impl census is enumeration authority, not the summary's aggregate name
// resolution completeness. Unresolved endpoints below still leave this coarse
// certificate open, including a possibly unresolved Deref implementation.
// Declaration kinds 0, 1 and 2 are owned structs, enums and unions. An alias
// or trait-bound identity does not identify the crate owning the actual type.
pub(in crate::analyzer::store) const RECEIVER_CENSUS: &str = r#"
SELECT
  summary.publication_state='complete' AND topology.publication_state='complete'
  AND NOT EXISTS (
    SELECT 1 FROM resolution_unit_summary_members m
    LEFT JOIN source_fact_manifests facts ON facts.blob_id=m.blob_id
    LEFT JOIN source_rust_item_manifests items ON items.blob_id=m.blob_id
    LEFT JOIN source_rust_impl_census_files census ON census.blob_id=m.blob_id
    WHERE m.summary_id=unit.summary_id AND (
      facts.publication_state IS NOT 'complete' OR items.facts_version IS NOT 2
      OR census.census_version IS NOT 1 OR census.boundary_count IS NOT 0
      OR census.impl_count IS NOT (SELECT count(*) FROM source_rust_impl_items i WHERE i.blob_id=m.blob_id)
      OR EXISTS (SELECT 1 FROM source_rust_impl_census_boundaries b WHERE b.blob_id=m.blob_id)
      OR NOT EXISTS (SELECT 1 FROM temp.selected_resolution_mounts selected
        WHERE selected.blob_id=m.blob_id AND selected.persisted_relative_path=m.rel_path
          AND selected.semantic_language='rust')))
  AND NOT EXISTS (SELECT 1 FROM rust_crate_gaps gap WHERE gap.topology_id=unit.topology_id
    AND gap.gap_kind IN ('unsupported_manifest','unknown_activation','unplaced_module','duplicate_placement'))
  AND NOT EXISTS (SELECT 1 FROM rust_crate_container_sources source
    WHERE source.topology_id=unit.topology_id AND NOT EXISTS (
      SELECT 1 FROM resolution_unit_summary_members m WHERE m.summary_id=unit.summary_id
        AND m.blob_id=source.blob_id AND m.rel_path=source.rel_path))
  AND NOT EXISTS (SELECT 1 FROM rust_resolution_unit_summary_trait_endpoints endpoint
    WHERE endpoint.summary_id=unit.summary_id AND (endpoint.endpoint_state<>'resolved'
      OR NOT EXISTS (SELECT 1 FROM rust_resolution_unit_summary_trait_endpoints other
        WHERE other.summary_id=endpoint.summary_id AND other.member_ordinal=endpoint.member_ordinal
          AND other.owner_module_path=endpoint.owner_module_path
          AND other.source_relation_key=endpoint.source_relation_key
          AND other.endpoint_role<>endpoint.endpoint_role)))
  AND NOT EXISTS (SELECT 1 FROM resolution_unit_summary_members m
    JOIN source_rust_impl_items impl ON impl.blob_id=m.blob_id
    WHERE m.summary_id=unit.summary_id
      AND NOT EXISTS (SELECT 1 FROM rust_resolution_unit_summary_inherent_impls inherent
        WHERE inherent.summary_id=m.summary_id AND inherent.impl_member_ordinal=m.member_ordinal
          AND inherent.impl_declaration_id=impl.declaration_id)
      AND NOT EXISTS (SELECT 1 FROM rust_resolution_unit_summary_trait_endpoints endpoint
        WHERE endpoint.summary_id=m.summary_id AND endpoint.member_ordinal=m.member_ordinal
          AND endpoint.impl_declaration_id=impl.declaration_id))
FROM temp.selected_resolution_mounts owner_mount
CROSS JOIN resolution_rust_declaration_authorities owner
  ON owner.blob_id=owner_mount.blob_id AND owner.semantic_key=?2
CROSS JOIN source_rust_declaration_properties owner_property
  ON owner_property.blob_id=owner.blob_id AND owner_property.declaration_id=owner.declaration
  AND owner_property.declaration_kind IN (0,1,2)
CROSS JOIN resolution_unit_summary_members owner_member
  ON owner_member.blob_id=owner.blob_id AND owner_member.rel_path=owner_mount.persisted_relative_path
CROSS JOIN selected_rust_unit_summaries unit ON unit.summary_id=owner_member.summary_id
CROSS JOIN rust_resolution_unit_summary_exports export
  ON export.summary_id=unit.summary_id AND export.declaration_member_ordinal=owner_member.member_ordinal
  AND export.declaration_site=owner.source_site AND export.namespace='type' AND export.origin='declaration'
CROSS JOIN resolution_unit_summaries summary ON summary.summary_id=unit.summary_id
CROSS JOIN rust_crate_topologies topology ON topology.topology_id=unit.topology_id
WHERE owner_mount.mount_ordinal=?1 AND owner_mount.semantic_language='rust'
"#;

// Drive exact candidate declarations. A missing inherent subject, including a
// trait impl or an unresolved self type, must survive every LEFT JOIN.
// A resolved alias is not yet a resolved nominal self type; preserve it too.
pub(in crate::analyzer::store) const INHERENT_SUBJECTS: &str = r#"
SELECT json_extract(request.value,'$[0]'), inherent.impl_declaration_id,
       unresolved.impl_declaration_id, subject_mount.mount_ordinal, subject.semantic_key,
       subject_property.declaration_kind
FROM json_each(?1) request
CROSS JOIN temp.selected_resolution_mounts member_mount
  ON member_mount.mount_ordinal=json_extract(request.value,'$[1]')
  AND member_mount.semantic_language='rust'
CROSS JOIN resolution_rust_declaration_authorities member
  ON member.blob_id=member_mount.blob_id AND member.semantic_key=json_extract(request.value,'$[2]')
LEFT JOIN source_rust_item_body_children child
  ON child.blob_id=member.blob_id AND child.declaration_id=member.declaration
LEFT JOIN resolution_unit_summary_members impl_member
  ON impl_member.blob_id=member.blob_id AND impl_member.rel_path=member_mount.persisted_relative_path
LEFT JOIN selected_rust_unit_summaries unit ON unit.summary_id=impl_member.summary_id
LEFT JOIN rust_resolution_unit_summary_inherent_impls inherent INDEXED BY rust_summary_inherent_declaration
  ON inherent.summary_id=unit.summary_id AND inherent.impl_member_ordinal=impl_member.member_ordinal
  AND inherent.impl_declaration_id=child.owner_declaration_id
LEFT JOIN rust_resolution_unit_summary_unresolved_inherent_impls unresolved
  ON unresolved.summary_id=unit.summary_id AND unresolved.impl_member_ordinal=impl_member.member_ordinal
  AND unresolved.impl_declaration_id=child.owner_declaration_id
LEFT JOIN selected_rust_unit_summaries foreign_unit
  ON inherent.subject_form='foreign' AND foreign_unit.unit_key=inherent.subject_unit_key
LEFT JOIN rust_resolution_unit_summary_exports foreign_export
  ON foreign_export.summary_id=foreign_unit.summary_id
  AND foreign_export.module_path=inherent.subject_module_path
  AND foreign_export.namespace=inherent.subject_namespace AND foreign_export.name=inherent.subject_name
  AND foreign_export.origin=inherent.subject_origin
LEFT JOIN resolution_unit_summary_members subject_member
  ON subject_member.summary_id=CASE inherent.subject_form WHEN 'local_site' THEN inherent.summary_id ELSE foreign_unit.summary_id END
  AND subject_member.member_ordinal=CASE inherent.subject_form WHEN 'local_site' THEN inherent.subject_member_ordinal ELSE foreign_export.declaration_member_ordinal END
LEFT JOIN temp.selected_resolution_mounts subject_mount
  ON subject_mount.blob_id=subject_member.blob_id
  AND subject_mount.persisted_relative_path=subject_member.rel_path AND subject_mount.semantic_language='rust'
LEFT JOIN resolution_rust_declaration_authorities subject INDEXED BY resolution_rust_declaration_authorities_source_site
  ON subject.blob_id=subject_member.blob_id
  AND subject.source_site=CASE inherent.subject_form WHEN 'local_site' THEN inherent.subject_site ELSE foreign_export.declaration_site END
LEFT JOIN source_rust_declaration_properties subject_property
  ON subject_property.blob_id=subject.blob_id AND subject_property.declaration_id=subject.declaration
"#;

pub(super) fn participation(
    source: &SelectedResolutionTypedSource<'_, '_>,
    definitions: &[SemanticId],
    receivers: Option<&[DeferredMemberReceiverType]>,
    cancellation: &CancellationToken,
) -> StoreResult<Option<Vec<bool>>> {
    let mut participation = vec![true; definitions.len()];
    if cancellation.is_cancelled() {
        return Ok(None);
    }
    let Some(receivers) = receivers.filter(|receivers| !receivers.is_empty()) else {
        return Ok(Some(participation));
    };
    let mut has_rust_candidate = false;
    for definition in definitions {
        if let Some(ordinal) = definition.ordinal() {
            has_rust_candidate |= source
                .selection
                .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?
                .semantic_language()
                == Language::Rust;
        }
    }
    if !has_rust_candidate {
        return Ok(Some(participation));
    }
    if !source.validate_selected_interiors(cancellation)? {
        return Ok(None);
    }
    for receiver in receivers {
        // Coherence: a workspace cannot add std's Deref to a primitive, or to
        // an external non-fundamental type. Fundamental wrapper projection
        // recursively exposes its payload, so Box<UserType> still requires
        // UserType's own crate census. Uncertified external heads stay open.
        if matches!(
            receiver.intrinsic_kind,
            Some(
                IntrinsicTypeKind::Primitive | IntrinsicTypeKind::Slice | IntrinsicTypeKind::Array
            )
        ) {
            continue;
        }
        let RustFragmentCoordinate::FragmentLocal((mount, key)) =
            rust_fragment_coordinate(&source.authority, receiver.identity, cancellation)?
        else {
            return Ok((!cancellation.is_cancelled()).then_some(participation));
        };
        let Some(closed) = source.read_statement(cancellation, |connection| {
            let mut statement = connection.prepare_cached(RECEIVER_CENSUS)?;
            let mut rows = statement.query(rusqlite::params![mount.get(), key])?;
            let mut found = false;
            while let Some(row) = rows.next()? {
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                found = true;
                if !row.get::<_, bool>(0)? {
                    return Ok(Some(false));
                }
            }
            Ok(Some(found))
        })?
        else {
            return Ok(None);
        };
        if !closed {
            return Ok(Some(participation));
        }
    }
    let receiver_ids = receivers
        .iter()
        .map(|receiver| receiver.identity)
        .collect::<BTreeSet<_>>();
    for (chunk_index, chunk) in definitions
        .chunks(MAX_TYPED_FACT_REQUESTS_PER_BATCH)
        .enumerate()
    {
        let mut requests = Vec::new();
        for (index, definition) in chunk.iter().copied().enumerate() {
            let RustFragmentCoordinate::FragmentLocal((mount, key)) =
                rust_fragment_coordinate(&source.authority, definition, cancellation)?
            else {
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                continue;
            };
            requests.push((index, mount.get(), key));
        }
        let requests =
            serde_json::to_string(&requests).expect("bounded declaration coordinates serialize");
        let Some(subjects) = source.read_statement(cancellation, |connection| {
            let mut statement = connection.prepare_cached(INHERENT_SUBJECTS)?;
            let mut rows = statement.query([&requests])?;
            let mut subjects = vec![(false, BTreeSet::new()); chunk.len()];
            while let Some(row) = rows.next()? {
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                let index: usize = row.get(0)?;
                let (unknown, identities) = &mut subjects[index];
                match (
                    row.get::<_, Option<i64>>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, Option<u32>>(3)?,
                    row.get::<_, Option<u32>>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                ) {
                    (Some(_), None, Some(mount), Some(key), Some(0..=2)) => {
                        let mount = source
                            .selection
                            .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(mount))?;
                        identities.insert(crate::analyzer::resolution::mounted_site_semantic(
                            mount.fragment_id(),
                            brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteId::new(
                                key,
                            ),
                        ));
                    }
                    _ => *unknown = true,
                }
            }
            Ok(Some(subjects))
        })?
        else {
            return Ok(None);
        };
        for (index, (unknown, subjects)) in subjects.into_iter().enumerate() {
            if !unknown && subjects.len() == 1 && subjects.is_disjoint(&receiver_ids) {
                participation[chunk_index * MAX_TYPED_FACT_REQUESTS_PER_BATCH + index] = false;
            }
        }
    }
    Ok((!cancellation.is_cancelled()).then_some(participation))
}
