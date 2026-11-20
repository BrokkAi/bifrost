//! Source-local candidates and selected authority for compiler-owned macro types.
use super::*;
use crate::analyzer::resolution::fact_source::ConditionalTypeProduction;
use brokk_bifrost_core::analyzer::resolution_facts::*;
use brokk_bifrost_rust::macro_matcher::{
    StandardMacroAuthority, StandardMacroIdentity, StandardMacroIdentityUnknown,
    StandardMacroResolution, certify_standard_macro,
};
use rusqlite::{Transaction, params};

/// The catalog key of one source type slot in a published blob. Every slot has
/// a catalog row, so a missing one is a publication defect, not an absence.
pub(super) fn catalog_slot_key(
    tx: &Transaction<'_>,
    blob: i64,
    slot: ResolutionTypeSlotId,
) -> Result<u32> {
    let identity = crate::analyzer::resolution::fact_lowering::type_slot_semantic_identity(slot);
    Ok(tx.prepare_cached("SELECT local_key FROM resolution_semantic_catalog WHERE blob_id=?1 AND identity_digest=?2")?.query_row(params![blob, identity.fragment_local_digest().as_slice()], |row| row.get(0))?)
}

pub fn publish(
    tx: &Transaction<'_>,
    blob: i64,
    facts: &FileResolutionFacts,
    cancellation: &CancellationToken,
) -> Result<()> {
    tx.prepare_cached("DELETE FROM resolution_macro_type_candidates WHERE blob_id=?1")?
        .execute([blob])?;
    let slot_key = |slot| catalog_slot_key(tx, blob, slot);
    for candidate in &facts.macro_type_candidates {
        if cancellation.is_cancelled() {
            return Ok(());
        }
        let output = slot_key(candidate.output)?;
        tx.prepare_cached("INSERT INTO resolution_macro_type_candidates(blob_id,output_slot,reference_site,invocation_site,element_count,segment_count,lexical_import_shadow) VALUES(?1,?2,?3,?4,?5,?6,?7)")?.execute(params![blob,output,candidate.reference.get(),candidate.site.get(),candidate.elements.len(),candidate.path.len(),candidate.lexical_import_shadow])?;
        for (ordinal, &element) in candidate.elements.iter().enumerate() {
            tx.prepare_cached("INSERT INTO resolution_macro_type_elements(blob_id,output_slot,ordinal,element_slot) VALUES(?1,?2,?3,?4)")?.execute(params![blob,output,ordinal,slot_key(element)?])?;
        }
        for (ordinal, segment) in candidate.path.iter().enumerate() {
            tx.prepare_cached("INSERT INTO resolution_macro_type_segments(blob_id,output_slot,ordinal,spelling) VALUES(?1,?2,?3,?4)")?.execute(params![blob,output,ordinal,segment])?;
        }
    }
    Ok(())
}

struct Authority {
    lexical_import_shadow: bool,
    closed_prelude: bool,
}
impl StandardMacroAuthority for Authority {
    fn resolution(&self) -> StandardMacroResolution<'_> {
        StandardMacroResolution::Unresolved
    }
    fn exact_is_locally_bound(&self) -> bool {
        false
    }
    fn lexical_shadow(&self, _: &str) -> Option<StandardMacroIdentity> {
        self.lexical_import_shadow
            .then_some(StandardMacroIdentity::Shadowed)
    }
    fn prelude_shadow(&self, _: &str) -> Option<StandardMacroIdentity> {
        (!self.closed_prelude).then_some(StandardMacroIdentity::Unknown(
            StandardMacroIdentityUnknown::Unresolved,
        ))
    }
    fn root_shadow(&self, _: &str) -> Option<StandardMacroIdentity> {
        Some(StandardMacroIdentity::Unknown(
            StandardMacroIdentityUnknown::Unresolved,
        ))
    }
}

#[expect(clippy::disallowed_methods, reason = "#12820: unmigrated answer read")]
pub fn productions(
    selection: &SelectedResolutionMountInventory<'_>,
    source: Option<&dyn super::super::language_support::SelectedTypeHeadSource>,
    slots: &[SemanticId],
    cancellation: &CancellationToken,
) -> Result<Vec<ConditionalTypeProduction>> {
    let conn = selection.connection();
    // SlotPrep retains these immutable rows (including absent candidates) and
    // only asks again for newly demanded slots. Page the request relation so
    // ordinary Rust slots without candidates cost one statement per page.
    let mut requested = Vec::new();
    for &slot in slots {
        let (Some(ordinal), Some(key)) = (slot.ordinal(), slot.local_key()) else {
            continue;
        };
        if ordinal as usize >= selection.persisted_mount_count() {
            continue;
        }
        let mount =
            selection.mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
        if mount.semantic_language() == Language::Rust {
            requested.push((ordinal, key, mount.blob_id()));
        }
    }
    let mut result = Vec::new();
    for page in requested.chunks(512) {
        if cancellation.is_cancelled() {
            return Ok(Vec::new());
        }
        let request = serde_json::json!(page).to_string();
        let candidates = conn
            .prepare_cached(
                "SELECT json_extract(request.value,'$[0]'), candidate.output_slot,
                    candidate.blob_id,candidate.reference_site,candidate.element_count,
                    candidate.segment_count,candidate.lexical_import_shadow
             FROM json_each(?1) request
             JOIN resolution_macro_type_candidates candidate
               ON candidate.blob_id=json_extract(request.value,'$[2]')
              AND candidate.output_slot=json_extract(request.value,'$[1]')",
            )?
            .query_map([request], |row| {
                Ok((
                    row.get::<_, u32>(0)?,
                    row.get::<_, u32>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, u32>(3)?,
                    row.get::<_, usize>(4)?,
                    row.get::<_, usize>(5)?,
                    row.get::<_, bool>(6)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (ordinal, key, blob, reference, element_count, segment_count, lexical_import_shadow) in
            candidates
        {
            if cancellation.is_cancelled() {
                return Ok(Vec::new());
            }
            let slot = SemanticId::local(ordinal, key);
            let segments = conn.prepare_cached("SELECT ordinal, spelling FROM resolution_macro_type_segments WHERE blob_id=?1 AND output_slot=?2 ORDER BY ordinal")?.query_map(params![blob,key],|row| Ok((row.get::<_,usize>(0)?,row.get::<_,String>(1)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
            let elements = conn.prepare_cached("SELECT ordinal, element_slot FROM resolution_macro_type_elements WHERE blob_id=?1 AND output_slot=?2 ORDER BY ordinal")?.query_map(params![blob,key],|row| Ok((row.get::<_,usize>(0)?,row.get::<_,u32>(1)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
            if segments.len() != segment_count
                || elements.len() != element_count
                || !segments
                    .iter()
                    .enumerate()
                    .all(|(expected, (ordinal, _))| expected == *ordinal)
                || !elements
                    .iter()
                    .enumerate()
                    .all(|(expected, (ordinal, _))| expected == *ordinal)
            {
                return Err(StoreError::corrupt(
                    "macro type candidate is missing source rows",
                ));
            }
            let segments = segments
                .into_iter()
                .map(|(_, segment)| segment)
                .collect::<Vec<_>>();
            let elements = elements
                .into_iter()
                .map(|(_, element)| element)
                .collect::<Vec<_>>();
            let [member] = segments.as_slice() else {
                continue;
            };
            // All selected placements must prove a closed macro lookup and std
            // prelude. No positive-root/partial-route exception is admitted here.
            if let Some(source) = source {
                let mount = selection
                    .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?;
                source.record_selected_derivation(
                    crate::analyzer::semantic::derivation::DerivationKindId(
                        "derivation:rust_file_units:v1",
                    ),
                    &crate::analyzer::semantic::derivation::DerivationQuestion {
                        language: Some(Language::Rust),
                        subject: None,
                        rel_path: Some(mount.persisted_relative_path().into()),
                        name: None,
                    },
                );
            }
            let placements = conn.prepare_cached("SELECT DISTINCT placement.topology_id,placement.container_path FROM resolution_rust_reference_contexts context JOIN selected_rust_container_placements placement ON placement.mount_ordinal=?1 AND placement.module_declaration IS context.module_declaration WHERE context.blob_id=?2 AND context.source_site=?3")?.query_map(params![ordinal,blob,reference],|row|Ok((row.get::<_,i64>(0)?,row.get::<_,String>(1)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
            let mut closed = !placements.is_empty();
            // Source lowering excludes visible local transcribers, including
            // unsupported arms; selected module lookup checks imported authorities.
            for (topology, path) in placements {
                // The same closure supplies macro-use providers and imported
                // macro targets. Certify every unit before consulting its rows.
                let roots = conn
                    .prepare_cached(
                        "SELECT unit_key FROM selected_rust_unit_summaries WHERE topology_id=?1",
                    )?
                    .query_map([topology], |row| row.get::<_, [u8; 32]>(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                let units = selection.rust_unit_closure_keys(&roots)?;
                assert!(
                    !units.is_empty(),
                    "a selected placement has its unit closure"
                );
                if let Some(source) = source {
                    for unit in units {
                        source.record_selected_derivation(
                            crate::analyzer::semantic::derivation::DerivationKindId(
                                "derivation:rust_unit_inputs:v3",
                            ),
                            &crate::analyzer::semantic::derivation::DerivationQuestion {
                                language: Some(Language::Rust),
                                subject: Some(unit),
                                rel_path: None,
                                name: None,
                            },
                        );
                    }
                }
                let complete = conn.prepare_cached("SELECT COALESCE(MIN(context.broad_complete),0) FROM selected_rust_unit_summaries unit JOIN main.rust_resolution_unit_summary_contexts context ON context.summary_id=unit.summary_id WHERE unit.topology_id=?1")?.query_row([topology],|row|row.get::<_,bool>(0))?;
                closed &= complete;
                let roots=conn.prepare_cached("SELECT DISTINCT member.blob_id FROM selected_rust_unit_summaries unit JOIN temp.rust_unit_summary_placements placement ON placement.summary_id=unit.summary_id AND placement.module_path='crate' JOIN temp.selected_unit_member_blobs member ON member.summary_id=placement.summary_id AND member.member_ordinal=placement.member_ordinal WHERE unit.topology_id=?1")?.query_map([topology],|row|row.get::<_,i64>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
                let [root] = roots.as_slice() else {
                    closed = false;
                    continue;
                };
                let suppressed=conn.prepare_cached("SELECT 1 FROM source_rust_inner_attributes WHERE blob_id=?1 AND name IN ('no_implicit_prelude','no_core','no_std','cfg_attr')")?.exists([root])?;
                closed &= !suppressed;
                let prelude = conn
                    .prepare_cached(super::rust_crate_context::TOPOLOGY_PRELUDE)?
                    .query_row([topology], |row| row.get::<_, String>(1))?;
                closed &= prelude == "std"
                    && super::rust_derive_helpers::helper_absent_from_macro_lookup(
                        conn, topology, &path, member,
                    )?;
            }
            let names = segments.iter().map(String::as_str).collect::<Vec<_>>();
            let head = matches!(certify_standard_macro(&names,&Authority{closed_prelude:closed,lexical_import_shadow}), StandardMacroIdentity::Standard{member,..} if member=="vec").then_some("alloc.vec.Vec");
            result.push(ConditionalTypeProduction {
                output: slot,
                elements: elements
                    .into_iter()
                    .map(|key| SemanticId::local(ordinal, key))
                    .collect(),
                head,
                language: Language::Rust,
            });
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::semantic::derivation::{DerivationKindId, DerivationQuestion};
    use crate::analyzer::store::language_support::SelectedTypeHeadSource;
    use crate::analyzer::store::resolution_selection::{
        SelectedResolutionLanguage, SelectedResolutionMountInventoryOutcome,
    };
    use crate::analyzer::store::{AnalyzerStore, WorkspaceSnapshotId};
    use std::cell::RefCell;

    #[test]
    #[expect(
        clippy::disallowed_methods,
        reason = "#12820: non-answer (writer, schema, GC or diagnostics); must not produce answers"
    )]
    fn macro_certification_records_empty_file_units_before_new_placement() {
        let (store, workspace, snapshots) =
            crate::analyzer::store::resolution_selection::tests::qualifier_completion_gap_fixture_in_language(
                AnalyzerStore::open_ephemeral().unwrap(), Language::Rust,
            );
        let snapshot = snapshots["rust"].clone();
        let writer_snapshot = snapshot.clone();
        store.conn.execute(move |conn| {
            let _fixture = crate::analyzer::store::sealed_families::Fixture::new(conn);
            let blob: i64 = conn.query_row("SELECT id FROM blobs WHERE lang='rust'", [], |row| row.get(0)).unwrap();
            conn.execute("INSERT INTO source_fact_manifests(blob_id,facts_version,source_bytes,occurrence_count,declaration_count,declaration_unit_count,node_count,role_count,occurrence_role_count,logical_rows,payload_bytes,publication_state) VALUES(?1,1,0,0,0,0,0,0,0,1,0,'building')", [blob]).unwrap();
            conn.execute("INSERT INTO source_rust_module_manifests VALUES(0,?1,1,0,0,0)", [blob]).unwrap();
            conn.execute("INSERT INTO source_rust_module_scopes VALUES(?1,0,NULL,NULL,'',1,NULL)", [blob]).unwrap();
            conn.execute("INSERT INTO source_rust_module_inventory VALUES(?1,0,0,NULL,'')", [blob]).unwrap();
            conn.execute("INSERT INTO source_rust_item_manifests VALUES(?1,2,4,0,1,1,1)", [blob]).unwrap();
            conn.execute("INSERT INTO source_rust_item_syntax VALUES(?1,0,0)", [blob]).unwrap();
            conn.execute("INSERT INTO source_rust_item_contexts VALUES(?1,0,0,NULL,NULL,0,0,0,0,NULL)", [blob]).unwrap();
            conn.execute("INSERT INTO source_rust_impl_census_files VALUES(?1,1,0,0,1)", [blob]).unwrap();
            conn.execute("UPDATE source_fact_manifests SET publication_state='complete' WHERE blob_id=?1", [blob]).unwrap();
            conn.execute("INSERT INTO rust_crate_topologies(topology_id,topology_digest,crate_key,producer_epoch,target_kind,crate_name,edition,prelude,cfg_atoms,inventory_complete,export_surface_digest,publication_state,broad_complete) VALUES(1,zeroblob(32),zeroblob(32),'fixture','lib','fixture','2021','std',jsonb('[]'),1,zeroblob(32),'complete',1)", []).unwrap();
            conn.execute("INSERT INTO resolution_unit_summaries(summary_id,lang,unit_kind,unit_key,summary_digest,producer_epoch,derivation_identity,complete,output_digest,publication_state) VALUES(1,'rust','rust_crate',zeroblob(32),zeroblob(32),(SELECT producer_epoch FROM resolution_producer_epochs WHERE lang='rust'),?1,1,zeroblob(32),'complete')", [crate::analyzer::store::rust_unit_summaries::rust_unit_summary_derivation_identity()]).unwrap();
            conn.execute("INSERT INTO resolution_unit_summary_versions(workspace_id,lang,generation,unit_key,valid_from,summary_id) VALUES(?1,'rust',?2,zeroblob(32),1,1)", params![writer_snapshot.workspace_id.as_str(),writer_snapshot.generation.0]).unwrap();
            conn.execute("INSERT INTO rust_resolution_unit_summary_versions(workspace_id,lang,generation,unit_key,valid_from,summary_id,topology_id) VALUES(?1,'rust',?2,zeroblob(32),1,1,1)", params![writer_snapshot.workspace_id.as_str(),writer_snapshot.generation.0]).unwrap();
            conn.execute("INSERT INTO rust_resolution_unit_summary_contexts VALUES(1,'lib','fixture','2021','std',jsonb('[]'),1,0,1)", []).unwrap();
            conn.execute("INSERT INTO resolution_unit_summary_members(summary_id,member_ordinal,blob_id,rel_path,source_role) VALUES(1,0,?1,'fixture.rust','source')", [blob]).unwrap();
        });
        let selection = match store
            .open_selected_resolution_mount_inventory(
                &workspace,
                &snapshots,
                &[SelectedResolutionLanguage::new("rust", Language::Rust)],
                &[],
                &CancellationToken::new(),
            )
            .unwrap()
        {
            SelectedResolutionMountInventoryOutcome::Ready(selection) => selection,
            SelectedResolutionMountInventoryOutcome::Unavailable(reason) => {
                panic!("unavailable: {reason:?}")
            }
            SelectedResolutionMountInventoryOutcome::Stale(reason) => panic!("stale: {reason:?}"),
            SelectedResolutionMountInventoryOutcome::Cancelled => panic!("cancelled"),
        };
        let conn = selection.connection();
        let mount = selection
            .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(0))
            .unwrap();
        let blob = mount.blob_id();
        // These TEMP fixtures deliberately bypass product reachability: normal
        // orphan/cfg files retain membership, while unplacing overlays stop
        // before macro certification. The empty recording is defensive.
        conn.execute_batch("CREATE TEMP TABLE macro_attachments AS SELECT * FROM selected_unit_member_blobs LIMIT 0;
            DROP VIEW selected_unit_member_blobs;
            CREATE TEMP TABLE selected_unit_member_blobs AS SELECT * FROM macro_attachments;
            DROP TABLE macro_attachments;
            CREATE TEMP TABLE macro_placements AS SELECT * FROM rust_unit_summary_placements LIMIT 0;
            DROP VIEW rust_unit_summary_placements;
            CREATE TEMP TABLE rust_unit_summary_placements AS SELECT * FROM macro_placements;
            DROP TABLE macro_placements;
            DROP VIEW IF EXISTS selected_rust_container_placements;
            CREATE TEMP TABLE selected_rust_container_placements(mount_ordinal,blob_id,scope_ordinal,module_declaration,topology_id,unit_key,summary_id,member_ordinal,container_path,placement_blob);
            CREATE TEMP TABLE resolution_macro_type_candidates(blob_id,output_slot,reference_site,element_count,segment_count,lexical_import_shadow);
            CREATE TEMP TABLE resolution_macro_type_segments(blob_id,output_slot,ordinal,spelling);
            CREATE TEMP TABLE resolution_macro_type_elements(blob_id,output_slot,ordinal,element_slot);
            CREATE TEMP TABLE resolution_rust_reference_contexts AS SELECT * FROM main.resolution_rust_reference_contexts LIMIT 0;").unwrap();
        conn.execute(
            "INSERT INTO resolution_macro_type_candidates VALUES(?1,0,0,0,1,0)",
            [blob],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO resolution_macro_type_segments VALUES(?1,0,0,'vec')",
            [blob],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO resolution_rust_reference_contexts VALUES(?1,0,0,0,0,NULL,jsonb('[]'))",
            [blob],
        )
        .unwrap();

        type MembershipRead = (DerivationKindId, DerivationQuestion, Vec<[u8; 32]>);
        struct Receipt<'a> {
            conn: &'a rusqlite::Connection,
            snapshot: &'a WorkspaceSnapshotId,
            keys: RefCell<Vec<MembershipRead>>,
        }
        impl SelectedTypeHeadSource for Receipt<'_> {
            fn named_reason(&self, _: SemanticId) -> Option<(&'static str, std::sync::Arc<str>)> {
                unreachable!("macro certification only records derivations")
            }
            fn cached_external_type_import_paths(&self, _: SemanticId) -> Vec<Vec<String>> {
                unreachable!("macro certification only records derivations")
            }
            fn external_type_import_path(&mut self, _: SemanticId) -> Result<Option<Vec<String>>> {
                unreachable!("macro certification only records derivations")
            }

            fn record_selected_derivation(
                &self,
                kind: DerivationKindId,
                question: &DerivationQuestion,
            ) {
                if kind.0 == "derivation:rust_file_units:v1" {
                    let answer = crate::analyzer::store::rust_unit_summaries::rust_file_units(
                        self.conn,
                        self.snapshot,
                        question.rel_path.as_deref().unwrap(),
                    )
                    .unwrap();
                    self.keys
                        .borrow_mut()
                        .push((kind, question.clone(), answer));
                }
            }
        }
        let receipt = Receipt {
            conn,
            snapshot: &snapshot,
            keys: RefCell::new(Vec::new()),
        };
        let slots = [SemanticId::local(0, 0)];
        let empty = productions(
            &selection,
            Some(&receipt),
            &slots,
            &CancellationToken::new(),
        )
        .unwrap();
        assert_eq!(empty.len(), 1);
        assert_eq!(empty[0].head, None);
        let keys = receipt.keys.borrow();
        let [(kind, question, answer)] = keys.as_slice() else {
            panic!("{keys:?}")
        };
        assert_eq!(kind.0, "derivation:rust_file_units:v1");
        assert_eq!(question.language, Some(Language::Rust));
        assert_eq!(question.rel_path.as_deref(), Some("fixture.rust"));
        assert!(question.subject.is_none() && question.name.is_none());
        assert!(answer.is_empty());
        // A new selected target attaches and places the previously unplaced file.
        conn.execute("INSERT INTO selected_unit_member_blobs(summary_id,member_ordinal,rel_path,blob_id) VALUES(1,0,'fixture.rust',?1)", [blob]).unwrap();
        conn.execute("INSERT INTO rust_unit_summary_placements(summary_id,member_ordinal,module_path) VALUES(1,0,'crate')", []).unwrap();
        conn.execute(
            "INSERT INTO selected_rust_container_placements(mount_ordinal,topology_id,container_path,module_declaration) VALUES(0,1,'crate',NULL)",
            [],
        )
        .unwrap();
        let verified = crate::analyzer::store::rust_unit_summaries::rust_file_units(
            conn,
            &snapshot,
            question.rel_path.as_deref().unwrap(),
        )
        .unwrap();
        assert_ne!(
            &verified, answer,
            "the earlier membership receipt must reject reuse"
        );
        assert_eq!(verified, vec![[0; 32]]);
        drop(keys);
        let placed = productions(
            &selection,
            Some(&receipt),
            &slots,
            &CancellationToken::new(),
        )
        .unwrap();
        assert_eq!(placed.len(), 1);
        assert_eq!(placed[0].head, Some("alloc.vec.Vec"));
        assert_eq!(receipt.keys.borrow().last().unwrap().2, verified);
    }
}
