//! Atomic one-producer projection entry points used by the selected operation.

use super::{SelectedResolutionStage, SelectedResolutionStageOutcome, coordinates, lexical, typed};
use crate::CancellationToken;
use crate::analyzer::Language;
use crate::analyzer::resolution::{
    LoweredResolutionFactsWithIdentityCatalog, LoweredResolutionFragment,
    ResolutionIdentityCatalog, ResolutionLookupSemanticRecipe, SemanticId,
};
use crate::analyzer::store::resolution::with_resolution_read_progress_handler;
use crate::analyzer::store::resolution_prepare::resolution_rows::{language_code, namespace_code};
use crate::analyzer::store::resolution_publication::{
    CapsuleArtifactVerification, PublishedResolutionContent, verify_capsule_artifact,
};
use crate::analyzer::store::resolution_selection::{
    SelectedResolutionMountRecord, SelectedResolutionTempTransaction,
};
use crate::analyzer::store::{Result, StoreError};
use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
use rusqlite::{OptionalExtension, params};
use serde_json::json;

pub(in crate::analyzer::store) const CAPSULE_MEMBERSHIP_SQL: &str = "SELECT EXISTS(SELECT 1 FROM temp.selected_resolution_mounts mount CROSS JOIN temp.selected_resolution_admissions admission ON admission.workspace_id=mount.workspace_id AND admission.storage_language=mount.storage_language AND admission.generation=mount.generation AND admission.revision=mount.revision AND admission.host_content_oid=mount.blob_oid AND admission.invocation=?2 AND admission.input_kind=1 CROSS JOIN temp.selected_resolution_stage_producers producer ON producer.host_ordinal=mount.mount_ordinal AND producer.admission_id=admission.admission_id AND producer.admission_id IS NOT NULL WHERE mount.mount_ordinal=?1)";

impl SelectedResolutionStage<'_, '_> {
    pub(crate) fn has_admitted_macro_input(
        &self,
        host: crate::analyzer::resolution::SelectedResolutionMountOrdinal,
        invocation: brokk_bifrost_core::analyzer::source_facts::SourceOccurrenceId,
        cancellation: &CancellationToken,
    ) -> Result<Option<bool>> {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let result = with_resolution_read_progress_handler(
            self.selection.connection(),
            cancellation,
            |connection| {
                let admitted = connection
                    .prepare_cached(CAPSULE_MEMBERSHIP_SQL)?
                    .query_row(params![host.get(), invocation.get()], |row| {
                        row.get::<_, bool>(0)
                    })?;
                Ok((!cancellation.is_cancelled()).then_some(admitted))
            },
        );
        match result {
            Err(error) if error.is_sqlite_interrupted() && cancellation.is_cancelled() => Ok(None),
            result => result,
        }
    }

    /// Admit one published capsule into the stage.
    ///
    /// `definition_names` gives each definition the capsule lowered the byte
    /// range of its name, in the host file's coordinates (a capsule parses its
    /// invocation at the host's offsets). Lowering publishes a range only for
    /// a reference site, and the stage records these on the capsule's own
    /// definition rows so that a crate-declared macro item
    /// (`rust_crate_macro_items`), whose declaration replay recorded at the
    /// same range, can be found and projected to its `CodeUnit`.
    pub(crate) fn admit_capsule(
        &self,
        content: PublishedResolutionContent,
        host: &SelectedResolutionMountRecord,
        dense: LoweredResolutionFactsWithIdentityCatalog,
        definition_names: &[(
            brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteId,
            usize,
            usize,
        )],
        cancellation: &CancellationToken,
    ) -> Result<SelectedResolutionStageOutcome> {
        // Verify before consuming retarget, including exact-repeat admissions.
        // The caller cannot attach a different assigned body to a valid receipt.
        match verify_capsule_artifact(
            self.selection.connection(),
            content.witness(),
            &dense,
            cancellation,
        )? {
            CapsuleArtifactVerification::Verified => {}
            CapsuleArtifactVerification::Cancelled => {
                return Ok(SelectedResolutionStageOutcome::Cancelled);
            }
            CapsuleArtifactVerification::Mismatch => {
                return Err(StoreError::new(
                    "capsule artifact does not match its published witness",
                ));
            }
        }
        self.with_capsule_admission(
            content,
            host,
            dense,
            cancellation,
            |connection, producer, assigned| {
                let Some(lexical) =
                    lexical::prepare_lexical_fragment(assigned.lexical(), cancellation)
                else {
                    return Ok(false);
                };
                if !lexical.validate_ordinary_paths(self.selection, cancellation)?
                    || !lexical.validate_ordinary_nodes(self.selection, cancellation)?
                    || !lexical.insert(connection, producer, host.ordinal(), cancellation)?
                {
                    return Ok(false);
                }
                let mut name = connection.prepare_cached(
                    "UPDATE temp.selected_resolution_stage_semantics SET start_byte=?1,end_byte=?2 WHERE host_ordinal=?3 AND source_site=?4 AND role=?5 AND producer_id=?6",
                )?;
                for &(site, start, end) in definition_names {
                    name.execute(params![
                        i64::try_from(start).expect("source byte offset fits SQLite integer"),
                        i64::try_from(end).expect("source byte offset fits SQLite integer"),
                        host.ordinal().get(),
                        site.get(),
                        crate::analyzer::store::resolution_prepare::resolution_rows::semantic_role_code(
                            crate::analyzer::resolution::LoweredSemanticRole::Definition
                        ),
                        producer
                    ])?;
                }
                drop(name);
                typed::insert_typed_fragment(
                    connection,
                    producer,
                    host.ordinal(),
                    assigned.typed(),
                    cancellation,
                )
            },
        )
    }

    /// A generated lexical bridge may have runtime authority without producer
    /// descriptors. No identity is manufactured when its catalog is absent.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn insert_generated_bridge(
        &self,
        host: &SelectedResolutionMountRecord,
        bridge_identity: [u8; 32],
        lexical_fragment: &LoweredResolutionFragment,
        assigned: Option<&ResolutionIdentityCatalog>,
        recipes: &[(SemanticId, ResolutionLookupSemanticRecipe)],
        closed_reasons: &[SemanticId],
        cancellation: &CancellationToken,
    ) -> Result<SelectedResolutionStageOutcome> {
        Ok(
            match self.with_generated_admission(cancellation, |connection| {
                Ok(self
                    .project_generated_bridge(
                        connection,
                        host,
                        bridge_identity,
                        lexical_fragment,
                        assigned,
                        recipes,
                        closed_reasons,
                        cancellation,
                    )?
                    .map(|changed| ((), changed)))
            })? {
                Some(()) => SelectedResolutionStageOutcome::Ready,
                None => SelectedResolutionStageOutcome::Cancelled,
            },
        )
    }

    pub(super) fn with_generated_admission<T>(
        &self,
        cancellation: &CancellationToken,
        project: impl FnOnce(&rusqlite::Connection) -> Result<Option<(T, bool)>>,
    ) -> Result<Option<T>> {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        self.selection.mark_stage_used();
        let committed = self.selection.with_owned_temp_transaction(|connection| {
            let result =
                with_resolution_read_progress_handler(connection, cancellation, |connection| {
                    Ok(match project(connection)? {
                        Some(value) if !cancellation.is_cancelled() => {
                            SelectedResolutionTempTransaction::Commit(Some(value))
                        }
                        _ => SelectedResolutionTempTransaction::Rollback(None),
                    })
                });
            match result {
                Err(error) if error.is_sqlite_interrupted() && cancellation.is_cancelled() => {
                    Ok(SelectedResolutionTempTransaction::Rollback(None))
                }
                result => result,
            }
        })?;
        Ok(committed.map(|(value, changed)| {
            if changed {
                self.selection.note_stage_content_commit();
            }
            value
        }))
    }

    /// The caller owns the transaction, including any coordinate reservations.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn project_generated_bridge(
        &self,
        connection: &rusqlite::Connection,
        host: &SelectedResolutionMountRecord,
        bridge_identity: [u8; 32],
        lexical_fragment: &LoweredResolutionFragment,
        assigned: Option<&ResolutionIdentityCatalog>,
        recipes: &[(SemanticId, ResolutionLookupSemanticRecipe)],
        closed_reasons: &[SemanticId],
        cancellation: &CancellationToken,
    ) -> Result<Option<bool>> {
        assert!(!connection.is_autocommit());
        assert_eq!(lexical_fragment.fragment().ordinal(), host.ordinal().get());
        let Some(lexical) = lexical::prepare_lexical_fragment(lexical_fragment, cancellation)
        else {
            return Ok(None);
        };
        let coordinates = match assigned {
            Some(assigned) => {
                assert_eq!(assigned.fragment(), lexical_fragment.fragment());
                let Some(coordinates) =
                    coordinates::PreparedStageCoordinates::new(assigned, &[], cancellation)
                else {
                    return Ok(None);
                };
                Some(coordinates)
            }
            None => None,
        };
        let mut recipe_rows = Vec::with_capacity(recipes.len());
        for (semantic, recipe) in recipes {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let (key, shared) = lexical::semantic_cells(*semantic);
            let language = Language::from_config_label(recipe.semantic_language())
                .expect("a generated recipe has a configured semantic language");
            recipe_rows.push(json!([
                key,
                shared,
                language_code(language),
                namespace_code(recipe.namespace()),
                recipe.spelling()
            ]));
        }
        let recipe_rows = serde_json::to_string(&recipe_rows).expect("bridge recipe parameters");
        let mut reason_rows = Vec::with_capacity(closed_reasons.len());
        for &reason in closed_reasons {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let (key, shared) = lexical::semantic_cells(reason);
            reason_rows.push(json!([key, shared]));
        }
        let reason_rows = serde_json::to_string(&reason_rows).expect("bridge closure parameters");
        let mut descriptor = CanonicalHasher::new(b"bifrost-selected-stage-bridge:v1");
        descriptor.field("lexical", &lexical.digest());
        descriptor.field("catalog-present", &[u8::from(coordinates.is_some())]);
        if let Some(coordinates) = &coordinates {
            descriptor.field("coordinates", &coordinates.digest());
        }
        descriptor.field("recipes", recipe_rows.as_bytes());
        descriptor.field("closed-reasons", reason_rows.as_bytes());
        let descriptor = descriptor.finish();
        let previous = connection.prepare_cached(
                    "SELECT producer_id,content_digest FROM temp.selected_resolution_stage_producers WHERE host_ordinal=?1 AND bridge_identity=?2",
                )?.query_row(params![host.ordinal().get(),bridge_identity], |row| {
                    Ok((row.get::<_,i64>(0)?,row.get::<_,[u8;32]>(1)?))
                }).optional()?;
        if let Some((producer, previous)) = previous {
            if previous != descriptor {
                return Err(StoreError::new(
                    "repeated generated bridge changed its complete descriptor",
                ));
            }
            if let Some(coordinates) = &coordinates
                && !coordinates.agrees(connection, producer)?
            {
                return Err(StoreError::new(
                    "repeated generated bridge changed its assigned coordinates",
                ));
            }
            return Ok((!cancellation.is_cancelled()).then_some(false));
        }
        connection.prepare_cached("INSERT INTO temp.selected_resolution_stage_producers(host_ordinal,bridge_identity,content_digest) VALUES(?1,?2,?3)")?.execute(params![host.ordinal().get(),bridge_identity,descriptor])?;
        let producer = connection.last_insert_rowid();
        let content_before = connection.total_changes();
        if let Some(coordinates) = &coordinates {
            coordinates.insert(connection, producer, host.ordinal())?;
        }
        if !lexical.validate_ordinary_paths(self.selection, cancellation)?
            || !lexical.validate_ordinary_nodes(self.selection, cancellation)?
            || !lexical.insert(connection, producer, host.ordinal(), cancellation)?
        {
            return Ok(None);
        }
        connection.prepare_cached("INSERT INTO temp.selected_resolution_stage_recipes(host_ordinal,producer_id,semantic_key,semantic_shared,semantic_language,namespace,spelling) SELECT ?1,?2,value->>0,value->>1,value->>2,value->>3,value->>4 FROM json_each(?3)")?.execute(params![host.ordinal().get(),producer,recipe_rows])?;
        connection.prepare_cached("INSERT INTO temp.selected_resolution_stage_closed_reasons(producer_id,semantic_key,semantic_shared) SELECT DISTINCT ?1,value->>0,value->>1 FROM json_each(?2)")?.execute(params![producer,reason_rows])?;
        Ok((!cancellation.is_cancelled()).then(|| connection.total_changes() != content_before))
    }
}

#[cfg(test)]
#[path = "projection_tests.rs"]
mod tests;
