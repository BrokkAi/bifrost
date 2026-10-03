//! Complete content publication and captured revision ownership.

use git2::{ObjectType, Oid};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};

use brokk_bifrost_core::analyzer::model::DeclarationKind;
use brokk_bifrost_core::analyzer::resolution_facts::{ResolutionScopeId, ResolutionSiteId};
use brokk_bifrost_core::analyzer::source_facts::{SourceDeclarationId, SourceOccurrenceId};
use brokk_bifrost_core::analyzer::{Range, canonical_hash::CanonicalHasher};

use crate::CancellationToken;
use crate::analyzer::resolution::ResolutionLocalKey;
use crate::analyzer::resolution::SharedNameId;

use super::resolution::{PreparedResolutionBundle, ResolutionManifestCounts};
use super::resolution_selection::{SelectedResolutionStale, SelectedResolutionUnavailable};
use super::{AnalyzerStore, PreparedParsedBlob, Result, WorkspaceSnapshotId};

#[derive(Debug)]
pub(crate) enum SelectedResolutionOverlayInputsOutcome {
    Ready {
        masks: Vec<super::resolution_selection::SelectedResolutionOverlayMask>,
        content_mounts: Vec<super::resolution_selection::SelectedResolutionContentMountRequest>,
    },
    Cancelled,
    Stale(SelectedResolutionStale),
    Unavailable(SelectedResolutionUnavailable),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ResolutionCapsuleKey {
    pub(crate) host_content_oid: Oid,
    pub(crate) invocation: SourceOccurrenceId,
    pub(crate) definition_content_oid: Oid,
    pub(crate) selected_declaration: SourceDeclarationId,
    pub(crate) matched_arm_index: usize,
    pub(crate) producer_epoch: String,
}

impl ResolutionCapsuleKey {
    pub(crate) fn digest(&self) -> [u8; 32] {
        let mut hash = CanonicalHasher::new(b"bifrost-resolution-capsule-content:v1");
        hash.field("host_content_oid", self.host_content_oid.as_bytes());
        hash.field("invocation", &self.invocation.get().to_be_bytes());
        hash.field(
            "definition_content_oid",
            self.definition_content_oid.as_bytes(),
        );
        hash.field(
            "selected_declaration",
            &self.selected_declaration.get().to_be_bytes(),
        );
        hash.field(
            "matched_arm_index",
            &u64::try_from(self.matched_arm_index)
                .expect("a matched arm index fits u64")
                .to_be_bytes(),
        );
        hash.field("producer_epoch", self.producer_epoch.as_bytes());
        hash.finish()
    }

    pub(crate) fn content_oid(&self) -> Result<Oid> {
        Oid::hash_object(ObjectType::Blob, &self.digest()).map_err(|error| {
            super::StoreError::new(format!("hash resolution capsule content: {error}"))
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ResolutionContentInput {
    Parsed {
        content_oid: Oid,
        semantic_language: super::Language,
    },
    Capsule {
        key: ResolutionCapsuleKey,
        checkpoint_digest: [u8; 32],
        host_module_scope: ResolutionScopeId,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ResolutionContentWitness {
    owner: WorkspaceSnapshotId,
    blob_id: i64,
    blob_oid: Oid,
    manifest_digest: [u8; 32],
    manifest_counts: ResolutionManifestCounts,
    producer_epoch: String,
    logical_rows: u64,
    payload_bytes: u64,
    input: ResolutionContentInput,
}

impl ResolutionContentWitness {
    pub(crate) fn owner(&self) -> &WorkspaceSnapshotId {
        &self.owner
    }
    pub(crate) const fn blob_id(&self) -> i64 {
        self.blob_id
    }
    pub(crate) const fn blob_oid(&self) -> Oid {
        self.blob_oid
    }
    pub(crate) const fn manifest_digest(&self) -> [u8; 32] {
        self.manifest_digest
    }
    pub(crate) fn manifest_counts(&self) -> &ResolutionManifestCounts {
        &self.manifest_counts
    }
    pub(crate) fn producer_epoch(&self) -> &str {
        &self.producer_epoch
    }
    pub(crate) const fn logical_rows(&self) -> u64 {
        self.logical_rows
    }
    pub(crate) const fn payload_bytes(&self) -> u64 {
        self.payload_bytes
    }
    pub(crate) fn input(&self) -> &ResolutionContentInput {
        &self.input
    }
}

#[derive(Debug)]
pub(crate) struct PublishedResolutionContent {
    witness: ResolutionContentWitness,
    membership: Vec<([u8; 32], SharedNameId)>,
}

impl PublishedResolutionContent {
    pub(crate) fn witness(&self) -> &ResolutionContentWitness {
        &self.witness
    }
    pub(crate) fn into_parts(self) -> (ResolutionContentWitness, Vec<([u8; 32], SharedNameId)>) {
        (self.witness, self.membership)
    }
}

#[derive(Debug)]
pub(crate) enum ResolutionContentPublicationOutcome {
    Ready(Box<PublishedResolutionContent>),
    Cancelled,
    Stale(SelectedResolutionStale),
    Unavailable(SelectedResolutionUnavailable),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ResolutionCapsuleDeclarationPresentation {
    pub(crate) semantic_key: ResolutionLocalKey,
    pub(crate) identifier: String,
    pub(crate) kind: DeclarationKind,
    pub(crate) name_range: Range,
    pub(crate) declaration_range: Range,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ResolutionCapsuleReferenceOwner {
    Unknown,
    Root,
    HostLocal(ResolutionLocalKey),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ResolutionCapsuleReferenceContext {
    pub(crate) semantic_key: ResolutionLocalKey,
    pub(crate) source_site: ResolutionSiteId,
    pub(crate) host_occurrence: SourceOccurrenceId,
    pub(crate) module_context: SourceOccurrenceId,
    pub(crate) module_declaration: Option<SourceDeclarationId>,
    pub(crate) reference_owner: ResolutionCapsuleReferenceOwner,
}

#[derive(Debug)]
pub(crate) struct PreparedResolutionCapsule {
    input: ResolutionContentInput,
    bundle: PreparedResolutionBundle,
    declarations: Vec<ResolutionCapsuleDeclarationPresentation>,
    references: Vec<ResolutionCapsuleReferenceContext>,
}

/// A same-generation parent repair cascades roots immediately even when foreign
/// keys are deferred. Capture all extant owners of this one blob before DELETE.
pub(super) fn repair_owners_tx(
    tx: &Transaction<'_>,
    oid: &str,
    lang: &str,
    generation: super::GenerationId,
    cancellation: &CancellationToken,
) -> Result<Option<Vec<WorkspaceSnapshotId>>> {
    let mut statement = tx.prepare_cached(
        "SELECT roots.workspace_id, roots.lang, roots.generation, roots.revision
         FROM blobs AS blob
         JOIN workspace_resolution_content_roots AS roots ON roots.blob_id = blob.id
         JOIN workspace_revisions AS revision
           ON revision.workspace_id = roots.workspace_id AND revision.lang = roots.lang
          AND revision.generation = roots.generation AND revision.revision = roots.revision
         LEFT JOIN analysis_epochs AS epoch ON epoch.lang = blob.lang
         WHERE blob.blob_oid = ?1 AND blob.lang = ?2 AND blob.generation = ?3
           AND roots.lang = blob.lang AND roots.generation = blob.generation
           AND COALESCE(epoch.generation, 0) = blob.generation",
    )?;
    let rows = statement.query_map(params![oid, lang, generation.0], |row| {
        Ok(WorkspaceSnapshotId {
            workspace_id: super::WorkspaceId(row.get(0)?),
            lang: row.get(1)?,
            generation: super::GenerationId(row.get(2)?),
            revision: row.get(3)?,
        })
    })?;
    let mut owners = Vec::new();
    for row in rows {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        owners.push(row?);
    }
    Ok(Some(owners))
}

pub(super) fn root_content_tx(
    tx: &Transaction<'_>,
    owner: &WorkspaceSnapshotId,
    blob_id: i64,
) -> Result<()> {
    let inserted = tx
        .prepare_cached(
            "INSERT INTO workspace_resolution_content_roots(
           workspace_id, lang, generation, revision, blob_id
         ) VALUES(?1, ?2, ?3, ?4, ?5) ON CONFLICT DO NOTHING",
        )?
        .execute(params![
            owner.workspace_id.as_str(),
            owner.lang,
            owner.generation.0,
            owner.revision,
            blob_id
        ])?;
    if inserted != 0 {
        tx.prepare_cached(
            "UPDATE blobs SET cascade_logical_rows = NULL, cascade_payload_bytes = NULL
             WHERE id = ?1",
        )?
        .execute([blob_id])?;
    }
    Ok(())
}

pub(super) fn validate_owner_conn(
    tx: &rusqlite::Connection,
    owner: &WorkspaceSnapshotId,
    expected_epoch: &str,
) -> Result<Option<ResolutionContentPublicationOutcome>> {
    let generation = super::current_generation_conn(tx, &owner.lang)?;
    if generation != owner.generation {
        return Ok(Some(ResolutionContentPublicationOutcome::Stale(
            SelectedResolutionStale::AnalysisGeneration {
                storage_language: owner.lang.clone(),
            },
        )));
    }
    let epoch: Option<String> = tx
        .query_row(
            "SELECT producer_epoch FROM resolution_producer_epochs WHERE lang = ?1",
            [&owner.lang],
            |row| row.get(0),
        )
        .optional()?;
    if epoch.as_deref() != Some(expected_epoch) {
        return Ok(Some(ResolutionContentPublicationOutcome::Stale(
            SelectedResolutionStale::ProducerEpoch {
                storage_language: owner.lang.clone(),
            },
        )));
    }
    let extant: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM workspace_revisions
         WHERE workspace_id = ?1 AND lang = ?2 AND generation = ?3 AND revision = ?4)",
        params![
            owner.workspace_id.as_str(),
            owner.lang,
            owner.generation.0,
            owner.revision
        ],
        |row| row.get(0),
    )?;
    if !extant {
        return Ok(Some(ResolutionContentPublicationOutcome::Stale(
            SelectedResolutionStale::WorkspaceRevision {
                storage_language: owner.lang.clone(),
            },
        )));
    }
    Ok(None)
}

fn publication_receipt_tx(
    tx: &Transaction<'_>,
    owner: &WorkspaceSnapshotId,
    blob_id: i64,
    blob_oid: Oid,
    input: ResolutionContentInput,
    cancellation: &CancellationToken,
) -> Result<Option<PublishedResolutionContent>> {
    let columns = super::resolution::RESOLUTION_MANIFEST_COUNT_COLUMNS.join(", ");
    let sql = format!(
        "SELECT interior_digest, producer_epoch, logical_rows, payload_bytes, {columns}
         FROM resolution_fragment_interiors WHERE blob_id = ?1 AND publication_state = 'complete'"
    );
    let witness = tx.prepare_cached(&sql)?.query_row([blob_id], |row| {
        let mut counts = [0; super::resolution::RESOLUTION_MANIFEST_COUNT_COLUMNS.len()];
        for (index, count) in counts.iter_mut().enumerate() {
            *count = row.get(index + 4)?;
        }
        Ok(ResolutionContentWitness {
            owner: owner.clone(),
            blob_id,
            blob_oid,
            manifest_digest: row.get(0)?,
            producer_epoch: row.get(1)?,
            logical_rows: row.get(2)?,
            payload_bytes: row.get(3)?,
            manifest_counts: ResolutionManifestCounts::from_array(counts),
            input,
        })
    })?;
    let mut statement = tx.prepare_cached(
        "SELECT identities.identity_digest, identities.id
         FROM resolution_semantic_catalog AS catalog
         JOIN resolution_identities AS identities ON identities.id = catalog.shared_identity
         WHERE catalog.blob_id = ?1 AND catalog.shared_identity IS NOT NULL",
    )?;
    let rows = statement.query_map([blob_id], |row| {
        Ok((row.get(0)?, SharedNameId::interned(row.get(1)?)))
    })?;
    let mut membership = Vec::new();
    for row in rows {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        membership.push(row?);
    }
    Ok(Some(PublishedResolutionContent {
        witness,
        membership,
    }))
}

impl AnalyzerStore {
    pub(crate) fn publish_selected_parsed_content(
        &self,
        owner: &WorkspaceSnapshotId,
        persisted_relative_path: &str,
        prepared: PreparedParsedBlob,
        cancellation: &CancellationToken,
    ) -> Result<ResolutionContentPublicationOutcome> {
        let owner = owner.clone();
        let path = persisted_relative_path.to_owned();
        let cancellation = cancellation.clone();
        self.conn.execute(move |conn| {
            let result =
                super::resolution::with_resolution_progress_handler(conn, &cancellation, |conn| {
                    if cancellation.is_cancelled() {
                        return Ok(ResolutionContentPublicationOutcome::Cancelled);
                    }
                    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
                    if let Some(outcome) =
                        validate_owner_conn(&tx, &owner, prepared.resolution.producer_epoch())?
                    {
                        return Ok(outcome);
                    }
                    if prepared.generation != owner.generation || prepared.lang != owner.lang {
                        return Ok(ResolutionContentPublicationOutcome::Stale(
                            SelectedResolutionStale::AnalysisGeneration {
                                storage_language: owner.lang,
                            },
                        ));
                    }
                    if !prepared.state.parse_complete {
                        return Ok(ResolutionContentPublicationOutcome::Unavailable(
                            SelectedResolutionUnavailable::IncompleteParsedBlob {
                                storage_language: owner.lang,
                                persisted_relative_path: path,
                            },
                        ));
                    }
                    let oid = prepared.oid;
                    let write = super::write_prepared_blob_rows_tx(
                        &tx,
                        &prepared,
                        owner.generation,
                        &cancellation,
                    );
                    if cancellation.is_cancelled() {
                        tx.rollback()?;
                        return Ok(ResolutionContentPublicationOutcome::Cancelled);
                    }
                    write?;
                    let blob_id = tx.query_row(
                        "SELECT id FROM blobs WHERE blob_oid = ?1 AND lang = ?2",
                        params![oid.to_string(), owner.lang],
                        |row| row.get(0),
                    )?;
                    root_content_tx(&tx, &owner, blob_id)?;
                    let receipt = publication_receipt_tx(
                        &tx,
                        &owner,
                        blob_id,
                        oid,
                        ResolutionContentInput::Parsed {
                            content_oid: oid,
                            semantic_language: prepared.resolution.semantic_language(),
                        },
                        &cancellation,
                    )?;
                    let Some(receipt) = receipt else {
                        tx.rollback()?;
                        return Ok(ResolutionContentPublicationOutcome::Cancelled);
                    };
                    if cancellation.is_cancelled() {
                        tx.rollback()?;
                        return Ok(ResolutionContentPublicationOutcome::Cancelled);
                    }
                    tx.commit()?;
                    if cancellation.is_cancelled() {
                        return Ok(ResolutionContentPublicationOutcome::Cancelled);
                    }
                    Ok(ResolutionContentPublicationOutcome::Ready(Box::new(
                        receipt,
                    )))
                });
            match result {
                Err(error) if error.is_sqlite_interrupted() && cancellation.is_cancelled() => {
                    Ok(ResolutionContentPublicationOutcome::Cancelled)
                }
                result => result,
            }
        })
    }

    pub(crate) fn admit_cached_selected_content(
        &self,
        owner: &WorkspaceSnapshotId,
        persisted_relative_path: &str,
        content_oid: Oid,
        expected_input: &ResolutionContentInput,
        cancellation: &CancellationToken,
    ) -> Result<ResolutionContentPublicationOutcome> {
        let owner = owner.clone();
        let path = persisted_relative_path.to_owned();
        let input = expected_input.clone();
        let cancellation = cancellation.clone();
        self.conn.execute(move |conn| {
            let result = super::resolution::with_resolution_progress_handler(conn, &cancellation, |conn| {
            if cancellation.is_cancelled() { return Ok(ResolutionContentPublicationOutcome::Cancelled); }
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let expected_epoch = match &input {
                ResolutionContentInput::Parsed { content_oid: expected, semantic_language } => {
                    assert_eq!(*expected, content_oid, "cached parsed input has its source OID");
                    super::resolution::resolution_bundle_epoch(*semantic_language)
                }
                ResolutionContentInput::Capsule { key, .. } => {
                    assert_eq!(key.content_oid()?, content_oid, "cached capsule has its derivation OID");
                    &key.producer_epoch
                }
            };
            if let Some(outcome) = validate_owner_conn(&tx, &owner, expected_epoch)? { return Ok(outcome); }
            let blob: Option<(i64, i64)> = tx.query_row(
                "SELECT id, generation FROM blobs WHERE blob_oid = ?1 AND lang = ?2",
                params![content_oid.to_string(), owner.lang], |row| Ok((row.get(0)?, row.get(1)?)),
            ).optional()?;
            let Some((blob_id, generation)) = blob else {
                return Ok(ResolutionContentPublicationOutcome::Unavailable(
                    SelectedResolutionUnavailable::MissingBlob { storage_language: owner.lang,
                        persisted_relative_path: path }
                ));
            };
            if generation != owner.generation.0 {
                return Ok(ResolutionContentPublicationOutcome::Stale(
                    SelectedResolutionStale::AnalysisGeneration { storage_language: owner.lang }
                ));
            }
            let manifest: Option<(String, String, String)> = tx.query_row(
                "SELECT producer_epoch, publication_state, semantic_language FROM resolution_fragment_interiors
                 WHERE blob_id = ?1 AND lang = ?2", params![blob_id, owner.lang],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            ).optional()?;
            let Some((epoch, state, semantic_language)) = manifest else {
                return Ok(ResolutionContentPublicationOutcome::Unavailable(
                    SelectedResolutionUnavailable::MissingInterior { storage_language: owner.lang,
                        persisted_relative_path: path }
                ));
            };
            if epoch != expected_epoch {
                return Ok(ResolutionContentPublicationOutcome::Stale(
                    SelectedResolutionStale::ProducerEpoch { storage_language: owner.lang }
                ));
            }
            if state != "complete" {
                return Ok(ResolutionContentPublicationOutcome::Unavailable(
                    SelectedResolutionUnavailable::IncompleteInterior { storage_language: owner.lang,
                        persisted_relative_path: path }
                ));
            }
            match &input {
                ResolutionContentInput::Parsed { semantic_language: expected_language, .. } => {
                    if semantic_language != expected_language.config_label() {
                        return Ok(ResolutionContentPublicationOutcome::Unavailable(
                            SelectedResolutionUnavailable::InteriorOwnershipMismatch {
                                storage_language: owner.lang, persisted_relative_path: path }
                        ));
                    }
                    let ready: bool = tx.query_row(
                        "SELECT EXISTS(SELECT 1 FROM blob_meta AS meta
                         JOIN source_fact_readiness AS source ON source.blob_id = meta.blob_id
                         WHERE meta.blob_id = ?1 AND meta.is_complete = 1 AND source.available = 1)",
                        [blob_id], |row| row.get(0),
                    )?;
                    if !ready {
                        return Ok(ResolutionContentPublicationOutcome::Unavailable(
                            SelectedResolutionUnavailable::IncompleteParsedBlob { storage_language: owner.lang,
                                persisted_relative_path: path }
                        ));
                    }
                }
                ResolutionContentInput::Capsule { key, checkpoint_digest, host_module_scope } => {
                    let matches: bool = tx.query_row(
                        "SELECT EXISTS(SELECT 1 FROM resolution_capsule_inputs
                         WHERE blob_id = ?1 AND host_content_oid = ?2 AND invocation = ?3
                           AND definition_content_oid = ?4 AND selected_declaration = ?5
                           AND matched_arm_index = ?6 AND producer_epoch = ?7
                           AND derivation_digest = ?8 AND checkpoint_digest = ?9 AND host_module_scope = ?10)",
                        params![blob_id, key.host_content_oid.to_string(), key.invocation.get(),
                            key.definition_content_oid.to_string(), key.selected_declaration.get(),
                            super::usize_to_i64(key.matched_arm_index)?, key.producer_epoch,
                            key.digest().as_slice(), checkpoint_digest.as_slice(), host_module_scope.get()],
                        |row| row.get(0),
                    )?;
                    if !matches {
                        return Ok(ResolutionContentPublicationOutcome::Unavailable(
                            SelectedResolutionUnavailable::InteriorOwnershipMismatch { storage_language: owner.lang,
                                persisted_relative_path: path }
                        ));
                    }
                }
            }
            root_content_tx(&tx, &owner, blob_id)?;
            let receipt = publication_receipt_tx(&tx, &owner, blob_id, content_oid, input, &cancellation)?;
            let Some(receipt) = receipt else {
                tx.rollback()?;
                return Ok(ResolutionContentPublicationOutcome::Cancelled);
            };
            if cancellation.is_cancelled() {
                tx.rollback()?;
                return Ok(ResolutionContentPublicationOutcome::Cancelled);
            }
            tx.commit()?;
            if cancellation.is_cancelled() { return Ok(ResolutionContentPublicationOutcome::Cancelled); }
            Ok(ResolutionContentPublicationOutcome::Ready(Box::new(receipt)))
            });
            match result {
                Err(error) if error.is_sqlite_interrupted() && cancellation.is_cancelled() =>
                    Ok(ResolutionContentPublicationOutcome::Cancelled),
                result => result,
            }
        })
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare_resolution_capsule(
    key: ResolutionCapsuleKey,
    checkpoint: crate::analyzer::resolution::ResolutionNodeIdentity,
    host_module_scope: ResolutionScopeId,
    dense: &crate::analyzer::resolution::LoweredResolutionFactsWithIdentityCatalog,
    lowering: &brokk_bifrost_rust::macro_matcher::SelectedMacroInputLowering,
    host_input_start_line: usize,
    references: Vec<ResolutionCapsuleReferenceContext>,
    cancellation: &CancellationToken,
) -> Result<Option<PreparedResolutionCapsule>> {
    use crate::analyzer::resolution::LoweredSemanticRole;
    if cancellation.is_cancelled() {
        return Ok(None);
    }
    let mut bundle = match super::resolution_prepare::prepare_resolution_bundle_with_unit_keys(
        dense,
        None,
        cancellation,
    ) {
        super::resolution_prepare::ResolutionInteriorPreparation::Prepared(bundle) => *bundle,
        super::resolution_prepare::ResolutionInteriorPreparation::Cancelled => return Ok(None),
    };
    assert_eq!(key.producer_epoch, bundle.producer_epoch());
    assert_eq!(bundle.semantic_language(), super::Language::Rust);
    assert!(host_input_start_line >= 1);
    // These maps belong to this one dense capsule preparation and die here.
    // They avoid repeated linear scans through its semantic catalog.
    let mut definition_keys = crate::hash::HashMap::default();
    let mut reference_keys = crate::hash::HashMap::default();
    for site in dense.lexical().semantics() {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let key = ResolutionLocalKey::new(i64::from(
            site.semantic()
                .local_key()
                .expect("dense capsule site has a producer-local semantic"),
        ));
        let previous = match site.role() {
            LoweredSemanticRole::Definition => definition_keys.insert(site.site(), key),
            LoweredSemanticRole::Reference => reference_keys.insert(site.site(), key),
        };
        assert!(
            previous.is_none(),
            "one dense semantic owns each source site and role"
        );
    }
    let absolute_range = |mut range: Range| {
        range.start_line += host_input_start_line - 1;
        range.end_line += host_input_start_line - 1;
        assert_range(range);
        range
    };
    let mut declarations = Vec::new();
    for &(site, declaration) in &lowering.declarations {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let Some(lexical) = lowering.sources.lexical_declaration(declaration) else {
            // Module-owned declarations and other native definitions need not
            // carry an out-of-graph lexical presentation.
            continue;
        };
        let semantic_key = *definition_keys
            .get(&site)
            .expect("a bridged lexical declaration belongs to a dense definition");
        let source = lowering.sources.declaration(declaration);
        declarations.push(ResolutionCapsuleDeclarationPresentation {
            semantic_key,
            identifier: lexical.identifier.clone(),
            kind: lexical.kind,
            name_range: absolute_range(
                lowering
                    .sources
                    .occurrence(
                        source
                            .name
                            .expect("a lexical source declaration has a name"),
                    )
                    .range,
            ),
            declaration_range: absolute_range(lowering.sources.occurrence(source.occurrence).range),
        });
    }
    for reference in &references {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        assert_eq!(
            reference_keys.remove(&reference.source_site),
            Some(reference.semantic_key),
            "capsule reference context preserves its exact source site and dense semantic"
        );
    }
    assert!(
        reference_keys.is_empty(),
        "capsule reference contexts omit dense references: {reference_keys:?}"
    );
    let input = ResolutionContentInput::Capsule {
        key,
        checkpoint_digest: checkpoint.digest(),
        host_module_scope,
    };
    let Some(digest) = complete_capsule_digest(
        bundle.interior_digest(),
        &input,
        &declarations,
        &references,
        cancellation,
    ) else {
        return Ok(None);
    };
    let ResolutionContentInput::Capsule { key, .. } = &input else {
        unreachable!()
    };
    let presentation_payload_bytes = 80usize
        .saturating_add(64)
        .saturating_add(key.producer_epoch.len())
        .saturating_add(
            declarations
                .iter()
                .map(|row| row.identifier.len() + row.kind.label().len())
                .sum::<usize>(),
        );
    bundle.set_capsule_manifest(
        digest,
        declarations.len(),
        references.len(),
        presentation_payload_bytes,
    );
    Ok(Some(PreparedResolutionCapsule {
        input,
        bundle,
        declarations,
        references,
    }))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CapsuleArtifactVerification {
    Verified,
    Cancelled,
    Mismatch,
}

/// Authenticate the producer's immutable dense artifact before any operation
/// assignment retargets it. Presentation is read from this witness's exact blob;
/// the same canonical digest covers it and every prepared body family.
pub(crate) fn verify_capsule_artifact(
    conn: &rusqlite::Connection,
    witness: &ResolutionContentWitness,
    dense: &crate::analyzer::resolution::LoweredResolutionFactsWithIdentityCatalog,
    cancellation: &CancellationToken,
) -> Result<CapsuleArtifactVerification> {
    use CapsuleArtifactVerification::{Cancelled, Mismatch, Verified};
    let verify = || -> Result<CapsuleArtifactVerification> {
        if cancellation.is_cancelled() {
            return Ok(Cancelled);
        }
        let ResolutionContentInput::Capsule { key, .. } = witness.input() else {
            return Ok(Mismatch);
        };
        let bundle = match super::resolution_prepare::prepare_resolution_bundle_with_unit_keys(
            dense,
            None,
            cancellation,
        ) {
            super::resolution_prepare::ResolutionInteriorPreparation::Prepared(bundle) => bundle,
            super::resolution_prepare::ResolutionInteriorPreparation::Cancelled => {
                return Ok(Cancelled);
            }
        };
        if bundle.producer_epoch() != key.producer_epoch
            || bundle.semantic_language() != super::Language::Rust
        {
            return Ok(Mismatch);
        }
        let mut declarations = Vec::new();
        let mut statement = conn.prepare_cached(
            "SELECT semantic_key,identifier,kind,name_start_byte,name_end_byte,name_start_line,name_end_line,
             declaration_start_byte,declaration_end_byte,declaration_start_line,declaration_end_line
             FROM resolution_capsule_declarations WHERE blob_id=?1 ORDER BY semantic_key",
        )?;
        let mut rows = statement.query([witness.blob_id()])?;
        while let Some(row) = rows.next()? {
            if cancellation.is_cancelled() {
                return Ok(Cancelled);
            }
            let kind: String = row.get(2)?;
            let kind = DeclarationKind::from_label(&kind).ok_or_else(|| {
                super::StoreError::new(format!("invalid capsule declaration kind {kind:?}"))
            })?;
            let range = |offset| -> rusqlite::Result<Range> {
                Ok(Range {
                    start_byte: row.get(offset)?,
                    end_byte: row.get(offset + 1)?,
                    start_line: row.get(offset + 2)?,
                    end_line: row.get(offset + 3)?,
                })
            };
            declarations.push(ResolutionCapsuleDeclarationPresentation {
                semantic_key: ResolutionLocalKey::new(row.get(0)?),
                identifier: row.get(1)?,
                kind,
                name_range: range(3)?,
                declaration_range: range(7)?,
            });
        }
        drop(rows);
        drop(statement);
        let mut references = Vec::new();
        let mut statement = conn.prepare_cached(
            "SELECT semantic_key,source_site,host_occurrence,module_context,module_declaration,reference_owner_kind,host_owner_key
             FROM resolution_capsule_reference_contexts WHERE blob_id=?1 ORDER BY semantic_key",
        )?;
        let mut rows = statement.query([witness.blob_id()])?;
        while let Some(row) = rows.next()? {
            if cancellation.is_cancelled() {
                return Ok(Cancelled);
            }
            let owner = match (row.get::<_, i64>(5)?, row.get::<_, Option<i64>>(6)?) {
                (0, None) => ResolutionCapsuleReferenceOwner::Unknown,
                (1, None) => ResolutionCapsuleReferenceOwner::Root,
                (2, Some(key)) => {
                    ResolutionCapsuleReferenceOwner::HostLocal(ResolutionLocalKey::new(key))
                }
                fields => {
                    return Err(super::StoreError::new(format!(
                        "invalid capsule reference owner {fields:?}"
                    )));
                }
            };
            references.push(ResolutionCapsuleReferenceContext {
                semantic_key: ResolutionLocalKey::new(row.get(0)?),
                source_site: ResolutionSiteId::new(row.get(1)?),
                host_occurrence: SourceOccurrenceId::new(row.get(2)?),
                module_context: SourceOccurrenceId::new(row.get(3)?),
                module_declaration: row.get::<_, Option<u32>>(4)?.map(SourceDeclarationId::new),
                reference_owner: owner,
            });
        }
        let Some(digest) = complete_capsule_digest(
            bundle.interior_digest(),
            witness.input(),
            &declarations,
            &references,
            cancellation,
        ) else {
            return Ok(Cancelled);
        };
        Ok(if digest == witness.manifest_digest {
            Verified
        } else {
            Mismatch
        })
    };
    match verify() {
        Err(error) if error.is_sqlite_interrupted() && cancellation.is_cancelled() => Ok(Cancelled),
        result => result,
    }
}

fn complete_capsule_digest(
    resolution_digest: [u8; 32],
    input: &ResolutionContentInput,
    declarations: &[ResolutionCapsuleDeclarationPresentation],
    references: &[ResolutionCapsuleReferenceContext],
    cancellation: &CancellationToken,
) -> Option<[u8; 32]> {
    if cancellation.is_cancelled() {
        return None;
    }
    let declarations = super::resolution::cancellable_sort_by(
        declarations.iter().collect::<Vec<_>>(),
        |left, right| left.semantic_key.cmp(&right.semantic_key),
        cancellation,
    )?;
    let references = super::resolution::cancellable_sort_by(
        references.iter().collect::<Vec<_>>(),
        |left, right| left.semantic_key.cmp(&right.semantic_key),
        cancellation,
    )?;
    for keys in [
        declarations
            .iter()
            .map(|row| row.semantic_key)
            .collect::<Vec<_>>(),
        references
            .iter()
            .map(|row| row.semantic_key)
            .collect::<Vec<_>>(),
    ] {
        for rows in keys.windows(2) {
            if cancellation.is_cancelled() {
                return None;
            }
            assert_ne!(
                rows[0], rows[1],
                "one presentation per semantic-key primary key"
            );
        }
    }
    let mut hash = CanonicalHasher::new(b"bifrost-complete-resolution-capsule:v1");
    hash.field("resolution", &resolution_digest);
    let ResolutionContentInput::Capsule {
        key,
        checkpoint_digest,
        host_module_scope,
    } = &input
    else {
        unreachable!("capsule preparation constructs capsule input")
    };
    hash.field("derivation", &key.digest());
    hash.field("checkpoint", checkpoint_digest);
    hash.field("host_module_scope", &host_module_scope.get().to_be_bytes());
    hash.field(
        "declaration_count",
        &(declarations.len() as u64).to_be_bytes(),
    );
    for declaration in &declarations {
        if cancellation.is_cancelled() {
            return None;
        }
        hash.field(
            "semantic_key",
            &declaration.semantic_key.get().to_be_bytes(),
        );
        hash.field("identifier", declaration.identifier.as_bytes());
        hash.field("kind", declaration.kind.label().as_bytes());
        hash_range(&mut hash, "name", declaration.name_range);
        hash_range(&mut hash, "declaration", declaration.declaration_range);
    }
    hash.field("reference_count", &(references.len() as u64).to_be_bytes());
    for reference in &references {
        if cancellation.is_cancelled() {
            return None;
        }
        hash.field("semantic_key", &reference.semantic_key.get().to_be_bytes());
        hash.field("source_site", &reference.source_site.get().to_be_bytes());
        hash.field(
            "host_occurrence",
            &reference.host_occurrence.get().to_be_bytes(),
        );
        hash.field(
            "module_context",
            &reference.module_context.get().to_be_bytes(),
        );
        match reference.module_declaration {
            Some(declaration) => hash.field("module_declaration", &declaration.get().to_be_bytes()),
            None => hash.field("module_declaration", b"none"),
        }
        let (kind, owner) = reference_owner_columns(reference.reference_owner);
        hash.field("reference_owner_kind", &kind.to_be_bytes());
        match owner {
            Some(key) => hash.field("host_owner_key", &key.to_be_bytes()),
            None => hash.field("host_owner_key", b"none"),
        }
    }
    if cancellation.is_cancelled() {
        None
    } else {
        Some(hash.finish())
    }
}

fn assert_range(range: Range) {
    assert!(range.end_byte >= range.start_byte);
    assert!(range.start_line >= 1 && range.end_line >= range.start_line);
}

fn hash_range(hash: &mut CanonicalHasher, name: &str, range: Range) {
    hash.field("range", name.as_bytes());
    hash.field("start_byte", &(range.start_byte as u64).to_be_bytes());
    hash.field("end_byte", &(range.end_byte as u64).to_be_bytes());
    hash.field("start_line", &(range.start_line as u64).to_be_bytes());
    hash.field("end_line", &(range.end_line as u64).to_be_bytes());
}

fn reference_owner_columns(owner: ResolutionCapsuleReferenceOwner) -> (i64, Option<i64>) {
    match owner {
        ResolutionCapsuleReferenceOwner::Unknown => (0, None),
        ResolutionCapsuleReferenceOwner::Root => (1, None),
        ResolutionCapsuleReferenceOwner::HostLocal(key) => (2, Some(key.get())),
    }
}

fn insert_capsule_presentation_tx(
    tx: &Transaction<'_>,
    blob_id: i64,
    prepared: &PreparedResolutionCapsule,
    cancellation: &CancellationToken,
) -> Result<bool> {
    let ResolutionContentInput::Capsule {
        key,
        checkpoint_digest,
        host_module_scope,
    } = &prepared.input
    else {
        unreachable!("only the capsule preparer constructs a prepared capsule")
    };
    tx.prepare_cached(
        "INSERT INTO resolution_capsule_inputs(blob_id, host_content_oid, invocation,
           definition_content_oid, selected_declaration, matched_arm_index, producer_epoch,
           derivation_digest, checkpoint_digest, host_module_scope)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
    )?
    .execute(params![
        blob_id,
        key.host_content_oid.to_string(),
        key.invocation.get(),
        key.definition_content_oid.to_string(),
        key.selected_declaration.get(),
        super::usize_to_i64(key.matched_arm_index)?,
        key.producer_epoch,
        key.digest().as_slice(),
        checkpoint_digest.as_slice(),
        host_module_scope.get()
    ])?;
    let mut declarations = tx.prepare_cached(
        "INSERT INTO resolution_capsule_declarations(blob_id, semantic_key, identifier, kind,
           name_start_byte,name_end_byte,name_start_line,name_end_line,
           declaration_start_byte,declaration_end_byte,declaration_start_line,declaration_end_line)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
    )?;
    for row in &prepared.declarations {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        declarations.execute(params![
            blob_id,
            row.semantic_key.get(),
            row.identifier,
            row.kind.label(),
            super::usize_to_i64(row.name_range.start_byte)?,
            super::usize_to_i64(row.name_range.end_byte)?,
            super::usize_to_i64(row.name_range.start_line)?,
            super::usize_to_i64(row.name_range.end_line)?,
            super::usize_to_i64(row.declaration_range.start_byte)?,
            super::usize_to_i64(row.declaration_range.end_byte)?,
            super::usize_to_i64(row.declaration_range.start_line)?,
            super::usize_to_i64(row.declaration_range.end_line)?
        ])?;
    }
    let mut references = tx.prepare_cached(
        "INSERT INTO resolution_capsule_reference_contexts(blob_id, semantic_key, source_site,
           host_occurrence, module_context, module_declaration, reference_owner_kind, host_owner_key)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8)"
    )?;
    for row in &prepared.references {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        let (kind, owner) = reference_owner_columns(row.reference_owner);
        references.execute(params![
            blob_id,
            row.semantic_key.get(),
            row.source_site.get(),
            row.host_occurrence.get(),
            row.module_context.get(),
            row.module_declaration.map(|id| id.get()),
            kind,
            owner
        ])?;
    }
    Ok(true)
}

impl AnalyzerStore {
    pub(crate) fn publish_selected_resolution_capsule(
        &self,
        owner: &WorkspaceSnapshotId,
        persisted_relative_path: &str,
        prepared: PreparedResolutionCapsule,
        cancellation: &CancellationToken,
    ) -> Result<ResolutionContentPublicationOutcome> {
        let owner = owner.clone();
        let path = persisted_relative_path.to_owned();
        let cancellation = cancellation.clone();
        self.conn.execute(move |conn| {
            let result = super::resolution::with_resolution_progress_handler(conn, &cancellation, |conn| {
            if cancellation.is_cancelled() { return Ok(ResolutionContentPublicationOutcome::Cancelled); }
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            if let Some(outcome) = validate_owner_conn(&tx, &owner, prepared.bundle.producer_epoch())? {
                return Ok(outcome);
            }
            let ResolutionContentInput::Capsule { key, checkpoint_digest, host_module_scope } = &prepared.input else {
                unreachable!("a prepared capsule carries its derivation input")
            };
            let oid = key.content_oid()?;
            let oid_text = oid.to_string();
            let existing: Option<(i64, [u8;32], bool)> = tx.query_row(
                "SELECT blob.id, manifest.interior_digest,
                   input.host_content_oid = ?5 AND input.invocation = ?6
                   AND input.definition_content_oid = ?7 AND input.selected_declaration = ?8
                   AND input.matched_arm_index = ?9 AND input.producer_epoch = ?4
                   AND input.derivation_digest = ?10 AND input.checkpoint_digest = ?11
                   AND input.host_module_scope = ?12
                 FROM blobs AS blob
                 JOIN resolution_fragment_interiors AS manifest ON manifest.blob_id = blob.id
                 JOIN resolution_capsule_inputs AS input ON input.blob_id = blob.id
                 WHERE blob.blob_oid = ?1 AND blob.lang = ?2 AND blob.generation = ?3
                   AND manifest.publication_state = 'complete' AND manifest.producer_epoch = ?4",
                params![oid_text, owner.lang, owner.generation.0, prepared.bundle.producer_epoch(),
                    key.host_content_oid.to_string(), key.invocation.get(), key.definition_content_oid.to_string(),
                    key.selected_declaration.get(), super::usize_to_i64(key.matched_arm_index)?,
                    key.digest().as_slice(), checkpoint_digest.as_slice(), host_module_scope.get()],
                |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
            ).optional()?;
            if let Some((blob_id, actual_digest, input_matches)) = existing {
                if actual_digest != prepared.bundle.interior_digest() || !input_matches {
                    return Ok(ResolutionContentPublicationOutcome::Unavailable(
                        SelectedResolutionUnavailable::InteriorOwnershipMismatch {
                            storage_language: owner.lang, persisted_relative_path: path }
                    ));
                }
                root_content_tx(&tx, &owner, blob_id)?;
                let Some(receipt) = publication_receipt_tx(&tx, &owner, blob_id, oid,
                    prepared.input, &cancellation)? else {
                    return Ok(ResolutionContentPublicationOutcome::Cancelled);
                };
                if cancellation.is_cancelled() { return Ok(ResolutionContentPublicationOutcome::Cancelled); }
                tx.commit()?;
                if cancellation.is_cancelled() { return Ok(ResolutionContentPublicationOutcome::Cancelled); }
                return Ok(ResolutionContentPublicationOutcome::Ready(Box::new(receipt)));
            }
            // Host-local ownership is source authority. Prove it against the
            // host catalog identified by the key, never a selected runtime ID.
            for row in &prepared.references {
                if cancellation.is_cancelled() { return Ok(ResolutionContentPublicationOutcome::Cancelled); }
                if let ResolutionCapsuleReferenceOwner::HostLocal(local) = row.reference_owner {
                    let valid: bool = tx.query_row(
                        "SELECT EXISTS(SELECT 1 FROM blobs AS host
                         JOIN resolution_semantic_catalog AS catalog ON catalog.blob_id = host.id
                         JOIN resolution_semantic_sites AS site ON site.blob_id = host.id
                           AND site.semantic_key = catalog.local_key AND site.semantic_role = 'definition'
                         WHERE host.blob_oid = ?1 AND host.lang = ?2 AND host.generation = ?3
                           AND catalog.local_key = ?4 AND catalog.identity_digest IS NOT NULL)",
                        params![key.host_content_oid.to_string(), owner.lang, owner.generation.0, local.get()],
                        |row| row.get(0),
                    )?;
                    if !valid {
                        return Ok(ResolutionContentPublicationOutcome::Unavailable(
                            SelectedResolutionUnavailable::InteriorOwnershipMismatch {
                                storage_language: owner.lang, persisted_relative_path: path }
                        ));
                    }
                }
            }
            let Some(previous_owners) = repair_owners_tx(&tx, &oid_text, &owner.lang, owner.generation, &cancellation)? else {
                return Ok(ResolutionContentPublicationOutcome::Cancelled);
            };
            tx.execute("DELETE FROM blobs WHERE blob_oid = ?1 AND lang = ?2", params![oid_text,owner.lang])?;
            tx.execute("INSERT INTO blobs(blob_oid,lang,generation) VALUES(?1,?2,?3)",
                params![oid_text,owner.lang,owner.generation.0])?;
            let blob_id = tx.last_insert_rowid();
            if !insert_capsule_presentation_tx(&tx, blob_id, &prepared, &cancellation)? ||
                !super::resolution::insert_prepared_bundle_tx(&tx, blob_id, &owner.lang, &prepared.bundle, &cancellation)? {
                tx.rollback()?;
                return Ok(ResolutionContentPublicationOutcome::Cancelled);
            }
            for previous in &previous_owners { root_content_tx(&tx, previous, blob_id)?; }
            root_content_tx(&tx, &owner, blob_id)?;
            let receipt = publication_receipt_tx(&tx, &owner, blob_id, oid, prepared.input, &cancellation)?;
            let Some(receipt) = receipt else {
                tx.rollback()?;
                return Ok(ResolutionContentPublicationOutcome::Cancelled);
            };
            if cancellation.is_cancelled() {
                tx.rollback()?;
                return Ok(ResolutionContentPublicationOutcome::Cancelled);
            }
            tx.commit()?;
            if cancellation.is_cancelled() { return Ok(ResolutionContentPublicationOutcome::Cancelled); }
            Ok(ResolutionContentPublicationOutcome::Ready(Box::new(receipt)))
            });
            match result {
                Err(error) if error.is_sqlite_interrupted() && cancellation.is_cancelled() =>
                    Ok(ResolutionContentPublicationOutcome::Cancelled),
                result => result,
            }
        })
    }
}

#[cfg(test)]
mod capsule_authentication_tests {
    use super::*;

    #[test]
    fn capsule_verification_authenticates_fresh_cached_and_reordered_artifacts() {
        use CapsuleArtifactVerification::{Cancelled, Mismatch, Verified};
        super::super::resolution_operation::with_dense_selected_macro_fixture(
            |store, owner, fixtures| {
                let fixture = fixtures.into_iter().last().unwrap();
                let prepare = |dense, references| {
                    prepare_resolution_capsule(
                        fixture.key.clone(),
                        fixture.checkpoint,
                        fixture.module_scope,
                        dense,
                        &fixture.lowering,
                        fixture.host_input_start_line,
                        references,
                        &CancellationToken::default(),
                    )
                    .unwrap()
                    .unwrap()
                };
                let prepared = prepare(&fixture.dense, fixture.references.clone());
                let ResolutionContentPublicationOutcome::Ready(fresh) = store
                    .publish_selected_resolution_capsule(
                        owner,
                        &fixture.host_path,
                        prepared,
                        &CancellationToken::default(),
                    )
                    .unwrap()
                else {
                    panic!("fresh capsule publication must be ready");
                };
                let witness = fresh.witness().clone();
                {
                    let conn = store.read_conn().unwrap();
                    assert_eq!(
                        verify_capsule_artifact(
                            &conn,
                            &witness,
                            &fixture.dense,
                            &CancellationToken::default()
                        )
                        .unwrap(),
                        Verified
                    );
                    assert_eq!(
                        verify_capsule_artifact(
                            &conn,
                            &witness,
                            &fixture.reordered,
                            &CancellationToken::default()
                        )
                        .unwrap(),
                        Verified
                    );
                    let cancelled = CancellationToken::default();
                    cancelled.cancel();
                    assert_eq!(
                        verify_capsule_artifact(&conn, &witness, &fixture.dense, &cancelled)
                            .unwrap(),
                        Cancelled
                    );
                }
                let mut references = fixture.references.clone();
                references.reverse();
                let before = store.conn.execute(|conn| conn.total_changes());
                let ResolutionContentPublicationOutcome::Ready(cached) = store
                    .publish_selected_resolution_capsule(
                        owner,
                        &fixture.host_path,
                        prepare(&fixture.reordered, references),
                        &CancellationToken::default(),
                    )
                    .unwrap()
                else {
                    panic!("reordered capsule publication must be ready");
                };
                assert_eq!(cached.witness(), &witness);
                assert_eq!(store.conn.execute(|conn| conn.total_changes()), before);
                let changed = fixture
                    .dense
                    .with_changed_reference_end_for_publication_test();
                assert_eq!(
                    changed.identities(),
                    fixture.dense.identities(),
                    "changing reference extent retains the complete identity catalog"
                );
                assert_ne!(changed.lexical(), fixture.dense.lexical());
                let altered = changed
                    .lexical()
                    .semantics()
                    .iter()
                    .zip(fixture.dense.lexical().semantics())
                    .find(|(left, right)| left != right)
                    .unwrap()
                    .0;
                let source_site = fixture
                    .lowering
                    .facts
                    .sites
                    .iter()
                    .find(|site| site.id == altered.site())
                    .unwrap();
                let source_scope = fixture
                    .lowering
                    .facts
                    .scopes
                    .iter()
                    .find(|scope| scope.id == source_site.scope)
                    .unwrap();
                let extent = altered.site_metadata().unwrap();
                assert!(
                    source_scope.start_byte <= extent.start_byte()
                        && extent.end_byte() <= source_scope.end_byte,
                    "changed body remains inside its actual source scope"
                );
                {
                    let conn = store.read_conn().unwrap();
                    assert_eq!(
                        verify_capsule_artifact(
                            &conn,
                            &witness,
                            &changed,
                            &CancellationToken::default()
                        )
                        .unwrap(),
                        Mismatch,
                        "same catalog cannot authenticate changed reference body bytes"
                    );
                }
                let dense = fixture.dense;
                store.conn.execute(move |conn| {
                assert_eq!(verify_capsule_artifact(conn,cached.witness(),&dense,&CancellationToken::default()).unwrap(),Verified);
                let tx = conn.unchecked_transaction().unwrap();
                tx.execute("UPDATE resolution_fragment_interiors SET publication_state='building' WHERE blob_id=?1",[witness.blob_id()]).unwrap();
                assert_eq!(tx.execute("UPDATE resolution_capsule_declarations SET declaration_end_byte=declaration_end_byte+1 WHERE blob_id=?1",[witness.blob_id()]).unwrap(),1);
                assert_eq!(verify_capsule_artifact(&tx,&witness,&dense,&CancellationToken::default()).unwrap(),Mismatch,
                    "same identity catalog cannot authenticate altered durable presentation");
                tx.rollback().unwrap();
            });
            },
        );
    }

    #[test]
    fn complete_capsule_digest_is_presentation_order_independent_and_rejects_duplicate_keys() {
        let input = ResolutionContentInput::Capsule {
            key: ResolutionCapsuleKey {
                host_content_oid: Oid::zero(),
                invocation: SourceOccurrenceId::new(0),
                definition_content_oid: Oid::zero(),
                selected_declaration: SourceDeclarationId::new(0),
                matched_arm_index: 0,
                producer_epoch: "test".to_owned(),
            },
            checkpoint_digest: [2; 32],
            host_module_scope: ResolutionScopeId::new(0),
        };
        let range = Range {
            start_byte: 3,
            end_byte: 4,
            start_line: 2,
            end_line: 2,
        };
        let mut declarations = (0..3)
            .map(|key| ResolutionCapsuleDeclarationPresentation {
                semantic_key: ResolutionLocalKey::new(key),
                identifier: format!("local{key}"),
                kind: DeclarationKind::LocalVariable,
                name_range: range,
                declaration_range: range,
            })
            .collect::<Vec<_>>();
        let mut references = (3..6)
            .map(|key| ResolutionCapsuleReferenceContext {
                semantic_key: ResolutionLocalKey::new(i64::from(key)),
                source_site: ResolutionSiteId::new(key),
                host_occurrence: SourceOccurrenceId::new(key + 1),
                module_context: SourceOccurrenceId::new(0),
                module_declaration: None,
                reference_owner: ResolutionCapsuleReferenceOwner::Root,
            })
            .collect::<Vec<_>>();
        let token = CancellationToken::default();
        let original =
            complete_capsule_digest([1; 32], &input, &declarations, &references, &token).unwrap();
        declarations.reverse();
        references.rotate_left(1);
        assert_eq!(
            Some(original),
            complete_capsule_digest([1; 32], &input, &declarations, &references, &token)
        );
        declarations[0].declaration_range.end_byte += 1;
        assert_ne!(
            Some(original),
            complete_capsule_digest([1; 32], &input, &declarations, &references, &token)
        );
        let unique_references = references.clone();
        references.push(references[0].clone());
        assert!(
            std::panic::catch_unwind(|| complete_capsule_digest(
                [1; 32],
                &input,
                &declarations,
                &references,
                &CancellationToken::new()
            ))
            .is_err()
        );
        declarations.push(declarations[0].clone());
        assert!(
            std::panic::catch_unwind(|| complete_capsule_digest(
                [1; 32],
                &input,
                &declarations,
                &unique_references,
                &CancellationToken::new()
            ))
            .is_err()
        );
    }
}
