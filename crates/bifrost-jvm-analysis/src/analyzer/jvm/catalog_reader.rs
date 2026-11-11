//! Request-owned JVM catalog membership and row access.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use brokk_bifrost_analysis::analyzer::semantic_model::FamilyOpen;
use brokk_bifrost_analysis::analyzer::semantic_model::catalog::CatalogError;
use brokk_bifrost_analysis::analyzer::semantic_model::catalog::PinnedCatalogStatus;
use brokk_bifrost_analysis::analyzer::semantic_model::catalog::{
    ExpectedCatalogEntry, PinnedCatalogReader, PinnedCatalogRow, PinnedCatalogSource,
    PinnedReaderError,
};
use brokk_bifrost_analysis::analyzer::semantic_model::{Completeness, MemberFact, TypeFact};
use brokk_bifrost_analysis::analyzer::store::AnalyzerStore;
use brokk_bifrost_analysis::analyzer::store::StoreError;
use brokk_bifrost_analysis::analyzer::store::jvm_external_inventory::jvm_external_projection;
use brokk_bifrost_analysis::analyzer::store::jvm_external_publication::{
    JvmExternalProjection, JvmExternalPublication,
};
use brokk_bifrost_analysis::analyzer::store::model_catalog::{
    CatalogPackSourceKind, CatalogRowReader, OwnedCatalogRows, ReaderBinding, RequestRowReader,
    RequestRowReaderSource,
};
use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
use brokk_bifrost_core::analyzer::external_selection::{
    ExternalSelectionAuthority, ExternalSelectionQuestionKind, SelectionRetry, VerifiedSelection,
};
use brokk_bifrost_core::analyzer::outer_request::{
    AdmittedSelection, JvmCatalogReaderKey, OuterRequest, RequestEntryKey, RequestResource,
    RequestResourceError,
};
use brokk_bifrost_core::analyzer::project::Project;
use brokk_bifrost_core::cancellation::CancellationToken;
use rusqlite::{Params, types::Value};

use super::external::{ExternalInventorySelection, SelectedJdk};
use brokk_bifrost_analysis::analyzer::store::active_models::{
    CatalogShardDatabase, ResolvedActiveSemanticModels,
};

pub struct JvmSelectionAuthority {
    pub config: brokk_bifrost_core::analyzer::config::JvmAnalyzerConfig,
    pub project: Arc<dyn Project>,
    /// The analyzer store's budget-charged region, shared by every JVM
    /// analyzer of the workspace: the JDK selection streams its content
    /// digests through it.
    pub digests: brokk_bifrost_core::content_digest::ContentDigestCache,
}

impl ExternalSelectionAuthority for JvmSelectionAuthority {
    fn answer(
        &self,
        request: &OuterRequest,
        question: &brokk_bifrost_core::analyzer::external_selection::ExternalSelectionQuestion,
        retry: &SelectionRetry,
        cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
    ) -> Result<
        Arc<VerifiedSelection>,
        brokk_bifrost_core::analyzer::external_selection::SelectionRefused,
    > {
        assert!(
            self.questions()
                .iter()
                .any(|candidate| candidate == question)
        );
        request.external_selection(self.project.as_ref(), question.digest, || {
            super::verified_selection::verify_selection(
                &self.config,
                self.project.as_ref(),
                &self.digests,
                question,
                retry,
                cancellation,
            )
        })
    }

    fn questions(
        &self,
    ) -> Vec<brokk_bifrost_core::analyzer::external_selection::ExternalSelectionQuestion> {
        brokk_bifrost_core::analyzer::external_selection::ExternalSelectionQuestion::for_jvm(
            &self.config,
        )
    }
}

pub struct JvmRequestRowReaderSource {
    pub authority: Arc<dyn ExternalSelectionAuthority>,
    pub project: Arc<dyn Project>,
    pub catalog: PinnedCatalogSource,
    pub store: Arc<AnalyzerStore>,
}

impl std::fmt::Debug for JvmRequestRowReaderSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("JvmRequestRowReaderSource")
    }
}

impl RequestRowReaderSource for JvmRequestRowReaderSource {
    fn identity(&self) -> Option<[u8; 32]> {
        let mut hash = CanonicalHasher::new(b"jvm-request-row-source-v1");
        for question in self.authority.questions() {
            hash.field("question", &question.digest);
        }
        if let Some(stamp) = self.project.view_stamp() {
            stamp.hash_into(&mut hash);
        }
        Some(hash.finish())
    }

    fn jvm_reader(
        &self,
        activation: &ResolvedActiveSemanticModels,
    ) -> Result<RequestRowReader, FamilyOpen> {
        let result = (|| {
            let request = brokk_bifrost_analysis::analyzer::i_analyzer::current_outer_request()
                .ok_or(FamilyOpen::jvm("no request scope"))?;
            let cancellation =
                brokk_bifrost_analysis::analyzer::i_analyzer::current_query_cancellation()
                    .unwrap_or_default();
            let access = jvm_catalog_reader_for_request(
                self.authority.as_ref(),
                activation,
                Some(&request),
                Arc::clone(&self.project),
                &self.catalog,
                &self.store,
                // Analyzer stores are writable; P1 publishes the provider certificate.
                true,
                cancellation.clone(),
            );
            let handle = match access {
                Ok(JvmCatalogReaderAccess::Ready(handle)) => handle,
                Ok(JvmCatalogReaderAccess::SelectionIncomplete) => {
                    return Err(FamilyOpen::jvm("JVM selection incomplete"));
                }
                Ok(JvmCatalogReaderAccess::CertificateConflict) => {
                    return Err(FamilyOpen::jvm("JVM provider certificate conflict"));
                }
                Ok(JvmCatalogReaderAccess::ProviderPublicationUnavailable) => {
                    return Err(FamilyOpen::jvm("JVM provider publication unavailable"));
                }
                Ok(JvmCatalogReaderAccess::Unavailable(_)) => {
                    return Err(FamilyOpen::jvm("JVM catalog unavailable"));
                }
                Ok(JvmCatalogReaderAccess::Stale) => {
                    return Err(FamilyOpen::jvm("JVM catalog stale"));
                }
                Ok(JvmCatalogReaderAccess::Closed) => {
                    return Err(FamilyOpen::jvm("JVM catalog closed"));
                }
                Ok(JvmCatalogReaderAccess::Cancelled) => return Err(cancelled_open()),
                Err(error) => return Err(reader_failure_open(error)),
            };
            let mut guard = handle.bindings.lock().expect("JVM bindings mutex poisoned");
            let bindings = &mut *guard;
            let membership_key = (
                activation.active_model_set_hash().to_owned(),
                activation.excluded_shards.digest(),
            );
            if !bindings.by_membership.contains_key(&membership_key) {
                let active = request_owned_view(activation);
                let rows = handle.membership().map_err(reader_failure_open)?;
                if rows.iter().any(|row| {
                    row.status != PinnedCatalogStatus::Present || row.shard_key.is_none()
                }) {
                    return Err(FamilyOpen::jvm("JVM selection shards unavailable"));
                }
                let pinned = rows
                    .iter()
                    .map(|row| {
                        let database = row.kind.shard_database();
                        (
                            database,
                            row.shard_key.expect("present row has a shard key"),
                        )
                    })
                    .collect::<std::collections::HashSet<_>>();
                if rows.iter().any(|row| {
                    let database = row.kind.shard_database();
                    !active.contains(&(
                        database,
                        row.shard_key.expect("present row has a shard key"),
                    )) && !row
                        .manifest_digest
                        .as_ref()
                        .zip(row.shard_id.as_ref())
                        .is_some_and(|(manifest, shard)| {
                            activation.excluded_shards.contains(manifest, shard)
                        })
                }) {
                    return Err(FamilyOpen::jvm("JVM selection outside the activation"));
                }
                if !active.is_subset(&pinned) {
                    return Err(FamilyOpen::jvm("JVM selection shards unavailable"));
                }
                // Publication writes each generated production's whole projection,
                // without shard provenance, under its semantic digest, and store
                // resolution reads every provider that an active shard of any source
                // names by that digest. So an excluded generated shard is safe only
                // when no active shard names its provider; otherwise its declarations
                // would answer as complete.
                let active_providers = activation
                    .shards
                    .iter()
                    .map(|shard| shard.manifest.semantic_sha256.as_str())
                    .collect::<std::collections::HashSet<_>>();
                if rows.iter().any(|row| {
                    row.kind == CatalogPackSourceKind::Generated
                        && !active.contains(&(
                            row.kind.shard_database(),
                            row.shard_key.expect("present row has a shard key"),
                        ))
                        && active_providers.contains(
                            row.manifest
                                .as_ref()
                                .expect("present row has a manifest")
                                .semantic_sha256
                                .as_str(),
                        )
                }) {
                    return Err(FamilyOpen::jvm("JVM production partially excluded"));
                }
                // The pinned reader loads every Present membership row into its active
                // view, including shards the activation excluded. Narrow the view to
                // the activation's shards so no read returns an excluded shard's rows.
                // Provider publication already ran on the full membership at open.
                // The reader key carries the view's digest, so every activation
                // bound to this handle asks for the same view.
                match &bindings.view {
                    Some(view) => assert_eq!(*view, active, "a JVM reader handle serves one view"),
                    None => {
                        handle
                            .reader
                            .restrict_active_shards(&active, &cancellation)
                            .map_err(|error| {
                                reader_failure_open(JvmCatalogReaderError::Reader(error))
                            })?;
                        bindings.view = Some(active);
                    }
                }
            }
            let binding = *bindings
                .by_membership
                .entry(membership_key)
                .or_insert_with(|| {
                    let key = handle.key();
                    let mut hash = CanonicalHasher::new(b"jvm-request-reader-binding-v1");
                    for selection in [&key.dependencies, &key.jdk] {
                        hash.field("question", &selection.question_digest);
                        hash.field("has_view", &[u8::from(selection.view_stamp.is_some())]);
                        if let Some(stamp) = &selection.view_stamp {
                            stamp.hash_into(&mut hash);
                        }
                        hash.field("answer", &selection.answer_digest);
                    }
                    hash.field("curated", &key.curated);
                    hash.field("view", &key.view);
                    hash.field("rules", &key.rules);
                    hash.field("generation", &key.generation.to_be_bytes());
                    hash.field(
                        "active_models",
                        activation.active_model_set_hash().as_bytes(),
                    );
                    // ProjectViewStamp contains a process-local view ID. This binding is an
                    // in-memory request key and never enters a persisted read receipt.
                    ReaderBinding(hash.finish())
                });
            drop(guard);
            let selections = [&handle.key().dependencies, &handle.key().jdk];
            if selections
                .iter()
                .all(|selection| selection.complete && selection.certified)
            {
                use brokk_bifrost_analysis::analyzer::read_ledger::{
                    LookupKind, LookupQuestion, ReadKey,
                };
                for selection in selections {
                    brokk_bifrost_analysis::analyzer::i_analyzer::record_request_row_selection_read(
                        ReadKey::Lookup {
                            kind: LookupKind::ExternalSelection,
                            question: LookupQuestion::ExternalSelection {
                                question_digest: selection.question_digest,
                            },
                            digest: brokk_bifrost_analysis::analyzer::semantic::ids::StableDigest::from_array(selection.answer_digest),
                        },
                    );
                }
            } else {
                brokk_bifrost_analysis::analyzer::i_analyzer::refuse_request_row_read_reuse();
            }
            Ok(RequestRowReader {
                reader: handle,
                binding,
            })
        })();
        if result.is_err() {
            brokk_bifrost_analysis::analyzer::i_analyzer::refuse_request_row_read_reuse();
        }
        result
    }
}

pub const JVM_CATALOG_COMPOSITION_RULE: &[u8] = b"jvm-catalog-composition:v1";
pub const JVM_CATALOG_PRECEDENCE_RULE: &[u8] = b"jvm-catalog-precedence:v1";

/// Immutable activation authority, supplied before opening the catalog reader.
#[derive(Debug, Clone)]
pub struct CuratedAuthority {
    pub admitted_digest: [u8; 32],
    pub shards: Vec<CuratedShard>,
}

#[derive(Debug, Clone)]
pub struct CuratedShard {
    pub kind: CatalogPackSourceKind,
    pub manifest_digest: String,
    pub shard_id: String,
}

/// The activation's request-owned active shards: the pinned view a reader
/// handle narrows to, and the membership the bind checks.
fn request_owned_view(
    activation: &ResolvedActiveSemanticModels,
) -> std::collections::HashSet<(CatalogShardDatabase, i64)> {
    activation
        .shards
        .iter()
        .filter(|shard| {
            brokk_bifrost_analysis::analyzer::store::active_models::shard_owner_index(
                shard,
                None,
                Some(0),
            ) == Some(0)
        })
        .filter_map(|shard| shard.row_store.map(|row| (row.database, row.shard_key)))
        .collect()
}

fn view_digest(view: &std::collections::HashSet<(CatalogShardDatabase, i64)>) -> [u8; 32] {
    let mut shards = view
        .iter()
        .map(|(database, shard_key)| {
            let database = match database {
                CatalogShardDatabase::Durable => 0u8,
                CatalogShardDatabase::Session => 1u8,
            };
            (database, *shard_key)
        })
        .collect::<Vec<_>>();
    shards.sort_unstable();
    let mut hash = CanonicalHasher::new(b"jvm-catalog-reader-view-v1");
    for (database, shard_key) in shards {
        hash.field("database", &[database]);
        hash.field("shard_key", &shard_key.to_be_bytes());
    }
    hash.finish()
}

/// The Open answer of a cancelled JVM read, wherever the bind observes it.
fn cancelled_open() -> FamilyOpen {
    brokk_bifrost_analysis::analyzer::i_analyzer::record_request_row_read_cancelled();
    FamilyOpen::jvm_cancelled()
}

/// The Open answer of a reader failure, keeping its cause class.
fn reader_failure_open(error: JvmCatalogReaderError) -> FamilyOpen {
    match error {
        JvmCatalogReaderError::Store(error)
            if error.kind()
                == brokk_bifrost_analysis::analyzer::store::StoreErrorKind::NotWritable =>
        {
            FamilyOpen::jvm("analyzer store not writable")
        }
        JvmCatalogReaderError::Store(_) => FamilyOpen::jvm("analyzer store unavailable"),
        JvmCatalogReaderError::Reader(PinnedReaderError::Cancelled) => cancelled_open(),
        JvmCatalogReaderError::Closed
        | JvmCatalogReaderError::Reader(PinnedReaderError::Closed) => {
            FamilyOpen::jvm("JVM catalog closed")
        }
        JvmCatalogReaderError::Reader(PinnedReaderError::Catalog(_)) => {
            FamilyOpen::jvm("JVM catalog reader failed")
        }
        JvmCatalogReaderError::Stale => FamilyOpen::jvm("JVM catalog stale"),
        JvmCatalogReaderError::InvalidProjection(_) => {
            FamilyOpen::jvm("JVM catalog reader invalidated")
        }
    }
}

#[derive(Debug)]
pub enum JvmCatalogReaderError {
    Closed,
    Stale,
    Reader(PinnedReaderError),
    InvalidProjection(String),
    Store(StoreError),
}

/// A store write stopped by cancellation is the request's cancellation, not a
/// store failure, so the request entry reports it as Cancelled.
fn store_failure(error: StoreError) -> JvmCatalogReaderError {
    match error.kind() {
        brokk_bifrost_analysis::analyzer::store::StoreErrorKind::Cancelled => {
            JvmCatalogReaderError::Reader(PinnedReaderError::Cancelled)
        }
        _ => JvmCatalogReaderError::Store(error),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderPublication {
    Certified,
    Unavailable,
    Conflict,
    Missing,
    Quarantined,
    Stale,
}

pub struct JvmCatalogReaderHandle {
    key: JvmCatalogReaderKey,
    project: Arc<dyn Project>,
    reader: PinnedCatalogReader,
    unresolved_coordinates: Vec<String>,
    provider_outcomes: Mutex<Option<Vec<(usize, ProviderPublication)>>>,
    bindings: Mutex<HandleBindings>,
}

/// A handle serves one active view: the first bind narrows the pinned reader's
/// `active_catalog_*` views to its activation's request-owned shards, and a later
/// bind must request exactly that set. One request uses one activation.
#[derive(Default)]
struct HandleBindings {
    /// `None` until the first bind narrows the reader.
    view: Option<std::collections::HashSet<(CatalogShardDatabase, i64)>>,
    by_membership: HashMap<(String, [u8; 32]), ReaderBinding>,
}

impl JvmCatalogReaderHandle {
    pub fn provider_outcomes(&self) -> Option<Vec<(usize, ProviderPublication)>> {
        self.provider_outcomes
            .lock()
            .expect("provider outcomes poisoned")
            .clone()
    }

    pub fn key(&self) -> &JvmCatalogReaderKey {
        &self.key
    }

    // A generated production owns one provider even when its manifest has several shards.
    // The pinned membership retains manifest shard order for the combined projection.
    fn for_each_provider(
        &self,
        cancellation: &CancellationToken,
        mut visit: impl FnMut(
            JvmExternalProjection,
        ) -> Result<ProviderPublication, JvmCatalogReaderError>,
    ) -> Result<Vec<(usize, ProviderPublication)>, JvmCatalogReaderError> {
        self.guard()?;
        let mut outcomes = Vec::new();
        let mut offset = 0;
        while offset < self.reader.membership.len() {
            if cancellation.is_cancelled() {
                return Err(JvmCatalogReaderError::Reader(PinnedReaderError::Cancelled));
            }
            let ordinal = self.reader.membership[offset].ordinal;
            let end = offset
                + self.reader.membership[offset..].partition_point(|row| row.ordinal == ordinal);
            let rows = &self.reader.membership[offset..end];
            offset = end;
            if rows[0].kind != CatalogPackSourceKind::Generated {
                continue;
            }
            let status = rows.iter().find_map(|row| match row.status {
                PinnedCatalogStatus::Present => None,
                PinnedCatalogStatus::Missing => Some(ProviderPublication::Missing),
                PinnedCatalogStatus::Quarantined => Some(ProviderPublication::Quarantined),
                PinnedCatalogStatus::Stale => Some(ProviderPublication::Stale),
            });
            if let Some(status) = status {
                outcomes.push((ordinal, status));
                continue;
            }
            let first = &rows[0];
            let manifest_digest = first
                .manifest_digest
                .as_ref()
                .expect("present manifest digest");
            let production_digest = first
                .production_digest
                .as_ref()
                .expect("generated production digest");
            let mut combined = JvmExternalProjection {
                provider_id: first
                    .manifest
                    .as_ref()
                    .expect("present manifest")
                    .semantic_sha256
                    .clone(),
                source_identity: format!("generated:{manifest_digest}:{production_digest}"),
                owners: Vec::new(),
                members: Vec::new(),
                supertypes: Vec::new(),
            };
            for row in rows {
                assert_eq!(row.manifest_digest.as_ref(), Some(manifest_digest));
                let shard = self
                    .external_projection(row, cancellation)?
                    .expect("present shard projects");
                assert_eq!(shard.provider_id, combined.provider_id);
                combined.owners.extend(shard.owners);
                combined.members.extend(shard.members);
                combined.supertypes.extend(shard.supertypes);
            }
            outcomes.push((ordinal, visit(combined)?));
        }
        Ok(outcomes)
    }

    pub fn publish_providers(
        &self,
        store: &AnalyzerStore,
        cancellation: &CancellationToken,
    ) -> Result<Vec<(usize, ProviderPublication)>, JvmCatalogReaderError> {
        self.for_each_provider(cancellation, |projection| {
            let cancellation = cancellation.clone();
            Ok(
                match store
                    .publish_jvm_external_projection(
                        || Ok(Some(projection)),
                        move || cancellation.is_cancelled(),
                    )
                    .map_err(store_failure)?
                {
                    JvmExternalPublication::Available => ProviderPublication::Certified,
                    JvmExternalPublication::Unavailable => ProviderPublication::Unavailable,
                    JvmExternalPublication::Conflict => ProviderPublication::Conflict,
                },
            )
        })
    }

    pub fn provider_certificate_status(
        &self,
        store: &AnalyzerStore,
        cancellation: &CancellationToken,
    ) -> Result<Vec<(usize, ProviderPublication)>, JvmCatalogReaderError> {
        self.for_each_provider(cancellation, |projection| {
            Ok(
                match store
                    .jvm_external_publication_status(projection)
                    .map_err(store_failure)?
                {
                    JvmExternalPublication::Available => ProviderPublication::Certified,
                    JvmExternalPublication::Unavailable => ProviderPublication::Unavailable,
                    JvmExternalPublication::Conflict => ProviderPublication::Conflict,
                },
            )
        })
    }

    /// Project exactly one present shard from the pinned pair of snapshots.
    pub fn external_projection(
        &self,
        membership: &PinnedCatalogRow,
        cancellation: &CancellationToken,
    ) -> Result<Option<JvmExternalProjection>, JvmCatalogReaderError> {
        if membership.status != PinnedCatalogStatus::Present {
            return Ok(None);
        }
        let manifest = membership
            .manifest
            .as_ref()
            .expect("present shard has manifest");
        let shard_key = membership.shard_key.expect("present shard has key");
        let shard_id = membership.shard_id.as_ref().expect("present shard has ID");
        let source_db = match membership.kind.shard_database() {
            CatalogShardDatabase::Session => "session",
            CatalogShardDatabase::Durable => "durable",
        };
        let read = |table: &str| -> Result<Vec<String>, JvmCatalogReaderError> {
            let statement = format!(
                "SELECT record_json FROM active_catalog_{table} WHERE source_db=?1 AND shard_key=?2 ORDER BY record_key"
            );
            self.owned_rows(&statement, (source_db, shard_key), cancellation)?
                .into_iter()
                .map(|row| match row.as_slice() {
                    [Value::Text(value)] => Ok(value.clone()),
                    _ => Err(JvmCatalogReaderError::InvalidProjection(
                        "catalog declaration record is not text".into(),
                    )),
                })
                .collect()
        };
        let types = read("declaration_types")?
            .into_iter()
            .map(|json| {
                serde_json::from_str::<TypeFact>(&json)
                    .map_err(|error| JvmCatalogReaderError::InvalidProjection(error.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let members = read("declaration_members")?
            .into_iter()
            .map(|json| {
                serde_json::from_str::<MemberFact>(&json)
                    .map_err(|error| JvmCatalogReaderError::InvalidProjection(error.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let source_identity = format!(
            "{}:{}:{}",
            membership.kind.as_str(),
            membership
                .manifest_digest
                .as_ref()
                .expect("present shard has digest"),
            shard_id
        );
        Ok(Some(
            jvm_external_projection(
                manifest.semantic_sha256.clone(),
                source_identity,
                types.iter().filter(|owner| owner.guard.is_none()),
                members.iter(),
                manifest.completeness == Completeness::Complete,
            )
            .map_err(|error| JvmCatalogReaderError::InvalidProjection(error.to_string()))?,
        ))
    }
    fn guard(&self) -> Result<(), JvmCatalogReaderError> {
        // The reader checks its own closed state under its connection lock.
        // Checking it first here preserves Closed precedence over stale views.
        if self.reader.is_closed() {
            return Err(JvmCatalogReaderError::Closed);
        }
        if self.project.analysis_generation() != self.key.generation
            || self.project.view_stamp() != self.key.dependencies.view_stamp
            || self.project.view_stamp() != self.key.jdk.view_stamp
        {
            return Err(JvmCatalogReaderError::Stale);
        }
        Ok(())
    }

    pub fn membership(&self) -> Result<Vec<PinnedCatalogRow>, JvmCatalogReaderError> {
        self.guard()?;
        Ok(self.reader.membership.clone())
    }

    /// Rows of one read, cancelled by the caller's own token.
    pub fn owned_rows(
        &self,
        statement: &str,
        bindings: impl Params,
        cancellation: &CancellationToken,
    ) -> Result<Vec<Vec<Value>>, JvmCatalogReaderError> {
        self.guard()?;
        self.reader
            .owned_rows(statement, bindings, cancellation)
            .map_err(|error| match error {
                PinnedReaderError::Closed => JvmCatalogReaderError::Closed,
                error => JvmCatalogReaderError::Reader(error),
            })
    }
}

impl CatalogRowReader for JvmCatalogReaderHandle {
    fn jvm_unresolved_coordinates(&self) -> &[String] {
        &self.unresolved_coordinates
    }

    fn owned_rows(
        &self,
        statement: &str,
        bindings: &[(&str, &dyn rusqlite::ToSql)],
        cancellation: &CancellationToken,
    ) -> Result<OwnedCatalogRows, CatalogError> {
        self.guard().map_err(|_| {
            CatalogError::FamilyOpen(FamilyOpen::jvm("JVM catalog reader invalidated"))
        })?;
        // Catalog row questions pass no token of their own. A read through the
        // request owner stops when the operation running it is cancelled: the
        // query context's token (searched through enclosing scopes), never
        // another caller's, and an explicit token that is already cancelled.
        if cancellation.is_cancelled() {
            brokk_bifrost_analysis::analyzer::i_analyzer::record_request_row_read_cancelled();
            return Err(CatalogError::Cancelled);
        }
        let current = brokk_bifrost_analysis::analyzer::i_analyzer::current_query_cancellation();
        let combined = current
            .as_ref()
            .map(|operation| cancellation.combined_with(operation));
        self.reader
            .owned_named_rows(
                statement,
                bindings,
                combined.as_ref().unwrap_or(cancellation),
            )
            .map_err(|error| match error {
                PinnedReaderError::Catalog(CatalogError::Unavailable) => {
                    CatalogError::FamilyOpen(FamilyOpen::jvm("JVM catalog busy"))
                }
                PinnedReaderError::Catalog(CatalogError::Sqlite { ref source, .. })
                    if matches!(
                        source.sqlite_error_code(),
                        Some(
                            rusqlite::ErrorCode::DatabaseBusy
                                | rusqlite::ErrorCode::DatabaseLocked
                                | rusqlite::ErrorCode::FileLockingProtocolFailed
                        )
                    ) =>
                {
                    CatalogError::FamilyOpen(FamilyOpen::jvm("JVM catalog busy"))
                }
                PinnedReaderError::Catalog(error) => error,
                PinnedReaderError::Cancelled => {
                    brokk_bifrost_analysis::analyzer::i_analyzer::record_request_row_read_cancelled(
                    );
                    CatalogError::Cancelled
                }
                // A request that closes between the guard and the read leaves
                // the JVM part open, like a guard failure.
                PinnedReaderError::Closed => {
                    CatalogError::FamilyOpen(FamilyOpen::jvm("JVM catalog reader invalidated"))
                }
            })
    }
}

impl RequestResource for JvmCatalogReaderHandle {
    fn close(&self) {
        match self.reader.close() {
            Ok(()) | Err(PinnedReaderError::Closed) => {}
            Err(error) => panic!("closing request-owned JVM catalog reader: {error:?}"),
        }
    }
}

#[allow(clippy::too_many_arguments)] // The admitted inputs are independently owned authorities.
pub fn open_jvm_catalog_reader(
    request: &OuterRequest,
    project: Arc<dyn Project>,
    catalog: &PinnedCatalogSource,
    dependencies: &VerifiedSelection,
    jdk: &VerifiedSelection,
    jdk_expectations: Vec<ExpectedCatalogEntry>,
    curated: CuratedAuthority,
    view: [u8; 32],
    cancellation: CancellationToken,
) -> Result<Arc<JvmCatalogReaderHandle>, RequestResourceError<PinnedReaderError>> {
    let admitted = |selection: &VerifiedSelection| AdmittedSelection {
        certified: selection.certified,
        complete: selection.complete,
        question_digest: selection.question_digest,
        view_stamp: selection.view_stamp.clone(),
        answer_digest: selection.answer_digest,
    };
    let mut rules = CanonicalHasher::new(b"bifrost-jvm-catalog-reader-rules:v1");
    rules.field("composition", JVM_CATALOG_COMPOSITION_RULE);
    rules.field("precedence", JVM_CATALOG_PRECEDENCE_RULE);
    let key = JvmCatalogReaderKey {
        dependencies: admitted(dependencies),
        jdk: admitted(jdk),
        curated: curated.admitted_digest,
        view,
        rules: rules.finish(),
        generation: project.analysis_generation(),
    };
    request.resource(RequestEntryKey::JvmCatalogReader(key.clone()), || {
        let inventory = dependencies
            .records
            .downcast_ref::<Option<ExternalInventorySelection>>()
            .expect("JVM dependency selection contains its typed inventory");
        let mut expected = inventory
            .as_ref()
            .expect("failed dependency capture checked before opening the reader")
            .generated_production_keys()
            .into_iter()
            .map(|key| match key {
                Some(key) => ExpectedCatalogEntry::Production {
                    production_digest: key.production_digest,
                },
                None => ExpectedCatalogEntry::MissingProduction,
            })
            .collect::<Vec<_>>();
        expected.extend(jdk_expectations);
        expected.extend(
            curated
                .shards
                .into_iter()
                .map(|shard| ExpectedCatalogEntry::Shard {
                    kind: shard.kind,
                    manifest_digest: shard.manifest_digest,
                    shard_id: shard.shard_id,
                }),
        );
        let reader = catalog.pinned_jvm_reader(&expected, cancellation)?;
        Ok(Arc::new(JvmCatalogReaderHandle {
            key,
            project,
            reader,
            unresolved_coordinates: if dependencies.complete {
                Vec::new()
            } else {
                inventory
                    .as_ref()
                    .unwrap()
                    .completeness
                    .only_unresolved_coordinates()
                    .unwrap_or_default()
                    .to_vec()
            },
            provider_outcomes: Mutex::new(None),
            bindings: Mutex::new(HandleBindings::default()),
        }))
    })
}

/// Typed result of asking an activation for its request-owned JVM reader.
pub enum JvmCatalogReaderAccess {
    Ready(Arc<JvmCatalogReaderHandle>),
    Unavailable(String),
    SelectionIncomplete,
    CertificateConflict,
    ProviderPublicationUnavailable,
    Stale,
    Closed,
    Cancelled,
}

/// Lazily open and bind the JVM catalog reader on the first request need.
#[allow(clippy::too_many_arguments)]
pub fn jvm_catalog_reader_for_request(
    authority: &dyn ExternalSelectionAuthority,
    activation: &ResolvedActiveSemanticModels,
    request: Option<&OuterRequest>,
    project: Arc<dyn Project>,
    catalog: &PinnedCatalogSource,
    store: &AnalyzerStore,
    store_writable: bool,
    cancellation: CancellationToken,
) -> Result<JvmCatalogReaderAccess, JvmCatalogReaderError> {
    let Some(request) = request else {
        return Ok(JvmCatalogReaderAccess::Unavailable("no query scope".into()));
    };
    if request.is_closed() {
        return Ok(JvmCatalogReaderAccess::Closed);
    }
    if cancellation.is_cancelled() {
        return Ok(JvmCatalogReaderAccess::Cancelled);
    }
    let activation_id = activation.active_model_set_hash();
    let view = view_digest(&request_owned_view(activation));
    if let Some(key) = request.jvm_catalog_binding(activation_id, view) {
        return match request.resource::<JvmCatalogReaderHandle, PinnedReaderError>(
            RequestEntryKey::JvmCatalogReader(key),
            || unreachable!("bound JVM reader is already open"),
        ) {
            Ok(handle) => match handle.guard() {
                Ok(()) => Ok(JvmCatalogReaderAccess::Ready(handle)),
                Err(JvmCatalogReaderError::Closed) => Ok(JvmCatalogReaderAccess::Closed),
                Err(JvmCatalogReaderError::Stale) => Ok(JvmCatalogReaderAccess::Stale),
                Err(error) => Err(error),
            },
            Err(RequestResourceError::Closed) => Ok(JvmCatalogReaderAccess::Closed),
            Err(RequestResourceError::Open(error)) => Err(JvmCatalogReaderError::Reader(error)),
        };
    }
    let questions = authority.questions();
    let Some(dependency_question) = questions
        .iter()
        .find(|q| q.kind == ExternalSelectionQuestionKind::Dependencies)
    else {
        return Ok(JvmCatalogReaderAccess::Unavailable(
            "dependency selection question missing".into(),
        ));
    };
    let Some(jdk_question) = questions
        .iter()
        .find(|q| q.kind == ExternalSelectionQuestionKind::Jdk)
    else {
        return Ok(JvmCatalogReaderAccess::Unavailable(
            "JDK selection question missing".into(),
        ));
    };
    let retry = SelectionRetry::default();
    let dependencies = match authority.answer(request, dependency_question, &retry, &cancellation) {
        Ok(selection) => selection,
        Err(brokk_bifrost_core::analyzer::external_selection::SelectionRefused::Cancelled) => {
            return Ok(JvmCatalogReaderAccess::Cancelled);
        }
        Err(_) => return Ok(JvmCatalogReaderAccess::Stale),
    };
    let unresolved_only = dependencies
        .records
        .downcast_ref::<Option<ExternalInventorySelection>>()
        .expect("JVM dependency selection contains its typed inventory")
        .as_ref()
        .and_then(|selection| selection.completeness.only_unresolved_coordinates())
        .is_some();
    if !dependencies.complete && !unresolved_only {
        return Ok(JvmCatalogReaderAccess::SelectionIncomplete);
    }
    if dependencies
        .records
        .downcast_ref::<Option<ExternalInventorySelection>>()
        .expect("JVM dependency selection contains its typed inventory")
        .is_none()
    {
        return Ok(JvmCatalogReaderAccess::Unavailable(
            "JVM dependency inventory capture failed".into(),
        ));
    }
    let jdk = match authority.answer(request, jdk_question, &retry, &cancellation) {
        Ok(selection) => selection,
        Err(brokk_bifrost_core::analyzer::external_selection::SelectionRefused::Cancelled) => {
            return Ok(JvmCatalogReaderAccess::Cancelled);
        }
        Err(_) => return Ok(JvmCatalogReaderAccess::Stale),
    };
    if !jdk.complete {
        return Ok(JvmCatalogReaderAccess::SelectionIncomplete);
    }
    if !dependencies.complete && !jdk.certified {
        return Ok(JvmCatalogReaderAccess::SelectionIncomplete);
    }
    let selected_jdk = jdk
        .records
        .downcast_ref::<SelectedJdk>()
        .expect("JVM JDK selection contains its typed inventory");
    // The reader pins exactly the curated shards it owns, by the same predicate
    // that `JvmRequestRowReaderSource::jvm_reader` uses for the activation side
    // of its membership check, so a shard the activation keeps (non-JVM, or a
    // generator-rule shard) never makes the two sets differ.
    let curated = CuratedAuthority {
        admitted_digest: activation.indexes.admission().curated,
        shards: activation
            .shards
            .iter()
            .filter(|shard| {
                shard.request_owned()
                    && matches!(
                        shard.source_kind,
                        CatalogPackSourceKind::Installed
                            | CatalogPackSourceKind::PreShipped
                            | CatalogPackSourceKind::Embedded
                    )
            })
            .map(|shard| CuratedShard {
                kind: shard.source_kind,
                manifest_digest: shard.manifest.content_sha256.clone(),
                shard_id: shard.descriptor.shard_id.clone(),
            })
            .collect(),
    };
    let handle = match open_jvm_catalog_reader(
        request,
        project,
        catalog,
        &dependencies,
        &jdk,
        selected_jdk.catalog_expectations(),
        curated,
        view,
        cancellation.clone(),
    ) {
        Ok(handle) => handle,
        Err(
            RequestResourceError::Closed | RequestResourceError::Open(PinnedReaderError::Closed),
        ) => return Ok(JvmCatalogReaderAccess::Closed),
        Err(RequestResourceError::Open(PinnedReaderError::Cancelled)) => {
            return Ok(JvmCatalogReaderAccess::Cancelled);
        }
        Err(RequestResourceError::Open(error)) => return Err(JvmCatalogReaderError::Reader(error)),
    };
    {
        let mut outcomes = handle
            .provider_outcomes
            .lock()
            .expect("provider outcomes poisoned");
        if outcomes.is_none() {
            let publication = if store_writable {
                handle.publish_providers(store, &cancellation)
            } else {
                handle.provider_certificate_status(store, &cancellation)
            };
            *outcomes = Some(match publication {
                Ok(outcomes) => outcomes,
                Err(JvmCatalogReaderError::Reader(PinnedReaderError::Cancelled)) => {
                    return Ok(JvmCatalogReaderAccess::Cancelled);
                }
                Err(JvmCatalogReaderError::Closed) => return Ok(JvmCatalogReaderAccess::Closed),
                Err(JvmCatalogReaderError::Stale) => return Ok(JvmCatalogReaderAccess::Stale),
                Err(error) => return Err(error),
            });
        }
        if outcomes
            .as_ref()
            .expect("provider outcomes initialized")
            .iter()
            .any(|(_, outcome)| *outcome == ProviderPublication::Conflict)
        {
            return Ok(JvmCatalogReaderAccess::CertificateConflict);
        }
        // A writable store answers Unavailable only when the projection
        // callback yields none, which the catalog's never does, so this
        // refuses a fault rather than a routine outcome. Consumers of the
        // projected inventory do not check certificates.
        if outcomes
            .as_ref()
            .expect("provider outcomes initialized")
            .iter()
            .any(|(_, outcome)| *outcome == ProviderPublication::Unavailable)
        {
            return Ok(JvmCatalogReaderAccess::ProviderPublicationUnavailable);
        }
    }
    if request.is_closed() {
        return Ok(JvmCatalogReaderAccess::Closed);
    }
    if cancellation.is_cancelled() {
        return Ok(JvmCatalogReaderAccess::Cancelled);
    }
    match handle.guard() {
        Ok(()) => {}
        Err(JvmCatalogReaderError::Closed) => return Ok(JvmCatalogReaderAccess::Closed),
        Err(JvmCatalogReaderError::Stale) => return Ok(JvmCatalogReaderAccess::Stale),
        Err(error) => return Err(error),
    }
    request.bind_jvm_catalog(activation_id.to_owned(), view, handle.key().clone());
    if request.is_closed() {
        return Ok(JvmCatalogReaderAccess::Closed);
    }
    Ok(JvmCatalogReaderAccess::Ready(handle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_analysis::analyzer::i_analyzer::{AnalyzerQueryScope, IAnalyzer};
    use brokk_bifrost_analysis::analyzer::semantic_model::catalog::{
        CatalogOpenMode, CatalogOptions, GeneratedProductionKey, PinnedCatalogStatus,
        SemanticPackCatalog,
    };
    use brokk_bifrost_core::analyzer::config::JvmAnalyzerConfig;
    use brokk_bifrost_core::analyzer::external_selection::{
        ExternalSelectionQuestion, SelectionRefused,
    };
    use brokk_bifrost_core::analyzer::model::Language;
    use brokk_bifrost_core::analyzer::project::{OverlayProject, TestProject};
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    fn composite_request_source_refuses_multiple_jvm_owners() {
        use brokk_bifrost_analysis::analyzer::multi_analyzer::{AnalyzerDelegate, MultiAnalyzer};
        use brokk_bifrost_analysis::analyzer::store::active_models::{
            MatcherIndexes, SemanticModelActivationReport,
        };
        use brokk_bifrost_core::analyzer::config::AnalyzerConfig;
        use std::collections::BTreeMap;

        let root = tempfile::tempdir().unwrap();
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root.path(), Language::Java));
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let activation = ResolvedActiveSemanticModels::new(
            "empty-jvm-activation".into(),
            None,
            Vec::new(),
            MatcherIndexes::default(),
            Vec::new(),
            Default::default(),
            Default::default(),
            SemanticModelActivationReport::default(),
        );
        let composite = |second_config: AnalyzerConfig| {
            MultiAnalyzer::new(BTreeMap::from([
                (
                    Language::Java,
                    AnalyzerDelegate::new(crate::analyzer::java::JavaAnalyzer::new(Arc::clone(
                        &project,
                    ))),
                ),
                (
                    Language::Kotlin,
                    AnalyzerDelegate::new(
                        crate::analyzer::kotlin::KotlinAnalyzer::new_with_config(
                            Arc::clone(&project),
                            second_config,
                        ),
                    ),
                ),
            ]))
        };
        let same_config = composite(AnalyzerConfig::default());
        let same_source = same_config
            .request_row_reader_source(&catalog.pinned_catalog_source(
                &brokk_bifrost_analysis::analyzer::store::cache_budget::StoreCacheBudget::new(
                    &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
                ),
            ))
            .unwrap();
        assert_eq!(
            same_source.jvm_reader(&activation).err(),
            Some(FamilyOpen::jvm("no request scope"))
        );

        let mut other_config = AnalyzerConfig::default();
        other_config
            .jvm
            .standard_library_discovery
            .discover_java_home = false;
        let different_config = composite(other_config);
        let different_source = different_config
            .request_row_reader_source(&catalog.pinned_catalog_source(
                &brokk_bifrost_analysis::analyzer::store::cache_budget::StoreCacheBudget::new(
                    &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
                ),
            ))
            .unwrap();
        assert_eq!(
            different_source.jvm_reader(&activation).err(),
            Some(FamilyOpen::jvm("several JVM selection configurations"))
        );
    }

    #[test]
    #[hardwon(
        "#9559: an active JVM generator-rule shard stayed in the reader's pinned curated set but left the activation side, so every request-owned JVM read was Open"
    )]
    #[hardwon(
        "#9559: a control-excluded shard of a selected JVM production made every request-owned read Open"
    )]
    fn real_request_reader_binds_with_an_active_jvm_generator_rule_shard() {
        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::{
            SessionPackSource, SessionPackSourceKind,
        };
        use brokk_bifrost_analysis::analyzer::semantic_model::runtime::{
            SemanticModelActivationControl, SemanticModelActivationEvidence,
            SemanticModelActivationRequest, SemanticModelControlAction, SemanticModelControlScope,
            SemanticModelPackSelector, SemanticModelRuntimeLimits, SemanticModelRuntimeOutcome,
            acquire_eager_semantic_models_with_request_owner_for_test,
        };
        use brokk_bifrost_analysis::analyzer::semantic_model::{
            AuthoredSemanticModelPack, CompilerOptions, PayloadKind, compile_pack,
        };
        use serde_json::{Value as JsonValue, json};

        let root = tempfile::tempdir().unwrap();
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root.path(), Language::Java));
        let analyzer = crate::analyzer::java::JavaAnalyzer::new(Arc::clone(&project));
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        for (authored, source_id) in [
            (
                &include_bytes!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../bifrost-analysis/testdata/semantic-model-packs/generator-rules-v1.json"
                ))[..],
                "generator-fixture",
            ),
            (
                &include_bytes!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../bifrost-analysis/testdata/semantic-model-packs/declarations-v1.json"
                ))[..],
                "declarations-fixture",
            ),
        ] {
            let mut authored: JsonValue = serde_json::from_slice(authored).unwrap();
            authored["schema_version"] = json!(
                brokk_bifrost_analysis::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION
            );
            authored["compatibility"] = json!({});
            authored["shards"][0]["activation"] = json!([{}]);
            let pack = compile_pack(
                &serde_json::from_value::<AuthoredSemanticModelPack>(authored).unwrap(),
                &CompilerOptions::default(),
            )
            .unwrap();
            catalog
                .register_compiled_pack(
                    &pack,
                    &SessionPackSource {
                        kind: SessionPackSourceKind::Embedded,
                        source_id: source_id.into(),
                    },
                )
                .unwrap();
        }
        let source = analyzer
            .request_row_reader_source(&catalog.pinned_catalog_source(
                &brokk_bifrost_analysis::analyzer::store::cache_budget::StoreCacheBudget::new(
                    &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
                ),
            ))
            .unwrap();
        let activation = SemanticModelActivationRequest {
            bifrost_version: semver::Version::new(0, 15, 1),
            approximate_standard_libraries: Vec::new(),
            evidence: vec![SemanticModelActivationEvidence {
                language: "java".into(),
                ecosystem: "maven".into(),
                package: None,
                module: None,
                toolchain: None,
                target: None,
                configuration: None,
                artifact_sha256: None,
            }],
            // Both fixture packs require review, so a workspace control enables them.
            controls: ["acme.builders", "acme.widget"]
                .into_iter()
                .map(|pack_id| SemanticModelActivationControl {
                    scope: SemanticModelControlScope::Workspace,
                    action: SemanticModelControlAction::Enable,
                    selector: SemanticModelPackSelector {
                        pack_id: pack_id.into(),
                        version: None,
                        manifest_digest: None,
                    },
                })
                .collect(),
            limits: SemanticModelRuntimeLimits::default(),
        };
        let SemanticModelRuntimeOutcome::Ready { active, .. } =
            acquire_eager_semantic_models_with_request_owner_for_test(
                &analyzer,
                &catalog,
                &activation,
                &CancellationToken::new(),
                true,
            )
        else {
            panic!("request owner activation ready")
        };
        let kinds = active
            .shards
            .iter()
            .map(|shard| (shard.descriptor.payload_kind, shard.request_owned()))
            .collect::<Vec<_>>();
        assert!(
            kinds.contains(&(PayloadKind::GeneratorRules, false))
                && kinds.iter().any(|(_, owned)| *owned),
            "{kinds:?} {:?}",
            active.report
        );
        let _scope = AnalyzerQueryScope::with_outer_request(&analyzer, OuterRequest::new());
        source
            .jvm_reader(&active)
            .expect("the generator-rule shard stays with the activation owner");
        drop(_scope);
        let mut activation = activation;
        activation.controls[1].action = SemanticModelControlAction::Disable;
        activation.limits.max_explanations = 0;
        let brokk_bifrost_analysis::analyzer::semantic_model::runtime::SemanticModelResolutionOutcome::Ready(active) =
            brokk_bifrost_analysis::analyzer::semantic_model::runtime::resolve_row_backed_semantic_models_for_test(
                &catalog, &activation, &CancellationToken::new(), &[],
            )
        else { panic!("disabled pack activation ready") };
        assert!(active.report.explanations.is_empty());
        assert!(!active.excluded_shards.is_empty());
        let _scope = AnalyzerQueryScope::with_outer_request(&analyzer, OuterRequest::new());
        source
            .jvm_reader(&active)
            .expect("explicit exclusions bind even when explanations are capped");
    }

    #[test]
    fn catalog_installation_between_requests_rotates_binding() {
        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::{
            SessionPackSource, SessionPackSourceKind,
        };
        use brokk_bifrost_analysis::analyzer::semantic_model::runtime::{
            SemanticModelActivationEvidence, SemanticModelActivationRequest,
            SemanticModelRuntimeLimits, SemanticModelRuntimeOutcome,
            acquire_eager_semantic_models_with_request_owner_for_test,
        };
        use brokk_bifrost_analysis::analyzer::semantic_model::{
            AuthoredSemanticModelPack, CompilerOptions, compile_pack,
        };
        use serde_json::{Value as JsonValue, json};

        let root = tempfile::tempdir().unwrap();
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root.path(), Language::Java));
        let analyzer = crate::analyzer::java::JavaAnalyzer::new(Arc::clone(&project));
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let source = analyzer
            .request_row_reader_source(&catalog.pinned_catalog_source(
                &brokk_bifrost_analysis::analyzer::store::cache_budget::StoreCacheBudget::new(
                    &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
                ),
            ))
            .unwrap();
        let activation = SemanticModelActivationRequest {
            bifrost_version: semver::Version::new(0, 15, 1),
            approximate_standard_libraries: Vec::new(),
            evidence: vec![SemanticModelActivationEvidence {
                language: "java".into(),
                ecosystem: "maven".into(),
                package: None,
                module: None,
                toolchain: None,
                target: None,
                configuration: None,
                artifact_sha256: None,
            }],
            controls: Vec::new(),
            limits: SemanticModelRuntimeLimits::default(),
        };
        let acquire = || {
            let SemanticModelRuntimeOutcome::Ready { active, .. } =
                acquire_eager_semantic_models_with_request_owner_for_test(
                    &analyzer,
                    &catalog,
                    &activation,
                    &CancellationToken::new(),
                    true,
                )
            else {
                panic!("JVM activation ready")
            };
            active
        };
        let before = acquire();
        let first_binding = {
            let request = OuterRequest::new();
            let _scope = AnalyzerQueryScope::with_outer_request(&analyzer, request);
            source
                .jvm_reader(&before)
                .expect("first JVM reader")
                .binding
        };

        let mut authored: JsonValue = serde_json::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../bifrost-analysis/testdata/semantic-model-packs/declarations-v1.json"
        )))
        .unwrap();
        authored["schema_version"] =
            json!(brokk_bifrost_analysis::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION);
        authored["compatibility"] = json!({});
        authored["shards"][0]["activation"] = json!([{}]);
        let pack = compile_pack(
            &serde_json::from_value::<AuthoredSemanticModelPack>(authored).unwrap(),
            &CompilerOptions::default(),
        )
        .unwrap();
        catalog
            .register_compiled_pack(
                &pack,
                &SessionPackSource {
                    kind: SessionPackSourceKind::EphemeralWorkspace,
                    source_id: "binding-rotation-fixture".into(),
                },
            )
            .unwrap();
        let after = acquire();
        assert_ne!(
            before.active_model_set_hash(),
            after.active_model_set_hash(),
            "after activation: {:?}",
            after.report
        );
        let second_binding = {
            let request = OuterRequest::new();
            let _scope = AnalyzerQueryScope::with_outer_request(&analyzer, request);
            source
                .jvm_reader(&after)
                .expect("second JVM reader")
                .binding
        };
        assert_ne!(first_binding, second_binding);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9559: a non-JVM model read bound the JVM request owner and recorded its selection reads"
    )]
    fn scoped_overlay_reads_record_only_the_requested_selection_family() {
        use brokk_bifrost_analysis::analyzer::read_ledger::{LookupKind, ReadKey, ReadLedger};
        use brokk_bifrost_analysis::analyzer::semantic::ids::StableDigest;
        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::{
            SessionPackSource, SessionPackSourceKind,
        };
        use brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay;
        use brokk_bifrost_analysis::analyzer::semantic_model::runtime::{
            SemanticModelActivationEvidence, SemanticModelActivationRequest,
            SemanticModelResolutionOutcome, SemanticModelRuntimeLimits,
            resolve_active_semantic_models,
        };
        use brokk_bifrost_analysis::analyzer::semantic_model::{
            AuthoredSemanticModelPack, CompilerOptions, compile_pack,
        };
        use serde_json::{Value as JsonValue, json};

        let root = tempfile::tempdir().unwrap();
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root.path(), Language::Java));
        let analyzer = crate::analyzer::java::JavaAnalyzer::new(Arc::clone(&project));
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        for (language, ecosystem) in [("python", "pypi"), ("java", "maven")] {
            let mut authored: JsonValue = serde_json::from_slice(include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../bifrost-analysis/testdata/semantic-model-packs/declarations-v1.json"
            )))
            .unwrap();
            authored["schema_version"] = json!(
                brokk_bifrost_analysis::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION
            );
            authored["compatibility"] = json!({});
            authored["pack_id"] = json!(format!("ledger.{language}"));
            authored["language"] = json!(language);
            authored["ecosystem"] = json!(ecosystem);
            authored["shards"][0]["activation"] = json!([{}]);
            let pack = compile_pack(
                &serde_json::from_value::<AuthoredSemanticModelPack>(authored).unwrap(),
                &CompilerOptions::default(),
            )
            .unwrap();
            catalog
                .register_compiled_pack(
                    &pack,
                    &SessionPackSource {
                        kind: SessionPackSourceKind::Embedded,
                        source_id: format!("ledger-{language}"),
                    },
                )
                .unwrap();
        }
        let activation = SemanticModelActivationRequest {
            bifrost_version: semver::Version::new(0, 15, 1),
            approximate_standard_libraries: Vec::new(),
            evidence: [("python", "pypi"), ("java", "maven")]
                .into_iter()
                .map(|(language, ecosystem)| SemanticModelActivationEvidence {
                    language: language.into(),
                    ecosystem: ecosystem.into(),
                    package: None,
                    module: None,
                    toolchain: None,
                    target: None,
                    configuration: None,
                    artifact_sha256: None,
                })
                .collect(),
            controls: Vec::new(),
            limits: SemanticModelRuntimeLimits::default(),
        };
        let SemanticModelResolutionOutcome::Ready(mut active) =
            resolve_active_semantic_models(&catalog, &activation, &CancellationToken::new())
        else {
            panic!("mixed activation ready")
        };
        assert_eq!(active.shards.len(), 2);
        for shard in &mut active.shards {
            let metadata = (*shard.metadata).clone();
            *shard = Arc::new(
                brokk_bifrost_analysis::analyzer::store::active_models::ActiveSemanticModelShard {
                    metadata: Arc::new(metadata),
                    decoded: None,
                },
            );
        }
        struct CertifiedAuthority(JvmSelectionAuthority, bool);
        impl ExternalSelectionAuthority for CertifiedAuthority {
            fn questions(
                &self,
            ) -> Vec<brokk_bifrost_core::analyzer::external_selection::ExternalSelectionQuestion>
            {
                self.0.questions()
            }
            fn answer(
                &self,
                request: &OuterRequest,
                question: &brokk_bifrost_core::analyzer::external_selection::ExternalSelectionQuestion,
                retry: &SelectionRetry,
                _cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
            ) -> Result<
                Arc<VerifiedSelection>,
                brokk_bifrost_core::analyzer::external_selection::SelectionRefused,
            > {
                let answer = self.0.answer(request, question, retry, _cancellation)?;
                Ok(Arc::new(VerifiedSelection {
                    question_digest: answer.question_digest,
                    answer_digest: answer.answer_digest,
                    view_stamp: answer.view_stamp.clone(),
                    certified: question.kind == ExternalSelectionQuestionKind::Dependencies
                        || self.1,
                    complete: answer.complete,
                    records: Arc::clone(&answer.records),
                }))
            }
        }
        {
            let installed_source: Option<Arc<dyn brokk_bifrost_analysis::analyzer::store::model_catalog::RequestRowReaderSource>> = Some(Arc::new(JvmRequestRowReaderSource {
                authority: Arc::new(CertifiedAuthority(
                    JvmSelectionAuthority {
                        config: Default::default(),
                        project: Arc::clone(&project),
                        digests: super::super::external::test_digests(),
                    },
                    true,
                )),
                project: Arc::clone(&project),
                catalog: catalog.pinned_catalog_source(&brokk_bifrost_analysis::analyzer::store::cache_budget::StoreCacheBudget::new(&brokk_bifrost_core::retention_budget::RetentionBudget::for_tests())),
                store: Arc::new(AnalyzerStore::open_ephemeral().unwrap()),
            }));
            active.install_request_source(installed_source).unwrap();
        };
        let active = Arc::new(active);
        let patterns = brokk_bifrost_analysis::analyzer::SearchSymbolPatternBatch::compile(
            vec![".*".into()],
            false,
            None,
        );
        let mut observations = Vec::new();
        for pooled in [false, true] {
            let _scope = AnalyzerQueryScope::with_outer_request(&analyzer, OuterRequest::new());
            let overlay = SemanticModelOverlay::build(
                &analyzer,
                &active,
                &CancellationToken::new(),
                64 << 20,
                &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
            )
            .unwrap();
            for language in ["python", "java"] {
                let ledger = Arc::new(ReadLedger::new());
                let answer = {
                    let _capture =
                        AnalyzerQueryScope::with_read_ledger(&analyzer, Arc::clone(&ledger));
                    // Match IAnalyzer::semantic_model_overlay's publication read before composition.
                    analyzer.record_read(ReadKey::Models(StableDigest::sha256(
                        active.active_model_set_hash(),
                    )));
                    overlay.symbols_with_id_for("type.widget", language)
                };
                let selections = ledger
                    .keys()
                    .into_iter()
                    .filter(|key| {
                        matches!(
                            key,
                            ReadKey::Lookup {
                                kind: LookupKind::ExternalSelection,
                                ..
                            }
                        )
                    })
                    .collect::<Vec<_>>();
                assert_eq!(
                    selections.len(),
                    if language == "python" { 0 } else { 2 },
                    "{language}: {selections:?}"
                );
                assert!(!answer.records.is_empty(), "{language}: {answer:?}");
                assert!(!ledger.reuse_refused(), "{language}");
                if language == "java" {
                    let _capture =
                        AnalyzerQueryScope::with_read_ledger(&analyzer, Arc::clone(&ledger));
                    let members = overlay.members_of_for("type.widget", language);
                    let relations = overlay.relations_from_for("member.widget.create", language);
                    assert!(!members.records.is_empty(), "{members:?}");
                    assert!(!relations.records.is_empty(), "{relations:?}");
                    // Search reports candidate visits, but this layer has no work-budget counter.
                    let search = overlay.search_with_limit(&patterns, usize::MAX, None);
                    observations.push((
                        ledger
                            .keys()
                            .into_iter()
                            .collect::<std::collections::HashSet<_>>(),
                        format!("{answer:?} {members:?} {relations:?} {search:?}"),
                        search.1,
                    ));
                }
            }
            let reader = active
                .request_source()
                .unwrap()
                .jvm_reader(&active)
                .unwrap();
            let marker = reader
                .reader
                .owned_rows("PRAGMA temp.cache_size", &[], &CancellationToken::new())
                .unwrap();
            assert_eq!(marker.rows == vec![vec![Value::Integer(-12345)]], pooled);
            if !pooled {
                reader
                    .reader
                    .owned_rows(
                        "PRAGMA temp.cache_size=-12345",
                        &[],
                        &CancellationToken::new(),
                    )
                    .unwrap();
            }
        }
        assert_eq!(observations[0], observations[1]);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#9559: request reader cancellation panicked and ignored the explicit token mid-read"
    )]
    fn real_request_source_reuses_one_binding_per_activation() {
        use brokk_bifrost_analysis::analyzer::semantic_model::runtime::{
            SemanticModelActivationRequest, SemanticModelRuntimeLimits,
            SemanticModelRuntimeOutcome, acquire_eager_semantic_models_for_test,
            acquire_eager_semantic_models_with_request_owner_for_test,
        };
        let root = tempfile::tempdir().unwrap();
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root.path(), Language::Java));
        let analyzer = crate::analyzer::java::JavaAnalyzer::new(Arc::clone(&project));
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let source = analyzer
            .request_row_reader_source(&catalog.pinned_catalog_source(
                &brokk_bifrost_analysis::analyzer::store::cache_budget::StoreCacheBudget::new(
                    &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
                ),
            ))
            .unwrap();
        let activation = SemanticModelActivationRequest {
            bifrost_version: semver::Version::new(0, 15, 1),
            approximate_standard_libraries: Vec::new(),
            evidence: Vec::new(),
            controls: Vec::new(),
            limits: SemanticModelRuntimeLimits::default(),
        };
        let SemanticModelRuntimeOutcome::Ready { active: off, .. } =
            acquire_eager_semantic_models_for_test(
                &analyzer,
                &catalog,
                &activation,
                &CancellationToken::new(),
            )
        else {
            panic!("empty activation ready")
        };
        assert!(off.request_source().unwrap().identity().is_none());
        let SemanticModelRuntimeOutcome::Ready { active, .. } =
            acquire_eager_semantic_models_with_request_owner_for_test(
                &analyzer,
                &catalog,
                &activation,
                &CancellationToken::new(),
                true,
            )
        else {
            panic!("request owner activation ready")
        };
        assert!(active.request_source().unwrap().identity().is_some());
        let request = OuterRequest::new();
        let _scope = AnalyzerQueryScope::with_outer_request(&analyzer, Arc::clone(&request));
        let first = source.jvm_reader(&active).expect("real JVM reader");
        let second = source.jvm_reader(&active).expect("reused JVM reader");
        assert_eq!(first.binding, second.binding);
        assert!(Arc::ptr_eq(&first.reader, &second.reader));
        let key = request
            .jvm_catalog_binding(
                active.active_model_set_hash(),
                super::view_digest(&super::request_owned_view(&active)),
            )
            .unwrap();
        let handle = request
            .resource::<JvmCatalogReaderHandle, PinnedReaderError>(
                RequestEntryKey::JvmCatalogReader(key),
                || unreachable!("reader already opened"),
            )
            .unwrap();
        assert_eq!(handle.bindings.lock().unwrap().by_membership.len(), 1);
        let ledger = Arc::new(brokk_bifrost_analysis::analyzer::read_ledger::ReadLedger::new());
        {
            let _capture = AnalyzerQueryScope::with_read_ledger(&analyzer, Arc::clone(&ledger));
            source.jvm_reader(&active).expect("captured JVM reader");
        }
        assert!(ledger.reuse_refused());
        // A cached product filled from a read through the request owner is
        // never retained, so a later request cannot reuse it warm; the same
        // fill without that read is retained.
        let through_owner =
            brokk_bifrost_analysis::analyzer::common::complete_query_cache_fill(&analyzer, || {
                source.jvm_reader(&active).is_ok()
            });
        assert_eq!(through_owner, Err(true));
        let without_owner =
            brokk_bifrost_analysis::analyzer::common::complete_query_cache_fill(&analyzer, || true);
        assert_eq!(without_owner, Ok(true));
        // The production placeholder remains inert under a capture.
        let placeholder =
            brokk_bifrost_analysis::analyzer::common::complete_query_cache_fill(&analyzer, || {
                off.question_row_owners(Some("jvm"));
                true
            });
        assert_eq!(placeholder, Ok(true));
        struct CertifiedAuthority(JvmSelectionAuthority, bool);
        impl ExternalSelectionAuthority for CertifiedAuthority {
            fn questions(
                &self,
            ) -> Vec<brokk_bifrost_core::analyzer::external_selection::ExternalSelectionQuestion>
            {
                self.0.questions()
            }
            fn answer(
                &self,
                request: &OuterRequest,
                question: &brokk_bifrost_core::analyzer::external_selection::ExternalSelectionQuestion,
                retry: &SelectionRetry,
                _cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
            ) -> Result<
                Arc<VerifiedSelection>,
                brokk_bifrost_core::analyzer::external_selection::SelectionRefused,
            > {
                let answer = self.0.answer(request, question, retry, _cancellation)?;
                Ok(Arc::new(VerifiedSelection {
                    question_digest: answer.question_digest,
                    answer_digest: answer.answer_digest,
                    view_stamp: answer.view_stamp.clone(),
                    certified: question.kind == ExternalSelectionQuestionKind::Dependencies
                        || self.1,
                    complete: answer.complete,
                    records: Arc::clone(&answer.records),
                }))
            }
        }
        let certified = JvmRequestRowReaderSource {
            authority: Arc::new(CertifiedAuthority(
                JvmSelectionAuthority {
                    config: Default::default(),
                    project: Arc::clone(&project),
                    digests: super::super::external::test_digests(),
                },
                true,
            )),
            project: Arc::clone(&project),
            catalog: catalog.pinned_catalog_source(
                &brokk_bifrost_analysis::analyzer::store::cache_budget::StoreCacheBudget::new(
                    &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
                ),
            ),
            store: Arc::new(AnalyzerStore::open_ephemeral().unwrap()),
        };
        let certified_scope =
            AnalyzerQueryScope::with_outer_request(&analyzer, OuterRequest::new());
        let mut captured = Vec::new();
        for _ in 0..2 {
            let ledger = Arc::new(brokk_bifrost_analysis::analyzer::read_ledger::ReadLedger::new());
            {
                let _capture = AnalyzerQueryScope::with_read_ledger(&analyzer, Arc::clone(&ledger));
                certified.jvm_reader(&active).expect("certified reader");
            }
            assert!(!ledger.reuse_refused());
            captured.push(ledger.keys().into_iter().filter(|key| matches!(key, brokk_bifrost_analysis::analyzer::read_ledger::ReadKey::Lookup { kind: brokk_bifrost_analysis::analyzer::read_ledger::LookupKind::ExternalSelection, .. })).collect::<Vec<_>>());
        }
        assert_eq!(captured[0], captured[1]);
        assert_eq!(captured[0].len(), 2);
        let retained =
            brokk_bifrost_analysis::analyzer::common::complete_query_cache_fill(&analyzer, || {
                certified.jvm_reader(&active).is_ok()
            });
        assert_eq!(retained, Ok(true));
        drop(certified_scope);
        let mixed = JvmRequestRowReaderSource {
            authority: Arc::new(CertifiedAuthority(
                JvmSelectionAuthority {
                    config: Default::default(),
                    project: Arc::clone(&project),
                    digests: super::super::external::test_digests(),
                },
                false,
            )),
            project: Arc::clone(&project),
            catalog: catalog.pinned_catalog_source(
                &brokk_bifrost_analysis::analyzer::store::cache_budget::StoreCacheBudget::new(
                    &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
                ),
            ),
            store: Arc::new(AnalyzerStore::open_ephemeral().unwrap()),
        };
        {
            let _scope = AnalyzerQueryScope::with_outer_request(&analyzer, OuterRequest::new());
            let ledger = Arc::new(brokk_bifrost_analysis::analyzer::read_ledger::ReadLedger::new());
            {
                let _capture = AnalyzerQueryScope::with_read_ledger(&analyzer, Arc::clone(&ledger));
                mixed
                    .jvm_reader(&active)
                    .expect("mixed certification reader");
            }
            assert!(ledger.reuse_refused());
            assert!(ledger.keys_satisfy(|key| !matches!(key, brokk_bifrost_analysis::analyzer::read_ledger::ReadKey::Lookup { kind: brokk_bifrost_analysis::analyzer::read_ledger::LookupKind::ExternalSelection, .. })));
            assert_eq!(
                brokk_bifrost_analysis::analyzer::common::complete_query_cache_fill(
                    &analyzer,
                    || mixed.jvm_reader(&active).is_ok()
                ),
                Err(true)
            );
        }
        // An ordinary row question through the request owner observes the
        // running operation's cancellation even though it passes no token.
        let reader = source.jvm_reader(&active).expect("bound JVM reader").reader;
        for explicit_stops in [true, false] {
            let stopping = CancellationToken::cancel_after_checks_for_test(8);
            let continuing = CancellationToken::new();
            let (explicit, operation) = if explicit_stops {
                (&stopping, &continuing)
            } else {
                (&continuing, &stopping)
            };
            let scope = AnalyzerQueryScope::with_cancellation(&analyzer, operation);
            let answer = CatalogRowReader::owned_rows(
                reader.as_ref(),
                "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<100) SELECT x FROM n",
                &[],
                explicit,
            );
            let open =
                brokk_bifrost_analysis::analyzer::store::model_catalog::semantic_catalog_question(
                    "cancellation",
                    (),
                    answer,
                )
                .unwrap_err();
            assert!(open.is_cancellation());
            let content = FamilyOpen::jvm("busy");
            assert!(content.merge(open).is_cancellation());
            assert!(open.merge(content).is_cancellation());
            assert!(matches!(brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelOverlayBuildError::from(open), brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelOverlayBuildError::Cancelled));
            assert_eq!(
                scope.read_completion(),
                Err(brokk_bifrost_analysis::analyzer::QueryReadIncomplete::Cancelled)
            );
            drop(scope);
            let fresh_scope =
                AnalyzerQueryScope::with_outer_request(&analyzer, OuterRequest::new());
            let fresh = source
                .jvm_reader(&active)
                .expect("new request can read after cancellation");
            assert_eq!(
                CatalogRowReader::owned_rows(
                    fresh.reader.as_ref(),
                    "SELECT 1",
                    &[],
                    &CancellationToken::new()
                )
                .unwrap()
                .rows
                .len(),
                1
            );
            drop(fresh_scope);
        }
        let token = CancellationToken::new();
        let _cancellable = AnalyzerQueryScope::with_cancellation(&analyzer, &token);
        token.cancel();
        assert!(matches!(
            (reader.as_ref() as &dyn CatalogRowReader).raw_rows(
                "SELECT t.* FROM active_catalog_declaration_types t",
                &[],
                &active.shards,
                |_| Ok(()),
            ),
            Err(CatalogError::Cancelled)
        ));
    }

    #[test]
    fn activation_binding_shares_one_request_and_reads_status_without_writing() {
        use brokk_bifrost_analysis::analyzer::store::active_models::{
            MatcherIndexes, SemanticModelActivationReport,
        };
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct Authority {
            project: Arc<dyn Project>,
            fills: AtomicUsize,
            failed_capture: bool,
        }
        impl ExternalSelectionAuthority for Authority {
            fn questions(&self) -> Vec<ExternalSelectionQuestion> {
                vec![
                    ExternalSelectionQuestion {
                        kind: ExternalSelectionQuestionKind::Dependencies,
                        digest: [1; 32],
                        uncertified: false,
                    },
                    ExternalSelectionQuestion {
                        kind: ExternalSelectionQuestionKind::Jdk,
                        digest: [2; 32],
                        uncertified: true,
                    },
                ]
            }
            fn answer(
                &self,
                request: &OuterRequest,
                question: &ExternalSelectionQuestion,
                _: &SelectionRetry,
                _cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
            ) -> Result<Arc<VerifiedSelection>, SelectionRefused> {
                request.external_selection(self.project.as_ref(), question.digest, || {
                    self.fills.fetch_add(1, Ordering::SeqCst);
                    let records: Arc<dyn std::any::Any + Send + Sync> = match question.kind {
                        ExternalSelectionQuestionKind::Dependencies => Arc::new(
                            (!self.failed_capture)
                                .then(ExternalInventorySelection::empty_for_catalog_reader_test),
                        ),
                        ExternalSelectionQuestionKind::Jdk => Arc::new(
                            super::super::external::JvmExternalDeclarationIndex::select_jdk(
                                &JvmAnalyzerConfig::default(),
                                self.project.as_ref(),
                                &super::super::external::test_digests(),
                                None,
                            )
                            .unwrap(),
                        ),
                    };
                    Ok(VerifiedSelection {
                        question_digest: question.digest,
                        answer_digest: question.digest,
                        view_stamp: self.project.view_stamp(),
                        certified: false,
                        complete: true,
                        records,
                    })
                })
            }
        }
        let root = tempfile::tempdir().unwrap();
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root.path(), Language::Java));
        let authority = Authority {
            project: Arc::clone(&project),
            fills: AtomicUsize::new(0),
            failed_capture: false,
        };
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let activation = ResolvedActiveSemanticModels::new(
            "empty-jvm-activation".into(),
            None,
            Vec::new(),
            MatcherIndexes::default(),
            Vec::new(),
            Default::default(),
            Default::default(),
            SemanticModelActivationReport::default(),
        );
        let source = JvmRequestRowReaderSource {
            authority: Arc::new(JvmSelectionAuthority {
                config: JvmAnalyzerConfig::default(),
                project: Arc::clone(&project),
                digests: super::super::external::test_digests(),
            }),
            project: Arc::clone(&project),
            catalog: catalog.pinned_catalog_source(
                &brokk_bifrost_analysis::analyzer::store::cache_budget::StoreCacheBudget::new(
                    &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
                ),
            ),
            store: Arc::new(AnalyzerStore::open_ephemeral().unwrap()),
        };
        assert_eq!(
            source.jvm_reader(&activation).err(),
            Some(FamilyOpen::jvm("no request scope"))
        );
        let get = |request: Option<&OuterRequest>| {
            jvm_catalog_reader_for_request(
                &authority,
                &activation,
                request,
                Arc::clone(&project),
                &catalog.pinned_catalog_source(
                    &brokk_bifrost_analysis::analyzer::store::cache_budget::StoreCacheBudget::new(
                        &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
                    ),
                ),
                &store,
                false,
                CancellationToken::new(),
            )
            .unwrap()
        };
        assert!(matches!(get(None), JvmCatalogReaderAccess::Unavailable(_)));
        let first_request = OuterRequest::new();
        let JvmCatalogReaderAccess::Ready(first) = get(Some(&first_request)) else {
            panic!("first reader unavailable")
        };
        assert_eq!(first.provider_outcomes(), Some(Vec::new()));
        let JvmCatalogReaderAccess::Ready(shared) = get(Some(&first_request)) else {
            panic!("shared reader unavailable")
        };
        assert!(Arc::ptr_eq(&first, &shared));
        assert_eq!(authority.fills.load(Ordering::SeqCst), 2);
        let second_request = OuterRequest::new();
        let JvmCatalogReaderAccess::Ready(other) = get(Some(&second_request)) else {
            panic!("second reader unavailable")
        };
        assert!(!Arc::ptr_eq(&first, &other));
        assert_eq!(authority.fills.load(Ordering::SeqCst), 4);
        let count: i64 = store
            .read_conn()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM jvm_external_provider_publications",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
        let failed_authority = Authority {
            project: Arc::clone(&project),
            fills: AtomicUsize::new(0),
            failed_capture: true,
        };
        let failed_request = OuterRequest::new();
        assert!(matches!(
            jvm_catalog_reader_for_request(
                &failed_authority, &activation, Some(&failed_request),
                Arc::clone(&project), &catalog.pinned_catalog_source(&brokk_bifrost_analysis::analyzer::store::cache_budget::StoreCacheBudget::new(&brokk_bifrost_core::retention_budget::RetentionBudget::for_tests())), &store, false, CancellationToken::new(),
            ).unwrap(),
            JvmCatalogReaderAccess::Unavailable(reason) if reason.contains("capture failed")
        ));
        assert_eq!(failed_authority.fills.load(Ordering::SeqCst), 1);
        first_request.close();
        assert!(matches!(
            get(Some(&first_request)),
            JvmCatalogReaderAccess::Closed
        ));
    }

    #[test]
    fn request_owner_admits_only_unresolved_coordinates() {
        use super::super::external::{
            ExternalSelectionFailure as Failure, JvmExternalDeclarationIndex,
        };
        struct CauseAuthority {
            project: Arc<dyn Project>,
            failures: Vec<fn() -> Failure>,
            filesystem: Option<JvmAnalyzerConfig>,
            jdk_complete: bool,
            jdk_certified: bool,
        }
        impl ExternalSelectionAuthority for CauseAuthority {
            fn questions(&self) -> Vec<ExternalSelectionQuestion> {
                [
                    ExternalSelectionQuestionKind::Dependencies,
                    ExternalSelectionQuestionKind::Jdk,
                ]
                .into_iter()
                .enumerate()
                .map(|(i, kind)| ExternalSelectionQuestion {
                    kind,
                    digest: [i as u8; 32],
                    uncertified: false,
                })
                .collect()
            }
            fn answer(
                &self,
                _: &OuterRequest,
                question: &ExternalSelectionQuestion,
                _: &SelectionRetry,
                _: &CancellationToken,
            ) -> Result<Arc<VerifiedSelection>, SelectionRefused> {
                let dependency = question.kind == ExternalSelectionQuestionKind::Dependencies;
                let records: Arc<dyn std::any::Any + Send + Sync> = if dependency {
                    let mut selection = if let Some(config) = &self.filesystem {
                        JvmExternalDeclarationIndex::select_external_inventory(
                            config,
                            self.project.as_ref(),
                            &super::super::dependency_discovery::LiveDiscoveryInputs(
                                self.project.as_ref(),
                            ),
                            |_| Ok::<_, std::convert::Infallible>(()),
                        )
                        .unwrap()
                    } else {
                        ExternalInventorySelection::empty_for_catalog_reader_test()
                    };
                    for failure in &self.failures {
                        selection.completeness.record(failure());
                    }
                    Arc::new(Some(selection))
                } else {
                    Arc::new(
                        JvmExternalDeclarationIndex::select_jdk(
                            &JvmAnalyzerConfig::default(),
                            self.project.as_ref(),
                            &super::super::external::test_digests(),
                            None,
                        )
                        .unwrap(),
                    )
                };
                Ok(Arc::new(VerifiedSelection {
                    question_digest: question.digest,
                    answer_digest: question.digest,
                    view_stamp: self.project.view_stamp(),
                    certified: dependency || self.jdk_certified,
                    complete: !dependency && self.jdk_complete,
                    records,
                }))
            }
        }
        let missing: fn() -> Failure =
            || Failure::UnresolvedCoordinates(vec!["g:missing:1".into()]);
        let partial: fn() -> Failure = || Failure::PartialManifest("pom.xml".into());
        let unreadable: fn() -> Failure =
            || Failure::UnreadableProbe("blocked/artifact.jar".into());
        // Selection-level causes isolate the admission contract from discovery's filesystem recipes.
        type AdmissionCase = (&'static str, Vec<fn() -> Failure>, bool, bool, bool);
        let cases: Vec<AdmissionCase> = vec![
            ("missing", vec![missing], true, true, true),
            (
                "discovery limit",
                vec![|| Failure::Discovery],
                true,
                true,
                false,
            ),
            (
                "discovery error",
                vec![|| Failure::Discovery],
                true,
                true,
                false,
            ),
            (
                "suppressed",
                vec![missing, || Failure::Discovery],
                true,
                true,
                false,
            ),
            ("partial", vec![partial], true, true, false),
            (
                "read",
                vec![|| Failure::ArtifactRead("blocked/a.jar".into())],
                true,
                true,
                false,
            ),
            ("limit", vec![|| Failure::ArtifactLimit], true, true, false),
            ("probe", vec![unreadable], true, true, false),
            ("missing partial", vec![missing, partial], true, true, false),
            (
                "missing probe",
                vec![missing, unreadable],
                true,
                true,
                false,
            ),
            ("jdk incomplete", vec![missing], false, true, false),
            ("jdk uncertified", vec![missing], true, false, false),
        ];
        let mut cases = cases;
        for (name, admitted) in [
            ("filesystem missing", true),
            ("filesystem removed", true),
            ("filesystem prior warning", true),
            ("filesystem malformed", false),
            // Windows reports a path below a regular file as not found, so the
            // probe is absent rather than unreadable and the missing jar is
            // the sole failure.
            ("filesystem probe", cfg!(windows)),
        ] {
            cases.push((name, Vec::new(), true, true, admitted));
        }
        for (name, failures, jdk_complete, jdk_certified, admitted) in cases {
            let root = tempfile::tempdir().unwrap();
            let (_, catalog, _, mut source, mut active) = generated_jvm_source(root.path());
            let project = Arc::clone(&source.project);
            let analyzer = crate::analyzer::java::JavaAnalyzer::new(Arc::clone(&project));
            let mut retained_index = None;
            let filesystem = name.starts_with("filesystem").then(|| {
                use brokk_bifrost_core::analyzer::config::{
                    JvmExternalDependencies, JvmMavenCoordinate,
                };
                let repository = root.path().join("repository");
                std::fs::create_dir_all(&repository).unwrap();
                if name == "filesystem malformed" {
                    std::fs::write(root.path().join("pom.xml"), "<project><broken>").unwrap();
                }
                if name == "filesystem probe" {
                    std::fs::write(repository.join("g"), "not a directory").unwrap();
                }
                let config = JvmAnalyzerConfig {
                    external_dependencies: JvmExternalDependencies {
                        coordinates: vec![JvmMavenCoordinate::new("g", "missing", "1")],
                        repository_roots: vec![repository.clone()],
                        ..Default::default()
                    },
                    ..Default::default()
                };
                if name == "filesystem removed" {
                    let jar = repository.join("g/missing/1/missing-1.jar");
                    std::fs::create_dir_all(jar.parent().unwrap()).unwrap();
                    zip::ZipWriter::new(std::fs::File::create(&jar).unwrap())
                        .finish()
                        .unwrap();
                    retained_index = Some(JvmExternalDeclarationIndex::build_for_project(
                        &config,
                        project.as_ref(),
                    ));
                    std::fs::remove_file(jar).unwrap();
                }
                config
            });
            let authority = CauseAuthority {
                filesystem,
                project: Arc::clone(&project),
                failures,
                jdk_complete,
                jdk_certified,
            };
            let ledger = Arc::new(brokk_bifrost_analysis::analyzer::read_ledger::ReadLedger::new());
            source.authority = Arc::new(authority);
            let _request = AnalyzerQueryScope::with_outer_request(&analyzer, OuterRequest::new());
            let _capture = AnalyzerQueryScope::with_read_ledger(&analyzer, Arc::clone(&ledger));
            let result = source.jvm_reader(&active);
            assert_eq!(
                result.is_ok(),
                admitted,
                "{name}: {:?}",
                result.as_ref().err()
            );
            if admitted {
                drop(_capture);
                assert_eq!(
                    result.unwrap().reader.jvm_unresolved_coordinates(),
                    &["g:missing:1"]
                );
                use brokk_bifrost_analysis::analyzer::semantic_model::catalog::{
                    SessionPackSource, SessionPackSourceKind,
                };
                use brokk_bifrost_analysis::analyzer::semantic_model::runtime::{
                    SemanticModelActivationEvidence, SemanticModelActivationRequest,
                    SemanticModelResolutionOutcome, SemanticModelRuntimeLimits,
                    resolve_active_semantic_models,
                };
                use brokk_bifrost_analysis::analyzer::semantic_model::{
                    AuthoredSemanticModelPack, CompilerOptions, compile_pack,
                };
                let mut authored: serde_json::Value =
                    serde_json::from_slice(include_bytes!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/../bifrost-analysis/testdata/semantic-model-packs/declarations-v1.json"
                    )))
                    .unwrap();
                authored["schema_version"] = serde_json::json!(
                    brokk_bifrost_analysis::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION
                );
                authored["compatibility"] = serde_json::json!({});
                authored["ecosystem"] = serde_json::json!("jdk");
                authored["shards"][0]["activation"] = serde_json::json!([{}]);
                authored["shards"][0]["payload"]["types"][0]["name"] =
                    serde_json::json!("java.test.Widget");
                authored["shards"][0]["payload"]["types"][0]["hierarchy"] = serde_json::json!([]);
                let pack = compile_pack(
                    &serde_json::from_value::<AuthoredSemanticModelPack>(authored).unwrap(),
                    &CompilerOptions::default(),
                )
                .unwrap();
                catalog
                    .register_compiled_pack(
                        &pack,
                        &SessionPackSource {
                            kind: SessionPackSourceKind::Embedded,
                            source_id: "10470-test-jdk".into(),
                        },
                    )
                    .unwrap();
                let activation = SemanticModelActivationRequest {
                    bifrost_version: semver::Version::new(0, 15, 2),
                    approximate_standard_libraries: Vec::new(),
                    evidence: vec![SemanticModelActivationEvidence {
                        language: "java".into(),
                        ecosystem: "jdk".into(),
                        package: None,
                        module: None,
                        toolchain: None,
                        target: None,
                        configuration: None,
                        artifact_sha256: None,
                    }],
                    controls: Vec::new(),
                    limits: SemanticModelRuntimeLimits::default(),
                };
                let SemanticModelResolutionOutcome::Ready(resolved) =
                    resolve_active_semantic_models(
                        &catalog,
                        &activation,
                        &CancellationToken::new(),
                    )
                else {
                    panic!("JDK fixture activation ready")
                };
                active = resolved;
                source.catalog = catalog.pinned_catalog_source(
                    &brokk_bifrost_analysis::analyzer::store::cache_budget::StoreCacheBudget::new(
                        &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
                    ),
                );
                active
                    .install_request_source(Some(Arc::new(source)))
                    .unwrap();
                let overlay = Arc::new(brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay::build(
                    &analyzer, &Arc::new(active), &CancellationToken::new(), 64 << 20,
                    &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
                ).unwrap());
                let _lookup_capture =
                    AnalyzerQueryScope::with_read_ledger(&analyzer, Arc::clone(&ledger));
                let index = retained_index
                    .unwrap_or_else(|| Arc::new(JvmExternalDeclarationIndex::default()));
                let mut index = index;
                if name == "filesystem prior warning" {
                    Arc::get_mut(&mut index).unwrap().add_discovery_gap_for_catalog_reader_test(
                        brokk_bifrost_analysis::analyzer::semantic_model::dependency::DependencyPackDiagnostic {
                            severity: brokk_bifrost_analysis::analyzer::semantic_model::dependency::DependencyPackDiagnosticSeverity::Warning,
                            code: super::super::producer_codes::KOTLIN_CLASSIFICATION_INCOMPLETE.code.into(),
                            dependency_id: Some("g:missing:1".into()), location: None,
                            message: "retained Kotlin classification warning".into(),
                        });
                }
                let gaps = std::cell::RefCell::new(Vec::new());
                let recorder = super::super::external::QueryGapRecorder::collecting(&gaps);
                if name == "filesystem removed" {
                    super::super::external::JvmExternalDeclarations::new(index.as_ref(), None)
                        .get(&recorder, "g.Missing");
                    assert!(!format!("{:?}", gaps.borrow()).contains("g:missing:1"));
                    gaps.borrow_mut().clear();
                }
                let surface = super::super::external::JvmExternalDeclarations::new(
                    index.as_ref(),
                    Some(overlay),
                );
                let owner = surface
                    .resolve_canonical_jdk_owner("java.test.Widget")
                    .expect("unshadowable JDK fixture owner");
                assert!(
                    surface
                        .resolve_model_signature_type(&recorder, "java.test.Widget", Some(&owner))
                        .is_some()
                );
                assert!(
                    !format!("{:?}", gaps.borrow()).contains("g:missing:1"),
                    "{name}: JDK lookup {:?}",
                    gaps.borrow()
                );
                surface.get(&recorder, "g.Missing");
                assert!(
                    format!("{:?}", gaps.borrow()).contains("g:missing:1"),
                    "{name}: {:?}",
                    gaps.borrow()
                );
            }
            assert!(ledger.reuse_refused(), "{name}");
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#10470: an artifact-index hit lost an unavailable request owner's typed incompleteness"
    )]
    fn artifact_hit_reports_open_request_owner() {
        use super::super::external::{
            JvmExternalDeclarationIndex, JvmExternalDeclarations, QueryGapRecorder,
        };
        use brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay;
        use brokk_bifrost_analysis::analyzer::store::model_catalog::RefusingRowReaderSource;
        use brokk_bifrost_core::analyzer::config::{JvmExternalArtifact, JvmExternalDependencies};
        use std::io::Write;
        let root = tempfile::tempdir().unwrap();
        let jar = root.path().join("present-sources.jar");
        let mut zip = zip::ZipWriter::new(std::fs::File::create(&jar).unwrap());
        zip.start_file("g/Present.java", zip::write::SimpleFileOptions::default())
            .unwrap();
        zip.write_all(b"package g; public class Present {}")
            .unwrap();
        zip.finish().unwrap();
        let index = JvmExternalDeclarationIndex::build(
            &JvmExternalDependencies {
                artifact_paths: vec![JvmExternalArtifact {
                    artifact_path: jar,
                    ..Default::default()
                }],
                ..Default::default()
            },
            root.path(),
        );
        for open in [
            FamilyOpen::jvm("JVM selection incomplete"),
            FamilyOpen::jvm_cancelled(),
        ] {
            let (_, _catalog, _, source, mut active) = generated_jvm_source(root.path());
            let analyzer = crate::analyzer::java::JavaAnalyzer::new(Arc::clone(&source.project));
            active
                .install_request_source(Some(Arc::new(RefusingRowReaderSource { reason: open })))
                .unwrap();
            let overlay = SemanticModelOverlay::build(
                &analyzer,
                &Arc::new(active),
                &CancellationToken::new(),
                64 << 20,
                &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
            )
            .unwrap();
            let gaps = std::cell::RefCell::new(Vec::new());
            let recorder = QueryGapRecorder::collecting(&gaps);
            let surface = JvmExternalDeclarations::new(&index, Some(Arc::new(overlay)));
            assert!(surface.get(&recorder, "g.Present").is_some());
            assert!(
                gaps.borrow()
                    .contains(&SemanticModelOverlay::open_read_incompleteness(open)),
                "{:?}",
                gaps.borrow()
            );
        }
    }

    /// A fixed-key generated-production authority for request-reader tests.
    struct Authority {
        project: Arc<dyn Project>,
        key: GeneratedProductionKey,
        complete: bool,
    }
    impl ExternalSelectionAuthority for Authority {
        fn questions(&self) -> Vec<ExternalSelectionQuestion> {
            vec![
                ExternalSelectionQuestion {
                    kind: ExternalSelectionQuestionKind::Dependencies,
                    digest: [1; 32],
                    uncertified: false,
                },
                ExternalSelectionQuestion {
                    kind: ExternalSelectionQuestionKind::Jdk,
                    digest: [2; 32],
                    uncertified: true,
                },
            ]
        }
        fn answer(
            &self,
            request: &OuterRequest,
            question: &ExternalSelectionQuestion,
            _: &SelectionRetry,
            _cancellation: &CancellationToken,
        ) -> Result<Arc<VerifiedSelection>, SelectionRefused> {
            request.external_selection(self.project.as_ref(), question.digest, || {
                let records: Arc<dyn std::any::Any + Send + Sync> = match question.kind {
                    ExternalSelectionQuestionKind::Dependencies => Arc::new(Some(
                        ExternalInventorySelection::empty_for_catalog_reader_test()
                            .with_generated_key_for_catalog_reader_test(self.key.clone()),
                    )),
                    ExternalSelectionQuestionKind::Jdk => Arc::new(
                        super::super::external::JvmExternalDeclarationIndex::select_jdk(
                            &JvmAnalyzerConfig::default(),
                            self.project.as_ref(),
                            &super::super::external::test_digests(),
                            None,
                        )
                        .unwrap(),
                    ),
                };
                Ok(VerifiedSelection {
                    question_digest: question.digest,
                    answer_digest: question.digest,
                    view_stamp: self.project.view_stamp(),
                    certified: false,
                    complete: self.complete,
                    records,
                })
            })
        }
    }

    /// A generated JVM production installed in a fresh catalog under `root`,
    /// a real request source over an ephemeral analyzer store, and an empty
    /// activation.
    fn generated_jvm_source(
        root: &std::path::Path,
    ) -> (
        brokk_bifrost_analysis::analyzer::semantic_model::CompiledSemanticModelPack,
        SemanticPackCatalog,
        GeneratedProductionKey,
        JvmRequestRowReaderSource,
        ResolvedActiveSemanticModels,
    ) {
        use brokk_bifrost_analysis::analyzer::semantic_model::{
            AuthoredSemanticModelPack, CompilerOptions, compile_pack,
        };
        use brokk_bifrost_analysis::analyzer::store::active_models::{
            MatcherIndexes, SemanticModelActivationReport,
        };
        use serde_json::{Value as JsonValue, json};
        let mut source: JsonValue = serde_json::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../bifrost-analysis/testdata/semantic-model-packs/declarations-v1.json"
        )))
        .unwrap();
        source["schema_version"] =
            json!(brokk_bifrost_analysis::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION);
        source["compatibility"] = json!({});
        source["shards"][0]["activation"] = json!([{}]);
        let pack = compile_pack(
            &serde_json::from_value::<AuthoredSemanticModelPack>(source).unwrap(),
            &CompilerOptions::default(),
        )
        .unwrap();
        let catalog =
            SemanticPackCatalog::open(root, CatalogOpenMode::ReadWrite, CatalogOptions::default())
                .unwrap();
        let key = GeneratedProductionKey::new(
            "a".repeat(64),
            "artifact-scanner",
            "2.0.0",
            brokk_bifrost_analysis::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION,
        )
        .unwrap();
        catalog.install_generated(&key, &pack).unwrap();
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root, Language::Java));
        let source = JvmRequestRowReaderSource {
            authority: Arc::new(Authority {
                project: Arc::clone(&project),
                key: key.clone(),
                complete: true,
            }),
            project,
            catalog: catalog.pinned_catalog_source(
                &brokk_bifrost_analysis::analyzer::store::cache_budget::StoreCacheBudget::new(
                    &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
                ),
            ),
            store: Arc::new(AnalyzerStore::open_ephemeral().unwrap()),
        };
        let activation = ResolvedActiveSemanticModels::new(
            "generated-jvm-test".into(),
            None,
            Vec::new(),
            MatcherIndexes::default(),
            Vec::new(),
            Default::default(),
            Default::default(),
            SemanticModelActivationReport::default(),
        );
        (pack, catalog, key, source, activation)
    }

    #[test]
    #[hardwon(
        "#9559: the JVM bind admitted a provider whose projection publication was unavailable"
    )]
    fn request_source_refuses_unavailable_provider_publication() {
        let root = tempfile::tempdir().unwrap();
        let (pack, _catalog, _key, source, mut activation) = generated_jvm_source(root.path());
        // Admit the production through an evaluated exclusion, as
        // request_source_opens_family_when_provider_publication_is_not_writable
        // does, so that without the refusal this bind is Ready.
        activation.excluded_shards =
            brokk_bifrost_analysis::analyzer::store::active_models::ActivationExclusions::new(
                [(
                    pack.manifest.content_sha256.clone(),
                    "declarations.widget".into(),
                )]
                .into(),
            );
        let analyzer = crate::analyzer::java::JavaAnalyzer::new(Arc::clone(&source.project));
        let request = OuterRequest::new();
        let cancellation = CancellationToken::new();
        let selections = source
            .authority
            .questions()
            .iter()
            .map(|question| {
                source
                    .authority
                    .answer(
                        &request,
                        question,
                        &SelectionRetry::default(),
                        &cancellation,
                    )
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let jdk = selections[1].records.downcast_ref::<SelectedJdk>().unwrap();
        // The bind finds this request's handle, so its publication cache is
        // where an Unavailable outcome can be placed: a writable store always
        // produces a projection.
        let handle = open_jvm_catalog_reader(
            &request,
            Arc::clone(&source.project),
            &source.catalog,
            &selections[0],
            &selections[1],
            jdk.catalog_expectations(),
            CuratedAuthority {
                admitted_digest: activation.indexes.admission().curated,
                shards: Vec::new(),
            },
            view_digest(&request_owned_view(&activation)),
            cancellation,
        )
        .unwrap();
        let ordinal = handle
            .reader
            .membership
            .iter()
            .find(|row| row.kind == CatalogPackSourceKind::Generated)
            .unwrap()
            .ordinal;
        *handle.provider_outcomes.lock().unwrap() =
            Some(vec![(ordinal, ProviderPublication::Unavailable)]);
        let _scope = AnalyzerQueryScope::with_outer_request(&analyzer, request);
        assert_eq!(
            source.jvm_reader(&activation).err(),
            Some(FamilyOpen::jvm("JVM provider publication unavailable"))
        );
    }

    #[test]
    #[hardwon("#9559: conflicting provider certificates admitted a Ready reader")]
    fn request_source_opens_family_when_provider_publication_is_not_writable() {
        use brokk_bifrost_analysis::analyzer::store::writer::StoreWriter;
        let root = tempfile::tempdir().unwrap();
        let (pack, catalog, key, source, mut activation) = generated_jvm_source(root.path());
        let StoreWriter::Local(writer) = &source.store.conn else {
            panic!("ephemeral writer")
        };
        writer
            .lock()
            .unwrap()
            .execute_batch("PRAGMA query_only=ON")
            .unwrap();
        let analyzer = crate::analyzer::java::JavaAnalyzer::new(Arc::clone(&source.project));
        let incomplete = JvmRequestRowReaderSource {
            authority: Arc::new(Authority {
                project: Arc::clone(&source.project),
                key: key.clone(),
                complete: false,
            }),
            project: Arc::clone(&source.project),
            catalog: source.catalog.clone(),
            store: Arc::clone(&source.store),
        };
        {
            let _scope = AnalyzerQueryScope::with_outer_request(&analyzer, OuterRequest::new());
            assert_eq!(
                incomplete.jvm_reader(&activation).err(),
                Some(FamilyOpen::jvm("JVM selection incomplete"))
            );
        }
        let _scope = AnalyzerQueryScope::with_outer_request(&analyzer, OuterRequest::new());
        assert_eq!(
            source.jvm_reader(&activation).err(),
            Some(FamilyOpen::jvm("analyzer store not writable"))
        );
        drop(_scope);
        writer
            .lock()
            .unwrap()
            .execute_batch("PRAGMA query_only=OFF")
            .unwrap();
        let _scope = AnalyzerQueryScope::with_outer_request(&analyzer, OuterRequest::new());
        assert_eq!(
            source.jvm_reader(&activation).err(),
            Some(FamilyOpen::jvm("JVM selection outside the activation"))
        );
        activation.excluded_shards =
            brokk_bifrost_analysis::analyzer::store::active_models::ActivationExclusions::new(
                [(
                    pack.manifest.content_sha256.clone(),
                    "declarations.widget".into(),
                )]
                .into(),
            );
        source
            .jvm_reader(&activation)
            .expect("evaluated exclusion permits a selected production");
        // The active hash is unchanged: membership must also key exclusions.
        activation.excluded_shards = Default::default();
        assert_eq!(
            source.jvm_reader(&activation).err(),
            Some(FamilyOpen::jvm("JVM selection outside the activation"))
        );
        drop(_scope);
        let conflicting_key = GeneratedProductionKey::new(
            "c".repeat(64),
            "artifact-scanner",
            "2.0.0",
            brokk_bifrost_analysis::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION,
        )
        .unwrap();
        catalog.install_generated(&conflicting_key, &pack).unwrap();
        let conflicting = JvmRequestRowReaderSource {
            authority: Arc::new(Authority {
                project: Arc::clone(&source.project),
                key: conflicting_key,
                complete: true,
            }),
            project: Arc::clone(&source.project),
            catalog: source.catalog.clone(),
            store: Arc::clone(&source.store),
        };
        let _scope = AnalyzerQueryScope::with_outer_request(&analyzer, OuterRequest::new());
        assert_eq!(
            conflicting.jvm_reader(&activation).err(),
            Some(FamilyOpen::jvm("JVM provider certificate conflict"))
        );
        drop(_scope);
        let missing = JvmRequestRowReaderSource {
            authority: Arc::new(Authority {
                project: Arc::clone(&source.project),
                key: GeneratedProductionKey::new(
                    "b".repeat(64),
                    "artifact-scanner",
                    "2.0.0",
                    brokk_bifrost_analysis::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION,
                )
                .unwrap(),
                complete: true,
            }),
            project: Arc::clone(&source.project),
            catalog: source.catalog.clone(),
            store: Arc::clone(&source.store),
        };
        let _scope = AnalyzerQueryScope::with_outer_request(&analyzer, OuterRequest::new());
        assert_eq!(
            missing.jvm_reader(&activation).err(),
            Some(FamilyOpen::jvm("JVM selection shards unavailable"))
        );
    }

    #[test]
    #[hardwon(
        "#9559: an excluded generated shard's published provider, named by an active shard's semantic digest, let its declarations resolve as complete, and a request's second activation with another view was refused or reached the first view's handle"
    )]
    fn request_reader_view_holds_only_the_activation_shards() {
        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::statements;
        use brokk_bifrost_analysis::analyzer::semantic_model::runtime::{
            SemanticModelActivationEvidence, SemanticModelActivationRequest,
            SemanticModelRuntimeLimits, SemanticModelRuntimeOutcome,
            acquire_eager_semantic_models_with_request_owner_for_test,
        };
        use brokk_bifrost_analysis::analyzer::semantic_model::{
            AuthoredSemanticModelPack, CompilerOptions, compile_pack,
        };
        use brokk_bifrost_analysis::analyzer::store::active_models::{
            MatcherIndexes, SemanticModelActivationReport,
        };
        use serde_json::{Value as JsonValue, json};

        // One generated production, two shards: "widget" matches the evidence and
        // "gadget" requires a package the evidence lacks, so the activation excludes it.
        let mut authored: JsonValue = serde_json::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../bifrost-analysis/testdata/semantic-model-packs/declarations-v1.json"
        )))
        .unwrap();
        authored["schema_version"] =
            json!(brokk_bifrost_analysis::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION);
        authored["compatibility"] = json!({});
        authored["shards"][0]["activation"] = json!([{}]);
        let gadget: JsonValue = serde_json::from_str(
            &authored["shards"][0]
                .to_string()
                .replace("widget", "gadget")
                .replace("Widget", "Gadget"),
        )
        .unwrap();
        authored["shards"].as_array_mut().unwrap().push(gadget);
        authored["shards"][1]["activation"] = json!([{
            "package": { "name": "com.acme:gadget", "version": ">=1.0.0, <2.0.0" },
            "targets": ["jvm"],
            "configurations": ["release"]
        }]);
        let pack = compile_pack(
            &serde_json::from_value::<AuthoredSemanticModelPack>(authored).unwrap(),
            &CompilerOptions::default(),
        )
        .unwrap();
        let root = tempfile::tempdir().unwrap();
        let catalog = SemanticPackCatalog::open(
            root.path(),
            CatalogOpenMode::ReadWrite,
            CatalogOptions::default(),
        )
        .unwrap();
        let key = GeneratedProductionKey::new(
            "a".repeat(64),
            "artifact-scanner",
            "2.0.0",
            brokk_bifrost_analysis::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION,
        )
        .unwrap();
        catalog.install_generated(&key, &pack).unwrap();
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root.path(), Language::Java));
        let analyzer = crate::analyzer::java::JavaAnalyzer::new(Arc::clone(&project));
        let request = SemanticModelActivationRequest {
            bifrost_version: semver::Version::new(0, 15, 1),
            approximate_standard_libraries: Vec::new(),
            evidence: vec![SemanticModelActivationEvidence {
                language: "java".into(),
                ecosystem: "maven".into(),
                package: None,
                module: None,
                toolchain: None,
                target: None,
                configuration: None,
                artifact_sha256: None,
            }],
            controls: Vec::new(),
            limits: SemanticModelRuntimeLimits::default(),
        };
        let SemanticModelRuntimeOutcome::Ready { active, .. } =
            acquire_eager_semantic_models_with_request_owner_for_test(
                &analyzer,
                &catalog,
                &request,
                &CancellationToken::new(),
                true,
            )
        else {
            panic!("generated production activation ready")
        };
        let owned = active
            .shards
            .iter()
            .filter(|shard| {
                brokk_bifrost_analysis::analyzer::store::active_models::shard_owner_index(
                    shard,
                    None,
                    Some(0),
                ) == Some(0)
            })
            .collect::<Vec<_>>();
        assert_eq!(owned.len(), 1, "{:?}", active.report);
        assert_eq!(owned[0].descriptor.shard_id, "declarations.widget");
        assert!(
            active
                .excluded_shards
                .contains(&pack.manifest.content_sha256, "declarations.gadget"),
            "{:?}",
            active.report
        );

        let store = Arc::new(AnalyzerStore::open_ephemeral().unwrap());
        let source = JvmRequestRowReaderSource {
            authority: Arc::new(Authority {
                project: Arc::clone(&project),
                key,
                complete: true,
            }),
            project,
            catalog: catalog.pinned_catalog_source(
                &brokk_bifrost_analysis::analyzer::store::cache_budget::StoreCacheBudget::new(
                    &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
                ),
            ),
            store,
        };
        let _scope = AnalyzerQueryScope::with_outer_request(&analyzer, OuterRequest::new());
        assert_eq!(
            source.jvm_reader(&active).err(),
            Some(FamilyOpen::jvm("JVM production partially excluded"))
        );

        // Evidence for the gadget package activates the whole production. Its
        // view differs from the wholly excluded activation below, and both bind
        // in the same request: each view opens its own handle.
        let mut whole_request = request.clone();
        whole_request
            .evidence
            .push(SemanticModelActivationEvidence {
                language: "java".into(),
                ecosystem: "maven".into(),
                package: Some(
                    brokk_bifrost_analysis::analyzer::semantic_model::catalog::CatalogCoordinate {
                        name: "com.acme:gadget".into(),
                        version: Some(semver::Version::new(1, 2, 0)),
                    },
                ),
                module: None,
                toolchain: None,
                target: Some("jvm".into()),
                configuration: Some("release".into()),
                artifact_sha256: None,
            });
        let SemanticModelRuntimeOutcome::Ready { active: whole, .. } =
            acquire_eager_semantic_models_with_request_owner_for_test(
                &analyzer,
                &catalog,
                &whole_request,
                &CancellationToken::new(),
                true,
            )
        else {
            panic!("whole production activation ready")
        };
        assert_eq!(
            whole
                .shards
                .iter()
                .filter(|shard| {
                    brokk_bifrost_analysis::analyzer::store::active_models::shard_owner_index(
                        shard,
                        None,
                        Some(0),
                    ) == Some(0)
                })
                .count(),
            2,
            "{:?}",
            whole.report
        );
        let whole_rows = |source: &JvmRequestRowReaderSource| {
            let reader = source.jvm_reader(&whole).expect("whole production binds");
            reader
                .reader
                .owned_rows(
                    statements::SEARCH_TYPE_IDENTITIES,
                    &[],
                    &CancellationToken::new(),
                )
                .unwrap()
                .rows
                .len()
        };
        let whole_before = whole_rows(&source);
        assert!(whole_before > 0);

        // Excluding the entire production is safe: no active shard selects its
        // published provider, and the narrowed catalog view must be empty.
        let other = ResolvedActiveSemanticModels::new(
            whole.active_model_set_hash().to_owned(),
            None,
            Vec::new(),
            MatcherIndexes::build(
                &active.shards,
                SemanticModelRuntimeLimits::default(),
                &CancellationToken::new(),
                &mut SemanticModelActivationReport::default(),
            )
            .unwrap(),
            Vec::new(),
            Default::default(),
            brokk_bifrost_analysis::analyzer::store::active_models::ActivationExclusions::new(
                [
                    (
                        pack.manifest.content_sha256.clone(),
                        "declarations.widget".into(),
                    ),
                    (
                        pack.manifest.content_sha256.clone(),
                        "declarations.gadget".into(),
                    ),
                ]
                .into(),
            ),
            SemanticModelActivationReport::default(),
        );
        let reader = source
            .jvm_reader(&other)
            .expect("wholly excluded production binds");
        let handle = &reader.reader;
        let cancellation = CancellationToken::new();
        let rows = handle
            .owned_rows(statements::SEARCH_TYPE_IDENTITIES, &[], &cancellation)
            .unwrap();
        assert!(rows.rows.is_empty(), "excluded production rows: {rows:?}");
        let raw = (&**handle as &dyn CatalogRowReader)
            .raw_rows(
                statements::SEARCH_TYPE_IDENTITIES,
                &[],
                &other.shards,
                |row| row.get::<_, i64>("record_key"),
            )
            .expect("wholly excluded rows are absent from the active view");
        assert!(raw.is_empty());
        assert_eq!(whole_rows(&source), whole_before);
        assert_eq!(
            source.jvm_reader(&active).err(),
            Some(FamilyOpen::jvm("JVM production partially excluded"))
        );

        // The same contents as a higher-precedence workspace pack: its widget shard
        // is active (activation-owned), and the generated production is wholly
        // excluded (widget shadowed, gadget unmatched). The workspace shard still
        // names the generated production's published provider by semantic digest,
        // which carries gadget, so the bind fails closed.
        catalog
            .register_session_pack(
                &pack,
                &brokk_bifrost_analysis::analyzer::semantic_model::catalog::SessionPackSource {
                    kind: brokk_bifrost_analysis::analyzer::semantic_model::catalog::SessionPackSourceKind::EphemeralWorkspace,
                    source_id: "workspace-copy".into(),
                },
            )
            .unwrap();
        let SemanticModelRuntimeOutcome::Ready {
            active: shadowed, ..
        } = acquire_eager_semantic_models_with_request_owner_for_test(
            &analyzer,
            &catalog,
            &request,
            &CancellationToken::new(),
            true,
        )
        else {
            panic!("workspace-shadowed activation ready")
        };
        assert!(
            shadowed
                .shards
                .iter()
                .all(|shard| shard.source_kind == CatalogPackSourceKind::EphemeralWorkspace),
            "{:?}",
            shadowed.report
        );
        assert_eq!(
            source.jvm_reader(&shadowed).err(),
            Some(FamilyOpen::jvm("JVM production partially excluded"))
        );
    }

    #[test]
    fn generated_provider_publication_and_status() {
        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::GeneratedProductionKey;
        use brokk_bifrost_analysis::analyzer::semantic_model::{
            AuthoredSemanticModelPack, CompilerOptions, compile_pack,
        };
        use brokk_bifrost_analysis::analyzer::store::writer::StoreWriter;
        use serde_json::{Value as JsonValue, json};

        let mut source: JsonValue = serde_json::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../bifrost-analysis/testdata/semantic-model-packs/declarations-v1.json"
        )))
        .unwrap();
        source["schema_version"] =
            json!(brokk_bifrost_analysis::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION);
        source["compatibility"] = json!({});
        source["shards"][0]["activation"] = json!([{}]);
        let pack = compile_pack(
            &serde_json::from_value::<AuthoredSemanticModelPack>(source).unwrap(),
            &CompilerOptions::default(),
        )
        .unwrap();
        let root = tempfile::tempdir().unwrap();
        let catalog = SemanticPackCatalog::open(
            root.path(),
            CatalogOpenMode::ReadWrite,
            CatalogOptions::default(),
        )
        .unwrap();
        let key = GeneratedProductionKey::new(
            "a".repeat(64),
            "artifact-scanner",
            "2.0.0",
            brokk_bifrost_analysis::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION,
        )
        .unwrap();
        catalog.install_generated(&key, &pack).unwrap();
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root.path(), Language::Java));
        let selection = |digest, records: Arc<dyn std::any::Any + Send + Sync>| VerifiedSelection {
            question_digest: [1; 32],
            answer_digest: digest,
            view_stamp: project.view_stamp(),
            certified: false,
            complete: true,
            records,
        };
        let dependencies = selection(
            [2; 32],
            Arc::new(Some(
                ExternalInventorySelection::empty_for_catalog_reader_test(),
            )),
        );
        let jdk = selection([3; 32], Arc::new(()));
        let open = |production_digest: String| {
            let request = OuterRequest::new();
            let handle = open_jvm_catalog_reader(
                &request,
                Arc::clone(&project),
                &catalog.pinned_catalog_source(
                    &brokk_bifrost_analysis::analyzer::store::cache_budget::StoreCacheBudget::new(
                        &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
                    ),
                ),
                &dependencies,
                &jdk,
                vec![
                    ExpectedCatalogEntry::Production { production_digest },
                    ExpectedCatalogEntry::MissingProduction,
                ],
                CuratedAuthority {
                    admitted_digest: [4; 32],
                    shards: vec![],
                },
                [0; 32],
                CancellationToken::new(),
            )
            .unwrap();
            (request, handle)
        };
        let (_request, handle) = open(key.production_digest().to_owned());
        let store = AnalyzerStore::open_ephemeral().unwrap();
        let token = CancellationToken::new();
        assert_eq!(
            handle.provider_certificate_status(&store, &token).unwrap(),
            vec![
                (0, ProviderPublication::Unavailable),
                (1, ProviderPublication::Missing)
            ]
        );
        let count = || -> i64 {
            store
                .read_conn()
                .unwrap()
                .query_row(
                    "SELECT count(*) FROM jvm_external_provider_publications",
                    [],
                    |row| row.get(0),
                )
                .unwrap()
        };
        assert_eq!(count(), 0);
        assert_eq!(
            handle.publish_providers(&store, &token).unwrap(),
            vec![
                (0, ProviderPublication::Certified),
                (1, ProviderPublication::Missing)
            ]
        );
        assert_eq!(count(), 1);
        assert_eq!(
            handle.publish_providers(&store, &token).unwrap(),
            vec![
                (0, ProviderPublication::Certified),
                (1, ProviderPublication::Missing)
            ]
        );
        assert_eq!(count(), 1);
        assert_eq!(
            handle.provider_certificate_status(&store, &token).unwrap()[0].1,
            ProviderPublication::Certified
        );

        let unwritable = AnalyzerStore::open_ephemeral().unwrap();
        let StoreWriter::Local(writer) = &unwritable.conn else {
            panic!("ephemeral test store has a local writer")
        };
        writer
            .lock()
            .unwrap()
            .execute_batch("PRAGMA query_only=ON")
            .unwrap();
        let Err(JvmCatalogReaderError::Store(error)) =
            handle.publish_providers(&unwritable, &token)
        else {
            panic!("provider publication must fail on a read-only store")
        };
        assert_eq!(
            error.kind(),
            brokk_bifrost_analysis::analyzer::store::StoreErrorKind::NotWritable
        );

        // The semantic SHA is the provider key. A different immutable production
        // under that key conflicts with its sealed source identity.
        let other = GeneratedProductionKey::new(
            "b".repeat(64),
            "artifact-scanner",
            "2.0.0",
            brokk_bifrost_analysis::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION,
        )
        .unwrap();
        catalog.install_generated(&other, &pack).unwrap();
        let (_second_request, second) = open(other.production_digest().to_owned());
        assert_eq!(
            second.publish_providers(&store, &token).unwrap()[0].1,
            ProviderPublication::Conflict
        );
        assert_eq!(count(), 1);
        assert_eq!(
            handle.provider_certificate_status(&store, &token).unwrap()[0].1,
            ProviderPublication::Certified
        );
    }

    /// The two readers that serve one row site must agree: the activation's
    /// reader and a request's pinned reader over the same shard answer a keyed
    /// question and a whole-table scan with the same rows.
    #[test]
    fn activation_and_pinned_readers_return_the_same_rows() {
        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::{
            SessionPackSource, SessionPackSourceKind, statements,
        };
        use brokk_bifrost_analysis::analyzer::semantic_model::{
            AuthoredSemanticModelPack, CompilerOptions, compile_pack,
        };
        use serde_json::{Value as JsonValue, json};
        let mut source: JsonValue = serde_json::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../bifrost-analysis/testdata/semantic-model-packs/declarations-v1.json"
        )))
        .unwrap();
        source["schema_version"] =
            json!(brokk_bifrost_analysis::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION);
        source["compatibility"] = json!({});
        source["shards"][0]["activation"] = json!([{}]);
        let pack = compile_pack(
            &serde_json::from_value::<AuthoredSemanticModelPack>(source).unwrap(),
            &CompilerOptions::default(),
        )
        .unwrap();
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        catalog
            .register_compiled_pack(
                &pack,
                &SessionPackSource {
                    kind: SessionPackSourceKind::EphemeralWorkspace,
                    source_id: "reader-parity".into(),
                },
            )
            .unwrap();
        let manifest_digest = pack.manifest.content_sha256.clone();
        let shard_id = pack.manifest.shards[0].shard_id.clone();
        let activation = catalog
            .runtime_source_reader([(
                manifest_digest.as_str(),
                shard_id.as_str(),
                CatalogPackSourceKind::EphemeralWorkspace,
            )])
            .unwrap();
        let root = tempfile::tempdir().unwrap();
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root.path(), Language::Java));
        let selection = |digest, records: Arc<dyn std::any::Any + Send + Sync>| VerifiedSelection {
            question_digest: [1; 32],
            answer_digest: digest,
            view_stamp: project.view_stamp(),
            certified: false,
            complete: true,
            records,
        };
        let dependencies = selection(
            [2; 32],
            Arc::new(Some(
                ExternalInventorySelection::empty_for_catalog_reader_test(),
            )),
        );
        let jdk = selection([3; 32], Arc::new(()));
        let request = OuterRequest::new();
        let handle = open_jvm_catalog_reader(
            &request,
            project,
            &catalog.pinned_catalog_source(
                &brokk_bifrost_analysis::analyzer::store::cache_budget::StoreCacheBudget::new(
                    &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
                ),
            ),
            &dependencies,
            &jdk,
            Vec::new(),
            CuratedAuthority {
                admitted_digest: [4; 32],
                shards: vec![CuratedShard {
                    kind: CatalogPackSourceKind::EphemeralWorkspace,
                    manifest_digest,
                    shard_id,
                }],
            },
            [0; 32],
            CancellationToken::new(),
        )
        .unwrap();
        let cancellation = CancellationToken::new();
        let rows = |reader: &dyn CatalogRowReader,
                    statement: &str,
                    bindings: &[(&str, &dyn rusqlite::ToSql)]| {
            let rows = reader
                .owned_rows(statement, bindings, &cancellation)
                .unwrap();
            let mut values = rows
                .rows
                .iter()
                .map(|row| format!("{row:?}"))
                .collect::<Vec<_>>();
            values.sort();
            (rows.columns, values)
        };
        type Bindings<'a> = &'a [(&'a str, &'a dyn rusqlite::ToSql)];
        let cases: [(&str, Bindings); 2] = [
            (
                statements::TYPES_BY_ID,
                rusqlite::named_params! { ":id": "type.widget" },
            ),
            (statements::SEARCH_TYPE_IDENTITIES, &[]),
        ];
        for (statement, bindings) in cases {
            let expected = rows(&activation, statement, bindings);
            assert!(!expected.1.is_empty(), "{statement}: fixture has rows");
            assert_eq!(
                rows(handle.as_ref(), statement, bindings),
                expected,
                "{statement}"
            );
        }
    }

    #[test]
    fn pinned_declaration_projection_matches_decoded_facts() {
        use brokk_bifrost_analysis::analyzer::semantic_model::catalog::{
            SessionPackSource, SessionPackSourceKind, validate_pack,
        };
        use brokk_bifrost_analysis::analyzer::semantic_model::{
            AuthoredSemanticModelPack, CompilerOptions, DecodeLimits, compile_pack,
        };
        use serde_json::{Value as JsonValue, json};
        let mut source: JsonValue = serde_json::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../bifrost-analysis/testdata/semantic-model-packs/declarations-v1.json"
        )))
        .unwrap();
        source["schema_version"] =
            json!(brokk_bifrost_analysis::analyzer::semantic_model::SEMANTIC_MODEL_SCHEMA_VERSION);
        source["compatibility"] = json!({});
        source["shards"][0]["activation"] = json!([{}]);
        let payload = &mut source["shards"][0]["payload"];
        let base = payload["types"][0].clone();
        let member = payload["members"][0].clone();
        payload["types"][0]["hierarchy"] =
            json!([{"hierarchy_kind":"extends","target":{"kind":"declared","id":"type.base"}}]);
        let mut additional = member.clone();
        additional["id"] = json!("member.additional");
        additional["name"] = json!("additional");
        payload["types"][0]["jvm_inventory"] = json!({"callables_complete":true,"values_complete":true,"types_complete":true,"supertypes_complete":true,"supertypes":[{"hierarchy_kind":"extends","target":{"kind":"declared","id":"type.base"}}],"nested_types":[{"name":"Inner","owner_fqn":"com.acme.Widget.Inner","visibility":"public","is_static":true}],"additional_members":[additional]});
        let mut base_owner = base;
        base_owner["id"] = json!("type.base");
        base_owner["name"] = json!("com.acme.Base");
        base_owner["hierarchy"] = json!([]);
        payload["types"].as_array_mut().unwrap().push(base_owner);
        let mut guarded = member;
        guarded["id"] = json!("member.guarded");
        guarded["guard"] = json!({"required_targets":["jvm"]});
        payload["members"].as_array_mut().unwrap().push(guarded);
        let mut guarded_owner = payload["types"][0].clone();
        guarded_owner["id"] = json!("type.guarded");
        guarded_owner["name"] = json!("com.acme.Guarded");
        guarded_owner["guard"] = json!({"required_targets":["jvm"]});
        payload["types"].as_array_mut().unwrap().push(guarded_owner);
        let authored: AuthoredSemanticModelPack = serde_json::from_value(source).unwrap();
        let pack = compile_pack(&authored, &CompilerOptions::default()).unwrap();
        let validated = validate_pack(&pack, &DecodeLimits::default()).unwrap();
        let (types, members, _) = validated.shards[0]
            .decoded
            .payload()
            .declaration_facts()
            .unwrap();
        let expected = jvm_external_projection(
            pack.manifest.semantic_sha256.clone(),
            String::new(),
            types
                .iter()
                .map(AsRef::as_ref)
                .filter(|owner| owner.guard.is_none()),
            members.iter().map(AsRef::as_ref),
            true,
        )
        .unwrap();
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        catalog
            .register_compiled_pack(
                &pack,
                &SessionPackSource {
                    kind: SessionPackSourceKind::EphemeralWorkspace,
                    source_id: "projection-parity".into(),
                },
            )
            .unwrap();
        let root = tempfile::tempdir().unwrap();
        let project: Arc<dyn Project> = Arc::new(TestProject::new(root.path(), Language::Java));
        let selection = |digest, records: Arc<dyn std::any::Any + Send + Sync>| VerifiedSelection {
            question_digest: [1; 32],
            answer_digest: digest,
            view_stamp: project.view_stamp(),
            certified: false,
            complete: true,
            records,
        };
        let dependencies = selection(
            [2; 32],
            Arc::new(Some(
                ExternalInventorySelection::empty_for_catalog_reader_test(),
            )),
        );
        let jdk = selection([3; 32], Arc::new(()));
        let request = OuterRequest::new();
        let handle = open_jvm_catalog_reader(
            &request,
            project,
            &catalog.pinned_catalog_source(
                &brokk_bifrost_analysis::analyzer::store::cache_budget::StoreCacheBudget::new(
                    &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
                ),
            ),
            &dependencies,
            &jdk,
            Vec::new(),
            CuratedAuthority {
                admitted_digest: [4; 32],
                shards: vec![CuratedShard {
                    kind: CatalogPackSourceKind::EphemeralWorkspace,
                    manifest_digest: pack.manifest.content_sha256.clone(),
                    shard_id: pack.manifest.shards[0].shard_id.clone(),
                }],
            },
            [0; 32],
            CancellationToken::new(),
        )
        .unwrap();
        let membership = handle.membership().unwrap();
        let actual = handle
            .external_projection(&membership[0], &CancellationToken::new())
            .unwrap()
            .unwrap();
        assert_eq!(actual.owners.len(), 2);
        assert_eq!(actual.members.len(), 3);
        assert_eq!(actual.supertypes.len(), 1);
        assert_eq!(actual.provider_id, expected.provider_id);
        assert_eq!(actual.owners, expected.owners);
        assert_eq!(actual.members, expected.members);
        assert_eq!(actual.supertypes, expected.supertypes);
    }

    #[test]
    #[hardwon("#9559: a catalog lock after the request guard panicked instead of leaving JVM Open")]
    fn request_keys_lifetime_and_generation() {
        let root = tempfile::tempdir().unwrap();
        let catalog = SemanticPackCatalog::open(
            root.path(),
            CatalogOpenMode::ReadWrite,
            CatalogOptions::default(),
        )
        .unwrap();
        let base: Arc<dyn Project> = Arc::new(TestProject::new(root.path(), Language::Java));
        let overlay = Arc::new(OverlayProject::new(base));
        let project: Arc<dyn Project> = overlay.clone();
        let selection =
            |answer_digest, records: Arc<dyn std::any::Any + Send + Sync>| VerifiedSelection {
                question_digest: [1; 32],
                answer_digest,
                view_stamp: project.view_stamp(),
                certified: false,
                complete: true,
                records,
            };
        let dependencies = selection(
            [2; 32],
            Arc::new(Some(
                ExternalInventorySelection::empty_for_catalog_reader_test(),
            )),
        );
        let jdk = selection([3; 32], Arc::new(()));
        let curated = |digest| CuratedAuthority {
            admitted_digest: digest,
            shards: Vec::new(),
        };
        let request = OuterRequest::new();
        let open = |jdk: &VerifiedSelection, digest| {
            open_jvm_catalog_reader(
                &request,
                project.clone(),
                &catalog.pinned_catalog_source(
                    &brokk_bifrost_analysis::analyzer::store::cache_budget::StoreCacheBudget::new(
                        &brokk_bifrost_core::retention_budget::RetentionBudget::for_tests(),
                    ),
                ),
                &dependencies,
                jdk,
                vec![ExpectedCatalogEntry::MissingProduction],
                curated(digest),
                [0; 32],
                CancellationToken::new(),
            )
            .unwrap()
        };
        let first = open(&jdk, [4; 32]);
        assert_eq!(
            first.membership().unwrap()[0].status,
            PinnedCatalogStatus::Missing
        );
        assert!(Arc::ptr_eq(&first, &open(&jdk, [4; 32])));
        // A separate rollback-journal database gives a deterministic SQLite
        // lock failure after the request guard has already admitted this handle.
        // The catalog connection refuses symlinked paths (SQLITE_OPEN_NOFOLLOW),
        // and macOS temp roots sit under the /var -> /private/var symlink, so
        // attach through the canonical path.
        let locked_path = root.path().canonicalize().unwrap().join("locked.sqlite");
        let locked = rusqlite::Connection::open(&locked_path).unwrap();
        locked
            .execute_batch(
                "CREATE TABLE locked_value(value INTEGER); INSERT INTO locked_value VALUES(1)",
            )
            .unwrap();
        CatalogRowReader::owned_rows(
            first.as_ref(),
            "ATTACH DATABASE :path AS locked",
            &[(":path", &locked_path.to_str().unwrap())],
            &CancellationToken::new(),
        )
        .unwrap();
        CatalogRowReader::owned_rows(
            first.as_ref(),
            "PRAGMA busy_timeout=1",
            &[],
            &CancellationToken::new(),
        )
        .unwrap();
        locked.execute_batch("BEGIN EXCLUSIVE").unwrap();
        assert!(matches!(
            CatalogRowReader::owned_rows(first.as_ref(), "SELECT * FROM locked.locked_value", &[], &CancellationToken::new()),
            Err(CatalogError::FamilyOpen(open)) if open == FamilyOpen::jvm("JVM catalog busy")
        ));
        locked.execute_batch("ROLLBACK").unwrap();
        let changed_jdk = selection([5; 32], Arc::new(()));
        assert!(!Arc::ptr_eq(&first, &open(&changed_jdk, [4; 32])));
        assert!(!Arc::ptr_eq(&first, &open(&jdk, [6; 32])));
        overlay.set(root.path().join("Changed.java"), "class Changed {}".into());
        assert!(matches!(
            first.membership(),
            Err(JvmCatalogReaderError::Stale)
        ));
        request.close();
        assert!(matches!(
            first.membership(),
            Err(JvmCatalogReaderError::Closed)
        ));
        assert!(matches!(
            CatalogRowReader::owned_rows(first.as_ref(), "SELECT 1", &[], &CancellationToken::new()),
            Err(CatalogError::FamilyOpen(open)) if open == FamilyOpen::jvm("JVM catalog reader invalidated")
        ));
    }
}
