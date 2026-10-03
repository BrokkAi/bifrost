//! Bounded typed-fact reads for one exact selected resolution inventory.
//!
//! The source borrows the retained connection and TEMP mount inventory opened
//! by `resolution_selection`. Every keyed request is translated back to exact
//! selected storage coordinates through the operation-local `MountRebaser`;
//! shared semantics are expanded only across the selected mounts. SQL remains
//! selected-first and keyset-paged, and parent rows are emitted only after all
//! ordered children and completion reasons have been decoded.

pub(super) mod go_members;
pub(super) mod java_access;
pub(super) mod java_inheritance;

use std::cell::Cell;
use std::collections::BTreeSet;
use std::rc::Rc;

use rusqlite::types::Value;
use rusqlite::{Connection, Row, params_from_iter};

use crate::CancellationToken;
use crate::analyzer::Language;
use brokk_bifrost_core::analyzer::structural::resolution::DeclaredVisibility;

use crate::analyzer::resolution::{
    BindingFragmentId, BindingNodeId, DeferredMemberOwnerLookupName, LoweredBindingProjection,
    LoweredCallApplicabilityObligation, LoweredCallableSignatureProperty,
    LoweredConstructionRequirementProperty, LoweredDeclarationTypeProperty,
    LoweredDeclarationVisibilityProperty, LoweredDeferredMemberOwner, LoweredDefinitionPropertyGap,
    LoweredIntrinsicSeed, LoweredMemberOwnerProperty, LoweredMemberScopeProperty,
    LoweredRustDeclarationAuthority, LoweredRustReferenceContext, LoweredSupertypeProperty,
    LoweredTypeComponent, LoweredTypeTransfer, LoweredTypedFrontier, LoweredUnderlyingType,
    MAX_TYPED_FACT_ROWS_PER_PAGE, PolledCompletionAccumulator, QualifiedRouteSlotLookup,
    ResolutionCompletion, ResolutionIncompleteReason, RustImplementedTraits,
    SelectedGapReasonProvenance, SelectedNodeProvenance, SelectedQualifiedRoute,
    SelectedResolutionMountOrdinal, SelectedSemanticProvenance, SelectedTypeFrontierCompletion,
    SelectedTypedFactSource, SelectedTypedRow, SemanticId, SharedNameInterner,
    TypedFactPageVisitor, TypedFactReadOutcome, TypedFactRequest,
};

use super::resolution::{TypedFactRelation, with_resolution_read_progress_handler};
use super::resolution_authority::SelectedResolutionAuthority;
use super::resolution_prepare::rust_authority;
use super::resolution_prepare::typed_rows::{self, TypedRowContext};
use super::resolution_selection::{
    SelectedResolutionMountInventory, SelectedResolutionMountRecord, SelectedResolutionReadStamp,
};
use super::{Result as StoreResult, StoreError};

/// The one tier 1 family every typed read's membership comes from: which
/// blobs hold a fact of a named relation under an interned identity.
///
/// There is no name-mention default and no name-mention relation. Asking which
/// blobs *spell* a name returns most of the workspace for an ordinary member
/// name and is the wrong question for a typed read; the relation this family
/// is keyed on is the right one, and a read that has no relation has no
/// membership.
const TYPED_FACT_LOOKUP_FAMILY: &str = "resolution_typed_fact_lookups";

const PAGE_ROWS: usize = MAX_TYPED_FACT_ROWS_PER_PAGE;

pub(super) const FRONTIER_SOURCE_READY_SQL: &str =
    "SELECT 1 FROM main.source_fact_readiness WHERE blob_id=?1 AND available=1";

/// Operation-local typed reader over one retained selected inventory.
pub(crate) struct SelectedResolutionTypedSource<'selection, 'store> {
    selection: &'selection SelectedResolutionMountInventory<'store>,
    selected_interiors_validation_stamp: Cell<Option<SelectedResolutionReadStamp>>,
    authority: Rc<SelectedResolutionAuthority<'selection>>,
}

impl<'selection, 'store> SelectedResolutionTypedSource<'selection, 'store> {
    pub(crate) fn new_on_demand(
        selection: &'selection SelectedResolutionMountInventory<'store>,
    ) -> Self {
        Self::with_authority(
            selection,
            Rc::new(SelectedResolutionAuthority::new(
                selection.connection(),
                selection.shared_name_table(),
                selection.requested_mount_rows(),
                selection.persisted_mount_count(),
                selection.authority_validations(),
            )),
        )
    }

    pub(super) fn with_authority(
        selection: &'selection SelectedResolutionMountInventory<'store>,
        authority: Rc<SelectedResolutionAuthority<'selection>>,
    ) -> Self {
        Self {
            selection,
            selected_interiors_validation_stamp: Cell::new(None),
            authority,
        }
    }

    /// The mounts whose authority can answer a request of this relation keyed
    /// on these semantics.
    ///
    /// `relation` is the question, not a mode: each read asks a different one
    /// of the same `(blob_id, identity_id)` shape, and answering any of them
    /// from "which blobs mention this name" opens every blob in the workspace
    /// that spells the name.
    fn interior_mounts_for_semantics(
        &self,
        semantics: &[SemanticId],
        relation: TypedFactRelation,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<SelectedResolutionMountOrdinal>>> {
        let Some(coordinates) = self.semantic_coordinates(semantics, relation, cancellation)?
        else {
            return Ok(None);
        };
        Ok(Some(
            coordinates
                .into_iter()
                .map(|coordinate| coordinate.mount)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
        ))
    }

    /// The mounts that hold any qualified route at all, inside the request's
    /// scope.
    ///
    /// The route inventory has no lookup to key on: an endpoint with an open
    /// tail and no fixed first symbol has to look at every route there is.
    /// What it does not have to do is open every blob. The route-lookup
    /// relation read with no identity predicate is exactly the question
    /// "which blobs hold a route", and it is exact because a route lookup is
    /// always a shared name recipe, which the writer asserts, so a blob with a
    /// route always has a row. `(blob_id, relation)` is a primary-key prefix.
    ///
    /// This is one of the two reads that can name a blob other than the one
    /// owning the requested identity, so it is one of the two that the request
    /// scope has to bound: with no identity predicate at all it would
    /// otherwise return every selected mount holding a route, dependents
    /// included, and a forward request in crate A can bind in nothing but A's
    /// dependency closure.
    fn interior_mounts_holding_a_qualified_route(
        &self,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<SelectedResolutionMountOrdinal>>> {
        let sql = format!(
            r#"SELECT m.mount_ordinal
               FROM temp.selected_resolution_mounts AS m
               JOIN temp.selected_resolution_scope_mounts AS scope
                 ON scope.mount_ordinal = m.mount_ordinal
               JOIN main.resolution_fragment_interiors AS interior
                 ON interior.blob_id = m.blob_id
                AND interior.lang = m.storage_language
                AND interior.semantic_language = m.semantic_language
                AND interior.producer_epoch = m.producer_epoch
                AND interior.interior_digest = m.interior_digest
                AND interior.publication_state = 'complete'
               WHERE EXISTS (
                 SELECT 1 FROM main.{TYPED_FACT_LOOKUP_FAMILY} AS route
                 WHERE route.blob_id = m.blob_id AND route.relation = {relation}
               )
               ORDER BY m.mount_ordinal"#,
            relation = TypedFactRelation::QualifiedRouteLookup.code(),
        );
        self.read_statement(cancellation, |conn| {
            let mut statement = conn.prepare_cached(&sql)?;
            let mut rows = statement.query([])?;
            let mut mounts = Vec::new();
            while let Some(row) = rows.next()? {
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                mounts.push(mount_ordinal(row, 0, "qualified route inventory mount")?);
            }
            Ok(Some(mounts))
        })
    }

    /// Read metadata for the requested persisted mount.
    fn mount(
        &self,
        ordinal: SelectedResolutionMountOrdinal,
    ) -> StoreResult<std::sync::Arc<SelectedResolutionMountRecord>> {
        self.selection
            .persisted_mount_record(ordinal)?
            .ok_or_else(|| {
                invalid_fact(format!(
                    "selected typed row names unknown mount ordinal {}",
                    ordinal.get()
                ))
            })
    }

    fn read_statement<T>(
        &self,
        cancellation: &CancellationToken,
        job: impl FnOnce(&Connection) -> StoreResult<Option<T>>,
    ) -> StoreResult<Option<T>> {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        match with_resolution_read_progress_handler(self.selection.connection(), cancellation, job)
        {
            Err(error) if error.is_sqlite_interrupted() && cancellation.is_cancelled() => Ok(None),
            Err(error) => Err(error),
            Ok(_) if cancellation.is_cancelled() => Ok(None),
            Ok(result) => Ok(result),
        }
    }

    fn empty_outcome(&self, cancellation: &CancellationToken) -> StoreResult<TypedFactReadOutcome> {
        if cancellation.is_cancelled() || !self.validate_selected_interiors(cancellation)? {
            return Ok(TypedFactReadOutcome::cancelled(
                ResolutionCompletion::Complete,
            ));
        }
        Ok(if !self.validate_selected_interiors(cancellation)? {
            TypedFactReadOutcome::cancelled(ResolutionCompletion::Complete)
        } else {
            TypedFactReadOutcome::exhausted(ResolutionCompletion::Complete)
        })
    }

    fn validate_selected_interiors(&self, cancellation: &CancellationToken) -> StoreResult<bool> {
        let Some(stamp) = self.read_statement(cancellation, |_conn| {
            Ok(Some(self.selection.read_change_stamp()?))
        })?
        else {
            return Ok(false);
        };
        if self.selected_interiors_validation_stamp.get() == Some(stamp) {
            return Ok(!cancellation.is_cancelled());
        }
        let expected = self.selection.persisted_mount_count();
        let Some((rows, complete)) = self.read_statement(cancellation, |conn| {
            let mut statement = conn.prepare_cached(
                r#"SELECT m.mount_ordinal, interior.blob_id
                   FROM temp.selected_resolution_mounts AS m
                   LEFT JOIN main.resolution_fragment_interiors AS interior
                     ON interior.blob_id = m.blob_id
                    AND interior.lang = m.storage_language
                    AND interior.semantic_language = m.semantic_language
                    AND interior.producer_epoch = m.producer_epoch
                    AND interior.interior_digest = m.interior_digest
                    AND interior.publication_state = 'complete'
                    AND EXISTS (
                      SELECT 1 FROM main.source_fact_readiness AS visibility
                      WHERE visibility.blob_id = m.blob_id AND visibility.available = 1
                    )
                   ORDER BY m.mount_ordinal"#,
            )?;
            let mut rows = statement.query([])?;
            let mut decoded = 0_usize;
            while let Some(row) = rows.next()? {
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                let ordinal = mount_ordinal(row, 0, "selected typed sentinel mount")?;
                self.mount(ordinal)?;
                if row.get::<_, Option<i64>>(1)?.is_none() {
                    return Err(invalid_fact(format!(
                        "selected typed mount {} lost its exact complete interior",
                        ordinal.get()
                    )));
                }
                decoded = decoded
                    .checked_add(1)
                    .expect("selected mount count fits usize");
            }
            Ok(Some((decoded, true)))
        })?
        else {
            return Ok(false);
        };
        if !complete || rows != expected {
            return Err(invalid_fact(format!(
                "selected typed sentinel expected {expected} mounts, decoded {rows}"
            )));
        }
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        // Keep the pre-scan stamp: a concurrent commit during validation must
        // cause the next boundary to rescan, not inherit a newer valid stamp.
        self.selected_interiors_validation_stamp.set(Some(stamp));
        Ok(true)
    }

    /// `relation` is what a workspace-shared request resolves its mounts
    /// through: the rows of the one tier 1 family under an interned identity
    /// and that relation. Which relation is the question being asked, not a
    /// mode: see [`TypedFactRelation`].
    fn semantic_coordinates(
        &self,
        identities: &[SemanticId],
        relation: TypedFactRelation,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<RequestCoordinate>>> {
        if identities.is_empty() {
            return Ok(Some(Vec::new()));
        }
        let mut direct = Vec::new();
        let mut shared = Vec::new();
        let names = self
            .selection
            .shared_name_table()
            .interner(self.selection.connection());
        for (request_ordinal, &identity) in identities.iter().enumerate() {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            if matches!(
                relation,
                TypedFactRelation::QualifiedRouteGapReason
                    | TypedFactRelation::CallApplicabilityGapReason
                    | TypedFactRelation::GapReasonProvenanceReason
                    | TypedFactRelation::DefinitionPropertyGapReason
            ) {
                // A gap reason has no catalog row, so no digest can classify
                // it: its key range does. An ordinary reason needs its blob
                // key here; a stage reason keeps its full runtime id and is
                // answered by the stage SQL.
                if let Some((mount, key)) = self.authority.ordinary_gap_reason(identity)? {
                    direct.push(RequestCoordinate::new(
                        request_ordinal,
                        mount,
                        i64::from(key),
                    ));
                }
                continue;
            }
            let provenance = if let Some(name) = identity.shared_name_id() {
                Some(SelectedSemanticProvenance::Shared(
                    crate::analyzer::resolution::ResolutionSemanticIdentity::shared(name),
                ))
            } else {
                let Some(provenance) = self
                    .authority
                    .semantic_catalog_provenance(identity, cancellation)?
                else {
                    return Ok(None);
                };
                provenance
            };
            match provenance {
                Some(SelectedSemanticProvenance::FragmentLocal(local)) => {
                    direct.push(RequestCoordinate::new(
                        request_ordinal,
                        local.mount().ordinal(),
                        local.local_key().get(),
                    ));
                }
                // Only the ordinary arm needs blob keys. The stage arm keeps
                // the original full runtime ID and queries its SQL authority.
                Some(SelectedSemanticProvenance::Stage(_)) => {}
                Some(SelectedSemanticProvenance::Shared(name)) => {
                    let Some(name) = name.shared_name() else {
                        panic!("a shared semantic provenance carries a shared name")
                    };
                    if let Some(stored) = names.to_persisted(name) {
                        shared.push((request_ordinal, stored));
                    }
                }
                None => {}
            }
        }
        if !shared.is_empty() {
            assert!(
                !matches!(
                    relation,
                    TypedFactRelation::RustReferenceContext
                        | TypedFactRelation::RustDeclarationAuthority
                ),
                "{relation:?} has no membership writer in prepare_typed_fact_lookups, \
                 so a shared key for it would name no mount and answer nothing silently"
            );
            let sql = shared_membership_sql(shared.len(), relation);
            let mut parameters = Vec::with_capacity(shared.len() * 2);
            for (ordinal, name) in &shared {
                parameters.push(Value::Integer(
                    i64::try_from(*ordinal).expect("request ordinal fits i64"),
                ));
                parameters.push(Value::Integer(i64::from(name.get())));
            }
            let Some(rows) = self.read_statement(cancellation, |conn| {
                let mut statement = conn.prepare_cached(&sql)?;
                let mut rows = statement.query(params_from_iter(parameters.iter()))?;
                let mut decoded = Vec::new();
                while let Some(row) = rows.next()? {
                    if cancellation.is_cancelled() {
                        return Ok(None);
                    }
                    decoded.push(RequestCoordinate::shared(
                        usize_from_nonnegative(row, 0, "shared request ordinal")?,
                        mount_ordinal(row, 1, "shared semantic mount")?,
                        nonnegative_i64(row, 2, "shared semantic key")?,
                    ));
                }
                Ok(Some(decoded))
            })?
            else {
                return Ok(None);
            };
            #[cfg(test)]
            shared_request_probe::observe(
                relation,
                shared.len(),
                rows.iter()
                    .map(|coordinate| coordinate.mount)
                    .collect::<BTreeSet<_>>()
                    .len(),
            );
            direct.extend(rows);
        }
        direct.sort_unstable();
        direct.dedup();
        Ok(Some(direct))
    }

    fn node_coordinates(
        &self,
        identities: &[BindingNodeId],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<RequestCoordinate>>> {
        let mut coordinates = Vec::with_capacity(identities.len());
        for (request_ordinal, &identity) in identities.iter().enumerate() {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let Some(provenance) = self
                .authority
                .node_catalog_provenance(identity, cancellation)?
            else {
                return Ok(None);
            };
            if provenance.is_none() {
                let Some(registered) = self.read_statement(cancellation, |connection| {
                    Ok(Some(connection.prepare_cached(
                        "SELECT EXISTS(SELECT 1 FROM temp.selected_resolution_stage_nodes WHERE node=?1) \
                         OR EXISTS(SELECT 1 FROM temp.selected_resolution_stage_node_coordinates WHERE runtime_key=?1)",
                    )?.query_row([super::resolution_stage::codec::encode_node(identity)], |row| row.get::<_, bool>(0))?))
                })? else {
                    return Ok(None);
                };
                if registered {
                    // Authority is request-wide; the stage result query applies
                    // the current scope. Catalog-only nodes remain valid too.
                    continue;
                }
            }
            match provenance {
                Some(SelectedNodeProvenance::FragmentLocal(local)) => {
                    coordinates.push(RequestCoordinate::new(
                        request_ordinal,
                        local.mount().ordinal(),
                        local.local_key().get(),
                    ))
                }
                Some(SelectedNodeProvenance::Stage(_)) => {}
                Some(SelectedNodeProvenance::UniversalRoot) => {
                    return Err(invalid_fact(
                        "universal root is not a persisted typed node request",
                    ));
                }
                Some(SelectedNodeProvenance::ContextBoundary) => {
                    return Err(invalid_fact(
                        "Java placement boundary is not a persisted typed node request",
                    ));
                }
                None => {
                    return Err(invalid_fact(format!(
                        "typed request node {identity} has no selected identity provenance"
                    )));
                }
            }
        }
        coordinates.sort_unstable();
        coordinates.dedup();
        Ok(Some(coordinates))
    }
}

/// Which identity space a resolved request key lives in.
///
/// A typed column holds one space and only one (the draft's section 1), and
/// the two spaces number independently: a blob-local catalog position 7 and
/// `resolution_identities.id` 7 are different things. A reader that bound a
/// shared id against a local column would match an unrelated row, so the space
/// travels with the key and each statement takes the keys of its own column's
/// space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum RequestKeySpace {
    /// A blob's own catalog position.
    Local,
    /// A `resolution_identities.id`.
    Shared,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct RequestCoordinate {
    request_ordinal: usize,
    mount: SelectedResolutionMountOrdinal,
    space: RequestKeySpace,
    keys: [i64; 2],
}

impl RequestCoordinate {
    const fn new(request_ordinal: usize, mount: SelectedResolutionMountOrdinal, key: i64) -> Self {
        Self {
            request_ordinal,
            mount,
            space: RequestKeySpace::Local,
            keys: [key, -1],
        }
    }

    const fn shared(
        request_ordinal: usize,
        mount: SelectedResolutionMountOrdinal,
        identity: i64,
    ) -> Self {
        Self {
            request_ordinal,
            mount,
            space: RequestKeySpace::Shared,
            keys: [identity, -1],
        }
    }
}

/// The mounts a workspace-shared typed request names, for `requests`
/// `(request_ordinal, identity_id)` pairs bound in that order.
///
/// Tier 1 keeps the shared slice of the term catalog as `(blob_id,
/// identity_id)` relations, so a shared request names its mounts without
/// opening any blob. Every join is inner: the statement returns one row per
/// mount that the relation actually names, not one row per request per
/// selected mount. A selected mount that lost its exact complete interior
/// drops out here and is reported by `validate_selected_interiors`, which
/// asserts that condition over the whole selection on its own.
///
/// This is the one read that can first put a blob other than the requested
/// identity's owner into a batch, so it is where the request scope belongs:
/// the membership predicate is `(relation, identity_id)` and nothing else, and
/// without the scope join it names every selected blob that holds the relation
/// under that name, dependents of the staged crate included. A reference in
/// crate A can bind only inside A's dependency closure, so those mounts cannot
/// contribute an answer and only cost unnecessary authority reads.
///
/// The mount is found by its blob. Without `INDEXED BY` the planner reached
/// it through the unique `(storage_language, persisted_relative_path)` index
/// with only the language bound, walking every Rust mount for every
/// membership row: on tract (1,027 mounts, 309 rows for the callable `name`)
/// that was about 96 ms a read, 522 reads and 50 s of one usage scan (#3761),
/// against about 1.5 ms through the blob index. `ANALYZE` with the bounded
/// analysis limit the store uses keeps the slow plan, so the plan is fixed
/// here rather than left to statistics.
pub(super) fn shared_membership_sql(requests: usize, relation: TypedFactRelation) -> String {
    let values = values_sql(requests, 2);
    format!(
        r#"WITH requested(request_ordinal, identity_id) AS (VALUES {values})
           SELECT r.request_ordinal, m.mount_ordinal, membership.identity_id
           FROM requested AS r
           JOIN main.{TYPED_FACT_LOOKUP_FAMILY} AS membership
             ON membership.relation = {relation}
            AND membership.identity_id = r.identity_id
           JOIN temp.selected_resolution_mounts AS m
                INDEXED BY selected_resolution_mounts_blob_ordinal
             ON m.blob_id = membership.blob_id
           JOIN temp.selected_resolution_scope_mounts AS scope
             ON scope.mount_ordinal = m.mount_ordinal
           JOIN main.resolution_fragment_interiors AS interior
             ON interior.blob_id = m.blob_id
            AND interior.lang = m.storage_language
            AND interior.semantic_language = m.semantic_language
            AND interior.producer_epoch = m.producer_epoch
            AND interior.interior_digest = m.interior_digest
            AND interior.publication_state = 'complete'
           ORDER BY r.request_ordinal, m.mount_ordinal"#,
        relation = relation.code(),
    )
}

fn values_sql(rows: usize, arity: usize) -> String {
    assert!(rows > 0);
    let mut parameter = 1_usize;
    (0..rows)
        .map(|_| {
            let row = (0..arity)
                .map(|_| {
                    let current = parameter;
                    parameter += 1;
                    format!("?{current}")
                })
                .collect::<Vec<_>>()
                .join(", ");
            format!("({row})")
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn invalid_fact(message: impl Into<String>) -> StoreError {
    StoreError::new(message)
}

fn mount_ordinal(
    row: &Row<'_>,
    index: usize,
    label: &str,
) -> StoreResult<SelectedResolutionMountOrdinal> {
    let value = nonnegative_i64(row, index, label)?;
    let value = u32::try_from(value)
        .map_err(|_| invalid_fact(format!("{label} {value} does not fit u32")))?;
    Ok(SelectedResolutionMountOrdinal::new(value))
}

fn nonnegative_i64(row: &Row<'_>, index: usize, label: &str) -> StoreResult<i64> {
    let value: i64 = row.get(index)?;
    if value < 0 {
        return Err(invalid_fact(format!("{label} cannot be negative: {value}")));
    }
    Ok(value)
}

fn usize_from_nonnegative(row: &Row<'_>, index: usize, label: &str) -> StoreResult<usize> {
    usize::try_from(nonnegative_i64(row, index, label)?)
        .map_err(|_| invalid_fact(format!("{label} does not fit usize")))
}

/// Compose one typed read's membership from the generic family.
///
/// The relation is a required argument. There is no default: a read with no
/// relation has no way to name the blobs that hold its facts, and the
/// name-mention relation that used to stand in for one opened every blob in
/// the workspace that spells the requested name.
/// Test-only accounting for what a workspace-shared typed request resolved to.
///
/// A pin that has to prove a read was *entered* with a shared identity and
/// then opened nothing cannot see either fact from outside the operation: the
/// mount set is consumed inside it, and a read that opens nothing looks
/// exactly like a read that never ran. This records both, per relation, in a
/// fixed-size array of counters on the operation's own thread -- the thread
/// that owns the retained connection `semantic_coordinates` reads through.
#[cfg(test)]
pub(super) mod shared_request_probe {
    use std::cell::Cell;

    use super::TypedFactRelation;

    thread_local! {
        static REQUESTS: [Cell<usize>; TypedFactRelation::COUNT] =
            const { [const { Cell::new(0) }; TypedFactRelation::COUNT] };
        static MOUNTS: [Cell<usize>; TypedFactRelation::COUNT] =
            const { [const { Cell::new(0) }; TypedFactRelation::COUNT] };
    }

    pub(crate) fn reset() {
        REQUESTS.with(|counters| counters.iter().for_each(|counter| counter.set(0)));
        MOUNTS.with(|counters| counters.iter().for_each(|counter| counter.set(0)));
    }

    pub(super) fn observe(relation: TypedFactRelation, requests: usize, mounts: usize) {
        let index = usize::try_from(relation.code()).expect("a relation code is nonnegative");
        REQUESTS.with(|counters| counters[index].set(counters[index].get() + requests));
        MOUNTS.with(|counters| counters[index].set(counters[index].get() + mounts));
    }

    /// Every relation that answered a shared request since the last [`reset`],
    /// with its request and mount counts. A pin prints this when it needs to
    /// say which reads a request actually entered.
    pub(crate) fn observed_all() -> Vec<(&'static str, usize, usize)> {
        TypedFactRelation::ALL
            .iter()
            .map(|relation| {
                let (requests, mounts) = observed(*relation);
                (relation.label(), requests, mounts)
            })
            .filter(|(_, requests, _)| *requests > 0)
            .collect()
    }

    /// The shared requests this relation answered, and the distinct mounts
    /// they resolved to, since the last [`reset`].
    pub(crate) fn observed(relation: TypedFactRelation) -> (usize, usize) {
        let index = usize::try_from(relation.code()).expect("a relation code is nonnegative");
        (
            REQUESTS.with(|counters| counters[index].get()),
            MOUNTS.with(|counters| counters[index].get()),
        )
    }
}

impl SelectedTypedFactSource for SelectedResolutionTypedSource<'_, '_> {
    fn selection_has_java_semantics(&self) -> bool {
        self.selection.has_java_semantics()
    }

    fn rust_crate_access(
        &self,
        crate_key: [u8; 32],
        base_blobs: &[(BindingFragmentId, i64)],
        reference: Option<&SelectedTypedRow<LoweredRustReferenceContext>>,
        definition: Option<&SelectedTypedRow<LoweredRustDeclarationAuthority>>,
    ) -> StoreResult<Option<crate::analyzer::resolution::DeclarationAccessDecision>> {
        super::resolution_operation::rust_crate_access::access(
            self.selection,
            crate_key,
            base_blobs,
            reference,
            definition,
        )
    }

    /// The crate-set visibility decision for one `pub(crate)` route.
    ///
    /// This reads the tier-1 crate rows, not the resolution interior, so it
    /// belongs on the selected typed source whatever the interior serves. The
    /// trait default answers `None`, which is "no decision" and silently
    /// admits a private route, so this override is not optional.
    fn rust_crate_set_access(
        &self,
        crate_key: [u8; 32],
        base_blobs: &[(BindingFragmentId, i64)],
        reference: Option<&SelectedTypedRow<LoweredRustReferenceContext>>,
        definition: Option<&SelectedTypedRow<LoweredRustDeclarationAuthority>>,
    ) -> StoreResult<Option<crate::analyzer::resolution::DeclarationAccessDecision>> {
        super::resolution_operation::rust_crate_access::set_access(
            self.selection,
            crate_key,
            base_blobs,
            reference,
            definition,
        )
    }

    /// Asked of the tier-1 crate rows, like the two access decisions above,
    /// so it belongs on the selected typed source whatever the interior
    /// serves. Only ordinary provenance has persisted crate rows: an owner or
    /// a reference that is staged content is `Unplaced`, never an empty set.
    fn rust_implemented_traits_nameable_at(
        &self,
        owner: SemanticId,
        reference: SemanticId,
        cancellation: &CancellationToken,
    ) -> StoreResult<RustImplementedTraits> {
        // A type identity that belongs to no file is an intrinsic or a shared
        // name: nothing in the workspace declares it, so no crate row binds it.
        if owner.ordinal().is_none() {
            return Ok(RustImplementedTraits::Traits(Vec::new()));
        }
        let reference_mount = SelectedResolutionMountOrdinal::new(
            reference
                .ordinal()
                .expect("a qualified member reference is written in a selected file"),
        );
        if self
            .selection
            .mount_record_by_ordinal(reference_mount)?
            .semantic_language()
            != Language::Rust
        {
            return Ok(RustImplementedTraits::Traits(Vec::new()));
        }
        let mut coordinates = [None, None];
        for (slot, semantic) in coordinates.iter_mut().zip([owner, reference]) {
            let Some(provenance) = self
                .authority
                .semantic_catalog_provenance(semantic, cancellation)?
            else {
                return Ok(RustImplementedTraits::Cancelled);
            };
            let Some(SelectedSemanticProvenance::FragmentLocal(local)) = provenance else {
                return Ok(RustImplementedTraits::Unplaced);
            };
            *slot = Some((local.mount().ordinal(), local.local_key().get()));
        }
        let [Some(owner), Some(reference)] = coordinates else {
            unreachable!("both coordinates are read above")
        };
        super::resolution_operation::rust_crate_rows::implemented_traits_nameable_at(
            self.selection,
            owner,
            reference,
            cancellation,
        )
    }

    /// Whether the reference can name this specific Rust trait, independent of its implementor.
    fn rust_trait_nameable_at(
        &self,
        owner: SemanticId,
        reference: SemanticId,
        cancellation: &CancellationToken,
    ) -> StoreResult<RustImplementedTraits> {
        // A type identity that belongs to no file is an intrinsic or a shared
        // name: nothing in the workspace declares it, so no crate row binds it.
        if owner.ordinal().is_none() {
            return Ok(RustImplementedTraits::Traits(Vec::new()));
        }
        let reference_mount = SelectedResolutionMountOrdinal::new(
            reference
                .ordinal()
                .expect("a qualified member reference is written in a selected file"),
        );
        if self
            .selection
            .mount_record_by_ordinal(reference_mount)?
            .semantic_language()
            != Language::Rust
        {
            return Ok(RustImplementedTraits::Traits(Vec::new()));
        }
        let mut coordinates = [None, None];
        for (slot, semantic) in coordinates.iter_mut().zip([owner, reference]) {
            let Some(provenance) = self
                .authority
                .semantic_catalog_provenance(semantic, cancellation)?
            else {
                return Ok(RustImplementedTraits::Cancelled);
            };
            let Some(SelectedSemanticProvenance::FragmentLocal(local)) = provenance else {
                return Ok(RustImplementedTraits::Unplaced);
            };
            *slot = Some((local.mount().ordinal(), local.local_key().get()));
        }
        let [Some(owner), Some(reference)] = coordinates else {
            unreachable!("both coordinates are read above")
        };
        super::resolution_operation::rust_crate_rows::trait_nameable_at(
            self.selection,
            owner,
            reference,
            cancellation,
        )
    }

    /// Asked of the tier-1 crate rows like the question above. A member that
    /// is staged content or belongs to no file has no persisted impl row, so
    /// its header is resolved instead.
    fn rust_impl_item_traits(
        &self,
        member: SemanticId,
        cancellation: &CancellationToken,
    ) -> StoreResult<RustImplementedTraits> {
        let Some(ordinal) = member.ordinal() else {
            return Ok(RustImplementedTraits::Unplaced);
        };
        if self
            .selection
            .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?
            .semantic_language()
            != Language::Rust
        {
            return Ok(RustImplementedTraits::Traits(Vec::new()));
        }
        let Some(provenance) = self
            .authority
            .semantic_catalog_provenance(member, cancellation)?
        else {
            return Ok(RustImplementedTraits::Cancelled);
        };
        let Some(SelectedSemanticProvenance::FragmentLocal(local)) = provenance else {
            return Ok(RustImplementedTraits::Unplaced);
        };
        super::resolution_operation::rust_crate_rows::impl_item_traits(
            self.selection,
            (local.mount().ordinal(), local.local_key().get()),
            cancellation,
        )
    }

    fn java_access_endpoints(
        &self,
        semantics: &[SemanticId],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<crate::analyzer::resolution::JavaAccessEndpoint>>> {
        java_access::read(self, semantics, cancellation)
    }

    fn go_callable_lookups(
        &self,
        lookups: &[(BindingFragmentId, SemanticId)],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<(SemanticId, SemanticId)>>> {
        use super::resolution_lexical::{
            SelectedLookupRecipeReadOutcome, SelectedLookupRecipeRequest,
            SelectedResolutionLexicalSource,
        };
        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;
        let lexical = SelectedResolutionLexicalSource::with_authority(
            self.selection,
            Rc::clone(&self.authority),
        );
        let requests = lookups
            .iter()
            .map(|&(fragment, semantic)| SelectedLookupRecipeRequest { fragment, semantic })
            .collect::<Vec<_>>();
        let SelectedLookupRecipeReadOutcome::Ready(recipes) =
            lexical.lookup_semantic_recipes(&requests, cancellation, None)?
        else {
            return Ok(None);
        };
        let names = self
            .selection
            .shared_name_table()
            .interner(self.selection.connection());
        let mut result = Vec::new();
        for ((_, lookup), recipe) in lookups.iter().zip(recipes.iter()) {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let Some(recipe) = recipe else {
                continue;
            };
            if recipe.semantic_language() == Language::Go.config_label()
                && matches!(
                    recipe.namespace(),
                    ResolutionNamespace::Value | ResolutionNamespace::Callable
                )
            {
                let callable = crate::analyzer::resolution::ResolutionLookupSemanticRecipe::new(
                    Language::Go,
                    ResolutionNamespace::Callable,
                    recipe.spelling(),
                )
                .semantic(&names);
                result.push((*lookup, callable));
            }
        }
        Ok(Some(result))
    }

    fn go_member_declarations(
        &self,
        definitions: &[SemanticId],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<crate::analyzer::resolution::GoMemberDeclaration>>> {
        go_members::read(self, definitions, cancellation)
    }

    fn hierarchy_terminal_nodes(
        &self,
        gaps: &[SelectedGapReasonProvenance],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<(SemanticId, BindingNodeId)>>> {
        assert!(gaps.len() <= crate::analyzer::resolution::MAX_TYPED_FACT_REQUESTS_PER_BATCH);
        let lexical = super::resolution_lexical::SelectedResolutionLexicalSource::with_authority(
            self.selection,
            Rc::clone(&self.authority),
        );
        let mut rows = Vec::new();
        for gap in gaps {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            if gap.origin() != crate::analyzer::resolution::LoweringGapOrigin::Extracted(
                brokk_bifrost_core::analyzer::resolution_facts::ResolutionGapKind::UnsupportedHierarchyTraversal,
            ) { continue; }
            let Some(node) = lexical.node_for_identity(
                gap.fragment(),
                crate::analyzer::resolution::hierarchy_terminal_node_identity(gap.source_site()),
                cancellation,
            )?
            else {
                return Ok(None);
            };
            if let Some(node) = node {
                rows.push((gap.reason(), node));
            }
        }
        Ok((!cancellation.is_cancelled()).then_some(rows))
    }

    fn java_inheritance_declarations(
        &self,
        definitions: &[SemanticId],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<crate::analyzer::resolution::JavaInheritanceDeclaration>>> {
        java_inheritance::read(self, definitions, cancellation)
    }

    fn rust_supertrait_owners(
        &self,
        owners: &[SemanticId],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<SemanticId>>> {
        let mut selected_owners = Vec::new();
        for &owner in owners {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let Some(ordinal) = owner.ordinal() else {
                continue;
            };
            if self
                .selection
                .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?
                .semantic_language()
                == Language::Rust
            {
                selected_owners.push(owner);
            }
        }
        Ok(Some(selected_owners))
    }

    /// Only a persisted Rust type import supplies an external type identity.
    /// Staged or non-Rust boundaries stay incomplete without an opaque value.
    fn rust_external_type_identities(
        &self,
        boundary: SemanticId,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<SemanticId>>> {
        let Some(ordinal) = boundary.ordinal() else {
            return Ok(Some(Vec::new()));
        };
        if self
            .selection
            .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?
            .semantic_language()
            != Language::Rust
        {
            return Ok(Some(Vec::new()));
        }
        let Some(provenance) = self
            .authority
            .semantic_catalog_provenance(boundary, cancellation)?
        else {
            return Ok(None);
        };
        let Some(SelectedSemanticProvenance::FragmentLocal(local)) = provenance else {
            return Ok(Some(Vec::new()));
        };
        super::resolution_operation::rust_crate_rows::external_type_identities(
            self.selection,
            (local.mount().ordinal(), local.local_key().get()),
            cancellation,
        )
    }

    fn rust_external_type_import_path(
        &self,
        boundary: SemanticId,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<String>>> {
        let Some(ordinal) = boundary.ordinal() else {
            return Ok(Some(Vec::new()));
        };
        if self
            .selection
            .mount_record_by_ordinal(SelectedResolutionMountOrdinal::new(ordinal))?
            .semantic_language()
            != Language::Rust
        {
            return Ok(Some(Vec::new()));
        }
        let Some(provenance) = self
            .authority
            .semantic_catalog_provenance(boundary, cancellation)?
        else {
            return Ok(None);
        };
        let Some(SelectedSemanticProvenance::FragmentLocal(local)) = provenance else {
            return Ok(Some(Vec::new()));
        };
        super::resolution_operation::rust_crate_rows::external_type_import_path(
            self.selection,
            (local.mount().ordinal(), local.local_key().get()),
            cancellation,
        )
    }

    /// One statement over the source module rows for the whole batch. A
    /// definition without a mount-local key (staged content, a shared name)
    /// has no persisted module row, and answers as not a module.
    fn rust_module_definitions(
        &self,
        definitions: &[SemanticId],
        cancellation: &CancellationToken,
    ) -> StoreResult<Vec<SemanticId>> {
        if cancellation.is_cancelled() {
            return Ok(Vec::new());
        }
        let keyed = definitions
            .iter()
            .filter_map(|&definition| {
                Some((
                    definition,
                    SelectedResolutionMountOrdinal::new(definition.ordinal()?),
                    i64::from(definition.local_key()?),
                ))
            })
            .collect::<Vec<_>>();
        super::resolution_operation::rust_crate_rows::module_definitions(self.selection, &keyed)
    }

    fn visit_selected_fragment_pages(
        &self,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, BindingFragmentId>,
    ) -> StoreResult<TypedFactReadOutcome> {
        if !self.validate_selected_interiors(cancellation)? {
            return Ok(TypedFactReadOutcome::cancelled(
                ResolutionCompletion::Complete,
            ));
        }
        for mounts in self.selection.mounts()?.chunks(PAGE_ROWS) {
            let mut page = Vec::with_capacity(mounts.len());
            for mount in mounts {
                if cancellation.is_cancelled() {
                    return Ok(TypedFactReadOutcome::cancelled(
                        ResolutionCompletion::Complete,
                    ));
                }
                page.push(mount.fragment_id());
            }
            let keep_going = visitor.visit_page(&page)?;
            if cancellation.is_cancelled() {
                return Ok(TypedFactReadOutcome::cancelled(
                    ResolutionCompletion::Complete,
                ));
            }
            if !keep_going {
                return Ok(TypedFactReadOutcome::stopped(
                    ResolutionCompletion::Complete,
                ));
            }
        }
        Ok(if self.validate_selected_interiors(cancellation)? {
            TypedFactReadOutcome::exhausted(ResolutionCompletion::Complete)
        } else {
            TypedFactReadOutcome::cancelled(ResolutionCompletion::Complete)
        })
    }

    fn read_selected_reverse_inventory_completion(
        &self,
        cancellation: &CancellationToken,
    ) -> StoreResult<TypedFactReadOutcome> {
        self.empty_outcome(cancellation)
    }

    fn visit_rust_reference_context_pages(
        &self,
        references: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredRustReferenceContext>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        visit_combined_typed_rows(
            cancellation,
            visitor,
            |visitor| {
                let Some(mounts) = self.local_keys_by_mount(
                    references.as_slice(),
                    TypedFactRelation::RustReferenceContext,
                    cancellation,
                )?
                else {
                    return cancelled();
                };
                self.visit_typed_rows(
                    &mounts,
                    rust_authority::REFERENCES_SQL,
                    cancellation,
                    visitor,
                    decode_rust_reference_context,
                )
            },
            |visitor| {
                super::resolution_stage::rust_context::visit_rust_reference_context_pages(
                    self.selection,
                    references,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    fn visit_rust_declaration_authority_pages(
        &self,
        definitions: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredRustDeclarationAuthority>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let Some(mounts) = self.local_keys_by_mount(
            definitions.as_slice(),
            TypedFactRelation::RustDeclarationAuthority,
            cancellation,
        )?
        else {
            return cancelled();
        };
        self.visit_typed_rows(
            &mounts,
            rust_authority::DECLARATIONS_SQL,
            cancellation,
            visitor,
            decode_rust_declaration_authority,
        )
    }

    fn visit_typed_frontier_pages(
        &self,
        slots: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredTypedFrontier>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        visit_combined_typed_rows(
            cancellation,
            visitor,
            |visitor| {
                let Some(mounts) = self.local_keys_by_mount(
                    slots.as_slice(),
                    TypedFactRelation::TypedFrontierSlot,
                    cancellation,
                )?
                else {
                    return cancelled();
                };
                self.visit_typed_rows(
                    &mounts,
                    typed_rows::TYPE_FRONTIERS_BY_SLOT_SQL,
                    cancellation,
                    visitor,
                    |context, row| {
                        Ok(SelectedTypedRow::new(
                            context.fragment,
                            typed_rows::decode_type_frontier(
                                context,
                                row.get(0)?,
                                row.get(1)?,
                                row.get(2)?,
                            ),
                        ))
                    },
                )
            },
            |visitor| {
                super::resolution_stage::typed::visit_typed_frontier_pages(
                    self.selection,
                    slots,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    fn visit_type_identity_observation_pages_for_references(
        &self,
        references: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredTypedFrontier>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        visit_combined_typed_rows(
            cancellation,
            visitor,
            |visitor| {
                let Some(mounts) = self.local_keys_by_mount(
                    references.as_slice(),
                    TypedFactRelation::TypeIdentityObservationReference,
                    cancellation,
                )?
                else {
                    return cancelled();
                };
                self.visit_typed_rows(
                    &mounts,
                    typed_rows::TYPE_FRONTIERS_BY_REFERENCE_SQL,
                    cancellation,
                    visitor,
                    |context, row| {
                        Ok(SelectedTypedRow::new(
                            context.fragment,
                            typed_rows::decode_type_frontier(
                                context,
                                row.get(0)?,
                                row.get(1)?,
                                row.get(2)?,
                            ),
                        ))
                    },
                )
            },
            |visitor| {
                super::resolution_stage::typed::visit_type_identity_observation_pages_for_references(
                    self.selection,
                    references,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    fn visit_type_frontier_completion_pages(
        &self,
        frontiers: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypeFrontierCompletion>,
    ) -> StoreResult<TypedFactReadOutcome> {
        // Ordinary frontier slots are local catalog coordinates. Shared keys
        // belong to the stage arm and must not expand discarded memberships.
        let ordinary = frontiers
            .as_slice()
            .iter()
            .copied()
            .filter(|semantic| semantic.shared_name_id().is_none())
            .collect::<Vec<_>>();
        let Some(mounts) = self.local_keys_by_mount(
            &ordinary,
            TypedFactRelation::TypeFrontierCompletionFrontier,
            cancellation,
        )?
        else {
            return cancelled();
        };
        // Catalog provenance checks the exact publication before looking up a
        // local key, so a lost requested publication cannot disappear as an
        // absent coordinate. Check each resulting host's source visibility too.
        for (host, _) in &mounts {
            let mount = self.mount(*host)?;
            if self
                .authority
                .ensure_authority(&mount, cancellation)?
                .is_none()
            {
                return cancelled();
            }
            let Some(ready) = self.read_statement(cancellation, |connection| {
                Ok(Some(
                    connection
                        .prepare_cached(FRONTIER_SOURCE_READY_SQL)?
                        .exists([mount.blob_id()])?,
                ))
            })?
            else {
                return cancelled();
            };
            if !ready {
                return Err(StoreError::stale_resolution(
                    "requested frontier source facts are unavailable",
                ));
            }
        }
        let mut main_requests = Vec::new();
        for (host, keys) in mounts {
            let base =
                super::resolution_stage::codec::encode_semantic(SemanticId::local(host.get(), 0));
            for key in keys {
                main_requests.push(serde_json::json!([host.get(), key, base]));
            }
        }
        let main_requests =
            serde_json::to_string(&main_requests).expect("frontier main request JSON");
        super::resolution_stage::frontier_completion::visit_frontier_completion(
            self.selection,
            &main_requests,
            frontiers,
            cancellation,
            visitor,
        )
    }

    fn visit_type_transfer_pages_from_sources(
        &self,
        source_slots: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredTypeTransfer>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let Some(mounts) = self.local_keys_by_mount(
            source_slots.as_slice(),
            TypedFactRelation::TypeTransferSourceSlot,
            cancellation,
        )?
        else {
            return cancelled();
        };
        visit_combined_typed_rows(
            cancellation,
            visitor,
            |collector| {
                self.visit_typed_rows(
                    &mounts,
                    typed_rows::TYPE_TRANSFERS_BY_SOURCE_SQL,
                    cancellation,
                    collector,
                    decode_transfer,
                )
            },
            |collector| {
                super::resolution_stage::typed::visit_type_transfer_pages_from_sources(
                    self.selection,
                    source_slots,
                    cancellation,
                    collector,
                )
            },
        )
    }

    fn visit_type_transfer_pages_to_targets(
        &self,
        target_slots: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredTypeTransfer>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        visit_combined_typed_rows(
            cancellation,
            visitor,
            |visitor| {
                let Some(mounts) = self.local_keys_by_mount(
                    target_slots.as_slice(),
                    TypedFactRelation::TypeTransferTargetSlot,
                    cancellation,
                )?
                else {
                    return cancelled();
                };
                self.visit_typed_rows(
                    &mounts,
                    typed_rows::TYPE_TRANSFERS_BY_TARGET_SQL,
                    cancellation,
                    visitor,
                    decode_transfer,
                )
            },
            |visitor| {
                super::resolution_stage::typed::visit_type_transfer_pages_to_targets(
                    self.selection,
                    target_slots,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    fn visit_type_component_pages_for_containers(
        &self,
        containers: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredTypeComponent>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let Some(mounts) = self.local_keys_by_mount(
            containers.as_slice(),
            TypedFactRelation::TypeComponentContainer,
            cancellation,
        )?
        else {
            return cancelled();
        };
        visit_combined_typed_rows(
            cancellation,
            visitor,
            |visitor| {
                self.visit_typed_rows(
                    &mounts,
                    typed_rows::TYPE_COMPONENTS_BY_CONTAINER_SQL,
                    cancellation,
                    visitor,
                    |context, row| {
                        Ok(SelectedTypedRow::new(
                            context.fragment,
                            typed_rows::decode_type_component(
                                context,
                                row.get(0)?,
                                row.get(1)?,
                                row.get(2)?,
                                row.get(3)?,
                            ),
                        ))
                    },
                )
            },
            |visitor| {
                super::resolution_stage::typed::visit_type_component_pages_for_containers(
                    self.selection,
                    containers,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    fn visit_underlying_type_pages_for_definitions(
        &self,
        definitions: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredUnderlyingType>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let Some(mounts) = self.local_keys_by_mount(
            definitions.as_slice(),
            TypedFactRelation::UnderlyingTypeDefinition,
            cancellation,
        )?
        else {
            return cancelled();
        };
        visit_combined_typed_rows(
            cancellation,
            visitor,
            |visitor| {
                self.visit_typed_rows(
                    &mounts,
                    typed_rows::UNDERLYING_TYPES_BY_DEFINITION_SQL,
                    cancellation,
                    visitor,
                    |context, row| {
                        Ok(SelectedTypedRow::new(
                            context.fragment,
                            typed_rows::decode_underlying_type(context, row.get(0)?, row.get(1)?),
                        ))
                    },
                )
            },
            |visitor| {
                super::resolution_stage::typed::visit_underlying_type_pages_for_definitions(
                    self.selection,
                    definitions,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    fn visit_intrinsic_seed_pages_for_slots(
        &self,
        slots: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredIntrinsicSeed>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        visit_combined_typed_rows(
            cancellation,
            visitor,
            |visitor| {
                let Some(mounts) = self.local_keys_by_mount(
                    slots.as_slice(),
                    TypedFactRelation::IntrinsicSeedSlot,
                    cancellation,
                )?
                else {
                    return cancelled();
                };
                self.visit_typed_rows(
                    &mounts,
                    typed_rows::INTRINSIC_SEEDS_BY_SLOT_SQL,
                    cancellation,
                    visitor,
                    decode_intrinsic_seed,
                )
            },
            |visitor| {
                super::resolution_stage::typed::visit_intrinsic_seed_pages_for_slots(
                    self.selection,
                    slots,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    fn visit_intrinsic_seed_pages_for_type_identities(
        &self,
        type_identities: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredIntrinsicSeed>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        visit_combined_typed_rows(
            cancellation,
            visitor,
            |visitor| {
                // Membership is the discriminating relation here, not an overshoot.
                // An intrinsic type identity enters a blob's identity catalog only
                // where lowering builds an intrinsic seed for it
                // (`typed_fact_lowering.rs`, the one construction site), so the blobs
                // that mention such an identity are exactly the blobs that seed it.
                let Some(mounts) = self.shared_keys_by_mount(
                    type_identities.as_slice(),
                    TypedFactRelation::IntrinsicSeedTypeIdentity,
                    cancellation,
                )?
                else {
                    return cancelled();
                };
                self.visit_typed_rows(
                    &mounts,
                    typed_rows::INTRINSIC_SEEDS_BY_IDENTITY_SQL,
                    cancellation,
                    visitor,
                    decode_intrinsic_seed,
                )
            },
            |visitor| {
                super::resolution_stage::typed::visit_intrinsic_seed_pages_for_type_identities(
                    self.selection,
                    type_identities,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    fn visit_binding_projection_pages_for_references(
        &self,
        references: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredBindingProjection>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        visit_combined_typed_rows(
            cancellation,
            visitor,
            |visitor| {
                let Some(mounts) = self.local_keys_by_mount(
                    references.as_slice(),
                    TypedFactRelation::BindingProjectionReference,
                    cancellation,
                )?
                else {
                    return cancelled();
                };
                self.visit_typed_rows(
                    &mounts,
                    typed_rows::BINDING_PROJECTIONS_BY_REFERENCE_SQL,
                    cancellation,
                    visitor,
                    decode_binding_projection,
                )
            },
            |visitor| {
                super::resolution_stage::typed::visit_binding_projection_pages_for_references(
                    self.selection,
                    references,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    fn visit_binding_projection_pages_for_outputs(
        &self,
        output_slots: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredBindingProjection>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        visit_combined_typed_rows(
            cancellation,
            visitor,
            |visitor| {
                let Some(mounts) = self.local_keys_by_mount(
                    output_slots.as_slice(),
                    TypedFactRelation::BindingProjectionOutputSlot,
                    cancellation,
                )?
                else {
                    return cancelled();
                };
                self.visit_typed_rows(
                    &mounts,
                    typed_rows::BINDING_PROJECTIONS_BY_OUTPUT_SQL,
                    cancellation,
                    visitor,
                    decode_binding_projection,
                )
            },
            |visitor| {
                super::resolution_stage::typed::visit_binding_projection_pages_for_outputs(
                    self.selection,
                    output_slots,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    fn visit_qualified_route_pages_for_references(
        &self,
        references: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedQualifiedRoute>,
    ) -> StoreResult<TypedFactReadOutcome> {
        visit_combined_typed_rows(
            cancellation,
            visitor,
            |visitor| {
                let Some(mounts) = self.local_keys_by_mount(
                    references.as_slice(),
                    TypedFactRelation::QualifiedRouteReference,
                    cancellation,
                )?
                else {
                    return cancelled();
                };
                self.visit_typed_rows(
                    &mounts,
                    typed_rows::QUALIFIED_ROUTES_BY_REFERENCE_SQL,
                    cancellation,
                    visitor,
                    decode_qualified_route,
                )
            },
            |visitor| {
                super::resolution_stage::typed::visit_qualified_route_pages_for_references(
                    self.selection,
                    references,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    /// Select exact qualifier slots paired with either the source lookup or
    /// the typed member lookup.
    ///
    /// The pair is the key, not the lookup alone: the interior indexes a route
    /// under `(qualifier_slot, lookup)` and lane CM's rule is that a rows
    /// reader reproduces the in-memory index's exact key. The mounts come from
    /// the lookup relation, because a blob answers only when it holds a route
    /// under the requested lookup and a qualifier slot cannot add a blob that
    /// relation omits; inside a blob, only a pair whose qualifier slot is that
    /// blob's own can match, which is what grouping the slot coordinates does.
    fn visit_qualified_route_pages_for_slot_lookups(
        &self,
        requests: TypedFactRequest<'_, QualifiedRouteSlotLookup>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedQualifiedRoute>,
    ) -> StoreResult<TypedFactReadOutcome> {
        visit_combined_typed_rows(
            cancellation,
            visitor,
            |visitor| {
                let slots = requests
                    .as_slice()
                    .iter()
                    .map(|request| request.qualifier_slot())
                    .collect::<Vec<_>>();
                let lookups = requests
                    .as_slice()
                    .iter()
                    .map(|request| request.lookup())
                    .collect::<Vec<_>>();
                let Some(slot_coordinates) = self.semantic_coordinates(
                    &slots,
                    TypedFactRelation::QualifiedRouteQualifierSlot,
                    cancellation,
                )?
                else {
                    return cancelled();
                };
                let Some(route_mounts) = self.interior_mounts_for_semantics(
                    &lookups,
                    TypedFactRelation::QualifiedRouteLookup,
                    cancellation,
                )?
                else {
                    return cancelled();
                };
                let names = self
                    .selection
                    .shared_name_table()
                    .interner(self.selection.connection());
                let mut evidence = PolledCompletionAccumulator::new(cancellation);
                for ordinal in route_mounts {
                    let mount = &*self.mount(ordinal)?;
                    let pairs = slot_coordinates
                        .iter()
                        .filter(|coordinate| {
                            coordinate.mount == ordinal
                                && coordinate.space == RequestKeySpace::Local
                        })
                        .filter_map(|coordinate| {
                            lookups[coordinate.request_ordinal]
                                .shared_name_id()
                                .and_then(|name| names.to_persisted(name))
                                .map(|lookup| (coordinate.keys[0], i64::from(lookup.get())))
                        })
                        .collect::<Vec<_>>();
                    if pairs.is_empty() {
                        continue;
                    }
                    let pair_array = json_pair_array(pairs.into_iter());
                    let Some(rows) = self.decode_page(
                        mount,
                        typed_rows::QUALIFIED_ROUTES_BY_SLOT_LOOKUP_SQL,
                        &[&mount.blob_id() as &dyn rusqlite::ToSql, &pair_array],
                        cancellation,
                        &decode_qualified_route,
                        &mut evidence,
                    )?
                    else {
                        return Ok(TypedFactReadOutcome::cancelled(
                            evidence.finish_semantic().0,
                        ));
                    };
                    match Self::page_out(&rows, cancellation, visitor)? {
                        PageOutcome::Exhausted => {}
                        PageOutcome::Stopped => {
                            let (completion, cancelled) = evidence.finish_semantic();
                            return Ok(if cancelled {
                                TypedFactReadOutcome::cancelled(completion)
                            } else {
                                TypedFactReadOutcome::stopped(completion)
                            });
                        }
                        PageOutcome::Cancelled => {
                            return Ok(TypedFactReadOutcome::cancelled(
                                evidence.finish_semantic().0,
                            ));
                        }
                    }
                }
                Ok(if cancellation.is_cancelled() {
                    TypedFactReadOutcome::cancelled(evidence.finish_semantic().0)
                } else {
                    TypedFactReadOutcome::exhausted(ResolutionCompletion::Complete)
                })
            },
            |visitor| {
                super::resolution_stage::typed::visit_qualified_route_pages_for_slot_lookups(
                    self.selection,
                    requests,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    fn visit_qualified_route_pages_for_qualifier_slots(
        &self,
        qualifier_slots: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedQualifiedRoute>,
    ) -> StoreResult<TypedFactReadOutcome> {
        visit_combined_typed_rows(
            cancellation,
            visitor,
            |visitor| {
                let Some(mounts) = self.local_keys_by_mount(
                    qualifier_slots.as_slice(),
                    TypedFactRelation::QualifiedRouteQualifierSlot,
                    cancellation,
                )?
                else {
                    return cancelled();
                };
                self.visit_typed_rows(
                    &mounts,
                    typed_rows::QUALIFIED_ROUTES_BY_QUALIFIER_SLOT_SQL,
                    cancellation,
                    visitor,
                    decode_qualified_route,
                )
            },
            |visitor| {
                super::resolution_stage::typed::visit_qualified_route_pages_for_qualifier_slots(
                    self.selection,
                    qualifier_slots,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    fn visit_qualified_route_pages_for_lookups(
        &self,
        lookups: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedQualifiedRoute>,
    ) -> StoreResult<TypedFactReadOutcome> {
        visit_combined_typed_rows(
            cancellation,
            visitor,
            |visitor| {
                let Some(mounts) = self.shared_keys_by_mount(
                    lookups.as_slice(),
                    TypedFactRelation::QualifiedRouteLookup,
                    cancellation,
                )?
                else {
                    return cancelled();
                };
                // A route answers under its member lookup and, when they differ,
                // under its source lookup. The statement tests both inside the blob's
                // own route prefix rather than through two indexes: this question has
                // no measured caller, and an index exists only for a statement that is
                // reached (owner decision, 2026-09-19).
                self.visit_typed_rows(
                    &mounts,
                    typed_rows::QUALIFIED_ROUTES_BY_LOOKUP_SQL,
                    cancellation,
                    visitor,
                    decode_qualified_route,
                )
            },
            |visitor| {
                super::resolution_stage::typed::visit_qualified_route_pages_for_lookups(
                    self.selection,
                    lookups,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    fn visit_qualified_route_pages_for_gap_reasons(
        &self,
        reasons: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedQualifiedRoute>,
    ) -> StoreResult<TypedFactReadOutcome> {
        visit_combined_typed_rows(
            cancellation,
            visitor,
            |visitor| {
                let Some(mounts) = self.local_keys_by_mount(
                    reasons.as_slice(),
                    TypedFactRelation::QualifiedRouteGapReason,
                    cancellation,
                )?
                else {
                    return cancelled();
                };
                self.visit_typed_rows(
                    &mounts,
                    typed_rows::QUALIFIED_ROUTES_BY_GAP_REASON_SQL,
                    cancellation,
                    visitor,
                    decode_qualified_route,
                )
            },
            |visitor| {
                super::resolution_stage::typed::visit_qualified_route_pages_for_gap_reasons(
                    self.selection,
                    reasons,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    fn visit_qualified_route_inventory_pages(
        &self,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedQualifiedRoute>,
    ) -> StoreResult<TypedFactReadOutcome> {
        visit_combined_typed_rows(
            cancellation,
            visitor,
            |visitor| {
                let Some(mounts) = self.interior_mounts_holding_a_qualified_route(cancellation)?
                else {
                    return cancelled();
                };
                self.visit_typed_rows_in_mounts(
                    &mounts,
                    typed_rows::QUALIFIED_ROUTES_INVENTORY_SQL,
                    cancellation,
                    visitor,
                    decode_qualified_route,
                )
            },
            |visitor| {
                super::resolution_stage::typed::visit_qualified_route_inventory_pages(
                    self.selection,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    fn visit_declaration_type_pages_for_definitions(
        &self,
        definitions: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredDeclarationTypeProperty>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        visit_combined_typed_rows(
            cancellation,
            visitor,
            |visitor| {
                let Some(mounts) = self.local_keys_by_mount(
                    definitions.as_slice(),
                    TypedFactRelation::DeclarationTypeDefinition,
                    cancellation,
                )?
                else {
                    return cancelled();
                };
                self.visit_typed_rows(
                    &mounts,
                    typed_rows::DECLARATION_TYPES_BY_DEFINITION_SQL,
                    cancellation,
                    visitor,
                    decode_declaration_type,
                )
            },
            |visitor| {
                super::resolution_stage::typed::visit_declaration_type_pages_for_definitions(
                    self.selection,
                    definitions,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    fn visit_declaration_type_pages_for_slots(
        &self,
        slots: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredDeclarationTypeProperty>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        visit_combined_typed_rows(
            cancellation,
            visitor,
            |visitor| {
                let Some(mounts) = self.local_keys_by_mount(
                    slots.as_slice(),
                    TypedFactRelation::DeclarationTypeSlot,
                    cancellation,
                )?
                else {
                    return cancelled();
                };
                self.visit_typed_rows(
                    &mounts,
                    typed_rows::DECLARATION_TYPES_BY_SLOT_SQL,
                    cancellation,
                    visitor,
                    decode_declaration_type,
                )
            },
            |visitor| {
                super::resolution_stage::typed::visit_declaration_type_pages_for_slots(
                    self.selection,
                    slots,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    /// Question 45 keeps the view it already has over the source declaration
    /// properties (draft section 6), so this reader adds no table.
    fn visit_declaration_visibility_pages_for_definitions(
        &self,
        definitions: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<
            '_,
            SelectedTypedRow<LoweredDeclarationVisibilityProperty>,
        >,
    ) -> StoreResult<TypedFactReadOutcome> {
        visit_combined_typed_rows(
            cancellation,
            visitor,
            |visitor| {
                let Some(mounts) = self.local_keys_by_mount(
                    definitions.as_slice(),
                    TypedFactRelation::DeclarationVisibilityDefinition,
                    cancellation,
                )?
                else {
                    return cancelled();
                };
                self.visit_typed_rows(
                &mounts,
                typed_rows::DECLARATION_VISIBILITIES_BY_DEFINITION_SQL,
                cancellation,
                visitor,
                |context, row| {
                    let label: String = row.get(1)?;
                    Ok(SelectedTypedRow::new(
                        context.fragment,
                        LoweredDeclarationVisibilityProperty::new(
                            context.semantic(row.get(0)?),
                            DeclaredVisibility::from_label(&label).ok_or_else(|| {
                                invalid_fact(format!(
                                    "stored declaration visibility {label:?} is outside its vocabulary"
                                ))
                            })?,
                        ),
                    ))
                },
            )
            },
            |visitor| {
                super::resolution_stage::typed::visit_declaration_visibility_pages_for_definitions(
                    self.selection,
                    definitions,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    fn visit_member_scope_pages_for_definitions(
        &self,
        definitions: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredMemberScopeProperty>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        visit_combined_typed_rows(
            cancellation,
            visitor,
            |visitor| {
                let Some(mounts) = self.local_keys_by_mount(
                    definitions.as_slice(),
                    TypedFactRelation::MemberScopeDefinition,
                    cancellation,
                )?
                else {
                    return cancelled();
                };
                self.visit_typed_rows(
                    &mounts,
                    typed_rows::MEMBER_SCOPES_BY_DEFINITION_SQL,
                    cancellation,
                    visitor,
                    decode_member_scope,
                )
            },
            |visitor| {
                super::resolution_stage::typed::visit_member_scope_pages_for_definitions(
                    self.selection,
                    definitions,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    fn visit_member_scope_pages_for_heads(
        &self,
        heads: TypedFactRequest<'_, BindingNodeId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredMemberScopeProperty>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        visit_combined_typed_rows(
            cancellation,
            visitor,
            |visitor| {
                let Some(mounts) = self.node_keys_by_mount(heads.as_slice(), cancellation)? else {
                    return cancelled();
                };
                self.visit_typed_rows(
                    &mounts,
                    typed_rows::MEMBER_SCOPES_BY_HEAD_SQL,
                    cancellation,
                    visitor,
                    decode_member_scope,
                )
            },
            |visitor| {
                super::resolution_stage::typed::visit_member_scope_pages_for_heads(
                    self.selection,
                    heads,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    fn visit_member_owner_pages_for_definitions(
        &self,
        definitions: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredMemberOwnerProperty>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        visit_combined_typed_rows(
            cancellation,
            visitor,
            |visitor| {
                let Some(mounts) = self.local_keys_by_mount(
                    definitions.as_slice(),
                    TypedFactRelation::MemberOwnerDefinition,
                    cancellation,
                )?
                else {
                    return cancelled();
                };
                self.visit_typed_rows(
                    &mounts,
                    typed_rows::MEMBER_OWNERS_BY_DEFINITION_SQL,
                    cancellation,
                    visitor,
                    decode_member_owner,
                )
            },
            |visitor| {
                super::resolution_stage::typed::visit_member_owner_pages_for_definitions(
                    self.selection,
                    definitions,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    fn visit_member_owner_pages_for_owners(
        &self,
        owner_definitions: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredMemberOwnerProperty>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        visit_combined_typed_rows(
            cancellation,
            visitor,
            |visitor| {
                let Some(mounts) = self.local_keys_by_mount(
                    owner_definitions.as_slice(),
                    TypedFactRelation::MemberOwnerOwnerDefinition,
                    cancellation,
                )?
                else {
                    return cancelled();
                };
                self.visit_typed_rows(
                    &mounts,
                    typed_rows::MEMBER_OWNERS_BY_OWNER_SQL,
                    cancellation,
                    visitor,
                    decode_member_owner,
                )
            },
            |visitor| {
                super::resolution_stage::typed::visit_member_owner_pages_for_owners(
                    self.selection,
                    owner_definitions,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    fn visit_deferred_member_owner_pages_for_definitions(
        &self,
        definitions: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredDeferredMemberOwner>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        visit_combined_typed_rows(
            cancellation,
            visitor,
            |visitor| {
                let Some(mounts) = self.local_keys_by_mount(
                    definitions.as_slice(),
                    TypedFactRelation::DeferredMemberOwnerDefinition,
                    cancellation,
                )?
                else {
                    return cancelled();
                };
                self.visit_typed_rows(
                    &mounts,
                    typed_rows::DEFERRED_MEMBER_OWNERS_BY_DEFINITION_SQL,
                    cancellation,
                    visitor,
                    decode_deferred_member_owner,
                )
            },
            |visitor| {
                super::resolution_stage::typed::visit_deferred_member_owner_pages_for_definitions(
                    self.selection,
                    definitions,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    fn visit_deferred_member_owner_pages_for_lookup_names(
        &self,
        lookups: TypedFactRequest<'_, DeferredMemberOwnerLookupName>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredDeferredMemberOwner>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        visit_combined_typed_rows(
            cancellation,
            visitor,
            |visitor| {
                let semantics = lookups
                    .as_slice()
                    .iter()
                    .map(|lookup| lookup.lookup())
                    .collect::<Vec<_>>();
                let Some(mounts) = self.shared_keys_by_mount(
                    &semantics,
                    TypedFactRelation::DeferredMemberOwnerLookup,
                    cancellation,
                )?
                else {
                    return cancelled();
                };
                self.visit_typed_rows(
                    &mounts,
                    typed_rows::DEFERRED_MEMBER_OWNERS_BY_LOOKUP_SQL,
                    cancellation,
                    visitor,
                    decode_deferred_member_owner,
                )
            },
            |visitor| {
                super::resolution_stage::typed::visit_deferred_member_owner_pages_for_lookup_names(
                    self.selection,
                    lookups,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    fn visit_construction_requirement_pages_for_definitions(
        &self,
        definitions: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<
            '_,
            SelectedTypedRow<LoweredConstructionRequirementProperty>,
        >,
    ) -> StoreResult<TypedFactReadOutcome> {
        visit_combined_typed_rows(
            cancellation,
            visitor,
            |visitor| {
                let Some(mounts) = self.local_keys_by_mount(
                    definitions.as_slice(),
                    TypedFactRelation::ConstructionRequirementDefinition,
                    cancellation,
                )?
                else {
                    return cancelled();
                };
                self.visit_typed_rows(
                    &mounts,
                    typed_rows::CONSTRUCTION_REQUIREMENTS_BY_DEFINITION_SQL,
                    cancellation,
                    visitor,
                    |context, row| {
                        Ok(SelectedTypedRow::new(
                            context.fragment,
                            typed_rows::decode_construction_requirement(
                                context,
                                row.get(0)?,
                                row.get(1)?,
                                row.get(2)?,
                            ),
                        ))
                    },
                )
            },
            |visitor| {
                super::resolution_stage::typed::visit_construction_requirement_pages_for_definitions(
                    self.selection,
                    definitions,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    fn visit_supertype_pages_for_definitions(
        &self,
        definitions: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredSupertypeProperty>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        visit_combined_typed_rows(
            cancellation,
            visitor,
            |visitor| {
                let Some(mounts) = self.local_keys_by_mount(
                    definitions.as_slice(),
                    TypedFactRelation::SupertypeDefinition,
                    cancellation,
                )?
                else {
                    return cancelled();
                };
                self.visit_typed_rows(
                    &mounts,
                    typed_rows::SUPERTYPES_BY_DEFINITION_SQL,
                    cancellation,
                    visitor,
                    decode_supertype,
                )
            },
            |visitor| {
                super::resolution_stage::typed::visit_supertype_pages_for_definitions(
                    self.selection,
                    definitions,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    fn visit_supertype_pages_for_references(
        &self,
        references: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredSupertypeProperty>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        visit_combined_typed_rows(
            cancellation,
            visitor,
            |visitor| {
                let Some(mounts) = self.local_keys_by_mount(
                    references.as_slice(),
                    TypedFactRelation::SupertypeReference,
                    cancellation,
                )?
                else {
                    return cancelled();
                };
                self.visit_typed_rows(
                    &mounts,
                    typed_rows::SUPERTYPES_BY_REFERENCE_SQL,
                    cancellation,
                    visitor,
                    decode_supertype,
                )
            },
            |visitor| {
                super::resolution_stage::typed::visit_supertype_pages_for_references(
                    self.selection,
                    references,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    fn visit_supertype_pages_for_frontiers(
        &self,
        frontiers: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredSupertypeProperty>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        visit_combined_typed_rows(
            cancellation,
            visitor,
            |visitor| {
                let Some(mounts) = self.local_keys_by_mount(
                    frontiers.as_slice(),
                    TypedFactRelation::SupertypeFrontier,
                    cancellation,
                )?
                else {
                    return cancelled();
                };
                self.visit_typed_rows(
                    &mounts,
                    typed_rows::SUPERTYPES_BY_FRONTIER_SQL,
                    cancellation,
                    visitor,
                    decode_supertype,
                )
            },
            |visitor| {
                super::resolution_stage::typed::visit_supertype_pages_for_frontiers(
                    self.selection,
                    frontiers,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    fn visit_definition_property_gap_pages_for_definitions(
        &self,
        definitions: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredDefinitionPropertyGap>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        visit_combined_typed_rows(
            cancellation,
            visitor,
            |visitor| {
                let Some(mounts) = self.local_keys_by_mount(
                    definitions.as_slice(),
                    TypedFactRelation::DefinitionPropertyGapDefinition,
                    cancellation,
                )?
                else {
                    return cancelled();
                };
                self.visit_typed_rows(
                    &mounts,
                    typed_rows::DEFINITION_PROPERTY_GAPS_BY_DEFINITION_SQL,
                    cancellation,
                    visitor,
                    |context, row| {
                        Ok(SelectedTypedRow::new(
                            context.fragment,
                            typed_rows::decode_definition_property_gap(
                                context,
                                row.get(0)?,
                                row.get(1)?,
                                row.get(2)?,
                                row.get(3)?,
                                row.get(4)?,
                            ),
                        ))
                    },
                )
            },
            |visitor| {
                super::resolution_stage::typed::visit_definition_property_gap_pages_for_definitions(
                    self.selection,
                    definitions,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    fn visit_definition_property_gap_pages_for_reasons(
        &self,
        reasons: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredDefinitionPropertyGap>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        visit_combined_typed_rows(
            cancellation,
            visitor,
            |visitor| {
                let Some(mounts) = self.local_keys_by_mount(
                    reasons.as_slice(),
                    TypedFactRelation::DefinitionPropertyGapReason,
                    cancellation,
                )?
                else {
                    return cancelled();
                };
                self.visit_typed_rows(
                    &mounts,
                    typed_rows::DEFINITION_PROPERTY_GAPS_BY_REASON_SQL,
                    cancellation,
                    visitor,
                    |context, row| {
                        Ok(SelectedTypedRow::new(
                            context.fragment,
                            typed_rows::decode_definition_property_gap(
                                context,
                                row.get(0)?,
                                row.get(1)?,
                                row.get(2)?,
                                row.get(3)?,
                                row.get(4)?,
                            ),
                        ))
                    },
                )
            },
            |visitor| {
                super::resolution_stage::typed::visit_definition_property_gap_pages_for_reasons(
                    self.selection,
                    reasons,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    fn visit_call_applicability_pages_for_callee_references(
        &self,
        callee_references: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<
            '_,
            SelectedTypedRow<LoweredCallApplicabilityObligation>,
        >,
    ) -> StoreResult<TypedFactReadOutcome> {
        visit_combined_typed_rows(
            cancellation,
            visitor,
            |visitor| {
                let Some(mounts) = self.local_keys_by_mount(
                    callee_references.as_slice(),
                    TypedFactRelation::CallApplicabilityCalleeReference,
                    cancellation,
                )?
                else {
                    return cancelled();
                };
                self.visit_typed_rows(
                    &mounts,
                    typed_rows::CALL_OBLIGATIONS_BY_CALLEE_SQL,
                    cancellation,
                    visitor,
                    decode_call_obligation,
                )
            },
            |visitor| {
                super::resolution_stage::typed::visit_call_applicability_pages_for_callee_references(
                    self.selection,
                    callee_references,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    fn visit_call_applicability_pages_for_gap_reasons(
        &self,
        reasons: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<
            '_,
            SelectedTypedRow<LoweredCallApplicabilityObligation>,
        >,
    ) -> StoreResult<TypedFactReadOutcome> {
        visit_combined_typed_rows(
            cancellation,
            visitor,
            |visitor| {
                let Some(mounts) = self.local_keys_by_mount(
                    reasons.as_slice(),
                    TypedFactRelation::CallApplicabilityGapReason,
                    cancellation,
                )?
                else {
                    return cancelled();
                };
                self.visit_typed_rows(
                    &mounts,
                    typed_rows::CALL_OBLIGATIONS_BY_REASON_SQL,
                    cancellation,
                    visitor,
                    decode_call_obligation,
                )
            },
            |visitor| {
                super::resolution_stage::typed::visit_call_applicability_pages_for_gap_reasons(
                    self.selection,
                    reasons,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    fn visit_callable_signature_pages_for_definitions(
        &self,
        definitions: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedTypedRow<LoweredCallableSignatureProperty>>,
    ) -> StoreResult<TypedFactReadOutcome> {
        visit_combined_typed_rows(
            cancellation,
            visitor,
            |visitor| {
                let Some(mounts) = self.local_keys_by_mount(
                    definitions.as_slice(),
                    TypedFactRelation::CallableSignatureDefinition,
                    cancellation,
                )?
                else {
                    return cancelled();
                };
                self.visit_typed_rows(
                    &mounts,
                    typed_rows::CALLABLE_SIGNATURES_BY_DEFINITION_SQL,
                    cancellation,
                    visitor,
                    |context, row| {
                        let body: String = row.get(1)?;
                        Ok(SelectedTypedRow::new(
                            context.fragment,
                            typed_rows::decode_callable_signature(context, row.get(0)?, &body),
                        ))
                    },
                )
            },
            |visitor| {
                super::resolution_stage::typed::visit_callable_signature_pages_for_definitions(
                    self.selection,
                    definitions,
                    cancellation,
                    visitor,
                )
            },
        )
    }

    fn visit_gap_reason_provenance_pages_for_reasons(
        &self,
        reasons: TypedFactRequest<'_, SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, SelectedGapReasonProvenance>,
    ) -> StoreResult<TypedFactReadOutcome> {
        visit_combined_typed_rows(
            cancellation,
            visitor,
            |visitor| {
                let Some(mounts) = self.local_keys_by_mount(
                    reasons.as_slice(),
                    TypedFactRelation::GapReasonProvenanceReason,
                    cancellation,
                )?
                else {
                    return cancelled();
                };
                self.visit_typed_rows(
                    &mounts,
                    typed_rows::GAP_REASON_PROVENANCE_SQL,
                    cancellation,
                    visitor,
                    |context, row| {
                        Ok(SelectedGapReasonProvenance::new(
                            context.fragment,
                            context.semantic(row.get(0)?),
                            brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteId::new(
                                row.get(1)?,
                            ),
                            super::resolution_prepare::resolution_rows::gap_origin_from_code(
                                row.get(2)?,
                            ),
                        ))
                    },
                )
            },
            |visitor| {
                super::resolution_stage::typed::visit_gap_reason_provenance_pages_for_reasons(
                    self.selection,
                    reasons,
                    cancellation,
                    visitor,
                )
            },
        )
    }
}

fn decode_rust_reference_context(
    context: TypedRowContext,
    row: &Row<'_>,
) -> StoreResult<SelectedTypedRow<LoweredRustReferenceContext>> {
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteId;
    use brokk_bifrost_core::analyzer::source_facts::{SourceDeclarationId, SourceOccurrenceId};
    Ok(SelectedTypedRow::new(
        context.fragment,
        LoweredRustReferenceContext::new(
            context.semantic(row.get(0)?),
            ResolutionSiteId::new(row.get(1)?),
            SourceOccurrenceId::new(row.get(2)?),
            SourceOccurrenceId::new(row.get(3)?),
            row.get::<_, Option<u32>>(4)?.map(SourceDeclarationId::new),
        )
        .with_cfg_condition(rust_authority::decode_cfg(&row.get::<_, String>(5)?)),
    ))
}

fn decode_rust_declaration_authority(
    context: TypedRowContext,
    row: &Row<'_>,
) -> StoreResult<SelectedTypedRow<LoweredRustDeclarationAuthority>> {
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionSiteId;
    use brokk_bifrost_core::analyzer::source_facts::{SourceDeclarationId, SourceOccurrenceId};
    Ok(SelectedTypedRow::new(
        context.fragment,
        LoweredRustDeclarationAuthority::new(
            context.semantic(row.get(0)?),
            ResolutionSiteId::new(row.get(1)?),
            SourceDeclarationId::new(row.get(2)?),
            row.get::<_, Option<String>>(3)?
                .map(|body| rust_authority::decode_visibility(&body)),
            SourceOccurrenceId::new(row.get(4)?),
            row.get::<_, Option<u32>>(5)?.map(SourceDeclarationId::new),
        )
        .with_cfg_condition(rust_authority::decode_cfg(&row.get::<_, String>(6)?))
        .with_activation_reason(
            row.get::<_, Option<i64>>(7)?
                .map(|key| context.semantic(key)),
        ),
    ))
}

fn cancelled() -> StoreResult<TypedFactReadOutcome> {
    Ok(TypedFactReadOutcome::cancelled(
        ResolutionCompletion::Complete,
    ))
}

fn decode_transfer(
    context: TypedRowContext,
    row: &Row<'_>,
) -> StoreResult<SelectedTypedRow<LoweredTypeTransfer>> {
    let completion: Option<String> = row.get(7)?;
    Ok(SelectedTypedRow::new(
        context.fragment,
        typed_rows::decode_type_transfer(
            context,
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
            row.get(5)?,
            row.get(6)?,
            completion.as_deref(),
        ),
    ))
}

fn decode_intrinsic_seed(
    context: TypedRowContext,
    row: &Row<'_>,
) -> StoreResult<SelectedTypedRow<LoweredIntrinsicSeed>> {
    let spelling: String = row.get(2)?;
    let possible_values: String = row.get(3)?;
    let completion: Option<String> = row.get(4)?;
    Ok(SelectedTypedRow::new(
        context.fragment,
        typed_rows::decode_intrinsic_seed(
            context,
            row.get(0)?,
            row.get(1)?,
            &spelling,
            &possible_values,
            completion.as_deref(),
        ),
    ))
}

fn decode_binding_projection(
    context: TypedRowContext,
    row: &Row<'_>,
) -> StoreResult<SelectedTypedRow<LoweredBindingProjection>> {
    Ok(SelectedTypedRow::new(
        context.fragment,
        typed_rows::decode_binding_projection(context, row.get(0)?, row.get(1)?, row.get(2)?),
    ))
}

/// A qualified route carries its reference's lexical node.
///
/// The row does not store it: a site, its semantic and its node carry one
/// number (`local_identity.rs`, `finish`), and a route's reference is a
/// reference site, so the node is the reference key at the same mount. The
/// writer asserts the same equality where it encodes an observation.
fn decode_qualified_route(
    context: TypedRowContext,
    row: &Row<'_>,
) -> StoreResult<SelectedQualifiedRoute> {
    let reference: i64 = row.get(0)?;
    Ok(SelectedQualifiedRoute::new(
        context.fragment,
        context.node(reference),
        typed_rows::decode_qualified_route(
            context,
            reference,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
            row.get(5)?,
            row.get(6)?,
            row.get(7)?,
            row.get(8)?,
            row.get(9)?,
        ),
    ))
}

fn decode_declaration_type(
    context: TypedRowContext,
    row: &Row<'_>,
) -> StoreResult<SelectedTypedRow<LoweredDeclarationTypeProperty>> {
    Ok(SelectedTypedRow::new(
        context.fragment,
        typed_rows::decode_declaration_type(context, row.get(0)?, row.get(1)?, row.get(2)?),
    ))
}

fn decode_member_scope(
    context: TypedRowContext,
    row: &Row<'_>,
) -> StoreResult<SelectedTypedRow<LoweredMemberScopeProperty>> {
    Ok(SelectedTypedRow::new(
        context.fragment,
        LoweredMemberScopeProperty::new(context.semantic(row.get(0)?), context.node(row.get(1)?)),
    ))
}

fn decode_member_owner(
    context: TypedRowContext,
    row: &Row<'_>,
) -> StoreResult<SelectedTypedRow<LoweredMemberOwnerProperty>> {
    let kind: String = row.get(3)?;
    let access: String = row.get(4)?;
    let compatibility: String = row.get(5)?;
    Ok(SelectedTypedRow::new(
        context.fragment,
        LoweredMemberOwnerProperty::new(
            context.semantic(row.get(0)?),
            context.semantic(row.get(1)?),
            context.node(row.get(2)?),
            typed_rows::member_kind_from_label(&kind),
            typed_rows::member_access_from_label(&access),
            typed_rows::member_qualifier_compatibility_from_label(&compatibility),
        ),
    ))
}

fn decode_deferred_member_owner(
    context: TypedRowContext,
    row: &Row<'_>,
) -> StoreResult<SelectedTypedRow<LoweredDeferredMemberOwner>> {
    let body: String = row.get(2)?;
    Ok(SelectedTypedRow::new(
        context.fragment,
        typed_rows::decode_deferred_member_owner(context, row.get(0)?, row.get(1)?, &body),
    ))
}

fn decode_supertype(
    context: TypedRowContext,
    row: &Row<'_>,
) -> StoreResult<SelectedTypedRow<LoweredSupertypeProperty>> {
    Ok(SelectedTypedRow::new(
        context.fragment,
        typed_rows::decode_supertype(context, row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?),
    ))
}

fn decode_call_obligation(
    context: TypedRowContext,
    row: &Row<'_>,
) -> StoreResult<SelectedTypedRow<LoweredCallApplicabilityObligation>> {
    let arguments: String = row.get(6)?;
    let rules: String = row.get(7)?;
    let completion: Option<String> = row.get(8)?;
    let type_arguments: String = row.get(9)?;
    Ok(SelectedTypedRow::new(
        context.fragment,
        typed_rows::decode_call_obligation(
            context,
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
            row.get(5)?,
            &arguments,
            &type_arguments,
            &rules,
            completion.as_deref(),
        ),
    ))
}

// ---------------------------------------------------------------------------
// Milestone 6 port block 4 (lane TF): every typed question below is answered
// from rows, one statement per blob per call.
// ---------------------------------------------------------------------------

/// One mount's share of a keyed typed read: the keys the request resolved to
/// inside that blob, in request order, deduplicated.
type MountKeys = (SelectedResolutionMountOrdinal, Vec<i64>);

impl<'selection, 'store> SelectedResolutionTypedSource<'selection, 'store> {
    /// Group one request's resolved coordinates by the blob that answers them.
    ///
    /// `semantic_coordinates` is unchanged: it is what turns a runtime
    /// identity into `(mount, key)` for a blob-local semantic and into
    /// `(mount, resolution_identities.id)` for a shared name through the one
    /// tier 1 membership family. What changes here is only what the key is
    /// then used for.
    fn local_keys_by_mount(
        &self,
        semantics: &[SemanticId],
        relation: TypedFactRelation,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<MountKeys>>> {
        self.keys_by_mount(semantics, relation, RequestKeySpace::Local, cancellation)
    }

    fn shared_keys_by_mount(
        &self,
        semantics: &[SemanticId],
        relation: TypedFactRelation,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<MountKeys>>> {
        self.keys_by_mount(semantics, relation, RequestKeySpace::Shared, cancellation)
    }

    fn keys_by_mount(
        &self,
        semantics: &[SemanticId],
        relation: TypedFactRelation,
        space: RequestKeySpace,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<MountKeys>>> {
        let Some(coordinates) = self.semantic_coordinates(semantics, relation, cancellation)?
        else {
            return Ok(None);
        };
        Ok(Some(group_keys(
            coordinates
                .into_iter()
                .filter(|coordinate| coordinate.space == space),
        )))
    }

    fn node_keys_by_mount(
        &self,
        nodes: &[BindingNodeId],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<MountKeys>>> {
        let Some(coordinates) = self.node_coordinates(nodes, cancellation)? else {
            return Ok(None);
        };
        Ok(Some(group_keys(coordinates.into_iter())))
    }

    /// Read one typed question from rows: one statement per blob, its keys
    /// delivered as one JSON array, its rows decoded by one function and paged
    /// out in the order the statement produced them.
    fn visit_typed_rows<T: TypedRowEvidence>(
        &self,
        mounts: &[MountKeys],
        sql: &str,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, T>,
        decode: impl Fn(TypedRowContext, &Row<'_>) -> StoreResult<T>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let mut evidence = PolledCompletionAccumulator::new(cancellation);
        for (ordinal, keys) in mounts {
            let mount = &*self.mount(*ordinal)?;
            let key_array = json_integer_array(keys.iter().copied());
            let Some(rows) = self.decode_page(
                mount,
                sql,
                &[&mount.blob_id() as &dyn rusqlite::ToSql, &key_array],
                cancellation,
                &decode,
                &mut evidence,
            )?
            else {
                return Ok(TypedFactReadOutcome::cancelled(
                    evidence.finish_semantic().0,
                ));
            };
            match Self::page_out(&rows, cancellation, visitor)? {
                PageOutcome::Exhausted => {}
                PageOutcome::Stopped => {
                    let (completion, cancelled) = evidence.finish_semantic();
                    return Ok(if cancelled {
                        TypedFactReadOutcome::cancelled(completion)
                    } else {
                        TypedFactReadOutcome::stopped(completion)
                    });
                }
                PageOutcome::Cancelled => {
                    return Ok(TypedFactReadOutcome::cancelled(
                        evidence.finish_semantic().0,
                    ));
                }
            }
        }
        Ok(if cancellation.is_cancelled() {
            TypedFactReadOutcome::cancelled(evidence.finish_semantic().0)
        } else {
            TypedFactReadOutcome::exhausted(ResolutionCompletion::Complete)
        })
    }

    /// The same read with no key predicate: one statement per blob of a mount
    /// set the caller established.
    fn visit_typed_rows_in_mounts<T: TypedRowEvidence>(
        &self,
        mounts: &[SelectedResolutionMountOrdinal],
        sql: &str,
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, T>,
        decode: impl Fn(TypedRowContext, &Row<'_>) -> StoreResult<T>,
    ) -> StoreResult<TypedFactReadOutcome> {
        let mut evidence = PolledCompletionAccumulator::new(cancellation);
        for ordinal in mounts {
            let mount = &*self.mount(*ordinal)?;
            let Some(rows) = self.decode_page(
                mount,
                sql,
                &[&mount.blob_id() as &dyn rusqlite::ToSql],
                cancellation,
                &decode,
                &mut evidence,
            )?
            else {
                return Ok(TypedFactReadOutcome::cancelled(
                    evidence.finish_semantic().0,
                ));
            };
            match Self::page_out(&rows, cancellation, visitor)? {
                PageOutcome::Exhausted => {}
                PageOutcome::Stopped => {
                    let (completion, cancelled) = evidence.finish_semantic();
                    return Ok(if cancelled {
                        TypedFactReadOutcome::cancelled(completion)
                    } else {
                        TypedFactReadOutcome::stopped(completion)
                    });
                }
                PageOutcome::Cancelled => {
                    return Ok(TypedFactReadOutcome::cancelled(
                        evidence.finish_semantic().0,
                    ));
                }
            }
        }
        Ok(if cancellation.is_cancelled() {
            TypedFactReadOutcome::cancelled(evidence.finish_semantic().0)
        } else {
            TypedFactReadOutcome::exhausted(ResolutionCompletion::Complete)
        })
    }

    /// One blob's rows for one statement, decoded.
    ///
    /// The whole answer for one blob lives for one call, which is the
    /// query-lifetime shape milestone 6 allows; nothing here outlives the
    /// request.
    fn decode_page<T: TypedRowEvidence>(
        &self,
        mount: &SelectedResolutionMountRecord,
        sql: &str,
        parameters: &[&dyn rusqlite::ToSql],
        cancellation: &CancellationToken,
        decode: &impl Fn(TypedRowContext, &Row<'_>) -> StoreResult<T>,
        evidence: &mut PolledCompletionAccumulator<'_>,
    ) -> StoreResult<Option<Vec<T>>> {
        let names = self
            .selection
            .shared_name_table()
            .interner(self.selection.connection());
        let context = TypedRowContext {
            fragment: mount.fragment_id(),
            ordinal: mount.ordinal().get(),
            names: &names,
        };
        self.read_statement(cancellation, |conn| {
            let mut statement = conn.prepare_cached(sql)?;
            let mut rows = statement.query(parameters)?;
            decode_typed_page(context, &mut rows, cancellation, decode, evidence)
        })
    }

    fn page_out<T>(
        rows: &[T],
        cancellation: &CancellationToken,
        visitor: &mut TypedFactPageVisitor<'_, T>,
    ) -> StoreResult<PageOutcome> {
        for page in rows.chunks(visitor.maximum_rows()) {
            if cancellation.is_cancelled() {
                return Ok(PageOutcome::Cancelled);
            }
            let keep_going = visitor.visit_page(page)?;
            if cancellation.is_cancelled() {
                return Ok(PageOutcome::Cancelled);
            }
            if !keep_going {
                return Ok(PageOutcome::Stopped);
            }
        }
        Ok(if cancellation.is_cancelled() {
            PageOutcome::Cancelled
        } else {
            PageOutcome::Exhausted
        })
    }
}

enum PageOutcome {
    Exhausted,
    Stopped,
    Cancelled,
}

/// Coordinates to one list of keys per mount, in mount order, each list in
/// request order and free of repeats.
fn group_keys(coordinates: impl Iterator<Item = RequestCoordinate>) -> Vec<MountKeys> {
    let mut grouped: Vec<MountKeys> = Vec::new();
    for coordinate in coordinates {
        match grouped
            .iter_mut()
            .find(|(ordinal, _)| *ordinal == coordinate.mount)
        {
            Some((_, keys)) => {
                if !keys.contains(&coordinate.keys[0]) {
                    keys.push(coordinate.keys[0]);
                }
            }
            None => grouped.push((coordinate.mount, vec![coordinate.keys[0]])),
        }
    }
    grouped
}

/// One batch of integer keys as the JSON array a `json_each(?)` statement
/// takes (milestone 6's rule, as `store/resolution_lexical.rs` states it).
fn json_integer_array(keys: impl Iterator<Item = i64>) -> String {
    let mut out = String::from("[");
    for (position, key) in keys.enumerate() {
        if position > 0 {
            out.push(',');
        }
        out.push_str(&key.to_string());
    }
    out.push(']');
    out
}

/// One batch of `(qualifier slot, lookup)` pairs as a JSON array of two-element
/// arrays, which is the exact composite key the interior's index carries.
fn json_pair_array(pairs: impl Iterator<Item = (i64, i64)>) -> String {
    let mut out = String::from("[");
    for (position, (first, second)) in pairs.enumerate() {
        if position > 0 {
            out.push(',');
        }
        out.push('[');
        out.push_str(&first.to_string());
        out.push(',');
        out.push_str(&second.to_string());
        out.push(']');
    }
    out.push(']');
    out
}

// Both arms answer one caller request. Preserve their row order and multiplicity;
// this buffer is dropped when that request finishes, before the next query.
fn visit_combined_typed_rows<T: TypedRowEvidence + Clone>(
    cancellation: &CancellationToken,
    visitor: &mut TypedFactPageVisitor<'_, T>,
    ordinary: impl FnOnce(&mut TypedFactPageVisitor<'_, T>) -> StoreResult<TypedFactReadOutcome>,
    stage: impl FnOnce(&mut TypedFactPageVisitor<'_, T>) -> StoreResult<TypedFactReadOutcome>,
) -> StoreResult<TypedFactReadOutcome> {
    let mut answer = Vec::new();
    let mut evidence = PolledCompletionAccumulator::new(cancellation);
    let ordinary = collect_typed_arm(&mut answer, &mut evidence, ordinary)?;
    if ordinary.is_cancelled() || cancellation.is_cancelled() {
        return Ok(TypedFactReadOutcome::cancelled(
            evidence.finish_semantic().0,
        ));
    }
    let stage = collect_typed_arm(&mut answer, &mut evidence, stage)?;
    if stage.is_cancelled() || cancellation.is_cancelled() {
        return Ok(TypedFactReadOutcome::cancelled(
            evidence.finish_semantic().0,
        ));
    }
    let terminal = SelectedResolutionTypedSource::page_out(&answer, cancellation, visitor)?;
    let (completion, cancelled) = evidence.finish_semantic();
    Ok(if cancelled || matches!(terminal, PageOutcome::Cancelled) {
        TypedFactReadOutcome::cancelled(completion)
    } else {
        match terminal {
            PageOutcome::Exhausted => {
                TypedFactReadOutcome::exhausted(ResolutionCompletion::Complete)
            }
            PageOutcome::Stopped => TypedFactReadOutcome::stopped(completion),
            PageOutcome::Cancelled => unreachable!("handled cancelled terminal"),
        }
    })
}

fn collect_typed_arm<T: TypedRowEvidence + Clone>(
    answer: &mut Vec<T>,
    evidence: &mut PolledCompletionAccumulator<'_>,
    read: impl FnOnce(&mut TypedFactPageVisitor<'_, T>) -> StoreResult<TypedFactReadOutcome>,
) -> StoreResult<TypedFactReadOutcome> {
    let outcome = read(&mut TypedFactPageVisitor::new(&mut |page| {
        for row in page {
            row.include_evidence(evidence);
        }
        answer.extend_from_slice(page);
        Ok(true)
    }))?;
    // A cancelled decoder may have observed rows it could not hand to our
    // collector. Its terminal evidence retains that decoded prefix.
    evidence.include(outcome.evidence());
    assert!(
        outcome.is_exhausted() || outcome.is_cancelled(),
        "the collecting visitor never stops an arm"
    );
    Ok(outcome)
}

// Eager decoding makes every decoded row source-known, even if a caller stops
// on an earlier page. Keep that evidence across blobs until the read terminates.
trait TypedRowEvidence {
    fn include_evidence(&self, _evidence: &mut PolledCompletionAccumulator<'_>) {}
}

macro_rules! no_typed_row_evidence {
    ($($row:ty),+ $(,)?) => { $(impl TypedRowEvidence for SelectedTypedRow<$row> {})+ };
}

no_typed_row_evidence!(
    LoweredRustReferenceContext,
    LoweredRustDeclarationAuthority,
    LoweredTypedFrontier,
    LoweredBindingProjection,
    LoweredDeclarationTypeProperty,
    LoweredDeclarationVisibilityProperty,
    LoweredMemberScopeProperty,
    LoweredMemberOwnerProperty,
    LoweredDeferredMemberOwner,
    LoweredConstructionRequirementProperty,
    LoweredSupertypeProperty,
);

impl TypedRowEvidence for SelectedTypedRow<LoweredTypeTransfer> {
    fn include_evidence(&self, evidence: &mut PolledCompletionAccumulator<'_>) {
        evidence.include(self.row().rule().completion());
    }
}

impl TypedRowEvidence for SelectedTypedRow<LoweredTypeComponent> {}

impl TypedRowEvidence for SelectedTypedRow<LoweredUnderlyingType> {}

impl TypedRowEvidence for SelectedTypedRow<LoweredIntrinsicSeed> {
    fn include_evidence(&self, evidence: &mut PolledCompletionAccumulator<'_>) {
        evidence.include(self.row().frontier().completion());
    }
}

impl TypedRowEvidence for SelectedGapReasonProvenance {}

impl TypedRowEvidence for SelectedTypeFrontierCompletion {
    fn include_evidence(&self, evidence: &mut PolledCompletionAccumulator<'_>) {
        evidence.include(self.completion());
    }
}

impl TypedRowEvidence for SelectedQualifiedRoute {
    fn include_evidence(&self, evidence: &mut PolledCompletionAccumulator<'_>) {
        evidence.include_reason(ResolutionIncompleteReason::UnsupportedSemantic(
            self.row().coarse_gap_reason(),
        ));
    }
}

impl TypedRowEvidence for SelectedTypedRow<LoweredDefinitionPropertyGap> {
    fn include_evidence(&self, evidence: &mut PolledCompletionAccumulator<'_>) {
        evidence.include_reason(ResolutionIncompleteReason::UnsupportedSemantic(
            self.row().reason_semantic(),
        ));
    }
}

impl TypedRowEvidence for SelectedTypedRow<LoweredCallApplicabilityObligation> {
    fn include_evidence(&self, evidence: &mut PolledCompletionAccumulator<'_>) {
        evidence.include(self.row().completion());
    }
}

impl TypedRowEvidence for SelectedTypedRow<LoweredCallableSignatureProperty> {
    fn include_evidence(&self, evidence: &mut PolledCompletionAccumulator<'_>) {
        evidence.include(self.row().completion());
    }
}

fn decode_typed_page<T: TypedRowEvidence>(
    context: TypedRowContext,
    rows: &mut rusqlite::Rows<'_>,
    cancellation: &CancellationToken,
    decode: &impl Fn(TypedRowContext, &Row<'_>) -> StoreResult<T>,
    evidence: &mut PolledCompletionAccumulator<'_>,
) -> StoreResult<Option<Vec<T>>> {
    let mut decoded = Vec::new();
    while let Some(row) = rows.next()? {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let row = decode(context, row)?;
        row.include_evidence(evidence);
        decoded.push(row);
    }
    Ok(Some(decoded))
}

#[cfg(test)]
mod row_evidence_tests {
    use super::*;
    use crate::analyzer::Language;
    use crate::analyzer::resolution::{
        LoweredTypedFragment, PreloadedFactResolutionService, ResolutionSlotValue,
        ResolutionTypeRef, SharedNameId, TypedFrontierState,
    };
    use brokk_bifrost_core::analyzer::resolution_facts::{
        IntrinsicTypeKind, ResolutionTypeSlotRole,
    };

    #[test]
    fn selected_hierarchy_terminals_preserve_mounts_and_cancellation() {
        use crate::analyzer::resolution::LoweringGapOrigin;
        use crate::analyzer::store::resolution_selection::tests::SelectionFixture;
        use brokk_bifrost_core::analyzer::resolution_facts::{ResolutionGapKind, ResolutionSiteId};
        let fixture = SelectionFixture::custom_source(2, "class Base {} class Box extends Base {}");
        let selection = fixture.open_ready(&[]);
        let origin = LoweringGapOrigin::Extracted(ResolutionGapKind::UnsupportedHierarchyTraversal);
        let gaps = selection.connection().prepare(
            "SELECT mount.mount_ordinal, gap.reason, gap.site FROM temp.selected_resolution_mounts mount JOIN main.resolution_gap_reasons gap ON gap.blob_id=mount.blob_id WHERE gap.origin=?1 ORDER BY mount.mount_ordinal,gap.reason"
        ).unwrap().query_map([super::super::resolution_prepare::resolution_rows::gap_origin_code(origin)], |row| {
            let mount: u32 = row.get(0)?;
            Ok(SelectedGapReasonProvenance::new(
                BindingFragmentId::at_ordinal(mount), SemanticId::local(mount,row.get(1)?),
                ResolutionSiteId::new(row.get(2)?), origin,
            ))
        }).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
        assert_eq!(
            gaps.len(),
            4,
            "each mount has Base's implicit and Box's explicit superclass obligations: {gaps:?}"
        );
        let source = SelectedResolutionTypedSource::new_on_demand(&selection);
        let rows = source
            .hierarchy_terminal_nodes(&gaps, &CancellationToken::new())
            .unwrap()
            .unwrap();
        assert_eq!(rows.len(), gaps.len(), "{rows:?}");
        assert_eq!(
            rows.iter()
                .map(|(_, node)| *node)
                .collect::<BTreeSet<_>>()
                .len(),
            4
        );
        for ((reason, node), gap) in rows.iter().zip(&gaps) {
            assert_eq!(*reason, gap.reason());
            assert_eq!(node.ordinal(), Some(gap.fragment().ordinal()));
        }
        assert!(
            source
                .hierarchy_terminal_nodes(
                    &gaps,
                    &CancellationToken::cancel_after_checks_for_test(0)
                )
                .unwrap()
                .is_none()
        );
        assert_eq!(
            source
                .hierarchy_terminal_nodes(&gaps, &CancellationToken::new())
                .unwrap()
                .unwrap(),
            rows
        );
    }

    fn seed(context: TypedRowContext, slot: u32) -> SelectedTypedRow<LoweredIntrinsicSeed> {
        SelectedTypedRow::new(
            context.fragment,
            LoweredIntrinsicSeed::new(
                IntrinsicTypeKind::Primitive,
                "int",
                TypedFrontierState::new(
                    context.semantic(i64::from(slot)),
                    [ResolutionSlotValue::runtime(
                        ResolutionTypeRef::new(
                            SemanticId::shared_name(SharedNameId::interned(1)),
                            0,
                        ),
                        false,
                    )],
                    ResolutionCompletion::incomplete([
                        ResolutionIncompleteReason::UnsupportedSemantic(
                            context.semantic(i64::from(slot + 100)),
                        ),
                    ]),
                ),
            ),
        )
    }

    #[test]
    fn frontier_completion_validates_requested_authority_without_unrelated_mounts() {
        use super::super::resolution_selection::tests::SelectionFixture;
        for damage in ["unrelated", "missing", "stale", "withdrawn_blob"] {
            let fixture =
                SelectionFixture::custom_source(2, "package demo; class Model { int value = 1; }");
            let selection = fixture.open_ready(&[]);
            let (blob, key): (i64, u32) = selection.connection().query_row(
                "SELECT m.blob_id,f.slot FROM temp.selected_resolution_mounts m JOIN main.resolution_type_frontiers f ON f.blob_id=m.blob_id WHERE m.mount_ordinal=0 LIMIT 1",
                [], |row| Ok((row.get(0)?, row.get(1)?)),
            ).unwrap();
            let slot = SemanticId::local(0, key);
            let source = SelectedResolutionTypedSource::new_on_demand(&selection);
            let read = |token: &CancellationToken| {
                let mut rows = Vec::new();
                let outcome = source.visit_type_frontier_completion_pages(
                    TypedFactRequest::new(&[slot]),
                    token,
                    &mut TypedFactPageVisitor::new(&mut |page| {
                        rows.extend_from_slice(page);
                        Ok(true)
                    }),
                )?;
                Ok::<_, StoreError>((outcome, rows))
            };
            let live = CancellationToken::new();
            let (_, before) = read(&live).unwrap();
            assert!(!before.is_empty());
            match damage {
                "withdrawn_blob" => {
                    // Sealed source requirements cannot be edited independently.
                    // Parsed-blob withdrawal lawfully cascades both publication
                    // authorities; this is not isolated readiness corruption.
                    assert_eq!(
                        fixture
                            .store
                            .conn
                            .lock()
                            .unwrap()
                            .execute("DELETE FROM blobs WHERE id=?1", [blob],)
                            .unwrap(),
                        1
                    );
                    assert!(
                        !selection
                            .connection()
                            .prepare(FRONTIER_SOURCE_READY_SQL)
                            .unwrap()
                            .exists([blob])
                            .unwrap()
                    );
                }
                _ => {
                    let damaged_blob = if damage == "unrelated" {
                        selection
                            .persisted_mount_record(SelectedResolutionMountOrdinal::new(1))
                            .unwrap()
                            .unwrap()
                            .blob_id()
                    } else {
                        blob
                    };
                    let writer = fixture.store.conn.lock().unwrap();
                    let sql = if damage == "missing" {
                        "DELETE FROM resolution_fragment_interiors WHERE blob_id=?1"
                    } else {
                        "UPDATE resolution_fragment_interiors SET interior_digest=zeroblob(32) WHERE blob_id=?1"
                    };
                    assert_eq!(writer.execute(sql, [damaged_blob]).unwrap(), 1);
                }
            }
            if damage == "unrelated" {
                let (outcome, after) = read(&live).unwrap();
                assert!(outcome.is_exhausted());
                assert_eq!(after, before);
            } else {
                assert!(
                    read(&live).is_err(),
                    "requested {damage} must not become an empty answer"
                );
            }
            let cancelled = CancellationToken::new();
            cancelled.cancel();
            let (outcome, rows) = read(&cancelled).unwrap();
            assert!(outcome.is_cancelled());
            assert!(rows.is_empty());
        }
    }

    #[test]
    fn frontier_source_visibility_pin_is_keyed_under_both_statistics_states() {
        use super::super::planner_statistics::pinned_plans::{pinned, plan_rows};
        use super::super::resolution_selection::tests::SelectionFixture;
        use brokk_bifrost_core::cache_gc::PlannerStatisticsState;
        use rusqlite::StatementStatus;
        for statistics in PlannerStatisticsState::BOTH {
            let mut tiny = Vec::new();
            let mut keyed = Vec::new();
            for count in [2, 32, 64] {
                let fixture = SelectionFixture::new(count);
                let writer = fixture.store.conn.lock().unwrap();
                statistics.install(&writer);
                let marker_count: usize = writer
                    .query_row(
                        "SELECT COUNT(*) FROM source_java_declaration_manifests",
                        [],
                        |row| row.get(0),
                    )
                    .unwrap();
                assert_eq!(marker_count, count);
                let (first, last): (i64, i64) = writer
                    .query_row(
                        "SELECT MIN(blob_id),MAX(blob_id) FROM resolution_fragment_interiors",
                        [],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .unwrap();
                let mut measured = Vec::new();
                for (blob, expected) in [(first, true), (last, true), (-1, false)] {
                    let mut query = pinned("frontier_source_ready");
                    query.params = vec![Value::Integer(blob)];
                    let plan = plan_rows(&writer, &query).unwrap();
                    for step in &plan {
                        if step.starts_with("SCAN ") {
                            assert!(
                                marker_count <= 2 && step == "SCAN java_marker LEFT-JOIN",
                                "{statistics:?}, markers={marker_count}: {plan:?}"
                            );
                        }
                    }
                    if marker_count > 2 {
                        assert!(
                            plan.iter().any(|step| step
                                .starts_with("SEARCH java_marker USING INTEGER PRIMARY KEY")),
                            "{statistics:?}, markers={marker_count}: {plan:?}"
                        );
                    }
                    let mut statement = writer.prepare(&query.sql).unwrap();
                    assert_eq!(statement.exists([blob]).unwrap(), expected);
                    measured.push(statement.get_status(StatementStatus::VmStep));
                }
                if count == 2 {
                    tiny = measured;
                } else {
                    assert!(
                        measured
                            .iter()
                            .zip(&tiny)
                            .all(|(large, small)| large <= small),
                        "{statistics:?}: tiny={tiny:?}, markers={marker_count}, work={measured:?}"
                    );
                    if count == 32 {
                        keyed = measured;
                    } else {
                        assert_eq!(measured, keyed, "{statistics:?}: keyed growth must be flat");
                    }
                }
            }
        }
    }

    #[test]
    fn actual_mixed_intrinsic_reader_retains_stage_evidence_on_stop_and_cancel() {
        use super::super::resolution_selection::{
            SelectedResolutionTempTransaction, tests::SelectionFixture,
        };
        let fixture =
            SelectionFixture::custom_source(1, "package demo; class Model { int value = 1; }");
        let selection = fixture.open_ready(&[]);
        let (host, key): (u32, u32) = selection.connection().query_row(
            "SELECT m.mount_ordinal,s.slot FROM temp.selected_resolution_mounts m JOIN main.resolution_intrinsic_seeds s ON s.blob_id=m.blob_id LIMIT 1",
            [], |row| Ok((row.get(0)?,row.get(1)?)),
        ).unwrap();
        let slot = SemanticId::local(host, key);
        let source = SelectedResolutionTypedSource::new_on_demand(&selection);
        let mut ordinary = Vec::new();
        assert!(
            source
                .visit_intrinsic_seed_pages_for_slots(
                    TypedFactRequest::new(&[slot]),
                    &CancellationToken::new(),
                    &mut TypedFactPageVisitor::new(&mut |page| {
                        ordinary.extend_from_slice(page);
                        Ok(true)
                    }),
                )
                .unwrap()
                .is_exhausted()
        );
        assert!(!ordinary.is_empty());
        let base = ordinary[0].row();
        let stage_completion =
            ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
                SemanticId::context_local(73),
            )]);
        let stage_slot = SemanticId::context_local(74);
        let seed = LoweredIntrinsicSeed::new(
            base.kind(),
            base.spelling(),
            TypedFrontierState::new(
                stage_slot,
                base.frontier().possible_values().to_vec(),
                stage_completion.clone(),
            ),
        );
        let mut frontiers = Vec::new();
        assert!(
            source
                .visit_typed_frontier_pages(
                    TypedFactRequest::new(&[slot]),
                    &CancellationToken::new(),
                    &mut TypedFactPageVisitor::new(&mut |page| {
                        frontiers
                            .extend(page.iter().map(|row| {
                                LoweredTypedFrontier::new(stage_slot, row.row().role())
                            }));
                        Ok(true)
                    }),
                )
                .unwrap()
                .is_exhausted()
        );
        assert!(!frontiers.is_empty());
        let fragment = LoweredTypedFragment::new(
            BindingFragmentId::at_ordinal(host),
            Language::Java,
            frontiers,
            vec![],
            vec![seed],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
        );
        selection.with_owned_temp_transaction(|connection| {
            connection.execute("INSERT INTO temp.selected_resolution_stage_producers(producer_id,host_ordinal,bridge_identity,content_digest) VALUES(1,?1,zeroblob(32),zeroblob(32))", [host])?;
            assert!(super::super::resolution_stage::typed::insert_typed_fragment(
                connection, 1, SelectedResolutionMountOrdinal::new(host), &fragment, &CancellationToken::new(),
            )?);
            Ok(SelectedResolutionTempTransaction::Commit(()))
        }).unwrap();
        let shared_name = selection
            .shared_name_table()
            .interner(selection.connection())
            .intern([91; 32]);
        let shared = SemanticId::shared_name(shared_name);
        selection.with_owned_temp_write(|connection| {
            connection.execute("INSERT INTO temp.selected_resolution_stage_type_frontiers(host_ordinal,producer_id,sequence,slot_shared,role) VALUES(?1,1,901,?2,0)", rusqlite::params![host,shared_name.get()])?;
            Ok(())
        }).unwrap();
        shared_request_probe::reset();
        let mut completions = Vec::new();
        assert!(
            source
                .visit_type_frontier_completion_pages(
                    TypedFactRequest::new(&[slot, stage_slot, shared]),
                    &CancellationToken::new(),
                    &mut TypedFactPageVisitor::new(&mut |page| {
                        completions.extend_from_slice(page);
                        Ok(true)
                    }),
                )
                .unwrap()
                .is_exhausted()
        );
        for requested in [slot, stage_slot, shared] {
            assert!(
                completions.iter().any(|row| row.frontier() == requested),
                "{completions:?}"
            );
        }
        assert_eq!(
            shared_request_probe::observed(TypedFactRelation::TypeFrontierCompletionFrontier),
            (0, 0)
        );
        for cancel in [false, true] {
            let cancellation = CancellationToken::new();
            let mut emitted = Vec::new();
            let outcome = source
                .visit_intrinsic_seed_pages_for_slots(
                    TypedFactRequest::new(&[slot, stage_slot]),
                    &cancellation,
                    &mut TypedFactPageVisitor::with_maximum_rows(
                        &mut |page| {
                            emitted.extend_from_slice(page);
                            if cancel {
                                cancellation.cancel();
                            }
                            Ok(false)
                        },
                        1,
                    ),
                )
                .unwrap();
            assert_eq!(emitted, ordinary[..1]);
            let live = CancellationToken::new();
            let mut evidence = PolledCompletionAccumulator::new(&live);
            for row in &ordinary {
                row.include_evidence(&mut evidence);
            }
            evidence.include(&stage_completion);
            let expected = evidence.finish_semantic().0;
            assert_eq!(
                outcome,
                if cancel {
                    TypedFactReadOutcome::cancelled(expected)
                } else {
                    TypedFactReadOutcome::stopped(expected)
                }
            );
        }
    }

    #[test]
    fn combined_typed_cancellation_keeps_an_unemitted_decode_prefix() {
        let cancellation = CancellationToken::new();
        let reason = ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::local(0, 71));
        let expected = ResolutionCompletion::incomplete([reason]);
        let mut visited = false;
        let outcome = visit_combined_typed_rows::<SelectedTypedRow<LoweredIntrinsicSeed>>(
            &cancellation,
            &mut TypedFactPageVisitor::new(&mut |_| {
                visited = true;
                Ok(true)
            }),
            |_| {
                Ok(TypedFactReadOutcome::exhausted(
                    ResolutionCompletion::Complete,
                ))
            },
            |_| {
                cancellation.cancel();
                Ok(TypedFactReadOutcome::cancelled(expected.clone()))
            },
        )
        .unwrap();
        assert!(!visited);
        assert_eq!(outcome, TypedFactReadOutcome::cancelled(expected));
    }

    #[test]
    fn combined_typed_rows_keep_multiplicity_and_unemitted_stage_evidence() {
        use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;
        use brokk_bifrost_core::analyzer::usages::resolution_session::{
            BoundedResolution, ResolutionSession,
        };
        let context = TypedRowContext {
            fragment: BindingFragmentId::for_test(b"combined-row-evidence"),
            ordinal: 0,
            names: crate::analyzer::resolution::test_shared_names(),
        };
        let ordinary = seed(context, 1);
        let stage = seed(context, 2);
        for stop in [false, true] {
            let cancellation = CancellationToken::new();
            let session = ResolutionSession::bounded(
                ReceiverAnalysisBudget {
                    max_scope_nodes: 3,
                    ..ReceiverAnalysisBudget::default()
                },
                Some(&cancellation),
            );
            let mut emitted = Vec::new();
            let outcome = visit_combined_typed_rows(
                &cancellation,
                &mut TypedFactPageVisitor::with_maximum_rows_in_session(
                    &mut |page| {
                        emitted.extend_from_slice(page);
                        Ok(!stop)
                    },
                    1,
                    &session,
                ),
                |collector| {
                    assert!(collector.visit_page(&[ordinary.clone(), ordinary.clone()])?);
                    Ok(TypedFactReadOutcome::exhausted(
                        ResolutionCompletion::Complete,
                    ))
                },
                |collector| {
                    assert!(collector.visit_page(std::slice::from_ref(&stage))?);
                    Ok(TypedFactReadOutcome::exhausted(
                        ResolutionCompletion::Complete,
                    ))
                },
            )
            .unwrap();
            let BoundedResolution::Complete { work, .. } = session.finish(()) else {
                panic!("three emitted rows must fit the exact three-step budget");
            };
            assert_eq!(work.scope_nodes, if stop { 1 } else { 3 });
            assert_eq!(work.scope_nodes, emitted.len());
            assert_eq!(work.setup_nodes, 0);
            assert_eq!(work.summary_expansions, 0);
            if stop {
                assert_eq!(emitted, vec![ordinary.clone()]);
                let expected = ResolutionCompletion::incomplete([101, 102].map(|reason| {
                    ResolutionIncompleteReason::UnsupportedSemantic(context.semantic(reason))
                }));
                assert_eq!(outcome, TypedFactReadOutcome::stopped(expected));
            } else {
                assert_eq!(
                    emitted,
                    vec![ordinary.clone(), ordinary.clone(), stage.clone()]
                );
                assert_eq!(
                    outcome,
                    TypedFactReadOutcome::exhausted(ResolutionCompletion::Complete)
                );
            }
        }
    }

    #[test]
    fn row_decode_and_preloaded_stop_preserve_the_same_observed_evidence() {
        let context = TypedRowContext {
            fragment: BindingFragmentId::for_test(b"row-evidence"),
            ordinal: 0,
            names: crate::analyzer::resolution::test_shared_names(),
        };
        let seed = seed(context, 1);
        let lowered = LoweredTypedFragment::new(
            context.fragment,
            Language::Java,
            vec![LoweredTypedFrontier::new(
                context.semantic(1),
                ResolutionTypeSlotRole::ExpressionValue,
            )],
            vec![],
            vec![seed.row().clone()],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
        );
        let empty = crate::analyzer::resolution::lower_for_test(
            context.fragment,
            Language::Java,
            &brokk_bifrost_core::analyzer::resolution_facts::FileResolutionFacts::default(),
        );
        let service = PreloadedFactResolutionService::from_lowered_fragments(
            [empty.lexical().clone()],
            [lowered],
        );
        // Cancellation wins even when the callback also returns false.
        for (keep_going, cancel) in [(true, false), (false, false), (true, true), (false, true)] {
            let cancellation = CancellationToken::new();
            let mut expected_rows = Vec::new();
            let expected = service
                .visit_intrinsic_seed_pages_for_slots(
                    TypedFactRequest::new(&[context.semantic(1)]),
                    &cancellation,
                    &mut TypedFactPageVisitor::with_maximum_rows(
                        &mut |page| {
                            expected_rows.extend_from_slice(page);
                            if cancel {
                                cancellation.cancel();
                            }
                            Ok(keep_going)
                        },
                        1,
                    ),
                )
                .unwrap();
            let cancellation = CancellationToken::new();
            let mut evidence = PolledCompletionAccumulator::new(&cancellation);
            let conn = Connection::open_in_memory().unwrap();
            let mut statement = conn.prepare("SELECT 1").unwrap();
            let rows = decode_typed_page(
                context,
                &mut statement.query([]).unwrap(),
                &cancellation,
                &|_, _| Ok(seed.clone()),
                &mut evidence,
            )
            .unwrap()
            .unwrap();
            let mut actual_rows = Vec::new();
            let terminal = SelectedResolutionTypedSource::page_out(
                &rows,
                &cancellation,
                &mut TypedFactPageVisitor::with_maximum_rows(
                    &mut |page| {
                        actual_rows.extend_from_slice(page);
                        if cancel {
                            cancellation.cancel();
                        }
                        Ok(keep_going)
                    },
                    1,
                ),
            )
            .unwrap();
            let (completion, _) = evidence.finish_semantic();
            let actual = match terminal {
                PageOutcome::Exhausted => {
                    TypedFactReadOutcome::exhausted(ResolutionCompletion::Complete)
                }
                PageOutcome::Stopped => TypedFactReadOutcome::stopped(completion),
                PageOutcome::Cancelled => TypedFactReadOutcome::cancelled(completion),
            };
            assert_eq!(actual_rows, expected_rows);
            assert_eq!(actual.terminal(), expected.terminal());
            assert_eq!(actual.evidence(), expected.evidence());
        }
    }

    #[test]
    fn eager_typed_decode_retains_unemitted_rows_and_cancelled_decode_prefix() {
        let context = TypedRowContext {
            fragment: BindingFragmentId::for_test(b"eager-row-evidence"),
            ordinal: 0,
            names: crate::analyzer::resolution::test_shared_names(),
        };
        let seeds = (1..=3).map(|slot| seed(context, slot)).collect::<Vec<_>>();
        let conn = Connection::open_in_memory().unwrap();
        for cancel_at in [None, Some(2_usize)] {
            let cancellation = CancellationToken::new();
            let mut evidence = PolledCompletionAccumulator::new(&cancellation);
            let mut statement = conn
                .prepare("SELECT 0 UNION ALL SELECT 1 UNION ALL SELECT 2")
                .unwrap();
            let rows = decode_typed_page(
                context,
                &mut statement.query([]).unwrap(),
                &cancellation,
                &|_, row| {
                    let index: usize = row.get(0)?;
                    if cancel_at == Some(index + 1) {
                        cancellation.cancel();
                    }
                    Ok(seeds[index].clone())
                },
                &mut evidence,
            )
            .unwrap();
            if cancel_at.is_some() {
                assert!(rows.is_none());
            } else {
                let mut emitted = 0;
                let terminal = SelectedResolutionTypedSource::page_out(
                    &rows.unwrap(),
                    &cancellation,
                    &mut TypedFactPageVisitor::with_maximum_rows(
                        &mut |page| {
                            emitted += page.len();
                            Ok(false)
                        },
                        1,
                    ),
                )
                .unwrap();
                assert!(matches!(terminal, PageOutcome::Stopped));
                assert_eq!(emitted, 1);
            }
            let count = cancel_at.unwrap_or(seeds.len());
            let expected = ResolutionCompletion::incomplete((1..=count).map(|slot| {
                ResolutionIncompleteReason::UnsupportedSemantic(
                    context.semantic((slot + 100) as i64),
                )
            }));
            assert_eq!(evidence.finish_semantic().0, expected);
        }
    }
}
