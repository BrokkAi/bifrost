//! Bounded lexical reads for one exact selected resolution inventory.
//!
//! This source borrows the retained reader and mount inventory produced by
//! `resolution_selection`. Construction indexes mount metadata only. Lexical
//! dictionaries, reference seeds, candidate heads, and path children remain
//! demand-loaded, and no read constructs a workspace graph or a compatibility
//! preload.
//!
//! Endpoint classification reads `resolution_member_scope_properties` by its
//! unique `(blob_id, scope_head_node_key)` key because the incumbent batch
//! contract includes that owner. That one companion read is not a general
//! typed source and does not strengthen the legacy semantic contract. Commit D
//! replaces the explicit typed-transfer error at the bottom of this module.

use super::resolution_stage::lexical_readers as stage;

use std::cell::{OnceCell, RefCell};
use std::collections::{BTreeMap, BTreeSet, HashSet};

use brokk_bifrost_core::analyzer::resolution_facts::{
    ResolutionCallableReceiverOrigin, ResolutionNamespace, ResolutionScopeId, ResolutionSiteId,
    ResolutionSiteKind,
};
use brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession;
use rusqlite::functions::FunctionFlags;
use rusqlite::{Connection, Row, params};
use serde::Deserialize;

use crate::CancellationToken;
use crate::analyzer::resolution::{
    BatchCandidateCompletionOutcome, BatchCandidateMatch, BatchCandidateOutcome,
    BatchCandidateRequest, BatchDefinitionNode, BatchEndpointClassification, BatchReferenceSeed,
    BatchResolutionFragmentSource, BindingFragmentId, BindingNodeId, BindingNodeKind,
    CandidatePathIdentity, CompletionReasons, EndpointSignature, FactReferenceSiteMetadata,
    LoweredCandidateDirection, MAX_SOURCE_ROWS_PER_BATCH, PartialPath, PartialPathId,
    PartialScopedSymbol, PrecedenceStep, ReferenceSeed, ReferenceSeedBatch,
    ReferenceSeedReadOutcome, ResolutionCompletion, ResolutionIncompleteReason, ResolutionLocalKey,
    ResolutionLookupSemanticRecipe, ResolutionNodeIdentity, ResolutionPathIdentity,
    ResolutionQuery, ResolutionSemanticIdentity, ResolutionStackVariableIdentity,
    ReverseCandidateGapCoverage, ReverseCandidateGapCoverageBuilder,
    ReverseCandidateGapExclusionPlan, ReverseCandidateGapRow, ReverseReferenceSeedRequest,
    SelectedNodeMount, SelectedNodeProvenance, SelectedResolutionMount,
    SelectedResolutionMountOrdinal, SelectedSemanticLocator, SelectedSemanticMount,
    SelectedSemanticProvenance, SemanticId, SharedNameId, SharedNameInterner, StackPattern,
    StackVariableId, TypeTransferRule, WitnessStep, definition_node_identity,
    reference_node_identity, scope_head_node_identity,
};
use crate::analyzer::structural::{
    BoundaryStatus, CandidateOutcome, CandidateOutcomeKind, PrecedenceTier, RejectionReason,
    ResolutionCompletionKind, ResolutionCompletionReasonKind, ResolutionWitnessKind,
};
use crate::hash::HashMap;

use super::resolution::with_resolution_read_progress_handler;
use super::resolution_prepare::resolution_rows::{
    ParsedEndpointCells, ParsedPathBody, PathBodyContext, RESOLUTION_FORWARD_CANDIDATE_MATCH_SQL,
    RESOLUTION_IDENTITY_RECIPES_SQL, RESOLUTION_PATHS_BY_KEY_SQL,
    RESOLUTION_REVERSE_CANDIDATE_MATCH_SQL, RESOLUTION_ROOT_TERMINAL_PATHS_SQL,
    RESOLUTION_SITES_BY_KEY_SQL, RootKeyBuilder, covers_candidate_endpoint,
    covers_candidate_inventory, decode_lookup_recipe, decode_path_row, decode_selected_endpoint,
    parse_endpoint_cells, parse_path_body,
};
use super::resolution_selection::{
    SelectedResolutionMountInventory, SelectedResolutionMountRecord, SelectedResolutionReadStamp,
};
use super::resolution_typed::SelectedResolutionTypedSource;
use super::{Result as StoreResult, StoreError};

// A reference's runtime ID already carries its ordinary mount and local key.
// Catalog membership and site payload are one indexed question for the batch.
pub(super) const REFERENCE_SITES_BY_KEY_SQL: &str = r#"
SELECT site.site, site.role, site.namespace, site.site_kind, site.start_byte,
       site.end_byte, site.unqualified, site.owner, site.receiver_origin, site.go_spelling_namespace, site.go_definition_namespaces, site.go_package_qualifier
FROM json_each(?2) requested
CROSS JOIN resolution_semantic_catalog catalog
 ON catalog.blob_id=?1 AND catalog.local_key=requested.value
CROSS JOIN resolution_sites site
 ON site.blob_id=catalog.blob_id AND site.site=catalog.local_key
WHERE catalog.identity_digest IS NOT NULL AND site.role=0
"#;

// Keep the coverage arms disjoint so ORDER BY cannot make SQLite scan every
// gap in a blob. Each arm seeks the existing (blob_id,covers,subject) prefix.
// The planner registry uses this same statement, including stage suppression.
pub(in crate::analyzer::store) fn reference_gap_completions_sql() -> String {
    format!(
        r#"WITH raw_gaps(host,covers,subject,reason_key,origin) AS (
 SELECT :host,fact.covers,fact.subject,:mount_base+fact.reason,reason.origin
 FROM main.resolution_gaps fact
 JOIN main.resolution_gap_reasons reason
   ON reason.blob_id=fact.blob_id AND reason.reason=fact.reason
 WHERE fact.blob_id=:blob AND fact.covers=0 AND fact.subject=0
 UNION ALL
 SELECT :host,fact.covers,fact.subject,:mount_base+fact.reason,reason.origin
 FROM main.resolution_gaps fact
 JOIN main.resolution_gap_reasons reason
   ON reason.blob_id=fact.blob_id AND reason.reason=fact.reason
 WHERE fact.blob_id=:blob AND fact.covers=4
   AND fact.subject IN(SELECT value FROM json_each(:keys))
)
SELECT g.covers,g.subject,g.reason_key FROM raw_gaps g
WHERE {} ORDER BY g.covers,g.subject"#,
        super::resolution_stage::frontier_completion::effective_gap_remains_sql()
    )
}

/// Query-owned lexical scope assignments for requested selected nodes.
pub(crate) type NodeSourceScopes =
    HashMap<BindingNodeId, Option<(BindingFragmentId, ResolutionScopeId)>>;

pub(super) fn register_resolution_identity_functions(
    connection: &Connection,
) -> rusqlite::Result<()> {
    connection.create_scalar_function(
        "resolution_node_identity",
        3,
        FunctionFlags::SQLITE_DETERMINISTIC | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            let kind = context.get::<Option<String>>(0)?;
            let ordinal = context.get::<Option<i64>>(1)?;
            let key = context.get::<Option<i64>>(2)?;
            let Some(_key) = key else {
                return Ok(None::<Vec<u8>>);
            };
            let identity = match (kind.as_deref(), ordinal) {
                (Some("scope"), Some(ordinal)) => scope_head_node_identity(ResolutionScopeId::new(
                    u32::try_from(ordinal).expect("scope ordinal fits u32"),
                )),
                (Some("reference"), Some(ordinal)) => {
                    reference_node_identity(ResolutionSiteId::new(
                        u32::try_from(ordinal).expect("reference site ordinal fits u32"),
                    ))
                }
                (Some("definition"), Some(ordinal)) => {
                    definition_node_identity(ResolutionSiteId::new(
                        u32::try_from(ordinal).expect("definition site ordinal fits u32"),
                    ))
                }
                // A node the row does not name a producer identity for used
                // to get one invented from its key, which was only correct
                // while `rekey_dense` overwrote a dense node's identity with
                // exactly that value. Nothing translates now, so there is no
                // identity to state and the function says so.
                _ => return Ok(None::<Vec<u8>>),
            };
            Ok(Some(identity.digest().to_vec()))
        },
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SelectedLookupRecipeRequest {
    pub(crate) fragment: BindingFragmentId,
    pub(crate) semantic: SemanticId,
}

#[derive(Debug)]
pub(crate) enum SelectedLookupRecipeReadOutcome {
    Ready(Box<[Option<ResolutionLookupSemanticRecipe>]>),
    Cancelled,
}

// Tier-1 boundary discovery. `resolution_path_endpoint_headers` holds one row
// per distinct (blob, direction, first-symbol identity, fixed symbol count,
// open tail) of a universal-root-rooted partial path, so this join names every
// blob whose interior can hold a match without opening any of them. A request
// whose first symbol does not compare across blobs binds `?2` to NULL and still
// admits the open-tail wildcard rows.
//
// `temp.selected_resolution_scope_mounts` is the request's scope: the whole
// selection for a reverse request and for every request that names no crate,
// and one crate's dependency closure for a forward Rust request. Every
// membership read joins it, so the scope is not a predicate a reader can
// forget.
//
// Each arm states one header shape, so each is a seek of
// `resolution_path_endpoint_headers_search`
// `(direction, identity_id, symbol_fixed_count, open_tail, blob_id)`:
//
// 1. the rows keyed by the request's first symbol, `(direction, identity_id)`;
// 2. the rows with no fixed symbol, which match any first symbol. The schema's
//    `CHECK(symbol_fixed_count > 0 OR identity_id IS NULL)` makes every such
//    row unkeyed, so `identity_id IS NULL` selects nothing away and completes
//    the seek to `(direction, identity_id, symbol_fixed_count)`;
// 3. the wildcard: a request with no fixed symbol and an open tail
//    (`?3 = 0 AND ?4 = 1`) admits every header of its direction.
//
// Arms 1 and 3 each carry a term that names only parameters. SQLite evaluates
// such a term once, before the loop, and skips the arm when it is false, so a
// request pays only for the arms its shape can match. The second arm used to
// fold the wildcard into its predicate: `(?3 = 0 AND ?4 = 1)` in an OR with
// the zero-fixed-symbol test left `direction` as its only seekable term, so
// every execution walked the direction's whole header range. On tract that is
// 7,491 forward or 4,339 reverse rows, about 150 us an execution, to answer a
// probe that the zero-fixed-symbol rows (none on tract) decide.
pub(super) const PATH_ENDPOINT_HEADER_MOUNTS_SQL: &str = r#"
SELECT DISTINCT m.mount_ordinal
FROM main.resolution_path_endpoint_headers AS h
CROSS JOIN temp.selected_resolution_mounts AS m
     INDEXED BY selected_resolution_mounts_blob_ordinal
JOIN temp.selected_resolution_scope_mounts AS scope
     ON scope.mount_ordinal = m.mount_ordinal
WHERE h.direction = ?1
  AND ?2 IS NOT NULL
  AND h.identity_id = ?2
  AND (h.symbol_fixed_count = ?3
       OR (h.symbol_fixed_count > ?3 AND ?4 = 1)
       OR (h.symbol_fixed_count < ?3 AND h.open_tail = 1))
  AND m.blob_id = h.blob_id
UNION
SELECT DISTINCT m.mount_ordinal
FROM main.resolution_path_endpoint_headers AS h
     INDEXED BY resolution_path_endpoint_headers_search
CROSS JOIN temp.selected_resolution_mounts AS m
     INDEXED BY selected_resolution_mounts_blob_ordinal
JOIN temp.selected_resolution_scope_mounts AS scope
     ON scope.mount_ordinal = m.mount_ordinal
WHERE h.direction = ?1
  AND h.identity_id IS NULL
  AND h.symbol_fixed_count = 0
  AND (?3 = 0 OR h.open_tail = 1)
  AND m.blob_id = h.blob_id
UNION
SELECT DISTINCT m.mount_ordinal
FROM main.resolution_path_endpoint_headers AS h
CROSS JOIN temp.selected_resolution_mounts AS m
     INDEXED BY selected_resolution_mounts_blob_ordinal
JOIN temp.selected_resolution_scope_mounts AS scope
     ON scope.mount_ordinal = m.mount_ordinal
WHERE ?3 = 0
  AND ?4 = 1
  AND h.direction = ?1
  AND m.blob_id = h.blob_id
"#;

// The same question as `PATH_ENDPOINT_HEADER_MOUNTS_SQL`, asked of one root
// read's mount scope rather than of the whole selection.
//
// The unscoped statement's wildcard arm has no identity predicate: an
// open-tail request with no fixed symbol (`?3 = 0 AND ?4 = 1`) admits every
// blob that carries any endpoint header in its direction, which is exactly the
// shape the scoped root readers send. Filtering that in Rust afterwards still
// charged the caller for the workspace. Here `json_each` over the scope is the
// only thing that can drive the join, so the read costs one primary-key seek
// and one index range per scoped mount and never names a mount the caller may
// not use. `rust_crate_context.rs` already binds a set this way
// (`json_each(gap.detail, '$.imports')`).
//
// The header rows split by identity, because their two blob-leading indexes
// are partial: `..._keyed` covers the rows that name a first-symbol identity
// and `..._unkeyed` the rows that do not, so each branch states which half it
// reads. `CHECK(symbol_fixed_count > 0 OR identity_id IS NULL)` makes every
// keyed row a fixed-symbol row, which is why the keyed branch's wildcard term
// reduces to `?3 = 0 AND ?4 = 1`.
//
// Two scopes meet here and they intersect: `?5` is the root read's own mount
// set, and `temp.selected_resolution_scope_mounts` is the request's, the whole
// selection unless a forward Rust request narrowed it to its crate's
// dependency closure.
pub(super) const SCOPED_PATH_ENDPOINT_HEADER_MOUNTS_SQL: &str = r#"
SELECT DISTINCT m.mount_ordinal
FROM json_each(?5) AS root
JOIN temp.selected_resolution_scope_mounts AS scope
     ON scope.mount_ordinal = root.value
JOIN temp.selected_resolution_mounts AS m
     ON m.mount_ordinal = scope.mount_ordinal
JOIN main.resolution_path_endpoint_headers AS h
     INDEXED BY resolution_path_endpoint_headers_keyed
     ON h.blob_id = m.blob_id
    AND h.direction = ?1
    AND h.identity_id IS NOT NULL
WHERE (?3 = 0 AND ?4 = 1)
   OR (?2 IS NOT NULL
       AND h.identity_id = ?2
       AND (h.symbol_fixed_count = ?3
            OR (h.symbol_fixed_count > ?3 AND ?4 = 1)
            OR (h.symbol_fixed_count < ?3 AND h.open_tail = 1)))
UNION
SELECT DISTINCT m.mount_ordinal
FROM json_each(?5) AS root
JOIN temp.selected_resolution_scope_mounts AS scope
     ON scope.mount_ordinal = root.value
JOIN temp.selected_resolution_mounts AS m
     ON m.mount_ordinal = scope.mount_ordinal
JOIN main.resolution_path_endpoint_headers AS h
     INDEXED BY resolution_path_endpoint_headers_unkeyed
     ON h.blob_id = m.blob_id
    AND h.direction = ?1
    AND h.identity_id IS NULL
WHERE (?3 = 0 AND (h.symbol_fixed_count = 0 OR ?4 = 1))
   OR (h.symbol_fixed_count = 0 AND h.open_tail = 1)
"#;

// Tier-1 terminal discovery for the root-import demand. The header holds one
// row per distinct (blob, direction, last-symbol identity, fixed symbol count)
// of a universal-root-terminated partial path; the demand needs at least three
// fixed symbols, which is the shape a root import half carries.
pub(super) const PATH_TERMINAL_HEADER_MOUNTS_SQL: &str = r#"
SELECT DISTINCT m.mount_ordinal
FROM main.resolution_path_terminal_headers AS h
CROSS JOIN temp.selected_resolution_mounts AS m
     INDEXED BY selected_resolution_mounts_blob_ordinal
JOIN temp.selected_resolution_scope_mounts AS scope
     ON scope.mount_ordinal = m.mount_ordinal
WHERE h.direction = 'reverse'
  AND h.identity_id = ?1
  AND h.symbol_fixed_count >= 3
  AND m.blob_id = h.blob_id
"#;

// One candidate direction's operation-wide unconditional completion, from
// `resolution_gaps` (milestone 6, port block 3, lane GR).
//
// A fragment-blocking gap and a candidate-inventory gap both qualify every
// candidate read of their own blob without naming an endpoint, so the box is a
// property of the selection and the direction alone. Each row carries the
// gap's blob-local reason key, which the reader remounts on that blob's own
// fragment, so the whole box is one indexed query and no blob's interior is
// produced to state it.
//
// The key is the question. `resolution_gaps` is keyed
// `(blob_id, covers, subject, lookup, gap)`, so "this blob's fragment-wide
// gaps of this direction" is two primary-key prefix seeks: `covers = 0`, the
// gaps that block the whole fragment in both directions, and `covers = 2` or
// `3`, this direction's candidate inventory. That is the same pair of row sets
// the deleted `resolution_candidate_gap_headers` held under
// `coverage_scope = 'fragment'`, with no index of its own and no text column.
//
// Completion honesty under a narrowed scope: a gap in a blob the request
// cannot bind into cannot qualify that request's answer, because nothing that
// blob hides was ever a candidate. A gap in a blob inside the scope still
// does, and the scope join is what separates the two. Narrowing therefore
// removes reasons that were never about this request; it can never turn a gap
// inside the scope into completeness, because a mount inside the scope is a
// row of `temp.selected_resolution_scope_mounts` and the join keeps it.
//
// The scope is what the read walks. Driving from the gap table instead would
// make one execution walk every gap the workspace holds for that direction
// (122,728 rows on tract), so the cost would be a property of the workspace
// and not of the request. Driving from the scope makes it one seek per
// in-scope mount, and a mount the request cannot bind into costs nothing.
//
// Why the partial index and not the primary key. `resolution_gaps` is keyed
// `(blob_id, covers, ...)`, so a seek for a `covers` a blob has no row of
// still descends that blob's rows before it fails: on tract the forward
// direction has no fragment-wide gap at all and the read paid 958 b-tree
// descents to say so, where the deleted header table's index led on
// `direction` and answered the same empty question in one trivial probe per
// mount (0.15 ms against 1.75 ms, measured on the two stores). Leading on
// `covers` restores that, and the index is partial and narrow -- 132,435 of
// tract's 866,258 gap rows, 2.29 MB -- because the fragment-wide question is
// the only one that asks it. `h.covers <= 3` is what lets SQLite prove the
// partial index applies; it selects nothing away, because the two `covers`
// this statement binds are 0 and 2 or 3.
//
// No `DISTINCT`: one blob's rows of one `covers` differ in `gap`, and the
// reader sorts and dedups the reasons it builds.
pub(super) const CANDIDATE_GAP_UNCONDITIONAL_SQL: &str = r#"
SELECT m.mount_ordinal, h.reason
FROM temp.selected_resolution_scope_mounts AS scope
CROSS JOIN temp.selected_resolution_mounts AS m
     ON m.mount_ordinal = scope.mount_ordinal
CROSS JOIN main.resolution_gaps AS h
     INDEXED BY resolution_gaps_fragment_wide
     ON h.covers <= 3
    AND h.covers IN (0, ?1)
    AND h.blob_id = m.blob_id
"#;

// One candidate direction's whole boundary-rooted branch coverage, from
// `resolution_gaps`.
//
// A gap endpoint is either the universal root or a node of the gap's own blob,
// so only a universal-root-rooted request can have its branch completion
// qualified by another blob, and these rows are exactly the gaps that qualify
// it: `covers = 5` or `6` with `subject = -1`, the universal root. Each row
// carries the shared lookup the gap names, or 0 for every lookup, and the
// gap's own blob-local reason. That is the same triple the blob's interior
// holds in its universal-root `CandidateCoverage`: an unkeyed bucket that
// qualifies every boundary-rooted request and one bucket per lookup symbol.
//
// One covering seek per in-scope mount, for the same reason the unconditional
// read takes its own partial index: root-rooted rows are 2,019 of tract's
// 866,258, so a primary-key seek pays a descent through the blob's other gaps
// to find them or to find none. `resolution_gaps_root_branches` is 98 KB and
// leads on `covers`, which makes both the hit and the miss cheap (2.02 ms to
// 0.53 ms for the 2,019 forward rows, 0.19 ms to 0.04 ms for the empty
// reverse direction, against the deleted header table). The planner does not
// choose a partial index over a primary key on its own, so the statement
// names it, as the schema's byte-range statement does.
//
// A gap header in a blob outside the request's scope cannot qualify this
// answer; `narrowed_forward_scope_keeps_in_closure_gap_reasons` pins the
// other half, that a gap inside the closure still does.
pub(super) const CANDIDATE_GAP_BOUNDARY_BRANCHES_SQL: &str = r#"
SELECT m.mount_ordinal, h.lookup, h.reason
FROM temp.selected_resolution_scope_mounts AS scope
CROSS JOIN temp.selected_resolution_mounts AS m
     ON m.mount_ordinal = scope.mount_ordinal
CROSS JOIN main.resolution_gaps AS h
     INDEXED BY resolution_gaps_root_branches
     ON h.subject = -1
    AND h.covers = ?1
    AND h.blob_id = m.blob_id
"#;

// One mount's candidate-endpoint branch coverage, for the endpoint nodes one
// batch names (milestone 6, port block 3, lane GR).
//
// This is the read that lets `lazy_candidate_completion` stop opening a blob.
// It used to run the blob's whole candidate match with a discard callback and
// keep only the completion the visit returned, so every request matched its
// candidates twice: once to learn its branch completion and once, through
// `lazy_candidate_matches`, for the rows. Against the rows it is one seek per
// endpoint node.
//
// Fixed-symbol requests seek the unkeyed bucket and their exact lookup bucket.
// Only an open tail with no fixed symbol reads every lookup for its subject.
// The caller deduplicates both key arrays and removes exact keys for subjects
// already covered by the all-lookup arm, so UNION ALL cannot duplicate a row.
pub(super) const CANDIDATE_GAP_ENDPOINT_BRANCHES_SQL: &str = r#"
SELECT h.subject, h.lookup, h.reason
FROM json_each(?3) AS requested
CROSS JOIN main.resolution_gaps AS h
  ON h.blob_id = ?1 AND h.covers = ?2
 AND h.subject = json_extract(requested.value, '$[0]')
 AND h.lookup = json_extract(requested.value, '$[1]')
UNION ALL
SELECT h.subject, h.lookup, h.reason
FROM json_each(?4) AS requested
CROSS JOIN main.resolution_gaps AS h
  ON h.blob_id = ?1 AND h.covers = ?2 AND h.subject = requested.value
"#;

// The lowest selected mount ordinal one blob is mounted at.
//
// `selected_resolution_mounts_blob_ordinal` is `(blob_id, mount_ordinal)`, so
// this is the first row of one index range and the selection never has to be
// indexed by blob in Rust to answer it.
pub(super) const SELECTED_MOUNT_OF_BLOB_SQL: &str = r#"
SELECT m.mount_ordinal
FROM temp.selected_resolution_mounts AS m
     INDEXED BY selected_resolution_mounts_blob_ordinal
WHERE m.blob_id = ?1
ORDER BY m.mount_ordinal
LIMIT 1
"#;

// Question #10's third field: which definition owns the member scope whose
// head is this node.
//
// `resolution_member_scope_properties` already carries
// `UNIQUE(blob_id, scope_head_node_key)`, so this is one seek per key over an
// index that exists; port block 2 adds no index for it.
//
// The keys drive it. Written as `scope_head_node_key IN (SELECT value FROM
// json_each(?2))` SQLite built a bloom filter and read the blob's whole
// prefix instead, so the cost was a property of the blob and not of the
// batch; `CROSS JOIN` from `json_each` is what makes it one two-column seek
// per key, and the plan pin is what holds it there.
pub(super) const MEMBER_SCOPE_OWNERS_BY_NODE_SQL: &str = r#"
SELECT p.scope_head_node_key, p.definition_semantic_key
FROM json_each(?2) AS k
CROSS JOIN main.resolution_member_scope_properties AS p
     ON p.blob_id = ?1
    AND p.scope_head_node_key = k.value
"#;

// The sentinel asks one question of the whole selection -- does every selected
// mount still have its own exact complete interior -- and the answer is two
// counts. `resolution_fragment_interiors` is keyed on `blob_id` alone, so the
// left join produces exactly one row per selected mount: the first count is
// the selection's size as the temp table holds it, and the second counts the
// mounts whose interior still matches. Aggregating in SQLite keeps the read
// one row whatever the selection's size, where the row-by-row form decoded a
// mount ordinal per mount and looked each one up again in an inventory the
// temp table's primary key already agrees with.
const SELECTED_INTERIOR_VALIDATION_SQL: &str = r#"
SELECT COUNT(*), COUNT(interior.blob_id)
FROM temp.selected_resolution_mounts AS m
LEFT JOIN main.resolution_fragment_interiors AS interior
  ON interior.blob_id = m.blob_id
 AND interior.lang = m.storage_language
 AND interior.semantic_language = m.semantic_language
 AND interior.producer_epoch = m.producer_epoch
 AND interior.interior_digest = m.interior_digest
 AND interior.publication_state = 'complete'
"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SelectedSemanticSite {
    semantic: SemanticId,
    node: BindingNodeId,
    namespace: ResolutionNamespace,
}

impl SelectedSemanticSite {
    pub(crate) const fn semantic(self) -> SemanticId {
        self.semantic
    }

    pub(crate) const fn node(self) -> BindingNodeId {
        self.node
    }

    pub(crate) const fn namespace(self) -> ResolutionNamespace {
        self.namespace
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SelectedSemanticLookupOutcome {
    Found(Vec<SelectedSemanticSite>),
    Missing,
    Cancelled,
}

#[derive(Debug)]
struct BoundaryPresenceDirectory {
    stamp: SelectedResolutionReadStamp,
    mounts: HashSet<SelectedResolutionMountOrdinal>,
}

type BoundaryWildcardProbeMask = for<'selection, 'store> fn(
    &SelectedResolutionLexicalSource<'selection, 'store>,
    &[CandidateProbe],
    &CancellationToken,
) -> StoreResult<Option<Vec<bool>>>;

/// One candidate direction's unconditional completion box, published once as a
/// shared completion base.
///
/// The box is the union of every in-scope blob's fragment-wide gap reasons, so
/// it is the same value for every candidate read of that direction in one
/// operation, and on a workspace of tract's size it is about 122,000 reasons.
/// Every request then combines it with a small per-reference completion
/// thousands of times. Built raw, each of those combines copied, sorted and
/// set-inserted the whole box, which is where a profile of a warm tract
/// `usage_graph` spent about half its CPU. Built as a shared base, each one is
/// a merge of two sparse deltas over one `Arc`, and every combine site in the
/// engine already takes that path when it sees a shared value.
#[derive(Debug)]
struct UnconditionalCandidateBox {
    /// The whole box: a shared base with no removals and no additions. This is
    /// what a read with no scope and no restated mount returns, by cloning the
    /// handle.
    whole: ResolutionCompletion,
    /// The selected mount position each base reason came from, in the base's
    /// own order, so a scoped or restated read names the positions it drops
    /// without rebuilding the set.
    positions: Box<[usize]>,
}

/// One candidate direction's boundary-rooted branch coverage, as tier-1 rows.
///
/// A blob's interior keeps its universal-root coverage as one bucket that
/// every boundary-rooted request takes and one bucket per lookup symbol that
/// only a request naming that symbol takes. These are the same buckets over
/// the whole selection, with the selected mount each reason came from so a
/// scoped read can drop the mounts it may not use.
#[derive(Debug, Default)]
struct BoundaryCandidateBranches {
    /// Gaps that name no lookup symbol: the interior's `all_lookups` bucket,
    /// which qualifies every boundary-rooted request of this direction.
    unkeyed: Vec<(usize, ResolutionIncompleteReason)>,
    /// Gaps keyed by a workspace-shared lookup symbol. A request takes one of
    /// these buckets when its own first fixed symbol is the same shared name.
    ///
    /// There is no blob-local bucket. A candidate-endpoint gap's lookup is
    /// always a shared lookup recipe, which the writer asserts where the row
    /// is built (lane ID, confirmed by reading both production constructions),
    /// so a request whose first fixed symbol is blob-local can never match a
    /// keyed bucket and takes the unkeyed rows alone.
    by_shared_lookup: HashMap<SharedNameId, Vec<(usize, ResolutionIncompleteReason)>>,
}

/// What one batch's completion read needs from the selection.
struct CandidateCompletionPlan {
    /// The mounts whose authority state their own coverage for this batch.
    positions: Vec<usize>,
    /// One selector per request, in request order.
    selectors: Vec<BoundaryBranchSelector>,
    /// For each request whose endpoint is a node of a selected blob, that
    /// blob's position in the selection and the endpoint's own local node key,
    /// which is what `resolution_gaps.subject` holds. `None` for a
    /// universal-root or context-boundary endpoint: no blob owns a branch
    /// bucket for it.
    endpoints: Vec<Option<(usize, i64)>>,
}

/// Which of one direction's boundary-rooted gap buckets qualify one request.
///
/// This mirrors `CandidateCoverage::completion_for_with_poll`: the unkeyed
/// bucket always, then the bucket the endpoint's own first fixed symbol names,
/// or every bucket when the endpoint has an open tail and no fixed symbol.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum BoundaryBranchSelector {
    /// The endpoint is not the universal root, so no other blob's gap can
    /// qualify it and its own mount states its whole branch box.
    OwnMount,
    /// Only the unkeyed bucket. A first fixed symbol that is blob-local also
    /// lands here, because every keyed bucket is keyed on a shared name.
    Unkeyed,
    /// The unkeyed bucket plus the bucket this shared lookup identity names.
    SharedLookup(SharedNameId),
    /// Every bucket, which is what an open tail with no fixed symbol takes.
    EveryLookup,
}

/// Which of one endpoint's candidate gap buckets qualify one request.
///
/// The same three-way choice `CandidateCoverage::completion_for_with_poll`
/// makes, over `resolution_gaps.lookup` instead of over a `HashMap` key.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum WantedLookup {
    /// The unkeyed bucket alone.
    Unkeyed,
    /// The unkeyed bucket plus the one this shared name keys.
    Shared(i64),
    /// Every bucket, which is what an open tail with no fixed symbol takes.
    Every,
}

/// A result owned by one user request, invalidated by committed stage changes.
struct OrdinaryCompletionSuppression {
    authority: [u8; 32],
    reasons: Vec<ResolutionIncompleteReason>,
}

/// Operation-local lexical reader over one retained selected inventory.
///
/// The source owns no connection and starts no transaction. It stages every
/// mounted identity named by one logical read, then registers the whole stage
/// only after every parent and child row has exhausted with a live token.
pub(crate) struct SelectedResolutionLexicalSource<'selection, 'store> {
    selection: &'selection SelectedResolutionMountInventory<'store>,
    typed: SelectedResolutionTypedSource<'selection, 'store>,
    forward_reference_fragments: Option<&'selection crate::hash::HashSet<BindingFragmentId>>,
    selected_interiors_validated: OnceCell<()>,
    ordinary_completion_suppression: RefCell<Option<OrdinaryCompletionSuppression>>,
    /// One candidate direction's unconditional completion box, forward then
    /// reverse. Every live candidate read of one direction operation must
    /// repeat the exact same box, and the box is a property of the selection
    /// rather than of any request, so it is read from tier 1 once and reused.
    unconditional_candidate_reasons: [OnceCell<UnconditionalCandidateBox>; 2],
    /// One candidate direction's boundary-rooted branch coverage, forward then
    /// reverse. Like the unconditional box this is a property of the selection
    /// and the direction, so it is read from tier 1 once and reused instead of
    /// producing every blob's interior to state it.
    boundary_candidate_branches: [OnceCell<BoundaryCandidateBranches>; 2],
    authority: std::rc::Rc<super::resolution_authority::SelectedResolutionAuthority<'selection>>,
}

/// Candidate rows examined between cooperative cancellation checks.
///
/// The same deterministic work quantum the in-heap candidate walk uses
/// (`resolution/engine.rs`'s `CANCELLATION_QUANTUM`), stated again here
/// because that module is private to `resolution` and the constant tunes how
/// often an atomic is read, not what any read answers.
const CANDIDATE_ROW_CANCELLATION_QUANTUM: usize = 32;

impl<'selection, 'store> SelectedResolutionLexicalSource<'selection, 'store> {
    /// Read a page of positioned reference names from their native lookup
    /// paths, in the namespace the reference spells them in. The stored
    /// lookup recipes retain parser-derived identifiers.
    ///
    /// The namespace is the caller's, not a constant: a bare path root is a
    /// Type-namespace lookup, and an unqualified macro name is a Macro one.
    pub(crate) fn reference_lookup_spellings(
        &self,
        references: &[SemanticId],
        namespace: ResolutionNamespace,
        cancellation: &CancellationToken,
    ) -> StoreResult<HashMap<SemanticId, String>> {
        assert!(references.len() <= MAX_SOURCE_ROWS_PER_BATCH);
        let Some(mut spellings) =
            stage::reference_lookup_spellings(self.selection, references, namespace, cancellation)?
        else {
            return Ok(HashMap::default());
        };
        let mut groups = BTreeMap::<SelectedResolutionMountOrdinal, Vec<u32>>::new();
        for &reference in references {
            if cancellation.is_cancelled() {
                return Ok(HashMap::default());
            }
            // Decode only a possible ordinary address. The batched query's
            // published blob and actual Reference site establish authority;
            // a stage-local numeric key alone never does.
            if let (Some(ordinal), Some(key)) = (reference.ordinal(), reference.local_key()) {
                let ordinal = SelectedResolutionMountOrdinal::new(ordinal);
                if self.selected_position(ordinal).is_some() {
                    groups.entry(ordinal).or_default().push(key);
                }
            }
        }
        for (ordinal, keys) in groups {
            let Some(mount) = self.selected_mount(ordinal)? else {
                continue;
            };
            let Some(rows) = self.authority.reference_lookup_spellings(
                &mount,
                &keys,
                namespace,
                cancellation,
            )?
            else {
                return Ok(HashMap::default());
            };
            for (reference, spelling) in rows {
                if let Some(previous) = spellings.insert(reference, spelling.clone())
                    && previous != spelling
                {
                    return Err(invalid_fact(format!(
                        "ordinary and stage reference lookup spellings disagree: {reference:?}, {previous:?}, {spelling:?}"
                    )));
                }
            }
        }
        Ok(spellings)
    }

    /// Read the immutable outgoing bindings of one include-splice scope.
    pub(crate) fn include_scope_paths(
        &self,
        fragment: BindingFragmentId,
        scope: brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeId,
        cancellation: &CancellationToken,
    ) -> StoreResult<Vec<(CandidatePathIdentity, PartialPath)>> {
        let mount = &*self.mount_record_of_fragment(fragment)?;
        let Some(paths) = self
            .authority
            .scope_start_paths(mount, scope, cancellation)?
        else {
            return Ok(Vec::new());
        };
        let candidates = paths
            .into_iter()
            .map(|path| CandidatePathIdentity::new(fragment, path))
            .collect::<Vec<_>>();
        let mut hydrated = Vec::with_capacity(candidates.len());
        for page in candidates.chunks(MAX_SOURCE_ROWS_PER_BATCH) {
            hydrated.extend(self.hydrate_candidate_paths(page, cancellation)?);
        }
        Ok(hydrated)
    }

    /// The position one mount ordinal occupies in the selected inventory, or
    /// `None` when the ordinal is not this persisted selection's.
    ///
    /// `read_selected_mounts` numbers the inventory densely from zero, so the
    /// ordinal *is* the position and inverting it needs no index. A transient
    /// replacement is numbered past the persisted inventory's end
    /// (`prepare_transient_selection`), which is the bounds miss this reports.
    fn selected_position(&self, mount: SelectedResolutionMountOrdinal) -> Option<usize> {
        let position = usize::try_from(mount.get()).expect("mount ordinal fits usize");
        (position < self.selection.persisted_mount_count()).then_some(position)
    }

    /// The selected mount one ordinal names, or `None` when the ordinal is not
    /// this persisted selection's.
    fn selected_mount(
        &self,
        mount: SelectedResolutionMountOrdinal,
    ) -> StoreResult<
        Option<std::sync::Arc<super::resolution_selection::SelectedResolutionMountRecord>>,
    > {
        self.selection.persisted_mount_record(mount)
    }

    /// The position of the mount that owns one fragment.
    ///
    /// The operation's mount rebaser indexes every mount it registers by
    /// fragment, and the selection registers its whole inventory there when it
    /// is staged, so this reads an index the operation already owns instead of
    /// a second copy of it.
    fn selected_position_of_fragment(&self, fragment: BindingFragmentId) -> Option<usize> {
        let mount = self
            .selection
            .mount_rebaser()
            .borrow()
            .mount_for_fragment(fragment)?;
        self.selected_position(mount.ordinal())
    }

    /// Resolve only the requested positions before applying the stable blob order.
    fn sort_mount_positions(&self, positions: &mut [usize]) -> StoreResult<()> {
        let mut keyed = positions
            .iter()
            .map(|&position| {
                let mount = self.mount_record(SelectedResolutionMountOrdinal::new(
                    u32::try_from(position).expect("mount position fits u32"),
                ))?;
                Ok(((mount.blob_id(), mount.ordinal().get()), position))
            })
            .collect::<StoreResult<Vec<_>>>()?;
        keyed.sort_by_key(|&(key, _)| key);
        for (position, (_, sorted)) in positions.iter_mut().zip(keyed) {
            *position = sorted;
        }
        Ok(())
    }

    /// The selected mount record one ordinal names.
    fn mount_record(
        &self,
        mount: SelectedResolutionMountOrdinal,
    ) -> StoreResult<std::sync::Arc<super::resolution_selection::SelectedResolutionMountRecord>>
    {
        self.selection.mount_record_by_ordinal(mount)
    }

    fn mount_record_of_fragment(
        &self,
        fragment: BindingFragmentId,
    ) -> StoreResult<std::sync::Arc<super::resolution_selection::SelectedResolutionMountRecord>>
    {
        self.mount_record(SelectedResolutionMountOrdinal::new(fragment.ordinal()))
    }

    /// Full selected provenance for one runtime semantic: the mount its own
    /// prefix names, and the storage-local key and recipe that mount's
    /// interior identity catalog gives it.
    ///
    /// `None` reports cancellation. Unknown identities are structured errors.
    pub(crate) fn semantic_provenance(
        &self,
        semantic: SemanticId,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<SelectedSemanticProvenance>> {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        if let Some(name) = semantic.shared_name_id() {
            return Ok(Some(SelectedSemanticProvenance::Shared(
                ResolutionSemanticIdentity::shared(name),
            )));
        }
        let Some(staged) = stage::semantic_provenance(self.selection, semantic, cancellation)?
        else {
            return Ok(None);
        };
        let Some(ordinary) = self
            .authority
            .semantic_catalog_provenance(semantic, cancellation)?
        else {
            return Ok(None);
        };
        if let Some((host, identity)) = staged {
            if let Some(SelectedSemanticProvenance::FragmentLocal(local)) = ordinary {
                if local.identity() != identity {
                    return Err(invalid_fact(format!(
                        "ordinary and stage semantic identity disagree: {semantic:?}, {ordinary:?}, {identity:?}"
                    )));
                }
                return Ok(ordinary);
            }
            let mount = self.mount_record(host)?;
            return Ok(Some(SelectedSemanticProvenance::stage(
                SelectedResolutionMount::from_ordinal(mount.ordinal()),
                identity,
            )));
        }
        if ordinary.is_some() {
            return Ok(ordinary);
        }
        // Context-owned reasons retain only their explicit request registration.
        // A missing ordinary/stage row never invents a shared identity.
        if let Some(provenance @ SelectedSemanticProvenance::Shared(_)) = self
            .selection
            .mount_rebaser()
            .borrow()
            .registered_semantic_provenance(semantic)
        {
            return Ok(Some(provenance));
        }
        Err(invalid_fact(format!(
            "semantic has no selected authority: {semantic:?}"
        )))
    }

    /// Ordinary and stage catalogs establish node identity. Explicit request
    /// registration preserves intrinsic root and context boundaries.
    /// The outer None is cancellation; inner None is an unknown node.
    pub(crate) fn node_provenance(
        &self,
        node: BindingNodeId,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Option<SelectedNodeProvenance>>> {
        let Some(staged) = stage::node_provenance(self.selection, node, cancellation)? else {
            return Ok(None);
        };
        let Some(ordinary) = self.authority.node_catalog_provenance(node, cancellation)? else {
            return Ok(None);
        };
        if let Some((_, identity)) = staged
            && let Some(SelectedNodeProvenance::FragmentLocal(local)) = ordinary
            && local.identity() != identity
        {
            return Err(invalid_fact(format!(
                "ordinary and stage node identity disagree: {node:?}, {ordinary:?}, {identity:?}"
            )));
        }
        if ordinary.is_some() {
            return Ok(Some(ordinary));
        }
        let boundary = self
            .selection
            .mount_rebaser()
            .borrow()
            .node_provenance(node);
        if matches!(
            boundary,
            Some(SelectedNodeProvenance::UniversalRoot | SelectedNodeProvenance::ContextBoundary)
        ) {
            return Ok(Some(boundary));
        }
        if let Some((host, identity)) = staged {
            let mount = self.mount_record(host)?;
            return Ok(Some(Some(SelectedNodeProvenance::stage(
                SelectedResolutionMount::from_ordinal(mount.ordinal()),
                identity,
            ))));
        }
        Ok(Some(None))
    }

    /// The source site one definition node declares.
    pub(crate) fn definition_source_site(
        &self,
        mount: SelectedResolutionMountOrdinal,
        definition: BindingNodeId,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Option<ResolutionSiteId>>> {
        self.authority
            .definition_source_site(&*self.mount_record(mount)?, definition, cancellation)
    }

    /// Resolve a request's already-held definition nodes with one site read per mount.
    pub(crate) fn definition_source_sites(
        &self,
        requests: &[(SelectedResolutionMountOrdinal, BindingNodeId)],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<Option<ResolutionSiteId>>>> {
        let mut groups = BTreeMap::<SelectedResolutionMountOrdinal, Vec<(usize, i64)>>::new();
        let mut result = vec![None; requests.len()];
        for (position, &(ordinal, node)) in requests.iter().enumerate() {
            if node.ordinal() == Some(ordinal.get()) {
                groups.entry(ordinal).or_default().push((
                    position,
                    i64::from(node.local_key().expect("local definition")),
                ));
            } else {
                if self
                    .authority
                    .ensure_authority(&*self.mount_record(ordinal)?, cancellation)?
                    .is_none()
                {
                    return Ok(None);
                }
            }
        }
        for (ordinal, keys) in groups {
            let mount = &*self.mount_record(ordinal)?;
            if self
                .authority
                .ensure_authority(mount, cancellation)?
                .is_none()
            {
                return Ok(None);
            }
            let Some(rows) = self.read_site_rows(
                mount.blob_id(),
                keys.iter().map(|(_, key)| *key),
                cancellation,
            )?
            else {
                return Ok(None);
            };
            for (position, key) in keys {
                if let Some(row) = rows.get(&key).filter(|row| row.role == 1) {
                    result[position] = Some(ResolutionSiteId::new(
                        u32::try_from(row.site).expect("source site"),
                    ));
                }
            }
        }
        Ok(Some(result))
    }

    /// The names under which the universal root reaches the declaration at
    /// one source site.
    pub(crate) fn root_export_halves(
        &self,
        mount: SelectedResolutionMountOrdinal,
        site: ResolutionSiteId,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<super::resolution_authority::RootExportHalf>>> {
        self.authority
            .root_export_halves(&*self.mount_record(mount)?, site, cancellation)
    }

    /// Every lookup recipe the blob's own catalog carries.
    pub(crate) fn lookup_recipes(
        &self,
        mount: SelectedResolutionMountOrdinal,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<ResolutionLookupSemanticRecipe>>> {
        self.authority
            .lookup_recipes(&*self.mount_record(mount)?, cancellation)
    }

    /// The selected mount this blob is mounted at, if the selection holds it.
    ///
    /// One blob can be mounted at several paths; they share one interior, so
    /// any of them answers an interior question about the blob, and the lowest
    /// ordinal is the one this names. `selected_resolution_mounts_blob_ordinal`
    /// is `(blob_id, mount_ordinal)`, so the first row of that index range is
    /// the answer and no blob-keyed map has to be built to hold it.
    ///
    /// The outer `None` is a cancelled read; the inner one is a blob this
    /// selection does not mount.
    fn mount_of_blob(
        &self,
        blob: i64,
        cancellation: &CancellationToken,
    ) -> StoreResult<
        Option<Option<std::sync::Arc<super::resolution_selection::SelectedResolutionMountRecord>>>,
    > {
        let Some(ordinal) = self.read_statement(cancellation, |conn| {
            let mut statement = conn.prepare_cached(SELECTED_MOUNT_OF_BLOB_SQL)?;
            let mut rows = statement.query([blob])?;
            let Some(row) = rows.next()? else {
                return Ok(Some(None));
            };
            Ok(Some(Some(mount_ordinal(row, 0, "selected mount of blob")?)))
        })?
        else {
            return Ok(None);
        };
        Ok(Some(
            ordinal
                .map(|ordinal| self.mount_record(ordinal))
                .transpose()?,
        ))
    }

    /// Every reference in one blob that looks a name up, optionally narrowed
    /// to the scope chain a named import binder governs.
    pub(crate) fn lookup_reference_sites(
        &self,
        blob: i64,
        lookup: SemanticId,
        binder_scope: Option<brokk_bifrost_core::analyzer::resolution_facts::ResolutionScopeId>,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<ResolutionSiteId>>> {
        let mount = match self.mount_of_blob(blob, cancellation)? {
            None => return Ok(None),
            Some(None) => return Ok(Some(Vec::new())),
            Some(Some(mount)) => mount,
        };
        self.authority
            .lookup_reference_sites(&mount, lookup, binder_scope, cancellation)
    }

    /// Every reference in one blob whose route to the crate root ends in a
    /// name.
    pub(crate) fn root_demand_reference_sites(
        &self,
        blob: i64,
        terminal: SemanticId,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<ResolutionSiteId>>> {
        let mount = match self.mount_of_blob(blob, cancellation)? {
            None => return Ok(None),
            Some(None) => return Ok(Some(Vec::new())),
            Some(Some(mount)) => mount,
        };
        self.authority
            .root_demand_reference_sites(&mount, terminal, cancellation)
    }

    /// Root-demand references whose head is a declared named import.
    pub(crate) fn imported_root_demand_reference_sites(
        &self,
        blob: i64,
        terminal: SemanticId,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<ResolutionSiteId>>> {
        let mount = match self.mount_of_blob(blob, cancellation)? {
            None => return Ok(None),
            Some(None) => return Ok(Some(Vec::new())),
            Some(Some(mount)) => mount,
        };
        self.authority
            .imported_root_demand_reference_sites(&mount, terminal, cancellation)
    }

    /// The same, restricted to the routes whose first segment is a type
    /// prefix rather than a module name.
    pub(crate) fn prefixed_root_demand_reference_sites(
        &self,
        blob: i64,
        terminal: SemanticId,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<ResolutionSiteId>>> {
        let mount = match self.mount_of_blob(blob, cancellation)? {
            None => return Ok(None),
            Some(None) => return Ok(Some(Vec::new())),
            Some(Some(mount)) => mount,
        };
        self.authority
            .prefixed_root_demand_reference_sites(&mount, terminal, cancellation)
    }

    /// The type references one reference site observes through its
    /// type-identity projection and the blob's identity transfers.
    pub(crate) fn type_identity_observation_sites(
        &self,
        blob: i64,
        site: ResolutionSiteId,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<ResolutionSiteId>>> {
        let mount = match self.mount_of_blob(blob, cancellation)? {
            None => return Ok(None),
            Some(None) => return Ok(Some(Vec::new())),
            Some(Some(mount)) => mount,
        };
        self.authority
            .type_identity_observation_sites(&mount, site, cancellation)
    }

    /// The trait references one member definition declares as a
    /// trait-implementation member of one kind.
    pub(crate) fn contract_reference_sites(
        &self,
        mount: SelectedResolutionMountOrdinal,
        definition: SemanticId,
        kind: brokk_bifrost_core::analyzer::resolution_facts::ResolutionMemberKind,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<ResolutionSiteId>>> {
        self.authority.contract_reference_sites(
            &*self.mount_record(mount)?,
            definition,
            kind,
            cancellation,
        )
    }

    /// The references in one blob whose structured qualified route looks one
    /// name up.
    pub(crate) fn qualified_route_reference_sites(
        &self,
        blob: i64,
        lookup: SemanticId,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<ResolutionSiteId>>> {
        let mount = match self.mount_of_blob(blob, cancellation)? {
            None => return Ok(None),
            Some(None) => return Ok(Some(Vec::new())),
            Some(Some(mount)) => mount,
        };
        self.authority
            .qualified_route_reference_sites(&mount, lookup, cancellation)
    }

    /// The reason semantics one unsupported scope, binder or expression at a
    /// source site publishes. A replayed macro closes exactly these.
    pub(crate) fn unsupported_gap_reasons(
        &self,
        mount: SelectedResolutionMountOrdinal,
        site: ResolutionSiteId,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<SemanticId>>> {
        self.authority
            .unsupported_gap_reasons(&*self.mount_record(mount)?, site, cancellation)
    }

    /// The staged definitions whose name is exactly `start..end` in the
    /// host's source: the definitions a capsule lowered for the item replay
    /// declared at that name. Empty when the request did not stage the host.
    pub(crate) fn stage_definitions_at_range(
        &self,
        host: SelectedResolutionMountOrdinal,
        start: usize,
        end: usize,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<(SemanticId, BindingNodeId)>>> {
        Ok(stage::semantic_sites_at_range(
            self.selection,
            host,
            start,
            end,
            crate::analyzer::resolution::LoweredSemanticRole::Definition,
            cancellation,
        )?
        .map(|rows| {
            rows.into_iter()
                .map(|(semantic, node, _)| (semantic, node))
                .collect()
        }))
    }

    pub(crate) fn stage_lexical_definitions(
        &self,
        requests: &[(SelectedResolutionMountOrdinal, SemanticId)],
        cancellation: &CancellationToken,
    ) -> StoreResult<
        Option<
            Vec<(
                SemanticId,
                crate::analyzer::lexical_definitions::LexicalDefinition,
            )>,
        >,
    > {
        stage::lexical_definitions(self.selection, requests, cancellation)
    }

    /// Remove only exact active-stage UnsupportedSemantic closure claims.
    pub(crate) fn close_completion(
        &self,
        completion: &ResolutionCompletion,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<ResolutionCompletion>> {
        stage::close_completion(self.selection, completion, cancellation)
    }

    /// Apply exact closure claims to one caller-owned batch in a single query.
    pub(crate) fn close_completions(
        &self,
        completions: &[ResolutionCompletion],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<ResolutionCompletion>>> {
        stage::close_completions(self.selection, completions, cancellation)
    }

    /// Restrict only default forward seed enumeration, borrowing caller state.
    pub(crate) fn with_forward_reference_fragments(
        mut self,
        fragments: &'selection crate::hash::HashSet<BindingFragmentId>,
    ) -> Self {
        self.forward_reference_fragments = Some(fragments);
        self
    }

    pub(crate) fn new_on_demand(
        selection: &'selection SelectedResolutionMountInventory<'store>,
    ) -> Self {
        Self::with_authority(
            selection,
            std::rc::Rc::new(
                super::resolution_authority::SelectedResolutionAuthority::new(
                    selection.connection(),
                    selection.shared_name_table(),
                    selection.requested_mount_rows(),
                    selection.persisted_mount_count(),
                    selection.authority_validations(),
                ),
            ),
        )
    }

    pub(crate) fn with_authority(
        selection: &'selection SelectedResolutionMountInventory<'store>,
        authority: std::rc::Rc<
            super::resolution_authority::SelectedResolutionAuthority<'selection>,
        >,
    ) -> Self {
        Self {
            selection,
            typed: SelectedResolutionTypedSource::with_authority(
                selection,
                std::rc::Rc::clone(&authority),
            ),
            forward_reference_fragments: None,
            selected_interiors_validated: OnceCell::new(),
            ordinary_completion_suppression: RefCell::new(None),
            unconditional_candidate_reasons: [OnceCell::new(), OnceCell::new()],
            boundary_candidate_branches: [OnceCell::new(), OnceCell::new()],
            authority,
        }
    }

    pub(crate) fn lookup_semantic_sites(
        &self,
        locator: &SelectedSemanticLocator,
        cancellation: &CancellationToken,
        session: &ResolutionSession,
    ) -> StoreResult<SelectedSemanticLookupOutcome> {
        let authority = &self.authority;
        if cancellation.is_cancelled() || !session.scope_step() {
            return Ok(SelectedSemanticLookupOutcome::Cancelled);
        }
        let Some(mount) = self
            .selection
            .mount_record_for_path(locator.storage_language(), locator.relative_path())?
        else {
            return Ok(SelectedSemanticLookupOutcome::Missing);
        };
        // Capsule source-site ordinals are producer-local. Only actual source
        // ranges participate in the stage locator override.
        let staged = if let Some((start, end)) = locator.reference_range() {
            let Some(staged) = stage::semantic_sites_at_range(
                self.selection,
                mount.ordinal(),
                start,
                end,
                crate::analyzer::resolution::LoweredSemanticRole::Reference,
                cancellation,
            )?
            else {
                return Ok(SelectedSemanticLookupOutcome::Cancelled);
            };
            staged
        } else {
            Vec::new()
        };
        let rows = if staged.is_empty() {
            let Some(rows) = authority.semantic_sites(&mount, locator, cancellation)? else {
                return Ok(SelectedSemanticLookupOutcome::Cancelled);
            };
            rows
        } else {
            staged
        };
        if rows.is_empty() {
            return Ok(SelectedSemanticLookupOutcome::Missing);
        }
        if locator.source_site().is_some() && rows.len() != 1 {
            return Err(invalid_fact(format!(
                "selected source-site locator {locator:?} returned rows {rows:?}"
            )));
        }
        if cancellation.is_cancelled() || !session.observe_cancellation() {
            return Ok(SelectedSemanticLookupOutcome::Cancelled);
        }
        Ok(SelectedSemanticLookupOutcome::Found(
            rows.into_iter()
                .map(|(semantic, node, namespace)| SelectedSemanticSite {
                    semantic,
                    node,
                    namespace,
                })
                .collect(),
        ))
    }

    /// Read the canonical spelling and namespace for shared lookup semantics
    /// owned by selected persisted fragments.
    ///
    /// A route can contain many shared semantic IDs, so this deliberately
    /// accepts a bounded batch instead of preparing one statement per
    /// reference. The semantic digest is the request key; the recipe relation
    /// is the only authority for its spelling and namespace.
    pub(crate) fn lookup_semantic_recipes(
        &self,
        requests: &[SelectedLookupRecipeRequest],
        cancellation: &CancellationToken,
        resolution_session: Option<&ResolutionSession>,
    ) -> StoreResult<SelectedLookupRecipeReadOutcome> {
        assert!(
            requests.len() <= MAX_SOURCE_ROWS_PER_BATCH,
            "lookup recipe batch has {} entries; maximum is {MAX_SOURCE_ROWS_PER_BATCH}",
            requests.len()
        );
        if requests.is_empty() {
            return Ok(SelectedLookupRecipeReadOutcome::Ready(
                Vec::new().into_boxed_slice(),
            ));
        }
        if cancellation.is_cancelled()
            || resolution_session.is_some_and(|session| !session.scope_step())
        {
            return Ok(SelectedLookupRecipeReadOutcome::Cancelled);
        }

        // Milestone 6's checkpoint. A recipe is a property of the name and not
        // of a file, so it lives once per store on `resolution_identities` and
        // the whole batch is one statement keyed by the digest a shared
        // `SemanticId` already is. The request's fragment is now only a
        // validity check: it no longer selects which blob's recipe page to
        // open, and the `Recipes` page is not produced on this route at all.
        for request in requests {
            assert!(
                self.selected_position_of_fragment(request.fragment)
                    .is_some(),
                "lookup recipe request names unselected fragment {}",
                request.fragment
            );
        }
        // Ordinary recipes bind the persisted alias of the request name.
        // A missing alias removes only that main seek; active stage recipes
        // remain keyed by the original request semantic.
        let shared_names = self
            .selection
            .shared_name_table()
            .interner(self.selection.connection());
        let names = requests
            .iter()
            .filter_map(|request| request.semantic.shared_name_id())
            .filter_map(|name| shared_names.to_persisted(name))
            .map(|name| i64::from(name.get()))
            .collect::<Vec<_>>();
        let id_array = json_integer_array(names.into_iter());
        let stage_requests = serde_json::to_string(
            &requests
                .iter()
                .map(|request| {
                    let (key, shared) =
                        super::resolution_stage::lexical::semantic_cells(request.semantic);
                    (request.fragment.ordinal(), key, shared)
                })
                .collect::<Vec<_>>(),
        )
        .expect("lookup recipe coordinates serialize");
        let Some(stored) = self.read_statement(cancellation, |conn| {
            let mut statement = conn.prepare_cached(RESOLUTION_IDENTITY_RECIPES_SQL)?;
            let mut rows = statement.query([&id_array])?;
            let mut stored: HashMap<SemanticId, ResolutionLookupSemanticRecipe> =
                HashMap::default();
            while let Some(row) = rows.next()? {
                let name = SemanticId::shared_name(shared_names.from_persisted(
                    SharedNameId::interned(row.get::<_, i64>(0)?),
                ));
                let Some(language) = row.get::<_, Option<i64>>(1)? else {
                    continue;
                };
                stored.insert(
                    name,
                    decode_lookup_recipe(language, row.get(2)?, &row.get::<_, String>(3)?),
                );
            }
            let mut statement = conn.prepare_cached(r#"
SELECT input.key,recipe.semantic_language,recipe.namespace,recipe.spelling
FROM json_each(?1) input
JOIN temp.selected_resolution_scope_mounts scope ON scope.mount_ordinal=input.value->>0
JOIN temp.selected_resolution_stage_recipes recipe
 ON recipe.host_ordinal=scope.mount_ordinal
 AND recipe.semantic_key IS input.value->>1
 AND recipe.semantic_shared IS input.value->>2
"#)?;
            let mut rows = statement.query([stage_requests])?;
            while let Some(row) = rows.next()? {
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                let position: usize = row.get(0)?;
                let semantic = requests[position].semantic;
                let recipe = decode_lookup_recipe(row.get(1)?, row.get(2)?, &row.get::<_, String>(3)?);
                if let Some(previous) = stored.get(&semantic) {
                    if previous != &recipe {
                        return Err(invalid_fact(format!("selected semantic has conflicting lookup recipes: {semantic:?}, {previous:?}, {recipe:?}")));
                    }
                } else {
                    stored.insert(semantic, recipe);
                }
            }
            Ok(Some(stored))
        })?
        else {
            return Ok(SelectedLookupRecipeReadOutcome::Cancelled);
        };
        Ok(SelectedLookupRecipeReadOutcome::Ready(
            requests
                .iter()
                .map(|request| stored.get(&request.semantic).cloned())
                .collect(),
        ))
    }

    fn mount(
        &self,
        ordinal: SelectedResolutionMountOrdinal,
    ) -> StoreResult<std::sync::Arc<SelectedResolutionMountRecord>> {
        self.selected_mount(ordinal)?.ok_or_else(|| {
            invalid_fact(format!(
                "selected lexical row names unknown mount ordinal {}",
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

    fn validate_selected_interiors_uncached(
        &self,
        cancellation: &CancellationToken,
    ) -> StoreResult<bool> {
        let expected = self.selection.persisted_mount_count();
        let Some((mounted, with_authority)) = self.read_statement(cancellation, |conn| {
            let mut statement = conn.prepare_cached(SELECTED_INTERIOR_VALIDATION_SQL)?;
            let counts = statement
                .query_row([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))?;
            Ok(Some(counts))
        })?
        else {
            return Ok(false);
        };
        if with_authority != mounted {
            return Err(StoreError::stale_resolution(format!(
                "selected resolution interior changed during shared-root candidate validation: {} of {mounted} selected mounts no longer name a complete interior",
                mounted - with_authority
            )));
        }
        let mounted = usize::try_from(mounted).expect("selected mount count fits usize");
        if mounted != expected {
            return Err(invalid_fact(format!(
                "selected lexical sentinel expected {expected} mounts, decoded {mounted}"
            )));
        }
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        Ok(true)
    }

    /// Read only the source-owned gaps of one admitted fragment. An empty
    /// reference list is not an inventory certificate without this evidence.
    pub(crate) fn reference_inventory_completion(
        &self,
        fragment: BindingFragmentId,
        cancellation: &CancellationToken,
        session: &ResolutionSession,
    ) -> StoreResult<ResolutionCompletion> {
        if !session.scope_step() || cancellation.is_cancelled() {
            return Ok(with_cancelled(ResolutionCompletion::Complete));
        }
        let position = self
            .selected_position_of_fragment(fragment)
            .ok_or_else(|| {
                invalid_fact(format!(
                    "reference inventory requested an unselected persisted fragment {fragment}"
                ))
            })?;
        // The source certification entry retains the mounted service's scope charge.
        if !session.scope_step() || cancellation.is_cancelled() {
            return Ok(with_cancelled(ResolutionCompletion::Complete));
        }
        let mount = &*self.mount_record(SelectedResolutionMountOrdinal::new(
            u32::try_from(position).expect("mount position fits u32"),
        ))?;
        if self
            .authority
            .ensure_authority(mount, cancellation)?
            .is_none()
        {
            return Ok(with_cancelled(ResolutionCompletion::Complete));
        }
        let fragments = std::iter::once(fragment).collect();
        let completion =
            stage::reference_inventory_completion(self.selection, Some(&fragments), cancellation)?;
        if let ResolutionCompletion::Incomplete(reasons) = &completion {
            for _ in reasons.iter() {
                if !session.scope_step() || cancellation.is_cancelled() {
                    return Ok(with_cancelled(completion));
                }
            }
        }
        Ok(
            if cancellation.is_cancelled() || !session.observe_cancellation() {
                with_cancelled(completion)
            } else {
                completion
            },
        )
    }

    /// The mount one fragment-local semantic names in its own bytes.
    ///
    /// Every read below wants the blob to open, not the key inside it, so this
    /// reads the ID's prefix and stops there.
    fn local_semantic_mount(
        &self,
        semantic: SemanticId,
        description: &str,
    ) -> StoreResult<SelectedResolutionMount> {
        match self
            .selection
            .mount_rebaser()
            .borrow()
            .semantic_mount(semantic)
        {
            SelectedSemanticMount::FragmentLocal(mount) => Ok(mount),
            SelectedSemanticMount::Shared(_) => Err(invalid_fact(format!(
                "{description} {semantic} is shared, but persisted reference and definition semantics are fragment-local"
            ))),
        }
    }

    fn local_node_mount(
        &self,
        node: BindingNodeId,
        description: &str,
    ) -> StoreResult<SelectedNodeMount> {
        self.selection
            .mount_rebaser()
            .borrow()
            .node_mount(node)
            .ok_or_else(|| {
                invalid_fact(format!(
                    "{description} {node} has no selected-mount provenance"
                ))
            })
    }

    /// Read the source scopes of a request's already-held nodes once per mount.
    pub(crate) fn node_scope_ordinals(
        &self,
        nodes: impl Iterator<Item = BindingNodeId>,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<NodeSourceScopes>> {
        let nodes = nodes.collect::<Vec<_>>();
        let Some(mut authority) = stage::scope_nodes(self.selection, &nodes, cancellation)? else {
            return Ok(None);
        };
        let mut groups = BTreeMap::<SelectedResolutionMountOrdinal, Vec<u32>>::new();
        for &node in &nodes {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            if let Some(ordinal) = node.ordinal() {
                let ordinal = SelectedResolutionMountOrdinal::new(ordinal);
                if self.selected_position(ordinal).is_some() {
                    groups
                        .entry(ordinal)
                        .or_default()
                        .push(node.local_key().expect("local scope node"));
                }
            }
        }
        for (ordinal, keys) in groups {
            let Some(rows) = self.authority.scope_catalog_nodes(
                &*self.mount_record(ordinal)?,
                &keys,
                cancellation,
            )?
            else {
                return Ok(None);
            };
            let fragment = BindingFragmentId::at_ordinal(ordinal.get());
            for (node, (identity, scope)) in rows {
                let ordinary = (identity, scope.map(|scope| (fragment, scope)));
                if let Some(staged) = authority.get(&node) {
                    if staged != &ordinary {
                        return Err(invalid_fact(format!(
                            "ordinary and stage node scope authority disagree: {node:?}, {ordinary:?}, {staged:?}"
                        )));
                    }
                } else {
                    authority.insert(node, ordinary);
                }
            }
        }
        Ok(Some(
            nodes
                .into_iter()
                .map(|node| (node, authority.get(&node).and_then(|(_, scope)| *scope)))
                .collect(),
        ))
    }

    pub(crate) fn node_is_scope_head_in(
        &self,
        scopes: &HashMap<BindingNodeId, Option<(BindingFragmentId, ResolutionScopeId)>>,
        node: BindingNodeId,
        fragment: BindingFragmentId,
        scope: ResolutionScopeId,
    ) -> bool {
        scopes
            .get(&node)
            .expect("scope batch includes every compared node")
            == &Some((fragment, scope))
    }

    /// Whether one selected node is the head of one scope of one mount.
    ///
    /// The scope head used to be computed: a node id was a pure function of
    /// its identity and its fragment, so a caller holding a scope ordinal
    /// could state the node and compare. A node id is a catalog position now,
    /// and the blob's catalog indexes its scope heads the way the producer
    /// published them, node to ordinal, so the same comparison is one forward
    /// read of the node the caller already holds.
    pub(crate) fn node_is_scope_head(
        &self,
        node: BindingNodeId,
        fragment: BindingFragmentId,
        scope: ResolutionScopeId,
        cancellation: &CancellationToken,
    ) -> StoreResult<bool> {
        Ok(self.scope_head_node_of(fragment, scope, cancellation)? == Some(node))
    }

    /// The runtime semantic from actual stage and ordinary identity authority.
    pub(crate) fn semantic_for_identity(
        &self,
        fragment: BindingFragmentId,
        identity: crate::analyzer::resolution::ResolutionSemanticIdentity,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Option<SemanticId>>> {
        let Some(staged) =
            stage::semantic_identities(self.selection, &[(fragment, identity)], cancellation)?
        else {
            return Ok(None);
        };
        let ordinal = SelectedResolutionMountOrdinal::new(fragment.ordinal());
        let ordinary = if self.selected_position(ordinal).is_some() {
            let Some(ordinary) = self.authority.semantic_for_identity(
                &*self.mount_record(ordinal)?,
                identity,
                cancellation,
            )?
            else {
                return Ok(None);
            };
            ordinary
        } else {
            None
        };
        if let (Some(ordinary), Some(staged)) = (ordinary, staged[0])
            && ordinary != staged
        {
            return Err(invalid_fact(format!(
                "ordinary and stage identity coordinates disagree: {fragment:?}, {identity:?}, {ordinary:?}, {staged:?}"
            )));
        }
        Ok(Some(ordinary.or(staged[0])))
    }

    pub(crate) fn local_semantics_for_identities(
        &self,
        requests: &[(
            BindingFragmentId,
            crate::analyzer::resolution::ResolutionSemanticIdentity,
        )],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<Option<SemanticId>>>> {
        use crate::analyzer::resolution::ResolutionSemanticIdentity;
        let mut groups = BTreeMap::<SelectedResolutionMountOrdinal, Vec<(usize, String)>>::new();
        let Some(mut result) = stage::semantic_identities(self.selection, requests, cancellation)?
        else {
            return Ok(None);
        };
        for (position, &(fragment, identity)) in requests.iter().enumerate() {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let ResolutionSemanticIdentity::FragmentLocal(digest) = identity else {
                return Err(invalid_fact(format!(
                    "selected context anchor identity is not fragment-local: {identity:?}"
                )));
            };
            let ordinal = SelectedResolutionMountOrdinal::new(fragment.ordinal());
            if self.selected_position(ordinal).is_some() {
                groups
                    .entry(ordinal)
                    .or_default()
                    .push((position, hex_digest(digest)));
            }
        }
        for (ordinal, keys) in groups {
            let digests = keys
                .iter()
                .map(|(_, digest)| digest.clone())
                .collect::<Vec<_>>();
            let Some(rows) = self.authority.semantics_for_identities(
                &*self.mount_record(ordinal)?,
                &digests,
                cancellation,
            )?
            else {
                return Ok(None);
            };
            for (index, runtime) in rows {
                let position = keys[index].0;
                if let Some(staged) = result[position]
                    && staged != runtime
                {
                    return Err(invalid_fact(format!(
                        "ordinary and stage semantic identity coordinates disagree: {:?}, {runtime:?}, {staged:?}",
                        requests[position]
                    )));
                }
                result[position] = Some(runtime);
            }
        }
        Ok(Some(result))
    }

    /// The runtime node from actual stage and ordinary identity authority.
    pub(crate) fn node_for_identity(
        &self,
        fragment: BindingFragmentId,
        identity: crate::analyzer::resolution::ResolutionNodeIdentity,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Option<BindingNodeId>>> {
        let Some(staged) =
            stage::node_identities(self.selection, &[(fragment, identity)], cancellation)?
        else {
            return Ok(None);
        };
        let ordinal = SelectedResolutionMountOrdinal::new(fragment.ordinal());
        let ordinary = if self.selected_position(ordinal).is_some() {
            let Some(ordinary) = self.authority.node_for_identity(
                &*self.mount_record(ordinal)?,
                identity,
                cancellation,
            )?
            else {
                return Ok(None);
            };
            ordinary
        } else {
            None
        };
        if let (Some(ordinary), Some(staged)) = (ordinary, staged[0])
            && ordinary != staged
        {
            return Err(invalid_fact(format!(
                "ordinary and stage identity coordinates disagree: {fragment:?}, {identity:?}, {ordinary:?}, {staged:?}"
            )));
        }
        Ok(Some(ordinary.or(staged[0])))
    }

    /// The node one mount gives one source scope's head.
    ///
    /// This is the direction [`Self::node_is_scope_head`] does not answer: a
    /// caller that has no node yet, because it is about to name one. The
    /// operation's own registrations answer first, which is what covers a
    /// transient mount that has no interior to open.
    pub(crate) fn scope_head_node_of(
        &self,
        fragment: BindingFragmentId,
        scope: ResolutionScopeId,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<BindingNodeId>> {
        Ok(self
            .node_for_identity(fragment, scope_head_node_identity(scope), cancellation)?
            .flatten())
    }

    fn forward_candidate_completion(
        &self,
        requests: &[BatchCandidateRequest],
        cancellation: &CancellationToken,
        _resolution_session: Option<&ResolutionSession>,
    ) -> StoreResult<(BatchCandidateCompletionOutcome, bool)> {
        self.lazy_candidate_completion(
            CandidateDirection::Forward,
            requests,
            None,
            None,
            cancellation,
        )
    }

    /// One candidate direction's unconditional completion reasons, read from
    /// the tier-1 candidate gap headers over the whole selection, with the
    /// selected mount each reason came from.
    ///
    /// A blob's fragment-blocking and candidate-inventory gaps qualify every
    /// candidate read of that blob in the named direction, whatever the
    /// request asked for, so the box is a property of the selection and this
    /// reads it with one indexed query instead of producing every blob's
    /// interior to ask. The reason identity each row carries is blob-local, so
    /// it remounts on that blob's own fragment and reproduces exactly the
    /// mounted reason the interior would have reported.
    ///
    /// The box is published as a shared completion base rather than as a list
    /// of reasons, because every later use of it either takes it whole or
    /// drops whole mounts from it, and because a shared base is what makes the
    /// engine's combine sites merge two sparse deltas instead of rebuilding a
    /// set of every reason in the workspace.
    fn selection_unconditional_box(
        &self,
        direction: CandidateDirection,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<&UnconditionalCandidateBox>> {
        if let Some(published) = self.unconditional_candidate_reasons[direction.position()].get() {
            return Ok(Some(published));
        }
        // The mounted reason is the identity mounted on the blob's own
        // fragment, which is what producing the interior would have reported.
        // Registering it as well used to be how a later read found its
        // storage coordinate; the ID names its own mount now, so a read of
        // the whole selection's gap headers leaves nothing behind.
        // The runtime semantic a reason names is the position it occupies in
        // its blob's catalog, and the row carries that position: the writer
        // puts the gap reason's dense local key in `reason_semantic_key`. The
        // read used to reconstruct the identity from the row's digest and ask
        // the mount's catalog for the position, which opened one interior per
        // mount in scope -- the cost this statement exists to avoid.
        let mut reasons = Vec::new();
        let live = self.read_statement(cancellation, |conn| {
            let mut statement = conn.prepare_cached(CANDIDATE_GAP_UNCONDITIONAL_SQL)?;
            let mut decoded =
                statement.query(params![covers_candidate_inventory(direction.lowered())])?;
            while let Some(row) = decoded.next()? {
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                let ordinal = mount_ordinal(row, 0, "unconditional candidate gap mount")?;
                let Some(position) = self.selected_position(ordinal) else {
                    continue;
                };
                let semantic =
                    gap_reason_semantic(row, 1, ordinal, "unconditional candidate gap reason")?;
                reasons.push((
                    ResolutionIncompleteReason::UnsupportedSemantic(semantic),
                    position,
                ));
            }
            Ok(Some(()))
        })?;
        if live.is_none() {
            return Ok(None);
        }
        // Sorted by reason, because that is the order a shared base is indexed
        // in and the order the positions run parallel to.
        reasons.sort_unstable();
        reasons.dedup();
        let published = if reasons.is_empty() {
            UnconditionalCandidateBox {
                whole: ResolutionCompletion::Complete,
                positions: Box::new([]),
            }
        } else {
            // A reason is the gap's blob-local digest mounted on one mount's
            // own fragment, so two mounts cannot mint the same reason and the
            // position each base reason came from is a function of it.
            assert!(
                reasons.windows(2).all(|pair| pair[0].0 < pair[1].0),
                "one unconditional candidate gap reason came from two selected mounts"
            );
            let positions = reasons
                .iter()
                .map(|&(_, position)| position)
                .collect::<Box<[usize]>>();
            let base = reasons
                .into_iter()
                .map(|(reason, _)| reason)
                .collect::<Box<[ResolutionIncompleteReason]>>();
            UnconditionalCandidateBox {
                whole: ResolutionCompletion::Incomplete(CompletionReasons::shared_from_canonical(
                    base,
                )),
                positions,
            }
        };
        Ok(Some(
            self.unconditional_candidate_reasons[direction.position()].get_or_init(|| published),
        ))
    }

    /// One candidate direction's boundary-rooted branch coverage, read from the
    /// tier-1 candidate gap headers over the whole selection.
    ///
    /// A gap endpoint is either the universal root or a node of the gap's own
    /// blob, so a boundary-rooted request is the only kind another blob can
    /// qualify, and the rows named here are exactly the gaps that qualify it.
    /// Reading them replaces opening every one of those blobs' authority and
    /// running the candidate visitor with a discard callback: on tract that was
    /// 282 productions for one candidate read. The reason identity each row
    /// carries is blob-local, so it remounts on that blob's own fragment and
    /// reproduces the mounted reason the interior would have reported.
    fn boundary_candidate_branches(
        &self,
        direction: CandidateDirection,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<&BoundaryCandidateBranches>> {
        if let Some(branches) = self.boundary_candidate_branches[direction.position()].get() {
            return Ok(Some(branches));
        }
        let mut rows = Vec::new();
        let live = self.read_statement(cancellation, |conn| {
            let mut statement = conn.prepare_cached(CANDIDATE_GAP_BOUNDARY_BRANCHES_SQL)?;
            let mut decoded =
                statement.query(params![covers_candidate_endpoint(direction.lowered())])?;
            while let Some(row) = decoded.next()? {
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                let ordinal = mount_ordinal(row, 0, "boundary candidate gap mount")?;
                rows.push((
                    ordinal,
                    nonnegative_i64(row, 1, "boundary candidate gap lookup")?,
                    gap_reason_semantic(row, 2, ordinal, "boundary candidate gap reason")?,
                ));
            }
            Ok(Some(()))
        })?;
        if live.is_none() {
            return Ok(None);
        }
        let mut branches = BoundaryCandidateBranches::default();
        // As above: the reason is the row's dense local key on the gap's own
        // mount, so nothing is opened to state one. `lookup` is 0 or a shared
        // name; no local lookup can reach a row, which the writer asserts.
        for (ordinal, lookup, semantic) in rows {
            let Some(position) = self.selected_position(ordinal) else {
                continue;
            };
            let reason = (
                position,
                ResolutionIncompleteReason::UnsupportedSemantic(semantic),
            );
            if lookup == 0 {
                branches.unkeyed.push(reason);
            } else {
                branches
                    .by_shared_lookup
                    .entry(
                        self.selection
                            .shared_name_table()
                            .interner(self.selection.connection())
                            .from_persisted(SharedNameId::interned(lookup)),
                    )
                    .or_default()
                    .push(reason);
            }
        }
        branches.unkeyed.sort_unstable();
        branches.unkeyed.dedup();
        for bucket in branches.by_shared_lookup.values_mut() {
            bucket.sort_unstable();
            bucket.dedup();
        }
        Ok(Some(
            self.boundary_candidate_branches[direction.position()].get_or_init(|| branches),
        ))
    }

    /// The selected mounts whose authority one completion read must open, and
    /// the tier-1 boundary bucket each request takes from every other mount.
    ///
    /// A request rooted at a fragment-local node is qualified only by its own
    /// mount. A boundary-rooted request is qualified by every blob that owns a
    /// boundary-rooted gap, which `boundary_candidate_branches` states without
    /// opening any of them. The unconditional box is not read here: it comes
    /// from `selection_unconditional_reasons`.
    fn completion_mount_positions(
        &self,
        requests: &[BatchCandidateRequest],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<CandidateCompletionPlan>> {
        let mut positions = BTreeSet::new();
        let mut selectors = Vec::with_capacity(requests.len());
        let mut endpoints = Vec::with_capacity(requests.len());
        for request in requests {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let endpoint = request.endpoint();
            if endpoint.node() == BindingNodeId::universal_root() {
                let selector = match endpoint.symbols().fixed().first() {
                    None if endpoint.symbols().tail().is_some() => {
                        BoundaryBranchSelector::EveryLookup
                    }
                    None => BoundaryBranchSelector::Unkeyed,
                    Some(symbol) => symbol.symbol().shared_name_id().map_or(
                        BoundaryBranchSelector::Unkeyed,
                        BoundaryBranchSelector::SharedLookup,
                    ),
                };
                endpoints.push(None);
                selectors.push(selector);
            } else {
                let coordinate = endpoint.node().ordinal().and_then(|ordinal| {
                    let ordinal = SelectedResolutionMountOrdinal::new(ordinal);
                    let position = self.selected_position(ordinal)?;
                    positions.insert(position);
                    Some((
                        position,
                        i64::from(endpoint.node().local_key().expect("local gap endpoint key")),
                    ))
                });
                endpoints.push(coordinate);
                selectors.push(BoundaryBranchSelector::OwnMount);
            }
        }
        Ok(Some(CandidateCompletionPlan {
            positions: positions.into_iter().collect(),
            selectors,
            endpoints,
        }))
    }

    /// Each request's own candidate-endpoint branch completion, from
    /// `resolution_gaps`.
    ///
    /// This is what `lazy_candidate_completion` used to get by running the
    /// blob's whole candidate match with a discard callback: every request
    /// matched its candidates twice, once for the completion the visit
    /// returned and once for the rows. The gap rows answer the completion half
    /// directly, one seek per endpoint node, so the completion pass opens no
    /// blob at all when no exclusion plan is in play.
    ///
    /// The selection rule is `CandidateCoverage::completion_for_with_poll`'s,
    /// unchanged: the unkeyed bucket (`lookup = 0`) always, then the bucket the
    /// endpoint's first fixed symbol names when that symbol is a shared name,
    /// or every bucket when the endpoint has an open tail and no fixed symbol.
    /// A blob-local first fixed symbol names no bucket, because every keyed
    /// bucket is keyed on a shared name.
    ///
    /// `Ok(None)` means the read was cancelled.
    fn endpoint_branch_completions(
        &self,
        direction: CandidateDirection,
        endpoints: &[Option<(usize, i64)>],
        requests: &[BatchCandidateRequest],
        scope: Option<&[SelectedResolutionMountOrdinal]>,
        branches: &mut [ResolutionCompletion],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<()>> {
        let mut by_position = BTreeMap::<usize, BTreeMap<i64, Vec<(usize, WantedLookup)>>>::new();
        {
            let names = self
                .selection
                .shared_name_table()
                .interner(self.selection.connection());
            for (index, request) in requests.iter().enumerate() {
                let Some((position, node)) = endpoints[index] else {
                    continue;
                };
                if !scope.is_none_or(|scope| {
                    scope_admits(
                        scope,
                        SelectedResolutionMountOrdinal::new(
                            u32::try_from(position).expect("mount position fits u32"),
                        ),
                    )
                }) {
                    continue;
                }
                let endpoint = request.endpoint();
                let wanted = match endpoint.symbols().fixed().first() {
                    None if endpoint.symbols().tail().is_some() => WantedLookup::Every,
                    None => WantedLookup::Unkeyed,
                    Some(symbol) => symbol
                        .symbol()
                        .shared_name_id()
                        .and_then(|shared| names.to_persisted(shared))
                        .map_or(WantedLookup::Unkeyed, |shared| {
                            WantedLookup::Shared(i64::from(shared.get()))
                        }),
                };
                by_position
                    .entry(position)
                    .or_default()
                    .entry(node)
                    .or_default()
                    .push((index, wanted));
            }
        }
        let covers = covers_candidate_endpoint(direction.lowered());
        let mut reasons = vec![Vec::new(); requests.len()];
        let mut live = true;
        for (position, nodes) in &by_position {
            let mount = &*self.mount_record(SelectedResolutionMountOrdinal::new(
                u32::try_from(*position).expect("mount position fits u32"),
            ))?;
            let mut exact = BTreeSet::new();
            let mut every = Vec::new();
            for (&node, wanted) in nodes {
                if wanted
                    .iter()
                    .any(|(_, wanted)| *wanted == WantedLookup::Every)
                {
                    every.push(node);
                } else {
                    exact.insert([node, 0]);
                    for (_, wanted) in wanted {
                        if let WantedLookup::Shared(lookup) = wanted {
                            exact.insert([node, *lookup]);
                        }
                    }
                }
            }
            let exact = serde_json::to_string(&exact).expect("integer tuples serialize");
            let every = json_integer_array(every.into_iter());
            let result = self.read_statement(cancellation, |conn| {
                let mut statement = conn.prepare_cached(CANDIDATE_GAP_ENDPOINT_BRANCHES_SQL)?;
                let mut decoded =
                    statement.query(params![mount.blob_id(), covers, exact, every])?;
                while let Some(row) = decoded.next()? {
                    if cancellation.is_cancelled() {
                        return Ok(None);
                    }
                    let node = row.get::<_, i64>(0)?;
                    let lookup = nonnegative_i64(row, 1, "candidate endpoint gap lookup")?;
                    let reason = gap_reason_semantic(
                        row,
                        2,
                        mount.ordinal(),
                        "candidate endpoint gap reason",
                    )?;
                    for &(index, wanted) in &nodes[&node] {
                        if match wanted {
                            WantedLookup::Every => true,
                            WantedLookup::Unkeyed => lookup == 0,
                            WantedLookup::Shared(name) => lookup == 0 || lookup == name,
                        } {
                            reasons[index]
                                .push(ResolutionIncompleteReason::UnsupportedSemantic(reason));
                        }
                    }
                }
                Ok(Some(()))
            })?;
            if result.is_none() {
                live = false;
                break;
            }
        }
        // Cancellation stops further reads, not the publication of evidence
        // already decoded. This also retains rows from an interrupted SQLite
        // statement, whose read_statement result is None.
        for (branch, reasons) in branches.iter_mut().zip(reasons) {
            if !reasons.is_empty() {
                *branch = branch.combine(&ResolutionCompletion::incomplete(reasons));
            }
        }
        Ok(live.then_some(()))
    }

    /// Validate exclusions against immutable all-host raw authority. The same
    /// read classifies scoped effective eligibility so cancellation cannot lose
    /// decoded evidence or resurrect closed reasons. Only certified exact gap
    /// exclusions apply; cached reason overlays never determine scoped answers.
    pub(super) fn reverse_completion_with_exclusions(
        &self,
        requests: &[BatchCandidateRequest],
        scope: Option<&[SelectedResolutionMountOrdinal]>,
        plan: &mut ReverseCandidateGapExclusionPlan,
        cancellation: &CancellationToken,
    ) -> StoreResult<(BatchCandidateCompletionOutcome, bool)> {
        let authority = self.selection.candidate_coverage_fingerprint();
        let already_prepared = !plan.needs_preparation_for_authority(authority)?;
        let mut ordinary_excluded = Vec::new();
        for identity in plan.identities() {
            self.selected_position_of_fragment(identity.fragment())
                .ok_or_else(|| {
                    invalid_fact(format!(
                        "excluded gap belongs to an unselected fragment: {identity:?}"
                    ))
                })?;
            // Ordinary gaps are dense per-blob ordinals below the stage
            // floor; a stage gap keeps the host's ordinal at or above it.
            if identity.gap_id().ordinal() == Some(identity.fragment().ordinal()) {
                let key = identity
                    .gap_id()
                    .local_key()
                    .expect("ordinary gap local key");
                if i64::from(key) < super::resolution_stage::allocation::BASE {
                    ordinary_excluded.push((identity.fragment().ordinal(), key));
                }
            }
        }
        let keys = self.candidate_request_keys(requests, cancellation)?;
        let nodes = keys
            .iter()
            .filter_map(|key| match key.node {
                CandidateRequestNode::UniversalRoot => Some((-1i64, -1i64)),
                CandidateRequestNode::Local(host, key) => Some((i64::from(host.get()), key)),
                CandidateRequestNode::Unmounted => None,
            })
            .collect::<BTreeSet<_>>();
        let nodes =
            serde_json::to_string(&nodes).expect("ordinary reverse endpoint requests serialize");
        let excluded = serde_json::to_string(&ordinary_excluded)
            .expect("ordinary reverse exclusions serialize");
        let scope_json = scope.map(|scope| {
            serde_json::to_string(&scope.iter().map(|host| host.get()).collect::<Vec<_>>())
                .expect("reverse scope serializes")
        });
        let qualified_origin = super::resolution_prepare::resolution_rows::gap_origin_code(
            crate::analyzer::resolution::LoweringGapOrigin::QualifiedReference,
        );
        let local_base = super::resolution_stage::codec::encode_semantic(SemanticId::local(0, 0));
        let names = self
            .selection
            .shared_name_table()
            .interner(self.selection.connection());
        let sql = format!(
            "{} SELECT g.host,g.covers,g.node,g.lookup,g.gap_key,g.reason_key,EXISTS(SELECT 1 FROM temp.selected_resolution_scope_mounts scope WHERE scope.mount_ordinal=g.host) AND (:scope IS NULL OR g.host IN(SELECT value FROM json_each(:scope))) AND ({}) FROM raw_gaps g WHERE {}",
            ordinary_reverse_gap_projection_sql(),
            super::resolution_stage::frontier_completion::effective_gap_remains_sql(),
            super::resolution_stage::frontier_completion::QUALIFIED_GAP_REMAINS_SQL
        );
        let mut evidence = Vec::new();
        let live=self.read_statement(cancellation,|connection| {
            let mut statement=connection.prepare_cached(&sql)?;
            let mut rows=statement.query(rusqlite::named_params! {":nodes":nodes,":excluded":excluded,":scope":scope_json,":qualified_origin":qualified_origin,":local_base":local_base})?;
            while let Some(row)=rows.next()? {
                evidence.push(ReverseCoverageEvidence::from_row(row,&names)?);
                if cancellation.is_cancelled() {return Ok(None);}
            }
            Ok(Some(()))
        })?;
        let mut cancelled = live.is_none();
        if !cancelled {
            let (staged, observed) = stage::raw_reverse_candidate_rows(
                self.selection,
                requests,
                plan.identities(),
                scope,
                cancellation,
            )?;
            evidence.extend(staged);
            cancelled |= observed;
        }
        // Preserve every decoded row even if cancellation won during its read.
        // Raw tuples remain available for proof; eligibility already records
        // exact closure and current scope and never requires a second query.
        let mut raw = HashMap::default();
        for row in &evidence {
            if let Some(gap) = row.gap
                && let Some(previous) = raw.insert(gap.identity(), gap)
                && previous != gap
            {
                return Err(invalid_fact(format!(
                    "selected reverse gap authority disagrees: {previous:?}, {gap:?}"
                )));
            }
        }
        cancelled |= cancellation.is_cancelled();
        let prepared = if already_prepared {
            true
        } else if cancelled {
            false
        } else {
            let mut proof = ReverseCandidateGapCoverageBuilder::default();
            for row in raw.values() {
                proof.push(*row)?;
            }
            let (proof, observed) = proof.finish_with_authority(authority, cancellation)?;
            cancelled |= observed;
            !cancelled && proof.prepare_exclusions(plan, cancellation)?
        };
        cancelled |= !prepared;
        let excluded = if prepared { plan.identities() } else { &[] };
        let (completion, observed) =
            finish_reverse_evidence(evidence, excluded, requests, cancellation)?;
        cancelled |= observed || cancellation.is_cancelled();
        let completion = candidate_completion_after_visit(
            requests.len(),
            completion,
            if cancelled {
                CandidatePageVisit::Cancelled
            } else {
                CandidatePageVisit::Exhausted
            },
            cancellation,
        )?;
        Ok((completion, cancelled))
    }

    /// Load the reasons the selected stage closed for the current candidate
    /// authority, unless they are already loaded. `false` means cancelled.
    fn refresh_ordinary_completion_suppression(
        &self,
        cancellation: &CancellationToken,
    ) -> StoreResult<bool> {
        let authority = self.selection.candidate_coverage_fingerprint();
        let refresh = self
            .ordinary_completion_suppression
            .borrow()
            .as_ref()
            .is_none_or(|cached| cached.authority != authority);
        if refresh {
            let Some(reasons) =
                stage::ordinary_completion_suppression(self.selection, cancellation)?
            else {
                return Ok(false);
            };
            *self.ordinary_completion_suppression.borrow_mut() =
                Some(OrdinaryCompletionSuppression { authority, reasons });
        }
        Ok(true)
    }

    fn lazy_candidate_completion(
        &self,
        direction: CandidateDirection,
        requests: &[BatchCandidateRequest],
        scope: Option<&[SelectedResolutionMountOrdinal]>,
        exclusions: Option<&mut ReverseCandidateGapExclusionPlan>,
        cancellation: &CancellationToken,
    ) -> StoreResult<(BatchCandidateCompletionOutcome, bool)> {
        if let Some(plan) = exclusions {
            assert_eq!(direction, CandidateDirection::Reverse);
            return self.reverse_completion_with_exclusions(requests, scope, plan, cancellation);
        }
        let (ordinary, mut cancelled) =
            self.ordinary_candidate_completion(direction, requests, scope, cancellation)?;
        if !self.refresh_ordinary_completion_suppression(cancellation)? {
            return Ok((
                BatchCandidateCompletionOutcome::new(
                    requests.len(),
                    with_cancelled(ordinary.unconditional_completion().clone()),
                    ordinary.branch_completions().to_vec(),
                ),
                true,
            ));
        }
        let cached = self.ordinary_completion_suppression.borrow();
        let cached = cached
            .as_ref()
            .expect("current suppression result was loaded");
        let mut suppress = |completion: &ResolutionCompletion| match completion {
            ResolutionCompletion::Complete => ResolutionCompletion::Complete,
            ResolutionCompletion::Incomplete(reasons) => reasons
                .without_reasons_with_poll(cached.reasons.iter().copied(), &mut || {
                    cancelled |= cancellation.is_cancelled();
                    false
                })
                .expect("observational polling finishes returned evidence")
                .map_or(
                    ResolutionCompletion::Complete,
                    ResolutionCompletion::Incomplete,
                ),
        };
        let unconditional = suppress(ordinary.unconditional_completion());
        let branches = ordinary
            .branch_completions()
            .iter()
            .map(&mut suppress)
            .collect::<Vec<_>>();
        let staged = stage::candidate_completion(
            self.selection,
            direction.lowered(),
            requests,
            scope,
            &[],
            cancellation,
        )?;
        let mut unconditional = unconditional.combine(staged.unconditional_completion());
        let branches = branches
            .into_iter()
            .zip(staged.branch_completions())
            .map(|(ordinary, staged)| ordinary.combine(staged))
            .collect::<Vec<_>>();
        cancelled |= cancellation.is_cancelled()
            || unconditional.contains_reason(ResolutionIncompleteReason::Cancelled);
        if cancelled {
            unconditional = with_cancelled(unconditional);
        }
        Ok((
            BatchCandidateCompletionOutcome::new(requests.len(), unconditional, branches),
            cancelled,
        ))
    }

    fn ordinary_candidate_completion(
        &self,
        direction: CandidateDirection,
        requests: &[BatchCandidateRequest],
        scope: Option<&[SelectedResolutionMountOrdinal]>,
        cancellation: &CancellationToken,
    ) -> StoreResult<(BatchCandidateCompletionOutcome, bool)> {
        let mut branches = vec![ResolutionCompletion::Complete; requests.len()];
        let cancelled_outcome = |unconditional: ResolutionCompletion, branches| {
            (
                BatchCandidateCompletionOutcome::new(
                    requests.len(),
                    with_cancelled(unconditional),
                    branches,
                ),
                true,
            )
        };
        let Some(published) = self.selection_unconditional_box(direction, cancellation)? else {
            return Ok(cancelled_outcome(ResolutionCompletion::Complete, branches));
        };
        // An exclusion plan subtracts gaps that a macro replay closed. Only a
        // fragment the plan names can lose a reason, so those mounts restate
        // their own box from their authority and the tier-1 rows supply the
        // rest.
        let mut restated = HashSet::<usize>::default();
        // A scoped read names the only mounts whose candidates it can use, so
        // only those mounts' gaps qualify its answer. A read that drops no
        // mount is the common one and takes the published box by its handle;
        // any other read names the base positions it drops, which keeps one
        // base for the whole operation however many scopes ask for it.
        let unconditional = if restated.is_empty() && scope.is_none() {
            published.whole.clone()
        } else {
            let dropped = published
                .positions
                .iter()
                .enumerate()
                .filter(|&(_, &position)| {
                    restated.contains(&position)
                        || !scope.is_none_or(|scope| {
                            scope_admits(
                                scope,
                                SelectedResolutionMountOrdinal::new(
                                    u32::try_from(position).expect("mount position fits u32"),
                                ),
                            )
                        })
                })
                .map(|(index, _)| index)
                .collect::<Box<[usize]>>();
            match &published.whole {
                ResolutionCompletion::Complete => ResolutionCompletion::Complete,
                ResolutionCompletion::Incomplete(_) if dropped.is_empty() => {
                    published.whole.clone()
                }
                ResolutionCompletion::Incomplete(base) => base
                    .shared_without_positions(dropped)
                    .map_or(ResolutionCompletion::Complete, |kept| {
                        ResolutionCompletion::Incomplete(kept)
                    }),
            }
        };
        let Some(CandidateCompletionPlan {
            mut positions,
            selectors,
            endpoints,
        }) = self.completion_mount_positions(requests, cancellation)?
        else {
            return Ok(cancelled_outcome(unconditional, branches));
        };
        if let Some(scope) = scope {
            positions.retain(|&position| {
                scope_admits(
                    scope,
                    SelectedResolutionMountOrdinal::new(
                        u32::try_from(position).expect("mount position fits u32"),
                    ),
                )
            });
            restated.retain(|&position| {
                scope_admits(
                    scope,
                    SelectedResolutionMountOrdinal::new(
                        u32::try_from(position).expect("mount position fits u32"),
                    ),
                )
            });
        }
        // An exclusion plan is the one thing the rows cannot answer: it is
        // prepared against a blob's raw reverse coverage and the interior is
        // the authority that prepared it, so a read that carries one restates
        // its mounts from their authority as before, and only then does an
        // opened mount also supply its own boundary buckets. Without a plan --
        // every forward read and every reverse read that closes no gap -- the
        // completion pass opens nothing: the endpoint branches come from
        // `resolution_gaps` and the boundary branches from the tier-1 box over
        // the whole scope.
        {
            debug_assert!(restated.is_empty(), "an exclusion plan is what restates");
            positions.clear();
            if self
                .endpoint_branch_completions(
                    direction,
                    &endpoints,
                    requests,
                    scope,
                    &mut branches,
                    cancellation,
                )?
                .is_none()
            {
                return Ok(cancelled_outcome(unconditional, branches));
            }
        }
        if selectors
            .iter()
            .any(|selector| *selector != BoundaryBranchSelector::OwnMount)
        {
            let Some(boundary) = self.boundary_candidate_branches(direction, cancellation)? else {
                return Ok(cancelled_outcome(unconditional, branches));
            };
            positions.sort_unstable();
            positions.dedup();
            // Every mount this read opens states its own boundary coverage
            // exactly, including the buckets an exclusion plan subtracts, so
            // the tier-1 rows supply the rest of the selection and nothing
            // twice.
            let opened = positions.iter().copied().collect::<HashSet<usize>>();
            let keep = |&(position, _): &(usize, ResolutionIncompleteReason)| {
                !opened.contains(&position)
                    && scope.is_none_or(|scope| {
                        scope_admits(
                            scope,
                            SelectedResolutionMountOrdinal::new(
                                u32::try_from(position).expect("mount position fits u32"),
                            ),
                        )
                    })
            };
            // Requests that take the same buckets take the same completion, and
            // a batch has at most one selector per request, so this builds each
            // distinct box once instead of once per request.
            let mut by_selector =
                HashMap::<BoundaryBranchSelector, ResolutionCompletion>::default();
            for (branch, selector) in branches.iter_mut().zip(&selectors) {
                if *selector == BoundaryBranchSelector::OwnMount {
                    continue;
                }
                let completion = by_selector.entry(*selector).or_insert_with(|| {
                    let keyed = match selector {
                        BoundaryBranchSelector::OwnMount | BoundaryBranchSelector::Unkeyed => {
                            Vec::new()
                        }
                        BoundaryBranchSelector::SharedLookup(digest) => boundary
                            .by_shared_lookup
                            .get(digest)
                            .map_or_else(Vec::new, |bucket| {
                                bucket.iter().filter(|row| keep(row)).collect()
                            }),
                        BoundaryBranchSelector::EveryLookup => boundary
                            .by_shared_lookup
                            .values()
                            .flatten()
                            .filter(|row| keep(row))
                            .collect(),
                    };
                    let kept = boundary
                        .unkeyed
                        .iter()
                        .filter(|row| keep(row))
                        .chain(keyed)
                        .map(|&(_, reason)| reason)
                        .collect::<Vec<_>>();
                    if kept.is_empty() {
                        ResolutionCompletion::Complete
                    } else {
                        ResolutionCompletion::incomplete(kept)
                    }
                });
                *branch = branch.combine(completion);
            }
        }
        let cancelled = cancellation.is_cancelled()
            || unconditional.contains_reason(ResolutionIncompleteReason::Cancelled);
        Ok((
            BatchCandidateCompletionOutcome::new(requests.len(), unconditional, branches),
            cancelled,
        ))
    }

    /// Emit candidate matches from every selected mount whose tier-1 headers
    /// admit one of these requests, from `resolution_paths` rows. Completion is
    /// owned by `lazy_candidate_completion`, which runs first over the whole
    /// selection.
    ///
    /// Port block 2 of milestone 6. What changed against the interior: a mount
    /// that can offer a candidate is read with one statement over
    /// `resolution_paths_forward` or `_reverse` instead of having its whole
    /// `Facts` page produced, so a request that matches candidates in a hundred
    /// blobs opens none of them. It still opens each matching blob's `Catalog`
    /// page, because a stored body holds integers and today's engine holds
    /// digests; milestone 4's stage 1b-ii removes that.
    ///
    /// The unbounded emitted set and candidate-identity order retain the
    /// interior contract. Reverse root seeks exclude incompatible fixed
    /// prefixes before decoding; all offered endpoints still pass the full
    /// Rust admission test. Charging remains one scope step per request and
    /// per examined row, so excluding rejected rows can advance a bounded read.
    #[allow(clippy::too_many_arguments)]
    fn lazy_candidate_matches(
        &self,
        direction: CandidateDirection,
        requests: &[BatchCandidateRequest],
        scope: Option<&[SelectedResolutionMountOrdinal]>,
        maximum_page_rows: usize,
        resolution_session: Option<&ResolutionSession>,
        exclusions: Option<&mut ReverseCandidateGapExclusionPlan>,
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
    ) -> StoreResult<CandidatePageVisit> {
        assert!((1..=MAX_SOURCE_ROWS_PER_BATCH).contains(&maximum_page_rows));
        // An exclusion plan subtracts reasons from the completion and never
        // changes which candidates match, which is what the interior does too:
        // its gap-exclusion reverse read runs the same index walk as the plain
        // one. `lazy_candidate_completion` has already prepared the plan.
        let _ = exclusions;
        let mut stopped = false;
        let mut emitted = HashSet::new();
        // A root request names the mounts whose halves its caller can use, and
        // the tier-1 headers name the mounts that carry a matching path. Only
        // their intersection can contribute, and the scope is bound into the
        // header statement, so this already holds only mounts that will open.
        let positions = self.candidate_mount_positions(direction, requests, scope, cancellation)?;
        let keys = self.candidate_request_keys(requests, cancellation)?;
        for &position in &positions {
            let mount = &*self.mount_record(SelectedResolutionMountOrdinal::new(
                u32::try_from(position).expect("mount position fits u32"),
            ))?;
            let mut forward = |page: &[BatchCandidateMatch]| {
                if stopped {
                    return Ok(false);
                }
                for row in page {
                    let identity = (row.request_ordinal(), row.candidate());
                    if !emitted.insert(identity) {
                        return Err(invalid_fact(format!(
                            "selected candidate source repeated row {identity:?}"
                        )));
                    }
                }
                let keep_going = visitor(page)?;
                stopped = !keep_going;
                Ok(keep_going)
            };
            let visit = self.visit_candidate_match_rows(
                direction,
                mount,
                requests,
                &keys,
                maximum_page_rows,
                resolution_session,
                cancellation,
                &mut forward,
            )?;
            if matches!(visit, CandidatePageVisit::Cancelled) || cancellation.is_cancelled() {
                return Ok(CandidatePageVisit::Cancelled);
            }
            if stopped {
                return Ok(CandidatePageVisit::Stopped);
            }
        }
        let mut forward = |page: &[BatchCandidateMatch]| {
            for row in page {
                let identity = (row.request_ordinal(), row.candidate());
                if !emitted.insert(identity) {
                    return Err(invalid_fact(format!(
                        "selected candidate source repeated row {identity:?}"
                    )));
                }
            }
            visitor(page)
        };
        match direction {
            CandidateDirection::Forward => stage::visit_forward_candidates(
                self.selection,
                requests,
                scope,
                maximum_page_rows,
                resolution_session,
                cancellation,
                &mut forward,
            ),
            CandidateDirection::Reverse => stage::visit_reverse_candidates(
                self.selection,
                requests,
                scope,
                maximum_page_rows,
                resolution_session,
                cancellation,
                &mut forward,
            ),
        }
    }

    /// What each request of one batch seeks, computed once for the whole call.
    ///
    /// A request names one node and at most one first fixed cell. The node
    /// decides which blobs can answer at all; the cell decides which bucket of
    /// that blob's index the request reads, exactly as `CandidateLeadCell` and
    /// `CandidateNodeIndex::extend_buckets_for` do in the heap.
    fn candidate_request_keys(
        &self,
        requests: &[BatchCandidateRequest],
        cancellation: &CancellationToken,
    ) -> StoreResult<Vec<CandidateRequestKey>> {
        let mut keys = Vec::with_capacity(requests.len());
        for request in requests {
            if cancellation.is_cancelled() {
                return Ok(Vec::new());
            }
            let endpoint = request.endpoint();
            let node = if endpoint.node() == BindingNodeId::universal_root() {
                CandidateRequestNode::UniversalRoot
            } else {
                match self
                    .authority
                    .node_catalog_provenance(endpoint.node(), cancellation)?
                {
                    None => return Ok(Vec::new()),
                    Some(Some(SelectedNodeProvenance::FragmentLocal(local))) => {
                        CandidateRequestNode::Local(
                            local.mount().ordinal(),
                            local.local_key().get(),
                        )
                    }
                    Some(_) => CandidateRequestNode::Unmounted,
                }
            };
            let lead = match endpoint.symbols().fixed().first() {
                None => CandidateRequestLead::Open,
                Some(symbol)
                    if symbol.symbol().ordinal().is_none()
                        && symbol.symbol().shared_name_id().is_none() =>
                {
                    CandidateRequestLead::Unrepresentable
                }
                Some(symbol) => {
                    let scoped = symbol.scopes().is_some();
                    if let Some(shared) = symbol.symbol().shared_name_id() {
                        match self
                            .selection
                            .shared_name_table()
                            .interner(self.selection.connection())
                            .to_persisted(shared)
                        {
                            Some(identity) => CandidateRequestLead::Shared { identity, scoped },
                            None => CandidateRequestLead::Unrepresentable,
                        }
                    } else if let Some(ordinal) = symbol.symbol().ordinal() {
                        CandidateRequestLead::Local {
                            mount: SelectedResolutionMountOrdinal::new(ordinal),
                            semantic: symbol.symbol(),
                            scoped,
                        }
                    } else {
                        CandidateRequestLead::Unrepresentable
                    }
                }
            };
            keys.push(CandidateRequestKey { node, lead });
        }
        Ok(keys)
    }

    /// One mount's candidate matches, from its `resolution_paths` rows.
    #[allow(clippy::too_many_arguments)]
    fn visit_candidate_match_rows(
        &self,
        direction: CandidateDirection,
        mount: &SelectedResolutionMountRecord,
        requests: &[BatchCandidateRequest],
        keys: &[CandidateRequestKey],
        maximum_page_rows: usize,
        resolution_session: Option<&ResolutionSession>,
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
    ) -> StoreResult<CandidatePageVisit> {
        assert!(
            requests.len() <= MAX_SOURCE_ROWS_PER_BATCH,
            "candidate request page has {} entries; maximum is {MAX_SOURCE_ROWS_PER_BATCH}",
            requests.len()
        );
        let fragment = mount.fragment_id();
        let Some(()) = self.authority.ensure_authority(mount, cancellation)? else {
            return Ok(CandidatePageVisit::Cancelled);
        };
        // Three non-root bucket arrays and one structured root-prefix array.
        // Every reverse batch is still one statement for this blob. Each root
        // key is bound once with cell boundaries, not once per proper prefix.
        let mut keyed = Vec::new();
        let mut open = Vec::new();
        let mut whole_node = Vec::new();
        let mut root_prefix = Vec::new();
        for (ordinal, key) in keys.iter().enumerate() {
            let Some(node) = key.node.local_key(mount.ordinal()) else {
                continue;
            };
            if direction == CandidateDirection::Reverse && node == -1 {
                let Some(prefix) = root_candidate_request(
                    &self
                        .selection
                        .shared_name_table()
                        .interner(self.selection.connection()),
                    ordinal,
                    &requests[ordinal],
                    mount.ordinal(),
                    cancellation,
                ) else {
                    return Ok(CandidatePageVisit::Cancelled);
                };
                root_prefix.push(prefix);
                continue;
            }
            match key.lead {
                CandidateRequestLead::Unrepresentable => open.push(format!("[{ordinal},{node}]")),
                CandidateRequestLead::Open => whole_node.push(format!("[{ordinal},{node}]")),
                CandidateRequestLead::Shared { identity, scoped } => {
                    keyed.push(format!(
                        "[{ordinal},{node},{},null,{}]",
                        identity.get(),
                        i64::from(scoped)
                    ));
                    open.push(format!("[{ordinal},{node}]"));
                }
                CandidateRequestLead::Local {
                    mount: lead_mount,
                    semantic,
                    scoped,
                } => {
                    // A blob-local first symbol is a position in its own
                    // blob's catalog, so only that blob's lead bucket can hold
                    // it; every other blob answers this request from its open
                    // bucket alone.
                    if lead_mount == mount.ordinal()
                        && let Some(local) = semantic.local_key()
                    {
                        keyed.push(format!(
                            "[{ordinal},{node},null,{},{}]",
                            local,
                            i64::from(scoped)
                        ));
                    }
                    open.push(format!("[{ordinal},{node}]"));
                }
            }
        }
        let statement = match direction {
            CandidateDirection::Forward => RESOLUTION_FORWARD_CANDIDATE_MATCH_SQL,
            CandidateDirection::Reverse => RESOLUTION_REVERSE_CANDIDATE_MATCH_SQL,
        };
        let blob_id = mount.blob_id();
        // A mount whose rows can answer no request of this batch is still
        // walked below, because the in-heap reader charged one scope step per
        // request per opened mount and the budget a request spends is part of
        // what it answers. What is skipped is the statement.
        let arrays = [
            keyed.as_slice(),
            open.as_slice(),
            whole_node.as_slice(),
            root_prefix.as_slice(),
        ];
        let arrays = &arrays[..match direction {
            CandidateDirection::Forward => 3,
            CandidateDirection::Reverse => 4,
        }];
        let empty = arrays.iter().all(|array| array.is_empty());
        let Some(mut offered) = self.read_offered_candidates(
            empty,
            direction,
            statement,
            blob_id,
            fragment,
            requests.len(),
            arrays,
            cancellation,
        )?
        else {
            return Ok(CandidatePageVisit::Cancelled);
        };
        let context = PathBodyContext { fragment };
        let mut page = Vec::with_capacity(maximum_page_rows);
        let mut work = 0_usize;
        let mut visit = CandidatePageVisit::Exhausted;
        'requests: for ((ordinal, request), rows) in
            requests.iter().enumerate().zip(offered.iter_mut())
        {
            assert_eq!(
                request.request_ordinal(),
                ordinal,
                "candidate requests use canonical local ordinals"
            );
            if resolution_session.is_some_and(|session| !session.scope_step()) {
                break;
            }
            work += 1;
            if work.is_multiple_of(CANDIDATE_ROW_CANCELLATION_QUANTUM)
                && cancellation.is_cancelled()
            {
                break;
            }
            // Candidate-identity order inside a request is what the interior's
            // merge of its sorted buckets produced, and it is what keeps a
            // page-limited read's answer identical.
            rows.sort_unstable_by_key(|row| row.identity);
            for row in rows.iter() {
                if resolution_session.is_some_and(|session| !session.scope_step()) {
                    break 'requests;
                }
                work += 1;
                if work.is_multiple_of(CANDIDATE_ROW_CANCELLATION_QUANTUM)
                    && cancellation.is_cancelled()
                {
                    break 'requests;
                }
                let offered_endpoint = decode_selected_endpoint(&context, row.node, &row.endpoint);
                if !request.admits_candidate(&offered_endpoint) {
                    continue;
                }
                page.push(BatchCandidateMatch::new(
                    row.identity,
                    request.request_ordinal(),
                ));
                if page.len() == maximum_page_rows {
                    if !visitor(&page)? {
                        return Ok(CandidatePageVisit::Stopped);
                    }
                    page.clear();
                }
            }
        }
        if !page.is_empty() && !cancellation.is_cancelled() && !visitor(&page)? {
            visit = CandidatePageVisit::Stopped;
        }
        if cancellation.is_cancelled() {
            return Ok(CandidatePageVisit::Cancelled);
        }
        Ok(visit)
    }

    /// The candidate rows one mount offers a whole batch, grouped by the
    /// request that asked for them.
    ///
    /// `empty` says the batch names nothing this mount can hold, which happens
    /// when the mount was opened for another request of the same batch. The
    /// statement is then not issued and every request gets an empty group.
    #[allow(clippy::too_many_arguments)]
    fn read_offered_candidates(
        &self,
        empty: bool,
        direction: CandidateDirection,
        statement: &str,
        blob_id: i64,
        fragment: BindingFragmentId,
        requests: usize,
        arrays: &[&[String]],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<Vec<OfferedCandidateRow>>>> {
        if empty {
            return Ok(Some((0..requests).map(|_| Vec::new()).collect::<Vec<_>>()));
        }
        self.read_statement(cancellation, |conn| {
            let mut prepared = conn.prepare_cached(statement)?;
            let parameters = std::iter::once(rusqlite::types::Value::Integer(blob_id)).chain(
                arrays
                    .iter()
                    .map(|array| rusqlite::types::Value::Text(json_array_of_arrays(array))),
            );
            let mut rows = prepared.query(rusqlite::params_from_iter(parameters))?;
            let mut offered: Vec<Vec<OfferedCandidateRow>> =
                (0..requests).map(|_| Vec::new()).collect();
            while let Some(row) = rows.next()? {
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                let ordinal = usize_from_nonnegative(row, 0, "candidate request ordinal")?;
                offered[ordinal].push(OfferedCandidateRow {
                    identity: CandidatePathIdentity::new(
                        fragment,
                        PartialPathId::local(fragment.ordinal(), row.get(1)?),
                    ),
                    node: match direction {
                        CandidateDirection::Forward => row.get(2)?,
                        CandidateDirection::Reverse => row.get(3)?,
                    },
                    endpoint: parse_endpoint_cells(&row.get::<_, String>(4)?),
                });
            }
            Ok(Some(offered))
        })
    }

    fn reference_gap_completions(
        &self,
        mount: &SelectedResolutionMountRecord,
        keys: &[i64],
        cancellation: &CancellationToken,
    ) -> StoreResult<(
        ResolutionCompletion,
        HashMap<i64, ResolutionCompletion>,
        bool,
    )> {
        let keys = json_integer_array(keys.iter().copied());
        let mut fragment = ResolutionCompletion::Complete;
        let mut local = HashMap::<i64, ResolutionCompletion>::default();
        let read = self.read_statement(cancellation, |conn| {
            let sql = reference_gap_completions_sql();
            let mut statement = conn.prepare_cached(&sql)?;
            let mut rows = statement.query(rusqlite::named_params! {
                ":blob":mount.blob_id(), ":host":mount.ordinal().get(), ":keys":keys,
                ":mount_base":super::resolution_stage::codec::encode_semantic(SemanticId::local(mount.ordinal().get(),0)),
                ":qualified_origin":super::resolution_prepare::resolution_rows::gap_origin_code(crate::analyzer::resolution::LoweringGapOrigin::QualifiedReference),
                ":local_base":super::resolution_stage::codec::encode_semantic(SemanticId::local(0,0)),
            })?;
            while let Some(row) = rows.next()? {
                let completion = ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::UnsupportedSemantic(super::resolution_stage::codec::decode_semantic(row.get(2)?)),
                ]);
                if row.get::<_, i64>(0)? == 0 {
                    fragment = fragment.combine(&completion);
                } else {
                    let previous = local
                        .entry(row.get(1)?)
                        .or_insert(ResolutionCompletion::Complete);
                    *previous = previous.combine(&completion);
                }
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
            }
            Ok(Some(()))
        })?;
        Ok((fragment, local, read.is_none()))
    }

    /// Every reference-seed read of this source passes through here: both seam
    /// methods, the reverse issue and the inventory walk call it. That is why
    /// the seed-key profile counts here and not at the seam: the selection's
    /// request identity, its committed stage epoch and its scope are the other
    /// half of a seed read's identity, and only this side holds them.
    fn persisted_reference_seeds(
        &self,
        queries: &[ResolutionQuery],
        cancellation: &CancellationToken,
    ) -> StoreResult<ReferenceSeedReadOutcome> {
        let outcome = self.read_persisted_reference_seeds(queries, cancellation)?;
        crate::analyzer::resolution::seed_key_profile::record_seed_reads(
            self.selection.seed_read_authority(),
            queries,
            outcome.rows(),
        );
        Ok(outcome)
    }

    fn read_persisted_reference_seeds(
        &self,
        queries: &[ResolutionQuery],
        cancellation: &CancellationToken,
    ) -> StoreResult<ReferenceSeedReadOutcome> {
        let Some(staged) = stage::reference_seed_rows(self.selection, queries, cancellation)?
        else {
            return Ok(ReferenceSeedReadOutcome::cancelled(
                ResolutionCompletion::Complete,
            ));
        };
        let (stage_completions, mut evidence, stage_cancelled) =
            stage::reference_completions(self.selection, queries, &staged, cancellation)?;
        if stage_cancelled {
            return Ok(ReferenceSeedReadOutcome::cancelled(evidence));
        }
        let mut result = staged
            .into_iter()
            .zip(stage_completions)
            .enumerate()
            .map(|(position, (seed, completion))| {
                seed.map(|seed| {
                    ReferenceSeed::new_with_site_metadata(
                        seed.host,
                        queries[position],
                        seed.node,
                        seed.metadata,
                        completion,
                    )
                })
            })
            .collect::<Vec<_>>();
        let mut groups = BTreeMap::<SelectedResolutionMountOrdinal, Vec<(usize, i64)>>::new();
        for (position, query) in queries.iter().enumerate() {
            if cancellation.is_cancelled() {
                return Ok(ReferenceSeedReadOutcome::cancelled(evidence));
            }
            let reference = query.reference();
            let (Some(ordinal), Some(key)) = (reference.ordinal(), reference.local_key()) else {
                continue;
            };
            if (ordinal as usize) < self.selection.persisted_mount_count() {
                groups
                    .entry(SelectedResolutionMountOrdinal::new(ordinal))
                    .or_default()
                    .push((position, i64::from(key)));
            }
        }
        for (ordinal, members) in groups {
            let Some(mount) = self.selection.persisted_mount_record(ordinal)? else {
                continue;
            };
            let mount = &*mount;
            if self
                .authority
                .ensure_authority(mount, cancellation)?
                .is_none()
            {
                return Ok(ReferenceSeedReadOutcome::cancelled(evidence));
            }
            let keys = members.iter().map(|(_, key)| *key).collect::<Vec<_>>();
            let Some(sites) =
                self.read_reference_site_rows(mount.blob_id(), &keys, cancellation)?
            else {
                return Ok(ReferenceSeedReadOutcome::cancelled(evidence));
            };
            let reference_keys = keys
                .iter()
                .copied()
                .filter(|key| sites.get(key).is_some_and(|site| site.role == 0))
                .collect::<Vec<_>>();
            if reference_keys.is_empty() {
                continue;
            }
            let (fragment, local, cancelled) =
                self.reference_gap_completions(mount, &reference_keys, cancellation)?;
            evidence = local
                .values()
                .fold(evidence.combine(&fragment), |evidence, completion| {
                    evidence.combine(completion)
                });
            if cancelled {
                return Ok(ReferenceSeedReadOutcome::cancelled(evidence));
            }
            for (position, key) in members {
                let Some(site) = sites.get(&key).filter(|site| site.role == 0) else {
                    continue;
                };
                let completion = local
                    .get(&key)
                    .map_or_else(|| fragment.clone(), |local| fragment.combine(local));
                let node = BindingNodeId::local(
                    ordinal.get(),
                    u32::try_from(key).expect("local reference key"),
                );
                let mut metadata = site.metadata(ordinal);
                let mut completion = completion;
                if let Some(staged) = &result[position] {
                    if staged.node() != node || staged.fragment() != mount.fragment_id() {
                        return Err(invalid_fact(format!(
                            "ordinary and stage reference seed coordinates disagree: {:?}, {staged:?}, {:?}, {node:?}",
                            queries[position],
                            mount.fragment_id()
                        )));
                    }
                    if let (Some(ordinary), Some(stage)) = (metadata, staged.site_metadata())
                        && ordinary != stage
                    {
                        return Err(invalid_fact(format!(
                            "ordinary and stage reference seed metadata disagree: {:?}, {ordinary:?}, {stage:?}",
                            queries[position]
                        )));
                    }
                    metadata = metadata.or(staged.site_metadata());
                    completion = completion.combine(staged.completion());
                }
                result[position] = Some(ReferenceSeed::new_with_site_metadata(
                    mount.fragment_id(),
                    queries[position],
                    node,
                    metadata,
                    completion,
                ));
            }
        }
        if cancellation.is_cancelled() {
            return Ok(ReferenceSeedReadOutcome::cancelled(evidence));
        }
        let completions = result
            .iter()
            .filter_map(|seed| seed.as_ref().map(|seed| seed.completion().clone()))
            .collect::<Vec<_>>();
        let Some(closed) = stage::close_completions(self.selection, &completions, cancellation)?
        else {
            return Ok(ReferenceSeedReadOutcome::cancelled(evidence));
        };
        for (seed, completion) in result.iter_mut().filter_map(Option::as_mut).zip(closed) {
            *seed = ReferenceSeed::new_with_site_metadata(
                seed.fragment(),
                seed.query(),
                seed.node(),
                seed.site_metadata(),
                completion,
            );
        }
        Ok(ReferenceSeedReadOutcome::exhausted(
            queries
                .iter()
                .copied()
                .zip(result)
                .enumerate()
                .map(|(ordinal, (query, seed))| BatchReferenceSeed::new(ordinal, query, seed))
                .collect::<Vec<_>>(),
        ))
    }

    fn visit_reference_inventory(
        &self,
        fragments: Option<&crate::hash::HashSet<BindingFragmentId>>,
        maximum_batch_size: usize,
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&ReferenceSeedBatch) -> StoreResult<bool>,
    ) -> StoreResult<ResolutionCompletion> {
        assert!(
            (1..=crate::analyzer::resolution::MAX_REFERENCE_SEEDS_PER_BATCH)
                .contains(&maximum_batch_size)
        );
        let (queries, completion, cancelled) =
            stage::reference_inventory(self.selection, fragments, cancellation)?;
        if cancelled {
            return Ok(with_cancelled(completion));
        }
        for chunk in queries.chunks(maximum_batch_size) {
            let seeds = self.persisted_reference_seeds(chunk, cancellation)?;
            if seeds.is_cancelled() {
                return Ok(with_cancelled(completion.combine(seeds.evidence())));
            }
            let seeds = seeds
                .rows()
                .iter()
                .map(|row| {
                    row.seed()
                        .expect("enumerated actual reference has a seed")
                        .clone()
                })
                .collect::<Vec<_>>();
            for host_seeds in seeds.chunk_by(|left, right| left.fragment() == right.fragment()) {
                let batch = ReferenceSeedBatch::new(host_seeds.iter().cloned());
                let keep_going = visitor(&batch)?;
                if cancellation.is_cancelled() {
                    return Ok(with_cancelled(completion));
                }
                if !keep_going {
                    return Ok(completion);
                }
            }
        }
        Ok(if cancellation.is_cancelled() {
            with_cancelled(completion)
        } else {
            completion
        })
    }

    fn read_reference_site_rows(
        &self,
        blob_id: i64,
        keys: &[i64],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<HashMap<i64, RawSiteRow>>> {
        let key_array = json_integer_array(keys.iter().copied());
        self.read_statement(cancellation, |conn| {
            let mut statement = conn.prepare_cached(REFERENCE_SITES_BY_KEY_SQL)?;
            let mut rows = statement.query(params![blob_id, &key_array])?;
            let mut sites = HashMap::default();
            while let Some(row) = rows.next()? {
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                let site = RawSiteRow::from_row(row)?;
                sites.insert(site.site, site);
            }
            Ok(Some(sites))
        })
    }

    /// One blob's site rows, by key, in one statement for the whole call.
    ///
    /// Site, semantic and node are one number (lane NB), so the caller passes
    /// whichever of the three it holds and the primary key answers.
    fn read_site_rows(
        &self,
        blob_id: i64,
        keys: impl Iterator<Item = i64>,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<HashMap<i64, RawSiteRow>>> {
        let key_array = json_integer_array(keys);
        self.read_statement(cancellation, |conn| {
            let mut statement = conn.prepare_cached(RESOLUTION_SITES_BY_KEY_SQL)?;
            let mut rows = statement.query(params![blob_id, &key_array])?;
            let mut sites: HashMap<i64, RawSiteRow> = HashMap::default();
            while let Some(row) = rows.next()? {
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                let site = RawSiteRow::from_row(row)?;
                sites.insert(site.site, site);
            }
            Ok(Some(sites))
        })
    }

    /// One blob's member-scope owners, by scope head node key, in one
    /// statement.
    ///
    /// `resolution_member_scope_properties` already carries
    /// `UNIQUE(blob_id, scope_head_node_key)`, which is the key this seeks by,
    /// so this read needs no new index.
    fn read_member_scope_owners(
        &self,
        blob_id: i64,
        keys: impl Iterator<Item = i64>,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<HashMap<i64, i64>>> {
        let key_array = json_integer_array(keys);
        self.read_statement(cancellation, |conn| {
            let mut statement = conn.prepare_cached(MEMBER_SCOPE_OWNERS_BY_NODE_SQL)?;
            let mut rows = statement.query(params![blob_id, &key_array])?;
            let mut owners: HashMap<i64, i64> = HashMap::default();
            while let Some(row) = rows.next()? {
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                owners.insert(row.get(0)?, row.get(1)?);
            }
            Ok(Some(owners))
        })
    }

    /// The fragment-local key one runtime semantic occupies in its own blob's
    /// catalog, and the mount that owns it.
    ///
    /// The catalog page is what turns a 32-byte digest into the integer a row
    /// is keyed by; milestone 4's stage 1b-ii makes the identity that integer
    /// and this whole step disappears.
    fn local_semantic_key(
        &self,
        semantic: SemanticId,
        description: &str,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Option<(SelectedResolutionMount, i64)>>> {
        match self
            .authority
            .semantic_catalog_provenance(semantic, cancellation)?
        {
            None => Ok(None),
            Some(Some(SelectedSemanticProvenance::FragmentLocal(local))) => {
                Ok(Some(Some((local.mount(), local.local_key().get()))))
            }
            Some(None) => Ok(Some(None)),
            Some(Some(other)) => Err(invalid_fact(format!(
                "{description} ordinary catalog returned nonordinary provenance: {semantic:?}, {other:?}"
            ))),
        }
    }

    /// Group a batch of fragment-local semantics by the mount that owns them,
    /// each with its blob-local key, so that a batch costs one statement per
    /// blob.
    #[allow(clippy::type_complexity)]
    fn group_semantics_by_mount(
        &self,
        semantics: &[SemanticId],
        description: &str,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<(SelectedResolutionMount, Vec<(SemanticId, i64)>)>>> {
        let mut groups: Vec<(SelectedResolutionMount, Vec<(SemanticId, i64)>)> = Vec::new();
        for &semantic in semantics {
            let Some(coordinate) = self.local_semantic_key(semantic, description, cancellation)?
            else {
                return Ok(None);
            };
            let Some((mount, key)) = coordinate else {
                continue;
            };
            match groups.iter_mut().find(|(known, _)| *known == mount) {
                Some((_, members)) => members.push((semantic, key)),
                None => groups.push((mount, vec![(semantic, key)])),
            }
        }
        Ok(Some(groups))
    }

    /// The selected mounts whose tier-1 headers admit one of these requests.
    ///
    /// A request rooted at a fragment-local node names exactly one mount. A
    /// boundary-rooted request is answered from `resolution_path_endpoint_headers`,
    /// the tier-1 relation that says which blobs carry a boundary-rooted partial
    /// path of the requested shape, so a demand opens only the authority that can
    /// contribute a match. Coverage reasons are not read here: the unconditional
    /// box is tier-1 rows and the branch boxes name their own mounts.
    fn candidate_mount_positions(
        &self,
        direction: CandidateDirection,
        requests: &[BatchCandidateRequest],
        scope: Option<&[SelectedResolutionMountOrdinal]>,
        cancellation: &CancellationToken,
    ) -> StoreResult<Vec<usize>> {
        let admitted = |mount: SelectedResolutionMountOrdinal| {
            scope.is_none_or(|scope| scope_admits(scope, mount))
        };
        let mut positions = BTreeSet::new();
        let mut boundary_probes = Vec::new();
        for request in requests {
            if cancellation.is_cancelled() {
                return Ok(Vec::new());
            }
            let endpoint = request.endpoint();
            if endpoint.node() != BindingNodeId::universal_root() {
                if let Some(ordinal) = endpoint.node().ordinal() {
                    let ordinal = SelectedResolutionMountOrdinal::new(ordinal);
                    if admitted(ordinal)
                        && let Some(position) = self.selected_position(ordinal)
                    {
                        positions.insert(position);
                    }
                }
                continue;
            }
            let symbol_fixed_count = endpoint.symbols().fixed().len();
            let symbol_has_tail = endpoint.symbols().tail().is_some();
            let first_symbol = if let Some(symbol) = endpoint.symbols().fixed().first() {
                if let Some(shared) = symbol.symbol().shared_name_id() {
                    self.selection
                        .shared_name_table()
                        .interner(self.selection.connection())
                        .to_persisted(shared)
                } else {
                    if let Some(ordinal) = symbol.symbol().ordinal() {
                        let ordinal = SelectedResolutionMountOrdinal::new(ordinal);
                        if admitted(ordinal)
                            && let Some(position) = self.selected_position(ordinal)
                        {
                            positions.insert(position);
                        }
                    }
                    None
                }
            } else {
                None
            };
            boundary_probes.push(BoundaryHeaderProbe {
                first_symbol,
                symbol_fixed_count,
                symbol_has_tail,
            });
        }
        // One array for the whole batch: the scope does not change between
        // probes, and a batch can carry up to `MAX_SOURCE_ROWS_PER_BATCH` of
        // them.
        let scope_array = scope.map(scope_ordinal_array);
        for probe in boundary_probes {
            if cancellation.is_cancelled() {
                return Ok(Vec::new());
            }
            self.extend_boundary_header_mounts(
                direction,
                probe,
                scope_array.as_deref(),
                &mut positions,
                cancellation,
            )?;
        }
        let mut positions = positions.into_iter().collect::<Vec<_>>();
        self.sort_mount_positions(&mut positions)?;
        Ok(positions)
    }

    /// Add the mounts whose tier-1 endpoint headers admit one probe.
    ///
    /// A scoped read binds its scope into the statement, so the rows it
    /// decodes are bounded by the scope; an unscoped read asks the same
    /// question of the whole selection, which is what a whole-selection
    /// candidate read means.
    fn extend_boundary_header_mounts(
        &self,
        direction: CandidateDirection,
        probe: BoundaryHeaderProbe,
        scope_array: Option<&str>,
        positions: &mut BTreeSet<usize>,
        cancellation: &CancellationToken,
    ) -> StoreResult<()> {
        let mut parameters = vec![
            rusqlite::types::Value::Text(direction.label().to_owned()),
            probe
                .first_symbol
                .map_or(rusqlite::types::Value::Null, |name| {
                    rusqlite::types::Value::Integer(i64::from(name.get()))
                }),
            rusqlite::types::Value::Integer(super::usize_to_i64(probe.symbol_fixed_count)?),
            rusqlite::types::Value::Integer(i64::from(probe.symbol_has_tail)),
        ];
        let sql = match scope_array {
            None => PATH_ENDPOINT_HEADER_MOUNTS_SQL,
            Some(scope_array) => {
                parameters.push(rusqlite::types::Value::Text(scope_array.to_owned()));
                SCOPED_PATH_ENDPOINT_HEADER_MOUNTS_SQL
            }
        };
        let mut ordinals = Vec::new();
        let live = self.read_statement(cancellation, |conn| {
            let mut statement = conn.prepare_cached(sql)?;
            let mut rows = statement.query(rusqlite::params_from_iter(parameters.iter()))?;
            while let Some(row) = rows.next()? {
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                ordinals.push(mount_ordinal(row, 0, "candidate header mount")?);
            }
            Ok(Some(()))
        })?;
        if live.is_none() {
            return Ok(());
        }
        for ordinal in ordinals {
            if let Some(position) = self.selected_position(ordinal) {
                positions.insert(position);
            }
        }
        Ok(())
    }

    fn reverse_candidate_completion(
        &self,
        requests: &[BatchCandidateRequest],
        exclusions: Option<&mut ReverseCandidateGapExclusionPlan>,
        cancellation: &CancellationToken,
    ) -> StoreResult<(BatchCandidateCompletionOutcome, bool)> {
        self.lazy_candidate_completion(
            CandidateDirection::Reverse,
            requests,
            None,
            exclusions,
            cancellation,
        )
    }

    fn is_open_universal_root_request(request: &BatchCandidateRequest) -> bool {
        let endpoint = request.endpoint();
        endpoint.node() == BindingNodeId::universal_root()
            && endpoint.scopes().fixed().is_empty()
            && endpoint.scopes().tail().is_none()
            && endpoint.symbols().fixed().is_empty()
            && endpoint.symbols().tail().is_some()
    }

    fn requests_are_open_universal_root(requests: &[BatchCandidateRequest]) -> bool {
        !requests.is_empty()
            && requests.iter().enumerate().all(|(ordinal, request)| {
                request.request_ordinal() == ordinal
                    && Self::is_open_universal_root_request(request)
            })
    }

    fn root_candidate_completion(
        &self,
        direction: CandidateDirection,
        requests: &[BatchCandidateRequest],
        cancellation: &CancellationToken,
    ) -> StoreResult<(BatchCandidateCompletionOutcome, bool)> {
        self.lazy_candidate_completion(direction, requests, None, None, cancellation)
    }

    fn materialize_candidate_matches(
        &self,
        direction: CandidateDirection,
        requests: &[BatchCandidateRequest],
        cancellation: &CancellationToken,
    ) -> StoreResult<BatchCandidateOutcome> {
        let (mut completion, initially_cancelled) =
            self.lazy_candidate_completion(direction, requests, None, None, cancellation)?;
        let mut matches = Vec::new();
        let visit = if initially_cancelled {
            CandidatePageVisit::Cancelled
        } else {
            self.lazy_candidate_matches(
                direction,
                requests,
                None,
                MAX_SOURCE_ROWS_PER_BATCH,
                None,
                None,
                cancellation,
                &mut |page| {
                    matches.extend_from_slice(page);
                    Ok(true)
                },
            )?
        };
        if matches!(visit, CandidatePageVisit::Cancelled) || cancellation.is_cancelled() {
            matches.clear();
            if !completion
                .unconditional_completion()
                .contains_reason(ResolutionIncompleteReason::Cancelled)
            {
                completion = BatchCandidateCompletionOutcome::new(
                    requests.len(),
                    with_cancelled(completion.unconditional_completion().clone()),
                    completion.branch_completions().iter().cloned(),
                );
            }
        }
        Ok(BatchCandidateOutcome::new(
            requests.len(),
            matches,
            completion.unconditional_completion().clone(),
            completion.branch_completions().iter().cloned(),
        ))
    }
}

impl SelectedResolutionLexicalSource<'_, '_> {
    /// Demand-local root-half discovery. Inputs retain shared
    /// lookup identity; source routes still come only from sealed path bodies.
    /// Duplicate demands are canonicalized before SQL. Rows retain the full
    /// reverse-root inventory evidence and each selected content mount.
    pub(crate) fn visit_root_import_half_pages_for_demands(
        &self,
        demands: &[SemanticId],
        cancellation: &CancellationToken,
        visitor: &mut crate::analyzer::resolution::FactPageVisitor<
            '_,
            crate::analyzer::resolution::SelectedRootPathHalf,
        >,
    ) -> StoreResult<crate::analyzer::resolution::FactReadOutcome> {
        use crate::analyzer::resolution::{
            FactReadOutcome, SelectedRootPathHalf, classify_selected_root_path_half,
        };

        assert!(demands.len() <= MAX_SOURCE_ROWS_PER_BATCH);
        if cancellation.is_cancelled() {
            return Ok(FactReadOutcome::cancelled(ResolutionCompletion::Complete));
        }
        let mut names = BTreeSet::new();
        {
            let rebaser = self.selection.mount_rebaser().borrow();
            for &demand in demands {
                match rebaser.semantic_mount(demand) {
                    SelectedSemanticMount::Shared(identity) => {
                        names.insert(
                            identity
                                .shared_name()
                                .expect("a shared semantic mount names a shared name"),
                        );
                    }
                    SelectedSemanticMount::FragmentLocal(mount) => {
                        return Err(invalid_fact(format!(
                            "root terminal demand {demand} requires selected shared provenance, but its ID names mount {} at fragment {}",
                            mount.ordinal().get(),
                            mount.fragment()
                        )));
                    }
                }
            }
        }
        // The reverse root inventory is the same evidence an open universal-root
        // reverse candidate request carries, so it is read through the one
        // candidate-completion path instead of a second completion reader.
        let root_request = [BatchCandidateRequest::new(
            0,
            EndpointSignature::new(
                BindingNodeId::universal_root(),
                StackPattern::new(Vec::new(), None),
                StackPattern::new(Vec::new(), None),
            ),
        )];
        let (root_completion, root_cancelled) = self.lazy_candidate_completion(
            CandidateDirection::Reverse,
            &root_request,
            None,
            None,
            cancellation,
        )?;
        let evidence = root_completion
            .unconditional_completion()
            .combine(&root_completion.branch_completions()[0]);
        if root_cancelled {
            return Ok(FactReadOutcome::cancelled(evidence));
        }

        let mut candidates = Vec::new();
        for name in names {
            for &position in &self.terminal_header_mount_positions(name, cancellation)? {
                let mount = &*self.mount_record(SelectedResolutionMountOrdinal::new(
                    u32::try_from(position).expect("mount position fits u32"),
                ))?;
                let Some(ordinary) = self.root_terminal_candidates(mount, name, cancellation)?
                else {
                    return Ok(FactReadOutcome::cancelled(evidence));
                };
                candidates.extend(ordinary);
            }
        }
        let Some(staged) = stage::root_terminal_candidates(self.selection, demands, cancellation)?
        else {
            return Ok(FactReadOutcome::cancelled(evidence));
        };
        candidates.extend(staged);
        let mut seen = HashSet::new();
        let mut halves = Vec::new();
        for page in candidates.chunks(MAX_SOURCE_ROWS_PER_BATCH) {
            for candidate in page {
                if !seen.insert(*candidate) {
                    return Err(invalid_fact(format!(
                        "selected root terminal source repeated candidate {candidate:?}"
                    )));
                }
            }
            for (identity, path) in self.hydrate_candidate_paths(page, cancellation)? {
                match classify_selected_root_path_half(self, identity, &path, cancellation)? {
                    Some(
                        half @ (SelectedRootPathHalf::Import { demand, .. }
                        | SelectedRootPathHalf::Reference { demand, .. }),
                    ) => {
                        if demands.contains(&demand) {
                            halves.push(half);
                        }
                    }
                    Some(SelectedRootPathHalf::Export { .. }) | None => {}
                }
            }
            if cancellation.is_cancelled() {
                return Ok(FactReadOutcome::cancelled(evidence));
            }
        }
        let mut start = 0_usize;
        while start < halves.len() {
            let end = (start + visitor.maximum_rows()).min(halves.len());
            if !visitor.visit_page(&halves[start..end])? {
                return Ok(FactReadOutcome::stopped(evidence));
            }
            if cancellation.is_cancelled() {
                return Ok(FactReadOutcome::cancelled(evidence));
            }
            start = end;
        }
        Ok(FactReadOutcome::exhausted(evidence))
    }

    /// The blob's universal-root-terminated paths that end in one shared name,
    /// in path-key order, which is the order the interior's own index holds.
    fn root_terminal_candidates(
        &self,
        mount: &SelectedResolutionMountRecord,
        name: SharedNameId,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<CandidatePathIdentity>>> {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let Some(name) = self
            .selection
            .shared_name_table()
            .interner(self.selection.connection())
            .to_persisted(name)
        else {
            return Ok(Some(Vec::new()));
        };
        let fragment = mount.fragment_id();
        let blob_id = mount.blob_id();
        self.read_statement(cancellation, |conn| {
            let mut statement = conn.prepare_cached(RESOLUTION_ROOT_TERMINAL_PATHS_SQL)?;
            let mut rows = statement.query(params![blob_id, i64::from(name.get())])?;
            let mut candidates = Vec::new();
            while let Some(row) = rows.next()? {
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                candidates.push(CandidatePathIdentity::new(
                    fragment,
                    PartialPathId::local(fragment.ordinal(), row.get(0)?),
                ));
            }
            Ok(Some(candidates))
        })
    }

    /// Blobs whose tier-1 terminal header names this shared identity as the
    /// last fixed symbol of a universal-root-terminated path.
    fn terminal_header_mount_positions(
        &self,
        name: SharedNameId,
        cancellation: &CancellationToken,
    ) -> StoreResult<Vec<usize>> {
        let Some(name) = self
            .selection
            .shared_name_table()
            .interner(self.selection.connection())
            .to_persisted(name)
        else {
            return Ok(Vec::new());
        };
        let mut ordinals = Vec::new();
        let live = self.read_statement(cancellation, |conn| {
            let mut statement = conn.prepare_cached(PATH_TERMINAL_HEADER_MOUNTS_SQL)?;
            let mut rows = statement.query(params![i64::from(name.get())])?;
            while let Some(row) = rows.next()? {
                if cancellation.is_cancelled() {
                    return Ok(None);
                }
                ordinals.push(mount_ordinal(row, 0, "root terminal header mount")?);
            }
            Ok(Some(()))
        })?;
        if live.is_none() {
            return Ok(Vec::new());
        }
        let mut positions = ordinals
            .into_iter()
            .filter_map(|ordinal| self.selected_position(ordinal))
            .collect::<Vec<_>>();
        self.sort_mount_positions(&mut positions)?;
        positions.dedup();
        Ok(positions)
    }
}

/// The blob that owns a root route's first symbol is what says which anchor
/// it is, and this source is what can ask it.
impl crate::analyzer::resolution::SelectedRootImportAnchors
    for SelectedResolutionLexicalSource<'_, '_>
{
    fn anchor_of(
        &self,
        semantic: SemanticId,
        cancellation: &CancellationToken,
    ) -> StoreResult<
        Option<brokk_bifrost_core::analyzer::resolution_facts::ResolutionRootImportAnchor>,
    > {
        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionRootImportAnchor;
        let Some(provenance) = self.semantic_provenance(semantic, cancellation)? else {
            return Ok(None);
        };
        let identity = match provenance {
            SelectedSemanticProvenance::FragmentLocal(provenance) => provenance.identity(),
            SelectedSemanticProvenance::Stage(provenance) => provenance.identity(),
            SelectedSemanticProvenance::Shared(_) => return Ok(None),
        };
        Ok([
            ResolutionRootImportAnchor::Lexical,
            ResolutionRootImportAnchor::Absolute,
        ]
        .into_iter()
        .find(|anchor| {
            crate::analyzer::resolution::root_import_anchor_semantic_identity(*anchor) == identity
        }))
    }
}

impl BatchResolutionFragmentSource for SelectedResolutionLexicalSource<'_, '_> {
    /// This source answers under its selection, and the selection already
    /// carries the three values that name it for the seed-key profile.
    fn selection_authority(&self) -> Option<crate::analyzer::resolution::SeedReadAuthority> {
        Some(self.selection.seed_read_authority())
    }

    fn reference_seed(
        &self,
        query: ResolutionQuery,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<ReferenceSeed>> {
        let read = self.persisted_reference_seeds(&[query], cancellation)?;
        Ok(read.rows().first().and_then(|row| row.seed().cloned()))
    }

    fn go_lookup_spelling(
        &self,
        reference: SemanticId,
        namespace: ResolutionNamespace,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<String>> {
        let mut spellings =
            self.reference_lookup_spellings(&[reference], namespace, cancellation)?;
        Ok(spellings.remove(&reference))
    }

    fn intern_shared_name_digest(
        &self,
        digest: [u8; 32],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<SemanticId>> {
        self.authority
            .intern_shared_name_digest(digest, cancellation)
    }

    fn supports_go_universe(&self) -> bool {
        true
    }

    fn lookup_reference_seeds(
        &self,
        queries: &[ResolutionQuery],
        cancellation: &CancellationToken,
    ) -> StoreResult<ReferenceSeedReadOutcome> {
        self.persisted_reference_seeds(queries, cancellation)
    }

    /// Question #5, from `resolution_sites` by primary key.
    ///
    /// Site, semantic and node are one number, so "which node does this
    /// definition declare" is one seek on `(blob_id, site)` plus the row's
    /// role. The catalog page still turns the digest into that number and the
    /// number back into the node; milestone 4's stage 1b-ii removes both.
    fn lookup_definition_node(
        &self,
        definition: SemanticId,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<BindingNodeId>> {
        let rows = self.lookup_definition_nodes(&[definition], cancellation)?;
        Ok(rows.first().and_then(|row| row.node()))
    }

    /// Question #6, the batched form of #5: one statement per blob for the
    /// whole batch.
    fn lookup_definition_nodes(
        &self,
        definitions: &[SemanticId],
        cancellation: &CancellationToken,
    ) -> StoreResult<Vec<BatchDefinitionNode>> {
        let Some(staged) = stage::definition_nodes(self.selection, definitions, cancellation)?
        else {
            return Ok(Vec::new());
        };
        let mut rows = Vec::with_capacity(definitions.len());
        let Some(groups) =
            self.group_semantics_by_mount(definitions, "definition node", cancellation)?
        else {
            return Ok(Vec::new());
        };
        let mut nodes: HashMap<SemanticId, BindingNodeId> = HashMap::default();
        for (mount, members) in &groups {
            let record = &*self.mount_record(mount.ordinal())?;
            let Some(sites) = self.read_site_rows(
                record.blob_id(),
                members.iter().map(|(_, key)| *key),
                cancellation,
            )?
            else {
                return Ok(Vec::new());
            };
            for (definition, key) in members {
                let Some(row) = sites.get(key) else {
                    continue;
                };
                if row.role != DEFINITION_SITE_ROLE {
                    continue;
                }
                nodes.insert(
                    *definition,
                    BindingNodeId::local(
                        record.ordinal().get(),
                        u32::try_from(*key).expect("stored node key"),
                    ),
                );
            }
        }
        for (definition, staged) in definitions.iter().zip(staged) {
            let ordinary = nodes.get(definition).copied();
            if let (Some(ordinary), Some(staged)) = (ordinary, staged)
                && ordinary != staged
            {
                return Err(invalid_fact(format!(
                    "ordinary and stage definition nodes disagree: {definition:?}, {ordinary:?}, {staged:?}"
                )));
            }
            rows.push(BatchDefinitionNode::new(*definition, ordinary.or(staged)));
        }
        Ok(rows)
    }

    fn issue_reverse_reference_seeds(
        &self,
        requests: &[ReverseReferenceSeedRequest],
        cancellation: &CancellationToken,
    ) -> StoreResult<Vec<ReferenceSeed>> {
        let queries = requests
            .iter()
            .map(|request| ResolutionQuery::new(request.reference()))
            .collect::<Vec<_>>();
        let seeds = self.persisted_reference_seeds(&queries, cancellation)?;
        Ok(requests
            .iter()
            .zip(seeds.rows())
            .filter_map(|(request, row)| {
                row.seed()
                    .filter(|seed| seed.node() == request.expected_node())
                    .cloned()
            })
            .collect())
    }

    fn visit_reference_seed_batches(
        &self,
        maximum_batch_size: usize,
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&ReferenceSeedBatch) -> StoreResult<bool>,
    ) -> StoreResult<ResolutionCompletion> {
        self.visit_reference_inventory(
            self.forward_reference_fragments,
            maximum_batch_size,
            cancellation,
            visitor,
        )
    }

    fn visit_reference_seed_batches_in_fragments(
        &self,
        fragments: &crate::hash::HashSet<BindingFragmentId>,
        maximum_batch_size: usize,
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&ReferenceSeedBatch) -> StoreResult<bool>,
    ) -> StoreResult<ResolutionCompletion> {
        self.visit_reference_inventory(Some(fragments), maximum_batch_size, cancellation, visitor)
    }

    /// Question #10, from `resolution_sites` by primary key.
    ///
    /// With site, semantic and node one number, "is this node a reference or a
    /// definition, and of what" is one seek on `(blob_id, node)`; the third
    /// field, the member-scope owner, is one seek on the unique index
    /// `resolution_member_scope_properties` already carries. This reader opens
    /// no blob's `Facts` page any more, which is what lets a request that
    /// matched candidates in a hundred blobs classify their endpoints without
    /// producing one of them.
    fn classify_endpoint_nodes(
        &self,
        nodes: &[BindingNodeId],
        cancellation: &CancellationToken,
    ) -> StoreResult<Vec<BatchEndpointClassification>> {
        let Some(mut payloads) = stage::node_payloads(self.selection, nodes, cancellation)? else {
            return Ok(Vec::new());
        };
        let Some(mut owners) = stage::member_scope_owners(self.selection, nodes, cancellation)?
        else {
            return Ok(Vec::new());
        };
        let Some(stage_catalog) = stage::scope_nodes(self.selection, nodes, cancellation)? else {
            return Ok(Vec::new());
        };
        let mut go_namespaces = if self.selection.has_go_semantics() {
            let Some(namespaces) =
                stage::go_definition_namespaces(self.selection, nodes, cancellation)?
            else {
                return Ok(Vec::new());
            };
            namespaces
        } else {
            HashMap::default()
        };
        // Generated include boundaries have catalog identity without a node
        // payload. Registration proves membership, not a synthetic node kind.
        let mut catalog_only = stage_catalog.into_keys().collect::<HashSet<_>>();
        let mut groups =
            BTreeMap::<SelectedResolutionMountOrdinal, Vec<(BindingNodeId, i64)>>::new();
        for &node in nodes {
            if cancellation.is_cancelled() {
                return Ok(Vec::new());
            }
            // A local tag supplies a seek coordinate, never catalog authority.
            if let Some(ordinal) = node.ordinal() {
                let ordinal = SelectedResolutionMountOrdinal::new(ordinal);
                if self.selected_position(ordinal).is_some() {
                    groups.entry(ordinal).or_default().push((
                        node,
                        i64::from(node.local_key().expect("local endpoint key")),
                    ));
                }
            }
        }
        let names = self
            .selection
            .shared_name_table()
            .interner(self.selection.connection());
        for (ordinal, members) in groups {
            let record = &*self.mount_record(ordinal)?;
            let keys = json_integer_array(members.iter().map(|(_, key)| *key));
            let Some(ordinary) = self.read_statement(cancellation, |connection| {
                let mut statement = connection.prepare_cached(
                    "SELECT node.local_key,node.kind,node.semantic_local_key,node.semantic_shared_identity,node.target_local_key,node.target_boundary_key FROM json_each(?2) input CROSS JOIN main.resolution_node_catalog node ON node.blob_id=?1 AND node.local_key=input.value"
                )?;
                let mut rows = statement.query(params![record.blob_id(),keys])?;
                let mut result = HashMap::default();
                while let Some(row) = rows.next()? {
                    if cancellation.is_cancelled() { return Ok(None); }
                    let payload = super::resolution_stage::lexical::decode_ordinary_node_kind(
                        ordinal.get(),row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,&names,
                    );
                    result.insert(row.get::<_,i64>(0)?,payload);
                }
                Ok(Some(result))
            })? else { return Ok(Vec::new()); };
            let Some(ordinary_owners) = self.read_member_scope_owners(
                record.blob_id(),
                members.iter().map(|(_, key)| *key),
                cancellation,
            )?
            else {
                return Ok(Vec::new());
            };
            let go_sites = if record.semantic_language() == crate::analyzer::Language::Go {
                let Some(sites) = self.read_site_rows(
                    record.blob_id(),
                    ordinary.values().filter_map(|payload| match payload {
                        Some(BindingNodeKind::Definition(semantic)) => {
                            semantic.local_key().map(i64::from)
                        }
                        _ => None,
                    }),
                    cancellation,
                )?
                else {
                    return Ok(Vec::new());
                };
                sites
            } else {
                HashMap::default()
            };
            for (node, key) in members {
                let Some(payload) = ordinary.get(&key) else {
                    continue;
                };
                if let Some(BindingNodeKind::Definition(semantic)) = payload
                    && let Some(bits) = semantic
                        .local_key()
                        .and_then(|key| go_sites.get(&i64::from(key)))
                        .and_then(|site| site.go_definition_namespaces)
                {
                    let namespaces =
                        crate::analyzer::resolution::GoDefinitionNamespaces::from_bits(bits);
                    if let Some(previous) = go_namespaces.insert(node, namespaces)
                        && previous != namespaces
                    {
                        return Err(invalid_fact(format!(
                            "ordinary and stage Go endpoint namespaces disagree: {node:?}, {previous:?}, {namespaces:?}"
                        )));
                    }
                }
                match payload {
                    Some(payload) => {
                        if let Some(staged) = payloads.get(&node) {
                            if staged != payload {
                                return Err(invalid_fact(format!(
                                    "ordinary and stage node payloads disagree: {node:?}, {payload:?}, {staged:?}"
                                )));
                            }
                        } else {
                            payloads.insert(node, *payload);
                        }
                    }
                    None => {
                        catalog_only.insert(node);
                    }
                }
                if let Some(owner) = ordinary_owners.get(&key) {
                    let owner = SemanticId::local(
                        ordinal.get(),
                        u32::try_from(*owner).expect("stored member scope owner key"),
                    );
                    if let Some(staged) = owners.insert(node, owner)
                        && staged != owner
                    {
                        return Err(invalid_fact(format!(
                            "ordinary and stage member scope owners disagree: {node:?}, {owner:?}, {staged:?}"
                        )));
                    }
                }
            }
        }
        let mut classified = Vec::with_capacity(nodes.len());
        for &node in nodes {
            if cancellation.is_cancelled() {
                break;
            }
            let (reference, definition) = match payloads.get(&node) {
                Some(BindingNodeKind::Reference(semantic)) => (Some(*semantic), None),
                Some(BindingNodeKind::Definition(semantic)) => (None, Some(*semantic)),
                Some(_) => (None, None),
                None if catalog_only.contains(&node) => (None, None),
                None => match self.selection.mount_rebaser().borrow().node_mount(node) {
                    Some(SelectedNodeMount::UniversalRoot | SelectedNodeMount::ContextBoundary) => {
                        (None, None)
                    }
                    _ => {
                        return Err(invalid_fact(format!(
                            "cannot classify unknown selected endpoint {node}"
                        )));
                    }
                },
            };
            classified.push(
                BatchEndpointClassification::new_with_member_scope_owner(
                    node,
                    reference,
                    definition,
                    owners.get(&node).copied(),
                )
                .with_go_definition_namespaces(go_namespaces.get(&node).copied()),
            );
        }
        Ok(classified)
    }

    fn match_forward_candidates(
        &self,
        requests: &[BatchCandidateRequest],
        cancellation: &CancellationToken,
    ) -> StoreResult<BatchCandidateOutcome> {
        self.materialize_candidate_matches(CandidateDirection::Forward, requests, cancellation)
    }

    fn visit_forward_candidate_match_pages(
        &self,
        requests: &[BatchCandidateRequest],
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
    ) -> StoreResult<BatchCandidateCompletionOutcome> {
        let (completion, cancelled) = self.lazy_candidate_completion(
            CandidateDirection::Forward,
            requests,
            None,
            None,
            cancellation,
        )?;
        if cancelled {
            return Ok(completion);
        }
        let visit = self.lazy_candidate_matches(
            CandidateDirection::Forward,
            requests,
            None,
            MAX_SOURCE_ROWS_PER_BATCH,
            None,
            None,
            cancellation,
            visitor,
        )?;
        candidate_completion_after_visit(requests.len(), completion, visit, cancellation)
    }

    fn visit_forward_root_candidate_match_pages(
        &self,
        requests: &[BatchCandidateRequest],
        mounts: Option<&[SelectedResolutionMountOrdinal]>,
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
    ) -> StoreResult<BatchCandidateCompletionOutcome> {
        if !Self::requests_are_open_universal_root(requests) {
            return self.visit_forward_candidate_match_pages(requests, cancellation, visitor);
        }
        let (completion, cancelled) = self.lazy_candidate_completion(
            CandidateDirection::Forward,
            requests,
            mounts,
            None,
            cancellation,
        )?;
        if cancelled {
            return Ok(completion);
        }
        let visit = self.lazy_candidate_matches(
            CandidateDirection::Forward,
            requests,
            mounts,
            MAX_SOURCE_ROWS_PER_BATCH,
            None,
            None,
            cancellation,
            visitor,
        )?;
        candidate_completion_after_visit(requests.len(), completion, visit, cancellation)
    }

    fn visit_forward_candidate_match_pages_limited(
        &self,
        requests: &[BatchCandidateRequest],
        maximum_page_rows: usize,
        resolution_session: Option<&ResolutionSession>,
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
    ) -> StoreResult<BatchCandidateCompletionOutcome> {
        let (completion, cancelled) = self.lazy_candidate_completion(
            CandidateDirection::Forward,
            requests,
            None,
            None,
            cancellation,
        )?;
        if cancelled {
            return Ok(completion);
        }
        let mut visit = self.lazy_candidate_matches(
            CandidateDirection::Forward,
            requests,
            None,
            maximum_page_rows,
            resolution_session,
            None,
            cancellation,
            visitor,
        )?;
        // The former aggregate stage source charged each completion branch
        // after the candidate walk, including when its visitor stopped early.
        // Preserve the already-read evidence when this budget is exhausted.
        for _ in requests {
            if resolution_session.is_some_and(|session| !session.scope_step()) {
                visit = CandidatePageVisit::Cancelled;
                break;
            }
        }
        candidate_completion_after_visit(requests.len(), completion, visit, cancellation)
    }

    fn match_reverse_candidates(
        &self,
        requests: &[BatchCandidateRequest],
        cancellation: &CancellationToken,
    ) -> StoreResult<BatchCandidateOutcome> {
        self.materialize_candidate_matches(CandidateDirection::Reverse, requests, cancellation)
    }

    fn visit_reverse_candidate_match_pages(
        &self,
        requests: &[BatchCandidateRequest],
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
    ) -> StoreResult<BatchCandidateCompletionOutcome> {
        let (completion, cancelled) = self.lazy_candidate_completion(
            CandidateDirection::Reverse,
            requests,
            None,
            None,
            cancellation,
        )?;
        if cancelled {
            return Ok(completion);
        }
        let visit = self.lazy_candidate_matches(
            CandidateDirection::Reverse,
            requests,
            None,
            MAX_SOURCE_ROWS_PER_BATCH,
            None,
            None,
            cancellation,
            visitor,
        )?;
        candidate_completion_after_visit(requests.len(), completion, visit, cancellation)
    }

    fn visit_reverse_root_candidate_match_pages(
        &self,
        requests: &[BatchCandidateRequest],
        mounts: Option<&[SelectedResolutionMountOrdinal]>,
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
    ) -> StoreResult<BatchCandidateCompletionOutcome> {
        if !Self::requests_are_open_universal_root(requests) {
            return self.visit_reverse_candidate_match_pages(requests, cancellation, visitor);
        }
        let (completion, cancelled) = self.lazy_candidate_completion(
            CandidateDirection::Reverse,
            requests,
            mounts,
            None,
            cancellation,
        )?;
        if cancelled {
            return Ok(completion);
        }
        let visit = self.lazy_candidate_matches(
            CandidateDirection::Reverse,
            requests,
            mounts,
            MAX_SOURCE_ROWS_PER_BATCH,
            None,
            None,
            cancellation,
            visitor,
        )?;
        candidate_completion_after_visit(requests.len(), completion, visit, cancellation)
    }

    fn visit_reverse_candidate_match_pages_with_gap_exclusions_shared(
        &self,
        requests: &[BatchCandidateRequest],
        exclusions: &mut ReverseCandidateGapExclusionPlan,
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
    ) -> StoreResult<BatchCandidateCompletionOutcome> {
        if exclusions.is_empty() {
            return self.visit_reverse_candidate_match_pages(requests, cancellation, visitor);
        }
        let (completion, cancelled) = self.lazy_candidate_completion(
            CandidateDirection::Reverse,
            requests,
            None,
            Some(exclusions),
            cancellation,
        )?;
        if cancelled {
            return Ok(completion);
        }
        let visit = self.lazy_candidate_matches(
            CandidateDirection::Reverse,
            requests,
            None,
            MAX_SOURCE_ROWS_PER_BATCH,
            None,
            Some(exclusions),
            cancellation,
            visitor,
        )?;
        candidate_completion_after_visit(requests.len(), completion, visit, cancellation)
    }

    /// Question 19, the most-called reader-seam question on every point route
    /// and in `missing_tests` (lane SC), answered from `resolution_paths`.
    ///
    /// Milestone 6's checkpoint. What changed against the interior: the
    /// candidates of one call are grouped by blob and each group's keys travel
    /// as one JSON array in one primary-key seek, so a call issues one
    /// statement per blob instead of one interior dispatch per candidate, and
    /// a hydration no longer opens the interior's `Facts` page. It still opens
    /// that blob's `Catalog` page, because a stored body holds integers and
    /// today's engine holds digests; milestone 4 removes that.
    fn hydrate_candidate_paths(
        &self,
        candidates: &[CandidatePathIdentity],
        cancellation: &CancellationToken,
    ) -> StoreResult<Vec<(CandidatePathIdentity, PartialPath)>> {
        if candidates.is_empty() {
            return Ok(Vec::new());
        }
        let Some(mut hydrated) =
            stage::hydrate_candidate_paths(self.selection, candidates, cancellation)?
        else {
            return Ok(Vec::new());
        };
        // Only ordinary candidates use the host's content-local path key.
        // Stage bodies already retained their full runtime and foreign keys.
        let mut groups: Vec<(BindingFragmentId, Vec<(usize, i64)>)> = Vec::new();
        for (position, candidate) in candidates.iter().enumerate() {
            if hydrated[position].is_some() {
                continue;
            }
            // The key is in the id. It used to be read back out of the
            // rebaser, which had registered every persisted path's coordinate
            // for exactly this; a local id carries its catalog position now,
            // so nothing has to have registered anything.
            let key = i64::from(candidate.path().local_key().unwrap_or_else(|| {
                panic!("tier-1 candidate {candidate:?} is not a blob's own path")
            }));
            match groups
                .iter_mut()
                .find(|(fragment, _)| *fragment == candidate.fragment())
            {
                Some((_, keys)) => keys.push((position, key)),
                None => groups.push((candidate.fragment(), vec![(position, key)])),
            }
        }
        for (fragment, keys) in &groups {
            let mount = &*self.mount_record_of_fragment(*fragment)?;
            let blob_id = mount.blob_id();
            let key_array = json_integer_array(keys.iter().map(|(_, key)| *key));
            let Some(bodies) = self.read_statement(cancellation, |conn| {
                let mut statement = conn.prepare_cached(RESOLUTION_PATHS_BY_KEY_SQL)?;
                let mut rows = statement.query(params![blob_id, &key_array])?;
                let mut bodies: HashMap<i64, (i64, i64, ParsedPathBody)> = HashMap::default();
                while let Some(row) = rows.next()? {
                    let key: i64 = row.get(0)?;
                    let start_node: i64 = row.get(1)?;
                    let end_node: i64 = row.get(2)?;
                    let body: String = row.get(3)?;
                    bodies.insert(key, (start_node, end_node, parse_path_body(&body)));
                }
                Ok(Some(bodies))
            })?
            else {
                return Ok(Vec::new());
            };
            let context = PathBodyContext {
                fragment: *fragment,
            };
            for (position, key) in keys {
                let (start_node, end_node, body) = bodies.get(key).unwrap_or_else(|| {
                    panic!("blob {blob_id} has no path row for candidate key {key}")
                });
                hydrated[*position] = Some(decode_path_row(&context, *start_node, *end_node, body));
            }
        }
        // A persisted path carries the reasons of the gaps it passes; one the
        // stage closed leaves the path as it leaves a candidate completion.
        let closed = if hydrated.iter().flatten().any(|path| {
            path.completion() != &crate::analyzer::resolution::ResolutionCompletion::Complete
        }) {
            if !self.refresh_ordinary_completion_suppression(cancellation)? {
                return Ok(Vec::new());
            }
            self.ordinary_completion_suppression
                .borrow()
                .as_ref()
                .expect("current suppression result was loaded")
                .reasons
                .clone()
        } else {
            Vec::new()
        };
        Ok(candidates
            .iter()
            .zip(hydrated)
            .map(|(candidate, path)| {
                let path =
                    path.expect("every requested candidate path hydrates from its blob's rows");
                (
                    *candidate,
                    if closed.is_empty() {
                        path
                    } else {
                        path.without_closed_reasons(&closed)
                    },
                )
            })
            .collect())
    }

    fn visit_type_transfer_rules(
        &self,
        source_slot: SemanticId,
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&TypeTransferRule) -> StoreResult<bool>,
    ) -> StoreResult<ResolutionCompletion> {
        use crate::analyzer::resolution::{
            FactPageVisitor, SelectedTypedFactSource, TypedFactRequest,
        };
        let mut rules = Vec::new();
        let mut collect_rules = |rows: &[crate::analyzer::resolution::SelectedTypedRow<
            crate::analyzer::resolution::LoweredTypeTransfer,
        >]| {
            rules.extend(rows.iter().map(|row| row.row().rule().clone()));
            Ok(true)
        };
        let read = self.typed.visit_type_transfer_pages_from_sources(
            TypedFactRequest::new(&[source_slot]),
            cancellation,
            &mut FactPageVisitor::new(&mut collect_rules),
        )?;
        let Some(staged) = stage::semantic_provenance(self.selection, source_slot, cancellation)?
        else {
            return Ok(with_cancelled(read.evidence().clone()));
        };
        let Some(ordinary) = self
            .authority
            .semantic_catalog_provenance(source_slot, cancellation)?
        else {
            return Ok(with_cancelled(read.evidence().clone()));
        };
        let mut coverage = ResolutionCompletion::Complete;
        if let Some(SelectedSemanticProvenance::FragmentLocal(ordinary)) = ordinary {
            if let Some((_, identity)) = staged
                && identity != ordinary.identity()
            {
                return Err(invalid_fact(format!(
                    "ordinary and stage type-transfer slot identities disagree: {source_slot:?}, {identity:?}, {ordinary:?}"
                )));
            }
            let (fragment, _, cancelled) = self.reference_gap_completions(
                &*self.mount_record(ordinary.mount().ordinal())?,
                &[],
                cancellation,
            )?;
            coverage = coverage.combine(&fragment);
            if cancelled {
                return Ok(with_cancelled(coverage.combine(read.evidence())));
            }
        }
        if staged.is_some() || source_slot.shared_name_id().is_some() {
            coverage = coverage.combine(&stage::fragment_completion(self.selection, cancellation)?);
        }
        let mut collect_coverage =
            |rows: &[crate::analyzer::resolution::SelectedTypeFrontierCompletion]| {
                for row in rows {
                    coverage = coverage.combine(row.completion());
                }
                Ok(true)
            };
        let frontier = self.typed.visit_type_frontier_completion_pages(
            TypedFactRequest::new(&[source_slot]),
            cancellation,
            &mut FactPageVisitor::new(&mut collect_coverage),
        )?;
        if read.is_cancelled() || frontier.is_cancelled() || cancellation.is_cancelled() {
            return Ok(with_cancelled(
                coverage
                    .combine(read.evidence())
                    .combine(frontier.evidence()),
            ));
        }
        for rule in &rules {
            if cancellation.is_cancelled() {
                break;
            }
            if !visitor(rule)? {
                break;
            }
        }
        Ok(if cancellation.is_cancelled() {
            with_cancelled(rules.iter().fold(coverage, |completion, rule| {
                completion.combine(rule.completion())
            }))
        } else {
            coverage
        })
    }
}

/// One batch of integer keys as the JSON array a `json_each(?)` statement
/// takes.
///
/// Milestone 6's rule: where a reader issues many seeks with keys it already
/// holds, it passes them as one JSON array in one statement.
/// A batch of already-rendered JSON arrays as the one array a `json_each(?)`
/// statement takes.
fn json_array_of_arrays(elements: &[String]) -> String {
    let mut out = String::from("[");
    out.push_str(&elements.join(","));
    out.push(']');
    out
}

pub(in crate::analyzer::store) fn finish_reverse_evidence(
    evidence: impl IntoIterator<Item = ReverseCoverageEvidence>,
    excluded: &[crate::analyzer::resolution::ReverseCandidateGapIdentity],
    requests: &[BatchCandidateRequest],
    cancellation: &CancellationToken,
) -> StoreResult<(BatchCandidateCompletionOutcome, bool)> {
    let excluded = excluded.iter().copied().collect::<HashSet<_>>();
    let mut effective = HashMap::default();
    let mut fragment_reasons = Vec::new();
    // Finish all returned rows after cancellation: eligibility was certified
    // by the read, and no further SQL or source authority is required here.
    for row in evidence {
        if !row.eligible {
            continue;
        }
        if let Some(gap) = row.gap {
            debug_assert_eq!(gap.identity().fragment(), row.host);
            if !excluded.contains(&gap.identity()) {
                effective.insert(gap.identity(), gap);
            }
        } else {
            fragment_reasons.push(row.reason);
        }
    }
    let fragment = if fragment_reasons.is_empty() {
        ResolutionCompletion::Complete
    } else {
        ResolutionCompletion::incomplete(fragment_reasons)
    };
    let (completion, observed) =
        reverse_completion_from_rows(effective.into_values(), fragment, requests, cancellation)?;
    let cancelled = observed || cancellation.is_cancelled();
    let completion = candidate_completion_after_visit(
        requests.len(),
        completion,
        if cancelled {
            CandidatePageVisit::Cancelled
        } else {
            CandidatePageVisit::Exhausted
        },
        cancellation,
    )?;
    Ok((completion, cancelled))
}

fn reverse_completion_from_rows(
    rows: impl IntoIterator<Item = ReverseCandidateGapRow>,
    fragment: ResolutionCompletion,
    requests: &[BatchCandidateRequest],
    cancellation: &CancellationToken,
) -> StoreResult<(BatchCandidateCompletionOutcome, bool)> {
    let mut builder = ReverseCandidateGapCoverageBuilder::default();
    for row in rows {
        builder.push(row)?;
    }
    let (coverage, mut cancelled) = builder.finish(cancellation)?;
    let mut work = 0;
    let mut branches = Vec::with_capacity(requests.len());
    for request in requests {
        let (completion, observed) =
            coverage.branch_completion_for_with_poll(request.endpoint(), cancellation, &mut work);
        cancelled |= observed;
        branches.push(completion);
    }
    let unconditional = fragment.combine(coverage.inventory_completion());
    Ok((
        BatchCandidateCompletionOutcome::new(requests.len(), unconditional, branches),
        cancelled,
    ))
}

/// Shared raw ordinary projection. Scope and effective closure are applied by
/// the answer query, never by the all-host exclusion proof query.
fn ordinary_reverse_gap_projection_sql() -> &'static str {
    r#"WITH ordinary(host,covers,node,lookup,gap,reason,blob) AS (
SELECT mount.mount_ordinal,fact.covers,fact.subject,fact.lookup,fact.gap,fact.reason,mount.blob_id
FROM temp.selected_resolution_mounts mount
JOIN main.resolution_gaps fact ON fact.blob_id=mount.blob_id AND fact.covers IN(0,3)
UNION
SELECT mount.mount_ordinal,fact.covers,fact.subject,fact.lookup,fact.gap,fact.reason,mount.blob_id
FROM json_each(:nodes) input
CROSS JOIN temp.selected_resolution_mounts mount ON mount.mount_ordinal=input.value->>0
CROSS JOIN main.resolution_gaps fact ON fact.blob_id=mount.blob_id AND fact.covers=6 AND fact.subject=input.value->>1
WHERE input.value->>0>=0
UNION
SELECT mount.mount_ordinal,fact.covers,fact.subject,fact.lookup,fact.gap,fact.reason,mount.blob_id
FROM json_each(:nodes) input CROSS JOIN temp.selected_resolution_mounts mount
CROSS JOIN main.resolution_gaps fact ON fact.blob_id=mount.blob_id AND fact.covers=6 AND fact.subject=-1
WHERE input.value->>0=-1
UNION
SELECT mount.mount_ordinal,fact.covers,fact.subject,fact.lookup,fact.gap,fact.reason,mount.blob_id
FROM json_each(:excluded) input
CROSS JOIN temp.selected_resolution_mounts mount ON mount.mount_ordinal=input.value->>0
CROSS JOIN main.resolution_gaps fact ON fact.blob_id=mount.blob_id AND fact.gap=input.value->>1 AND fact.covers IN(3,6)
), raw_gaps(host,covers,node,lookup,gap_key,reason_key,origin) AS (
SELECT ordinary.host,ordinary.covers,ordinary.node,ordinary.lookup,
 :local_base+(ordinary.host<<32)+ordinary.gap,
 :local_base+(ordinary.host<<32)+ordinary.reason,reason.origin
FROM ordinary JOIN main.resolution_gap_reasons reason ON reason.blob_id=ordinary.blob AND reason.reason=ordinary.reason
)"#
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::analyzer::store) struct ReverseCoverageEvidence {
    pub host: BindingFragmentId,
    pub gap: Option<ReverseCandidateGapRow>,
    pub reason: ResolutionIncompleteReason,
    pub eligible: bool,
}

impl ReverseCoverageEvidence {
    fn from_row(
        row: &Row<'_>,
        names: &dyn crate::analyzer::resolution::SharedNameInterner,
    ) -> StoreResult<Self> {
        use crate::analyzer::resolution::{
            ReverseCandidateGapIdentity, ReverseCandidateGapLocation,
        };
        let host = BindingFragmentId::at_ordinal(row.get(0)?);
        let reason = ResolutionIncompleteReason::UnsupportedSemantic(
            super::resolution_stage::codec::decode_semantic(row.get(5)?),
        );
        let covers: i64 = row.get(1)?;
        let gap = if covers == 0 {
            None
        } else {
            let location = if covers == 3 {
                ReverseCandidateGapLocation::Inventory
            } else {
                let node: i64 = row.get(2)?;
                let lookup: i64 = row.get(3)?;
                ReverseCandidateGapLocation::Endpoint {
                    endpoint: if node == -1 {
                        BindingNodeId::universal_root()
                    } else {
                        BindingNodeId::local(
                            host.ordinal(),
                            u32::try_from(node).expect("ordinary endpoint local key"),
                        )
                    },
                    lookup: (lookup != 0).then(|| {
                        SemanticId::shared_name(
                            names.from_persisted(SharedNameId::interned(lookup)),
                        )
                    }),
                }
            };
            Some(ReverseCandidateGapRow::new(
                ReverseCandidateGapIdentity::new(
                    host,
                    super::resolution_stage::codec::decode_semantic(row.get(4)?),
                ),
                location,
                reason,
            ))
        };
        Ok(Self {
            host,
            gap,
            reason,
            eligible: row.get(6)?,
        })
    }
}

/// Which node one candidate request is rooted at, in the terms a stored row
/// uses: the universal root is `-1`, a fragment-local node is its own blob's
/// node key, and anything else is a node no blob's rows can hold.
#[derive(Clone, Copy, Debug)]
enum CandidateRequestNode {
    UniversalRoot,
    Local(SelectedResolutionMountOrdinal, i64),
    Unmounted,
}

impl CandidateRequestNode {
    /// The stored `start_node` or `end_node` this request seeks in one mount's
    /// rows, or `None` when that mount can hold no path leaving this node.
    const fn local_key(self, mount: SelectedResolutionMountOrdinal) -> Option<i64> {
        match self {
            Self::UniversalRoot => Some(-1),
            Self::Local(owner, key) if owner.get() == mount.get() => Some(key),
            Self::Local(..) | Self::Unmounted => None,
        }
    }
}

/// One request's first fixed cell, as the candidate index keys it.
#[derive(Clone, Copy, Debug)]
enum CandidateRequestLead {
    /// An operation/context-local symbol can match only an empty open bucket.
    Unrepresentable,
    /// The endpoint fixes no symbol, so it shares a decidable cell with every
    /// stored endpoint of its node and reads them all.
    Open,
    Shared {
        identity: SharedNameId,
        scoped: bool,
    },
    Local {
        mount: SelectedResolutionMountOrdinal,
        semantic: SemanticId,
        scoped: bool,
    },
}

/// One root request's linear-sized SQL parameter, or cancellation evidence.
///
/// Cells and byte boundaries are constructed together from structured IDs.
/// A foreign/context-local identity ends representability without discarding
/// shorter open candidates. SQLite forms each proper-prefix string during its
/// indexed seek; it never receives a quadratic collection of prefix strings.
pub(super) fn root_candidate_request(
    names: &dyn crate::analyzer::resolution::SharedNameInterner,
    ordinal: usize,
    request: &BatchCandidateRequest,
    mount: SelectedResolutionMountOrdinal,
    cancellation: &CancellationToken,
) -> Option<String> {
    let mut key = RootKeyBuilder::default();
    let mut complete = true;
    for symbol in request.endpoint().symbols().fixed() {
        if cancellation.is_cancelled() {
            return None;
        }
        let semantic = symbol.symbol();
        if let Some(shared) = semantic.shared_name_id() {
            let Some(shared) = names.to_persisted(shared) else {
                complete = false;
                break;
            };
            key.push(
                None,
                Some(i64::from(shared.get())),
                symbol.scopes().is_some(),
            );
        } else if semantic.ordinal() == Some(mount.get()) {
            key.push(
                Some(i64::from(
                    semantic
                        .local_key()
                        .expect("a mounted semantic has a local key"),
                )),
                None,
                symbol.scopes().is_some(),
            );
        } else {
            complete = false;
            break;
        }
    }
    if cancellation.is_cancelled() {
        return None;
    }
    let (key, mut boundaries) = key.finish();
    if complete {
        boundaries
            .pop()
            .expect("every canonical key has its final boundary");
    }
    Some(
        serde_json::to_string(&(
            ordinal,
            key,
            i64::from(request.endpoint().symbols().tail().is_some()),
            i64::from(complete),
            boundaries,
        ))
        .expect("a structured root request serializes to JSON"),
    )
}

/// What one candidate request seeks, for the whole batch.
#[derive(Clone, Copy, Debug)]
struct CandidateRequestKey {
    node: CandidateRequestNode,
    lead: CandidateRequestLead,
}

/// `resolution_sites.role`: `0` a reference, `1` a definition.
const DEFINITION_SITE_ROLE: i64 = 1;

/// One `resolution_sites` row as it comes off the statement.
#[derive(Clone, Copy, Debug)]
struct RawSiteRow {
    site: i64,
    role: i64,
    namespace: i64,
    site_kind: Option<i64>,
    start_byte: Option<i64>,
    end_byte: Option<i64>,
    unqualified: Option<i64>,
    owner: Option<i64>,
    receiver_origin: Option<i64>,
    go_spelling_namespace: Option<i64>,
    go_definition_namespaces: Option<u8>,
    go_package_qualifier: bool,
}

impl RawSiteRow {
    fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            site: row.get(0)?,
            role: row.get(1)?,
            namespace: row.get(2)?,
            site_kind: row.get(3)?,
            start_byte: row.get(4)?,
            end_byte: row.get(5)?,
            unqualified: row.get(6)?,
            owner: row.get(7)?,
            receiver_origin: row.get(8)?,
            go_spelling_namespace: row.get(9)?,
            go_definition_namespaces: row.get(10)?,
            go_package_qualifier: row.get(11)?,
        })
    }

    fn metadata(
        &self,
        ordinal: SelectedResolutionMountOrdinal,
    ) -> Option<FactReferenceSiteMetadata> {
        use super::resolution_prepare::resolution_rows::{from_code, namespace_from_code};
        use brokk_bifrost_core::analyzer::resolution_facts::{
            ALL_RESOLUTION_CALLABLE_RECEIVER_ORIGINS, ALL_RESOLUTION_SITE_KINDS,
        };
        let kind = self.site_kind?;
        Some(
            FactReferenceSiteMetadata::new(
                ResolutionSiteId::new(u32::try_from(self.site).expect("source site")),
                namespace_from_code(self.namespace),
                from_code(ALL_RESOLUTION_SITE_KINDS, kind, "site kind"),
                usize::try_from(self.start_byte.expect("reference start"))
                    .expect("reference start"),
                usize::try_from(self.end_byte.expect("reference end")).expect("reference end"),
                self.unqualified.expect("reference qualification") != 0,
                self.owner.map(|owner| {
                    if owner == -1 {
                        None
                    } else {
                        Some(SemanticId::local(
                            ordinal.get(),
                            u32::try_from(owner).expect("reference owner"),
                        ))
                    }
                }),
                self.receiver_origin.map(|origin| {
                    from_code(
                        ALL_RESOLUTION_CALLABLE_RECEIVER_ORIGINS,
                        origin,
                        "receiver origin",
                    )
                }),
            )
            .with_go_spelling_namespace(self.go_spelling_namespace.map(namespace_from_code))
            .with_go_package_qualifier(self.go_package_qualifier),
        )
    }
}

/// One row the candidate index offered, before the full admission test.
///
/// It carries the endpoint admission decides on and not the path: almost every
/// offered row is rejected, and a rejected row must not cost a whole body.
struct OfferedCandidateRow {
    identity: CandidatePathIdentity,
    node: i64,
    endpoint: ParsedEndpointCells,
}

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

/// One 32-byte digest as the uppercase hexadecimal text `unhex()` reads.
///
/// `json_each` yields JSON values, and JSON has no blob, so a batch of digests
/// travels as text and SQLite turns each one back into the blob the unique
/// index is over.
pub(super) fn hex_digest(digest: [u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push_str(&format!("{byte:02X}"));
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CandidateDirection {
    Forward,
    Reverse,
}

impl CandidateDirection {
    const fn label(self) -> &'static str {
        match self {
            Self::Forward => "forward",
            Self::Reverse => "reverse",
        }
    }

    const fn position(self) -> usize {
        match self {
            Self::Forward => 0,
            Self::Reverse => 1,
        }
    }

    /// The lowering's own direction, which is what the gap rows are coded by.
    const fn lowered(self) -> LoweredCandidateDirection {
        match self {
            Self::Forward => LoweredCandidateDirection::Forward,
            Self::Reverse => LoweredCandidateDirection::Reverse,
        }
    }

    fn from_label(label: &str) -> StoreResult<Self> {
        match label {
            "forward" => Ok(Self::Forward),
            "reverse" => Ok(Self::Reverse),
            _ => Err(invalid_fact(format!(
                "unknown candidate-gap direction {label:?}"
            ))),
        }
    }
}

struct RawCandidateGapDemandBatchRow {
    gap: RawCandidateGap,
    mount: SelectedResolutionMountOrdinal,
    demand_ordinal: usize,
}

impl RawCandidateGapDemandBatchRow {
    fn from_row(row: &Row<'_>) -> StoreResult<Self> {
        Ok(Self {
            gap: RawCandidateGap::from_row(row)?,
            mount: mount_ordinal(row, 1, "candidate-gap batch mount")?,
            demand_ordinal: usize_from_nonnegative(row, 21, "candidate-gap demand ordinal")?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MountedCandidateGapLocation {
    Inventory,
    Endpoint {
        endpoint: BindingNodeId,
        lookup: Option<SemanticId>,
    },
}

#[derive(Debug)]
struct RawCandidateGap {
    direction: String,
    gap_key: i64,
    coverage_scope: String,
    endpoint_node_key: Option<i64>,
    endpoint_node_digest: Option<[u8; 32]>,
    endpoint_boundary_key: Option<i64>,
    lookup_semantic_key: Option<i64>,
    lookup_semantic_space: Option<String>,
    lookup_semantic_digest: Option<[u8; 32]>,
    reason: RawCompletionReason,
    gap_semantic_key: i64,
    gap_semantic_space: String,
    gap_semantic_digest: [u8; 32],
}

impl RawCandidateGap {
    fn from_row(row: &Row<'_>) -> StoreResult<Self> {
        let gap_key = nonnegative_i64(row, 3, "candidate gap key")?;
        Ok(Self {
            direction: row.get(2)?,
            gap_key,
            coverage_scope: row.get(4)?,
            endpoint_node_key: optional_nonnegative_i64(row, 5, "candidate gap endpoint node key")?,
            endpoint_node_digest: optional_digest(row, 6, "candidate gap endpoint node digest")?,
            endpoint_boundary_key: optional_nonnegative_i64(
                row,
                7,
                "candidate gap endpoint boundary key",
            )?,
            lookup_semantic_key: optional_nonnegative_i64(
                row,
                8,
                "candidate gap lookup semantic key",
            )?,
            lookup_semantic_space: row.get(9)?,
            lookup_semantic_digest: optional_digest(
                row,
                10,
                "candidate gap lookup semantic digest",
            )?,
            reason: RawCompletionReason {
                position: gap_key,
                kind: row.get(11)?,
                cyclic_path_key: optional_nonnegative_i64(
                    row,
                    12,
                    "candidate gap cyclic path key",
                )?,
                cyclic_path_digest: optional_digest(row, 13, "candidate gap cyclic path digest")?,
                semantic_key: optional_nonnegative_i64(
                    row,
                    14,
                    "candidate gap reason semantic key",
                )?,
                semantic_space: row.get(15)?,
                semantic_digest: optional_digest(row, 16, "candidate gap reason semantic digest")?,
                boundary_status: row.get(17)?,
            },
            gap_semantic_key: nonnegative_i64(row, 18, "candidate gap semantic key")?,
            gap_semantic_space: row.get(19)?,
            gap_semantic_digest: required_digest(row, 20, "candidate gap semantic digest")?,
        })
    }

    fn mount(
        self,
        mount: &SelectedResolutionMountRecord,
        identities: &mut IdentityStage<'_>,
    ) -> StoreResult<MountedCandidateGap> {
        if self.gap_semantic_space != "fragment_local" {
            return Err(invalid_fact(format!(
                "candidate gap {} does not rejoin its fragment-local semantic identity",
                self.gap_key
            )));
        }
        let gap_id = identities.semantic(
            mount,
            self.gap_semantic_key,
            self.gap_semantic_space,
            self.gap_semantic_digest,
        )?;
        let lookup = mount_optional_semantic(
            identities,
            mount,
            self.lookup_semantic_key,
            self.lookup_semantic_space,
            self.lookup_semantic_digest,
        )?;
        let endpoint = match (self.endpoint_node_key, self.endpoint_node_digest) {
            (None, None) => None,
            (Some(key), Some(digest)) => Some(identities.node(mount, key, digest)?),
            values => {
                return Err(invalid_fact(format!(
                    "candidate gap endpoint node key and digest disagree: {values:?}"
                )));
            }
        };
        let boundary = self
            .endpoint_boundary_key
            .map(boundary_node_from_key)
            .transpose()?;
        let location = match self.coverage_scope.as_str() {
            "fragment" if endpoint.is_none() && boundary.is_none() && lookup.is_none() => {
                MountedCandidateGapLocation::Inventory
            }
            "endpoint" if endpoint.is_some() ^ boundary.is_some() => {
                MountedCandidateGapLocation::Endpoint {
                    endpoint: endpoint.or(boundary).expect("one endpoint location exists"),
                    lookup,
                }
            }
            scope => {
                return Err(invalid_fact(format!(
                    "candidate gap {} has inconsistent coverage scope {scope:?}",
                    self.gap_key
                )));
            }
        };
        let reason = self.reason.mount(mount, identities)?;
        Ok(MountedCandidateGap {
            direction: CandidateDirection::from_label(&self.direction)?,
            gap_id,
            location,
            reason,
        })
    }
}

#[derive(Debug, Clone, Copy)]
struct MountedCandidateGap {
    direction: CandidateDirection,
    gap_id: SemanticId,
    location: MountedCandidateGapLocation,
    reason: ResolutionIncompleteReason,
}

#[derive(Debug, Clone)]
struct SelectedDirectionCandidateInventory {
    coverage: ReverseCandidateGapCoverage,
    authority: [u8; 32],
}

impl SelectedDirectionCandidateInventory {
    fn new(
        rows: Vec<ReverseCandidateGapRow>,
        authority: [u8; 32],
        cancellation: &CancellationToken,
    ) -> StoreResult<(Self, bool)> {
        let mut builder = ReverseCandidateGapCoverageBuilder::default();
        for row in rows {
            // Returned evidence is retained even if the read was interrupted.
            builder.push(row)?;
        }
        #[cfg(test)]
        SELECTED_CANDIDATE_INVENTORY_AGGREGATIONS.with(|count| count.set(count.get() + 1));
        let (coverage, cancelled) = builder.finish_with_authority(authority, cancellation)?;
        Ok((
            Self {
                coverage,
                authority,
            },
            cancelled,
        ))
    }

    const fn authority(&self) -> [u8; 32] {
        self.authority
    }
}

struct DirectionCandidateInventoryRead<'source> {
    inventory: std::borrow::Cow<'source, SelectedDirectionCandidateInventory>,
    cancelled: bool,
}

impl DirectionCandidateInventoryRead<'_> {
    fn inventory(&self) -> &SelectedDirectionCandidateInventory {
        &self.inventory
    }

    const fn is_cancelled(&self) -> bool {
        self.cancelled
    }
}

#[cfg(test)]
thread_local! {
    static SELECTED_CANDIDATE_INVENTORY_AGGREGATIONS: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}

/// Completion evidence needed by the selected root stitcher.
///
/// This is intentionally independent from [`SelectedDirectionCandidateInventory`].
/// The latter is the complete direction-wide candidate-gap cache used by
/// arbitrary endpoint requests; root stitching needs only fragment-wide
/// evidence and the universal-root endpoint bucket.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RootCandidateCompletion {
    unconditional: ResolutionCompletion,
    branch: ResolutionCompletion,
}

enum RootCandidateCompletionRead<'source> {
    Exhausted(&'source RootCandidateCompletion),
    Cancelled(RootCandidateCompletion),
}

impl RootCandidateCompletionRead<'_> {
    fn completion(&self) -> &RootCandidateCompletion {
        match self {
            Self::Exhausted(completion) => completion,
            Self::Cancelled(completion) => completion,
        }
    }

    const fn is_cancelled(&self) -> bool {
        matches!(self, Self::Cancelled(_))
    }
}

struct CandidateGapCoverageRead<'source> {
    inventory: DirectionCandidateInventoryRead<'source>,
    coverage: ReverseCandidateGapCoverage,
    cancelled: bool,
}

impl CandidateGapCoverageRead<'_> {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum CandidateEndpointCoordinate {
    Local(ResolutionLocalKey),
    Boundary(i64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct CandidateSemanticDescriptor {
    space: &'static str,
    digest: [u8; 32],
}

#[derive(Debug, Clone, Copy)]
struct CandidateProbe {
    mount: SelectedResolutionMountOrdinal,
    endpoint: CandidateEndpointCoordinate,
    symbol_fixed_count: usize,
    first_symbol: Option<CandidateSemanticDescriptor>,
    symbol_has_tail: bool,
}

/// One boundary-rooted candidate request reduced to the tier-1 header
/// predicate that decides which blobs can answer it.
#[derive(Debug, Clone, Copy)]
struct BoundaryHeaderProbe {
    /// The shared identity of the request's first fixed symbol, when it has
    /// one that compares across blobs. A fragment-local first symbol names its
    /// own mount directly and leaves this `None`, which still admits every
    /// blob whose header carries an open symbol tail.
    first_symbol: Option<SharedNameId>,
    symbol_fixed_count: usize,
    symbol_has_tail: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SharedRootCandidateProbe {
    first_symbol_digest: [u8; 32],
    symbol_fixed_count: usize,
    symbol_has_tail: bool,
}

#[derive(Clone, Copy, Debug)]
struct RawCandidateMatch {
    mount: SelectedResolutionMountOrdinal,
    path_key: i64,
    path_digest: [u8; 32],
}

impl RawCandidateMatch {
    fn from_row(row: &Row<'_>) -> StoreResult<Self> {
        Ok(Self {
            mount: mount_ordinal(row, 1, "candidate match mount")?,
            path_key: nonnegative_i64(row, 2, "candidate path key")?,
            path_digest: required_digest(row, 3, "candidate path digest")?,
        })
    }
}

struct RawBoundaryCandidateMatch {
    mount: SelectedResolutionMountOrdinal,
    path_key: i64,
    path_digest: [u8; 32],
    probe_ordinal: usize,
}

impl RawBoundaryCandidateMatch {
    fn from_row(row: &Row<'_>) -> StoreResult<Self> {
        Ok(Self {
            mount: mount_ordinal(row, 1, "boundary candidate mount")?,
            path_key: nonnegative_i64(row, 2, "boundary candidate path key")?,
            path_digest: required_digest(row, 3, "boundary candidate path digest")?,
            probe_ordinal: usize_from_nonnegative(row, 4, "boundary candidate probe ordinal")?,
        })
    }
}

#[derive(Debug)]
struct RawSharedRootSemantic {
    blob_id: i64,
    semantic_key: i64,
    mount: SelectedResolutionMountOrdinal,
}

impl RawSharedRootSemantic {
    fn from_row(row: &Row<'_>) -> StoreResult<Self> {
        Ok(Self {
            blob_id: nonnegative_i64(row, 1, "shared-root semantic blob")?,
            semantic_key: nonnegative_i64(row, 2, "shared-root semantic key")?,
            mount: mount_ordinal(row, 3, "shared-root representative mount")?,
        })
    }
}

#[derive(Debug)]
struct RawSharedRootCandidateMatch {
    mount: SelectedResolutionMountOrdinal,
    blob_id: i64,
    path_key: i64,
    path_digest: [u8; 32],
}

impl RawSharedRootCandidateMatch {
    fn from_row(row: &Row<'_>) -> StoreResult<Self> {
        Ok(Self {
            mount: mount_ordinal(row, 1, "shared-root wildcard mount")?,
            blob_id: nonnegative_i64(row, 2, "shared-root wildcard blob")?,
            path_key: nonnegative_i64(row, 3, "shared-root wildcard path key")?,
            path_digest: required_digest(row, 4, "shared-root wildcard path digest")?,
        })
    }
}

#[derive(Debug, Clone, Copy)]
struct SharedRootCandidateCursor {
    blob_id: i64,
    path_key: i64,
}

impl SharedRootCandidateCursor {
    fn advance(self, blob_id: i64, path_key: i64) -> StoreResult<Self> {
        if (blob_id, path_key) <= (self.blob_id, self.path_key) {
            return Err(invalid_fact(format!(
                "shared-root wildcard page did not advance after ({}, {})",
                self.blob_id, self.path_key
            )));
        }
        Ok(Self { blob_id, path_key })
    }
}

struct CandidateMatchPage<'names> {
    rows: Vec<BatchCandidateMatch>,
    maximum_rows: usize,
    identities: IdentityStage<'names>,
    // A selected mount inventory has unique fragments, and each physical path
    // occurs in exactly one of the disjoint keyed/wildcard query buckets. A
    // page-local check therefore proves the bounded publisher did not repeat a
    // logical result without retaining an unbounded operation-wide set.
    returned: BTreeSet<(usize, CandidatePathIdentity)>,
    validate_after_publish: bool,
}

impl<'names> CandidateMatchPage<'names> {
    fn new(
        maximum_rows: usize,
        names: &'names dyn crate::analyzer::resolution::SharedNameInterner,
    ) -> Self {
        assert!((1..=MAX_SOURCE_ROWS_PER_BATCH).contains(&maximum_rows));
        Self {
            rows: Vec::with_capacity(maximum_rows),
            maximum_rows,
            identities: IdentityStage::new(names),
            returned: BTreeSet::new(),
            validate_after_publish: false,
        }
    }

    fn len(&self) -> usize {
        self.rows.len()
    }

    #[allow(clippy::too_many_arguments)]
    fn push(
        &mut self,
        source: &SelectedResolutionLexicalSource<'_, '_>,
        request_ordinal: usize,
        mount: &SelectedResolutionMountRecord,
        path_key: i64,
        path_digest: [u8; 32],
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
    ) -> StoreResult<Option<CandidatePageVisit>> {
        if cancellation.is_cancelled() {
            return Ok(Some(CandidatePageVisit::Cancelled));
        }
        let path = self.identities.path(mount, path_key, path_digest)?;
        let candidate = CandidatePathIdentity::new(mount.fragment_id(), path);
        if !self.returned.insert((request_ordinal, candidate)) {
            return Err(invalid_fact(format!(
                "candidate request {request_ordinal} returned duplicate {candidate:?}"
            )));
        }
        self.rows
            .push(BatchCandidateMatch::new(candidate, request_ordinal));
        if self.rows.len() != self.maximum_rows {
            return Ok(None);
        }
        if cancellation.is_cancelled() {
            return Ok(Some(CandidatePageVisit::Cancelled));
        }
        let keep_going = visitor(&self.rows)?;
        if self.validate_after_publish
            && !source.validate_selected_interiors_uncached(cancellation)?
        {
            return Ok(Some(CandidatePageVisit::Cancelled));
        }
        if cancellation.is_cancelled() {
            return Ok(Some(CandidatePageVisit::Cancelled));
        }
        if !keep_going {
            return Ok(Some(CandidatePageVisit::Stopped));
        }
        self.rows.clear();
        self.returned.clear();
        Ok(None)
    }

    fn finish(
        self,
        source: &SelectedResolutionLexicalSource<'_, '_>,
        cancellation: &CancellationToken,
        visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
    ) -> StoreResult<CandidatePageVisit> {
        if cancellation.is_cancelled() {
            return Ok(CandidatePageVisit::Cancelled);
        }
        if !self.rows.is_empty() {
            let keep_going = visitor(&self.rows)?;
            if self.validate_after_publish
                && !source.validate_selected_interiors_uncached(cancellation)?
            {
                return Ok(CandidatePageVisit::Cancelled);
            }
            if cancellation.is_cancelled() {
                return Ok(CandidatePageVisit::Cancelled);
            }
            if !keep_going {
                return Ok(CandidatePageVisit::Stopped);
            }
        }
        Ok(if cancellation.is_cancelled() {
            CandidatePageVisit::Cancelled
        } else {
            CandidatePageVisit::Exhausted
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CandidatePageVisit {
    Exhausted,
    Stopped,
    Cancelled,
}

fn candidate_completion_after_visit(
    request_count: usize,
    completion: BatchCandidateCompletionOutcome,
    visit: CandidatePageVisit,
    cancellation: &CancellationToken,
) -> StoreResult<BatchCandidateCompletionOutcome> {
    if !matches!(visit, CandidatePageVisit::Cancelled) && !cancellation.is_cancelled() {
        return Ok(completion);
    }
    Ok(BatchCandidateCompletionOutcome::new(
        request_count,
        with_cancelled(completion.unconditional_completion().clone()),
        completion.branch_completions().iter().cloned(),
    ))
}

#[derive(Debug, Clone, Copy)]
struct LocalPathRequest {
    request_ordinal: usize,
    candidate: CandidatePathIdentity,
    mount: SelectedResolutionMountOrdinal,
    path_key: ResolutionLocalKey,
}

#[derive(Debug)]
struct RawPathHead {
    blob_id: i64,
    request_ordinal: usize,
    mount: SelectedResolutionMountOrdinal,
    path_key: i64,
    path_digest: [u8; 32],
    start_node: RawNodeCoordinate,
    end_node: RawNodeCoordinate,
    start_symbol_tail: RawVariableCoordinate,
    end_symbol_tail: RawVariableCoordinate,
    completion_kind: String,
    start_symbol_count: usize,
    end_symbol_count: usize,
    start_first_symbol: RawSemanticCoordinate,
    end_first_symbol: RawSemanticCoordinate,
    body: String,
    semantic_catalog: Option<String>,
    node_catalog: Option<String>,
    variable_catalog: Option<String>,
    path_catalog: Option<String>,
}

impl RawPathHead {
    fn from_row(row: &Row<'_>) -> StoreResult<Self> {
        Ok(Self {
            blob_id: row.get(0)?,
            request_ordinal: usize_from_nonnegative(row, 1, "path request ordinal")?,
            mount: mount_ordinal(row, 2, "path head mount")?,
            path_key: nonnegative_i64(row, 3, "path head key")?,
            path_digest: required_digest(row, 4, "path head digest")?,
            start_node: RawNodeCoordinate::from_row(row, 5, 6, 7, "start node")?,
            end_node: RawNodeCoordinate::from_row(row, 8, 9, 10, "end node")?,
            start_symbol_tail: RawVariableCoordinate::from_row(row, 11, 12, "start symbol tail")?,
            end_symbol_tail: RawVariableCoordinate::from_row(row, 13, 14, "end symbol tail")?,
            completion_kind: row.get(15)?,
            start_symbol_count: usize_from_nonnegative(row, 16, "start symbol count")?,
            end_symbol_count: usize_from_nonnegative(row, 17, "end symbol count")?,
            start_first_symbol: RawSemanticCoordinate::from_row(
                row,
                18,
                19,
                20,
                "start first symbol",
            )?,
            end_first_symbol: RawSemanticCoordinate::from_row(row, 21, 22, 23, "end first symbol")?,
            body: row.get(24)?,
            semantic_catalog: row.get(25)?,
            node_catalog: row.get(26)?,
            variable_catalog: row.get(27)?,
            path_catalog: row.get(28)?,
        })
    }

    fn mount(
        self,
        source: &SelectedResolutionLexicalSource<'_, '_>,
        request: &LocalPathRequest,
        catalog: &RawPathIdentityCatalog,
        identities: &mut IdentityStage<'_>,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<(CandidatePathIdentity, PartialPath)>> {
        if self.mount != request.mount || self.path_key != request.path_key.get() {
            return Err(invalid_fact(format!(
                "path request {} returned coordinate ({}, {}) instead of ({}, {})",
                request.request_ordinal,
                self.mount.get(),
                self.path_key,
                request.mount.get(),
                request.path_key.get()
            )));
        }
        let mount = &*source.mount(self.mount)?;
        let catalog_path_digest = catalog.path_digest(self.path_key)?;
        if catalog_path_digest != self.path_digest {
            return Err(invalid_fact(format!(
                "path head digest disagrees with the body identity catalog for key {}",
                self.path_key
            )));
        }
        let path = identities.path(mount, self.path_key, self.path_digest)?;
        if path != request.candidate.path() || mount.fragment_id() != request.candidate.fragment() {
            return Err(invalid_fact(format!(
                "path head does not reconstruct requested candidate {:?}",
                request.candidate
            )));
        }
        let body = serde_json::from_str::<RawPartialPathBody>(&self.body)
            .map_err(|error| invalid_fact(format!("invalid partial-path JSON body: {error}")))?;
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let start_first_symbol = self.start_first_symbol.mount(mount, identities)?;
        let end_first_symbol = self.end_first_symbol.mount(mount, identities)?;
        let start = body.start.mount(
            self.start_node.mount(mount, identities)?,
            self.start_symbol_tail.mount(mount, identities)?,
            self.start_symbol_count,
            start_first_symbol,
            mount,
            catalog,
            identities,
            cancellation,
        )?;
        let Some(start) = start else {
            return Ok(None);
        };
        let end = body.end.mount(
            self.end_node.mount(mount, identities)?,
            self.end_symbol_tail.mount(mount, identities)?,
            self.end_symbol_count,
            end_first_symbol,
            mount,
            catalog,
            identities,
            cancellation,
        )?;
        let Some(end) = end else {
            return Ok(None);
        };
        let mut precedence = Vec::with_capacity(body.precedence.len());
        for raw in body.precedence {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let tier = PrecedenceTier::from_label(&raw.tier).ok_or_else(|| {
                invalid_fact(format!("unknown path precedence tier {:?}", raw.tier))
            })?;
            namespace_from_label(&raw.namespace)?;
            precedence.push(PrecedenceStep {
                tier,
                ordinal: raw.ordinal,
                semantic: catalog.mount_semantic(raw.semantic, mount, identities)?,
            });
        }
        let mut witness = Vec::with_capacity(body.witness.len());
        for raw in body.witness {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            witness.push(raw.mount(mount, catalog, identities)?);
        }
        let mut reasons = BTreeSet::new();
        for raw in body.reasons {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            let reason = raw.mount(mount, catalog, identities)?;
            if !reasons.insert(reason) {
                return Err(invalid_fact(format!(
                    "path {} repeats completion reason {reason:?}",
                    request.candidate.path()
                )));
            }
        }
        let completion = completion_from_parent(
            &self.completion_kind,
            reasons.len(),
            reasons,
            "candidate path",
        )?;
        let Some(path) = PartialPath::new_with_poll(
            start,
            end,
            precedence.into_boxed_slice(),
            witness.into_boxed_slice(),
            completion,
            &mut || cancellation.is_cancelled(),
        ) else {
            return Ok(None);
        };
        Ok(Some((request.candidate, path)))
    }
}

#[derive(Debug, Deserialize)]
struct RawPartialPathBody {
    start: RawPathBodyEndpoint,
    end: RawPathBodyEndpoint,
    precedence: Vec<RawPathBodyPrecedence>,
    witness: Vec<RawPathBodyWitness>,
    reasons: Vec<RawPathBodyCompletionReason>,
}

#[derive(Debug, Deserialize)]
struct RawPathBodyEndpoint {
    symbols: Vec<RawPathBodySymbol>,
    scopes: Vec<RawPathBodyNode>,
    scope_tail: Option<i64>,
}

impl RawPathBodyEndpoint {
    #[allow(clippy::too_many_arguments)]
    fn mount(
        self,
        node: BindingNodeId,
        symbol_tail: Option<StackVariableId>,
        expected_symbol_count: usize,
        expected_first_symbol: Option<SemanticId>,
        mount: &SelectedResolutionMountRecord,
        catalog: &RawPathIdentityCatalog,
        identities: &mut IdentityStage<'_>,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<EndpointSignature>> {
        if self.symbols.len() != expected_symbol_count {
            return Err(invalid_fact(format!(
                "partial-path body has {} symbols but its head declares {expected_symbol_count}",
                self.symbols.len()
            )));
        }
        let mut symbols = Vec::with_capacity(self.symbols.len());
        for raw in self.symbols {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            symbols.push(raw.mount(mount, catalog, identities)?);
        }
        if symbols.first().map(PartialScopedSymbol::symbol) != expected_first_symbol {
            return Err(invalid_fact(
                "partial-path body's first symbol disagrees with its indexed head predicate",
            ));
        }
        let mut scopes = Vec::with_capacity(self.scopes.len());
        for raw in self.scopes {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            scopes.push(raw.mount(mount, catalog, identities)?);
        }
        let scope_tail = self
            .scope_tail
            .map(|key| catalog.mount_variable(key, mount, identities))
            .transpose()?;
        Ok(Some(EndpointSignature::new_scoped(
            node,
            StackPattern::new(symbols, symbol_tail),
            StackPattern::new(scopes, scope_tail),
        )))
    }
}

#[derive(Debug, Deserialize)]
struct RawPathBodySymbol {
    symbol: i64,
    scopes: Option<Vec<RawPathBodyNode>>,
    scope_tail: Option<i64>,
}

impl RawPathBodySymbol {
    fn mount(
        self,
        mount: &SelectedResolutionMountRecord,
        catalog: &RawPathIdentityCatalog,
        identities: &mut IdentityStage<'_>,
    ) -> StoreResult<PartialScopedSymbol> {
        let symbol = catalog.mount_semantic(self.symbol, mount, identities)?;
        match self.scopes {
            None if self.scope_tail.is_none() => Ok(PartialScopedSymbol::unscoped(symbol)),
            None => Err(invalid_fact(
                "unscoped partial-path symbol carries an attached scope tail",
            )),
            Some(raw_scopes) => {
                let scopes = raw_scopes
                    .into_iter()
                    .map(|raw| raw.mount(mount, catalog, identities))
                    .collect::<StoreResult<Vec<_>>>()?;
                let tail = self
                    .scope_tail
                    .map(|key| catalog.mount_variable(key, mount, identities))
                    .transpose()?;
                Ok(PartialScopedSymbol::scoped(
                    symbol,
                    StackPattern::new(scopes, tail),
                ))
            }
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum RawPathBodyNode {
    Local { key: i64 },
    Boundary { key: i64 },
}

impl RawPathBodyNode {
    fn mount(
        self,
        mount: &SelectedResolutionMountRecord,
        catalog: &RawPathIdentityCatalog,
        identities: &mut IdentityStage<'_>,
    ) -> StoreResult<BindingNodeId> {
        match self {
            Self::Local { key } => catalog.mount_node(key, mount, identities),
            Self::Boundary { key } => boundary_node_from_key(key),
        }
    }
}

#[derive(Debug, Deserialize)]
struct RawPathBodyPrecedence {
    tier: String,
    ordinal: u32,
    namespace: String,
    semantic: i64,
}

#[derive(Debug, Deserialize)]
struct RawPathBodyWitness {
    kind: String,
    node: Option<RawPathBodyNode>,
    semantic: Option<i64>,
    outcome: Option<String>,
    rejection: Option<String>,
    status: Option<String>,
}

impl RawPathBodyWitness {
    fn mount(
        self,
        mount: &SelectedResolutionMountRecord,
        catalog: &RawPathIdentityCatalog,
        identities: &mut IdentityStage<'_>,
    ) -> StoreResult<WitnessStep> {
        let kind = ResolutionWitnessKind::from_label(&self.kind).ok_or_else(|| {
            invalid_fact(format!("unknown partial-path witness kind {:?}", self.kind))
        })?;
        match (
            kind,
            self.node,
            self.semantic,
            self.outcome,
            self.rejection,
            self.status,
        ) {
            (ResolutionWitnessKind::Node, Some(node), None, None, None, None) => {
                Ok(WitnessStep::Node(node.mount(mount, catalog, identities)?))
            }
            (
                ResolutionWitnessKind::Candidate,
                None,
                Some(semantic),
                Some(outcome),
                rejection,
                None,
            ) => {
                let outcome_kind = CandidateOutcomeKind::from_label(&outcome).ok_or_else(|| {
                    invalid_fact(format!("unknown candidate witness outcome {outcome:?}"))
                })?;
                let outcome = match (outcome_kind, rejection.as_deref()) {
                    (CandidateOutcomeKind::Selected, None) => CandidateOutcome::Selected,
                    (CandidateOutcomeKind::Rejected, Some(reason)) => CandidateOutcome::Rejected(
                        RejectionReason::from_label(reason).ok_or_else(|| {
                            invalid_fact(format!("unknown candidate rejection reason {reason:?}"))
                        })?,
                    ),
                    values => {
                        return Err(invalid_fact(format!(
                            "candidate witness has inconsistent outcome {values:?}"
                        )));
                    }
                };
                Ok(WitnessStep::Candidate {
                    semantic: catalog.mount_semantic(semantic, mount, identities)?,
                    outcome,
                })
            }
            (ResolutionWitnessKind::Boundary, None, Some(semantic), None, None, Some(status)) => {
                let status = BoundaryStatus::from_label(&status).ok_or_else(|| {
                    invalid_fact(format!("unknown witness boundary status {status:?}"))
                })?;
                Ok(WitnessStep::Boundary {
                    semantic: catalog.mount_semantic(semantic, mount, identities)?,
                    status,
                })
            }
            shape => Err(invalid_fact(format!(
                "partial-path witness has inconsistent shape {shape:?}"
            ))),
        }
    }
}

#[derive(Debug, Deserialize)]
struct RawPathBodyCompletionReason {
    kind: String,
    path: Option<i64>,
    semantic: Option<i64>,
    status: Option<String>,
}

impl RawPathBodyCompletionReason {
    fn mount(
        self,
        mount: &SelectedResolutionMountRecord,
        catalog: &RawPathIdentityCatalog,
        identities: &mut IdentityStage<'_>,
    ) -> StoreResult<ResolutionIncompleteReason> {
        let kind = ResolutionCompletionReasonKind::from_label(&self.kind).ok_or_else(|| {
            invalid_fact(format!(
                "unknown partial-path completion reason kind {:?}",
                self.kind
            ))
        })?;
        match (kind, self.path, self.semantic, self.status) {
            (ResolutionCompletionReasonKind::CyclicExpansion, Some(path), None, None) => {
                Ok(ResolutionIncompleteReason::CyclicExpansion(
                    catalog.mount_path(path, mount, identities)?,
                ))
            }
            (
                ResolutionCompletionReasonKind::InconsistentPrecedence,
                None,
                Some(semantic),
                None,
            ) => Ok(ResolutionIncompleteReason::InconsistentPrecedence(
                catalog.mount_semantic(semantic, mount, identities)?,
            )),
            (ResolutionCompletionReasonKind::OpenBoundary, None, Some(semantic), Some(status)) => {
                let status = BoundaryStatus::from_label(&status).ok_or_else(|| {
                    invalid_fact(format!("unknown resolution boundary status {status:?}"))
                })?;
                Ok(ResolutionIncompleteReason::OpenBoundary {
                    semantic: catalog.mount_semantic(semantic, mount, identities)?,
                    status,
                })
            }
            (ResolutionCompletionReasonKind::UnsupportedSemantic, None, Some(semantic), None) => {
                Ok(ResolutionIncompleteReason::UnsupportedSemantic(
                    catalog.mount_semantic(semantic, mount, identities)?,
                ))
            }
            shape => Err(invalid_fact(format!(
                "partial-path completion reason has inconsistent shape {shape:?}"
            ))),
        }
    }
}

#[derive(Debug, Deserialize)]
struct RawSemanticCatalogEntry {
    key: i64,
    space: String,
    digest: String,
}

#[derive(Debug, Deserialize)]
struct RawLocalCatalogEntry {
    key: i64,
    digest: String,
}

struct RawPathIdentityCatalog {
    semantics: BTreeMap<i64, (String, [u8; 32])>,
    nodes: BTreeMap<i64, [u8; 32]>,
    variables: BTreeMap<i64, [u8; 32]>,
    paths: BTreeMap<i64, [u8; 32]>,
}

impl RawPathIdentityCatalog {
    fn path_digest(&self, key: i64) -> StoreResult<[u8; 32]> {
        self.paths
            .get(&key)
            .copied()
            .ok_or_else(|| invalid_fact(format!("partial-path body names absent path key {key}")))
    }

    fn mount_semantic(
        &self,
        key: i64,
        mount: &SelectedResolutionMountRecord,
        identities: &mut IdentityStage<'_>,
    ) -> StoreResult<SemanticId> {
        let (space, digest) = self.semantics.get(&key).ok_or_else(|| {
            invalid_fact(format!("partial-path body names absent semantic key {key}"))
        })?;
        identities.semantic(mount, key, space.clone(), *digest)
    }

    fn mount_node(
        &self,
        key: i64,
        mount: &SelectedResolutionMountRecord,
        identities: &mut IdentityStage<'_>,
    ) -> StoreResult<BindingNodeId> {
        let digest = self.nodes.get(&key).copied().ok_or_else(|| {
            invalid_fact(format!("partial-path body names absent node key {key}"))
        })?;
        identities.node(mount, key, digest)
    }

    fn mount_variable(
        &self,
        key: i64,
        mount: &SelectedResolutionMountRecord,
        identities: &mut IdentityStage<'_>,
    ) -> StoreResult<StackVariableId> {
        let digest = self.variables.get(&key).copied().ok_or_else(|| {
            invalid_fact(format!(
                "partial-path body names absent stack-variable key {key}"
            ))
        })?;
        identities.variable(mount, key, digest)
    }

    fn mount_path(
        &self,
        key: i64,
        mount: &SelectedResolutionMountRecord,
        identities: &mut IdentityStage<'_>,
    ) -> StoreResult<PartialPathId> {
        identities.path(mount, key, self.path_digest(key)?)
    }
}

#[derive(Debug)]
struct RawSemanticCoordinate {
    key: Option<i64>,
    space: Option<String>,
    digest: Option<[u8; 32]>,
}

impl RawSemanticCoordinate {
    fn from_row(
        row: &Row<'_>,
        key: usize,
        space: usize,
        digest: usize,
        description: &str,
    ) -> StoreResult<Self> {
        Ok(Self {
            key: optional_nonnegative_i64(row, key, description)?,
            space: row.get(space)?,
            digest: optional_digest(row, digest, description)?,
        })
    }

    fn mount(
        self,
        mount: &SelectedResolutionMountRecord,
        identities: &mut IdentityStage<'_>,
    ) -> StoreResult<Option<SemanticId>> {
        mount_optional_semantic(identities, mount, self.key, self.space, self.digest)
    }
}

#[derive(Debug)]
struct RawNodeCoordinate {
    key: Option<i64>,
    digest: Option<[u8; 32]>,
    boundary_key: Option<i64>,
}

impl RawNodeCoordinate {
    fn from_row(
        row: &Row<'_>,
        key: usize,
        digest: usize,
        boundary_key: usize,
        description: &str,
    ) -> StoreResult<Self> {
        Ok(Self {
            key: optional_nonnegative_i64(row, key, description)?,
            digest: optional_digest(row, digest, description)?,
            boundary_key: optional_nonnegative_i64(row, boundary_key, description)?,
        })
    }

    fn mount(
        self,
        mount: &SelectedResolutionMountRecord,
        identities: &mut IdentityStage<'_>,
    ) -> StoreResult<BindingNodeId> {
        self.mount_optional(mount, identities)?
            .ok_or_else(|| invalid_fact("required path node coordinate is absent"))
    }

    fn mount_optional(
        self,
        mount: &SelectedResolutionMountRecord,
        identities: &mut IdentityStage<'_>,
    ) -> StoreResult<Option<BindingNodeId>> {
        let local = match (self.key, self.digest) {
            (None, None) => None,
            (Some(key), Some(digest)) => Some(identities.node(mount, key, digest)?),
            values => {
                return Err(invalid_fact(format!(
                    "path node key and digest disagree: {values:?}"
                )));
            }
        };
        let boundary = self.boundary_key.map(boundary_node_from_key).transpose()?;
        match (local, boundary) {
            (None, None) => Ok(None),
            (Some(node), None) | (None, Some(node)) => Ok(Some(node)),
            (Some(_), Some(_)) => Err(invalid_fact(
                "path node names both a local and universal-boundary coordinate",
            )),
        }
    }
}

#[derive(Debug)]
struct RawVariableCoordinate {
    key: Option<i64>,
    digest: Option<[u8; 32]>,
}

impl RawVariableCoordinate {
    fn from_row(row: &Row<'_>, key: usize, digest: usize, description: &str) -> StoreResult<Self> {
        Ok(Self {
            key: optional_nonnegative_i64(row, key, description)?,
            digest: optional_digest(row, digest, description)?,
        })
    }

    fn mount(
        self,
        mount: &SelectedResolutionMountRecord,
        identities: &mut IdentityStage<'_>,
    ) -> StoreResult<Option<StackVariableId>> {
        match (self.key, self.digest) {
            (None, None) => Ok(None),
            (Some(key), Some(digest)) => identities.variable(mount, key, digest).map(Some),
            values => Err(invalid_fact(format!(
                "stack variable key and digest disagree: {values:?}"
            ))),
        }
    }
}

#[derive(Clone, Copy)]
struct LocalSemanticRequest {
    request_ordinal: usize,
    query: ResolutionQuery,
    mount: SelectedResolutionMountOrdinal,
    semantic_key: ResolutionLocalKey,
}

#[derive(Clone, Copy)]
struct LocalNodeRequest {
    request_ordinal: usize,
    mount: SelectedResolutionMountOrdinal,
    node_key: ResolutionLocalKey,
}

enum ReferenceCompletionBatchRead {
    Exhausted(Vec<ResolutionCompletion>),
    Cancelled(ResolutionCompletion),
}

#[derive(Debug)]
struct RawReferenceHead {
    request_ordinal: usize,
    mount: SelectedResolutionMountOrdinal,
    semantic_key: i64,
    semantic_space: String,
    semantic_digest: [u8; 32],
    node_key: i64,
    node_digest: [u8; 32],
    site: Option<i64>,
    namespace: Option<String>,
    site_kind: Option<String>,
    start_byte: Option<i64>,
    end_byte: Option<i64>,
    unqualified: Option<i64>,
    owner_known: i64,
    owner_key: Option<i64>,
    owner_space: Option<String>,
    owner_digest: Option<[u8; 32]>,
    callable_receiver_origin: Option<String>,
    completion_kind: String,
    expected_reason_count: usize,
}

impl RawReferenceHead {
    fn from_row(row: &Row<'_>, request_ordinal: usize, base: usize) -> StoreResult<Self> {
        Ok(Self {
            request_ordinal,
            mount: mount_ordinal(row, base, "reference mount")?,
            semantic_key: nonnegative_i64(row, base + 1, "reference semantic key")?,
            semantic_space: row.get(base + 2)?,
            semantic_digest: required_digest(row, base + 3, "reference semantic digest")?,
            node_key: nonnegative_i64(row, base + 4, "reference node key")?,
            node_digest: required_digest(row, base + 5, "reference node digest")?,
            site: row.get(base + 6)?,
            namespace: row.get(base + 7)?,
            site_kind: row.get(base + 8)?,
            start_byte: row.get(base + 9)?,
            end_byte: row.get(base + 10)?,
            unqualified: row.get(base + 11)?,
            owner_known: row.get(base + 12)?,
            owner_key: optional_nonnegative_i64(row, base + 13, "reference owner key")?,
            owner_space: row.get(base + 14)?,
            owner_digest: optional_digest(row, base + 15, "reference owner digest")?,
            callable_receiver_origin: row.get(base + 16)?,
            completion_kind: row.get(base + 17)?,
            expected_reason_count: usize_from_nonnegative(
                row,
                base + 18,
                "reference expected reason count",
            )?,
        })
    }

    fn semantic(
        &self,
        source: &SelectedResolutionLexicalSource<'_, '_>,
        identities: &mut IdentityStage<'_>,
    ) -> StoreResult<SemanticId> {
        identities.semantic(
            &*source.mount(self.mount)?,
            self.semantic_key,
            self.semantic_space.clone(),
            self.semantic_digest,
        )
    }

    fn mount(
        self,
        source: &SelectedResolutionLexicalSource<'_, '_>,
        query: ResolutionQuery,
        identities: &mut IdentityStage<'_>,
    ) -> StoreResult<DecodedReferenceHead> {
        let mount = &*source.mount(self.mount)?;
        if self.semantic_space != "fragment_local" {
            return Err(invalid_fact(format!(
                "reference node uses nonlocal semantic identity space {:?}",
                self.semantic_space
            )));
        }
        let semantic = identities.semantic(
            mount,
            self.semantic_key,
            self.semantic_space,
            self.semantic_digest,
        )?;
        if semantic != query.reference() {
            return Err(invalid_fact(format!(
                "reference head semantic {semantic} disagrees with query {}",
                query.reference()
            )));
        }
        let node = identities.node(mount, self.node_key, self.node_digest)?;
        let owner = mount_optional_semantic(
            identities,
            mount,
            self.owner_key,
            self.owner_space,
            self.owner_digest,
        )?;
        let site_metadata = reference_site_metadata(
            self.site,
            self.namespace,
            self.site_kind,
            self.start_byte,
            self.end_byte,
            self.unqualified,
            self.owner_known,
            owner,
            self.callable_receiver_origin,
        )?;
        Ok(DecodedReferenceHead {
            mount: self.mount,
            fragment: mount.fragment_id(),
            semantic_key: self.semantic_key,
            semantic,
            node_key: self.node_key,
            node,
            site_metadata,
            completion_kind: self.completion_kind,
            expected_reason_count: self.expected_reason_count,
        })
    }
}

#[derive(Clone)]
struct DecodedReferenceHead {
    mount: SelectedResolutionMountOrdinal,
    fragment: BindingFragmentId,
    semantic_key: i64,
    semantic: SemanticId,
    node_key: i64,
    node: BindingNodeId,
    site_metadata: Option<FactReferenceSiteMetadata>,
    completion_kind: String,
    expected_reason_count: usize,
}

#[derive(Debug)]
struct RawDefinitionNode {
    request_ordinal: usize,
    mount: SelectedResolutionMountOrdinal,
    node_key: i64,
    node_digest: [u8; 32],
}

impl RawDefinitionNode {
    fn from_row(row: &Row<'_>) -> StoreResult<Option<Self>> {
        ensure_selected_interior(row, 0, "definition lookup")?;
        if row.get::<_, Option<i64>>(3)?.is_none() {
            return Ok(None);
        }
        Ok(Some(Self {
            request_ordinal: usize_from_nonnegative(row, 1, "definition request ordinal")?,
            mount: mount_ordinal(row, 2, "definition mount")?,
            node_key: nonnegative_i64(row, 3, "definition node key")?,
            node_digest: required_digest(row, 4, "definition node digest")?,
        }))
    }
}

#[derive(Debug)]
struct RawEndpointClassification {
    local_request_ordinal: usize,
    kind: String,
    semantic_key: Option<i64>,
    semantic_space: Option<String>,
    semantic_digest: Option<[u8; 32]>,
    member_owner_key: Option<i64>,
    member_owner_space: Option<String>,
    member_owner_digest: Option<[u8; 32]>,
}

impl RawEndpointClassification {
    fn from_row(row: &Row<'_>) -> StoreResult<Self> {
        ensure_selected_interior(row, 0, "endpoint classification")?;
        if row.get::<_, Option<i64>>(3)?.is_none() {
            return Err(invalid_fact(
                "endpoint classification names a missing selected node",
            ));
        }
        Ok(Self {
            local_request_ordinal: usize_from_nonnegative(
                row,
                1,
                "endpoint local request ordinal",
            )?,
            kind: row.get(4)?,
            semantic_key: optional_nonnegative_i64(row, 5, "endpoint semantic key")?,
            semantic_space: row.get(6)?,
            semantic_digest: optional_digest(row, 7, "endpoint semantic digest")?,
            member_owner_key: optional_nonnegative_i64(row, 8, "member-scope owner key")?,
            member_owner_space: row.get(9)?,
            member_owner_digest: optional_digest(row, 10, "member-scope owner digest")?,
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn reference_site_metadata(
    site: Option<i64>,
    namespace: Option<String>,
    site_kind: Option<String>,
    start_byte: Option<i64>,
    end_byte: Option<i64>,
    unqualified: Option<i64>,
    owner_known: i64,
    owner: Option<SemanticId>,
    callable_receiver_origin: Option<String>,
) -> StoreResult<Option<FactReferenceSiteMetadata>> {
    let reference_owner = match (owner_known, owner) {
        (0, None) => None,
        (1, owner) => Some(owner),
        (0, Some(owner)) => {
            return Err(invalid_fact(format!(
                "unknown reference owner carries semantic {owner}"
            )));
        }
        (known, _) => {
            return Err(invalid_fact(format!(
                "reference owner-known flag must be 0 or 1, found {known}"
            )));
        }
    };
    let callable_receiver_origin = callable_receiver_origin
        .as_deref()
        .map(callable_receiver_origin_from_label)
        .transpose()?;
    let Some(site) = site else {
        if namespace.is_some()
            || site_kind.is_some()
            || start_byte.is_some()
            || end_byte.is_some()
            || unqualified.is_some()
            || reference_owner.is_some()
            || callable_receiver_origin.is_some()
        {
            return Err(invalid_fact(
                "reference without a source site carries partial metadata",
            ));
        }
        return Ok(None);
    };
    let site = u32::try_from(site)
        .map(ResolutionSiteId::new)
        .map_err(|_| invalid_fact(format!("reference source site is outside u32: {site}")))?;
    let namespace = namespace
        .as_deref()
        .ok_or_else(|| invalid_fact("reference site omits namespace"))
        .and_then(namespace_from_label)?;
    let site_kind = site_kind
        .as_deref()
        .ok_or_else(|| invalid_fact("reference site omits site kind"))
        .and_then(site_kind_from_label)?;
    let start_byte = start_byte
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| invalid_fact("reference site has invalid start byte"))?;
    let end_byte = end_byte
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| invalid_fact("reference site has invalid end byte"))?;
    let unqualified = match unqualified {
        Some(0) => false,
        Some(1) => true,
        value => {
            return Err(invalid_fact(format!(
                "reference unqualified flag must be 0 or 1, found {value:?}"
            )));
        }
    };
    if start_byte > end_byte {
        return Err(invalid_fact(format!(
            "reference source range is reversed: {start_byte}..{end_byte}"
        )));
    }
    if callable_receiver_origin.is_some()
        && (namespace != ResolutionNamespace::Callable
            || !matches!(
                site_kind,
                ResolutionSiteKind::CallableReference | ResolutionSiteKind::MemberReference
            ))
    {
        return Err(invalid_fact(
            "callable receiver origin belongs to a non-callable reference",
        ));
    }
    if callable_receiver_origin
        .is_some_and(|origin| unqualified != (origin == ResolutionCallableReceiverOrigin::Implicit))
    {
        return Err(invalid_fact(
            "reference qualification disagrees with callable receiver origin",
        ));
    }
    Ok(Some(FactReferenceSiteMetadata::new(
        site,
        namespace,
        site_kind,
        start_byte,
        end_byte,
        unqualified,
        reference_owner,
        callable_receiver_origin,
    )))
}

fn site_kind_from_label(label: &str) -> StoreResult<ResolutionSiteKind> {
    ResolutionSiteKind::from_label(label)
        .ok_or_else(|| invalid_fact(format!("unknown resolution site kind {label:?}")))
}

fn callable_receiver_origin_from_label(
    label: &str,
) -> StoreResult<ResolutionCallableReceiverOrigin> {
    ResolutionCallableReceiverOrigin::from_label(label)
        .ok_or_else(|| invalid_fact(format!("unknown callable receiver origin {label:?}")))
}

fn completion_from_parent(
    kind: &str,
    decoded: usize,
    reasons: BTreeSet<ResolutionIncompleteReason>,
    description: &str,
) -> StoreResult<ResolutionCompletion> {
    let kind = ResolutionCompletionKind::from_label(kind)
        .ok_or_else(|| invalid_fact(format!("unknown {description} completion kind {kind:?}")))?;
    match (kind, decoded) {
        (ResolutionCompletionKind::Complete, 0) => Ok(ResolutionCompletion::Complete),
        (ResolutionCompletionKind::Complete, count) => Err(invalid_fact(format!(
            "complete {description} carries {count} incompleteness rows"
        ))),
        (ResolutionCompletionKind::Incomplete, 0) => Err(invalid_fact(format!(
            "incomplete {description} has no incompleteness row"
        ))),
        (ResolutionCompletionKind::Incomplete, _) => Ok(completion_from_set(reasons)),
    }
}

fn combine_evidence(
    completions: impl IntoIterator<Item = ResolutionCompletion>,
) -> ResolutionCompletion {
    let mut evidence = crate::analyzer::resolution::ResolutionCompletionAccumulator::default();
    for completion in completions {
        evidence.include(&completion);
    }
    evidence.finish()
}

fn with_cancelled(completion: ResolutionCompletion) -> ResolutionCompletion {
    combine_evidence([
        completion,
        ResolutionCompletion::incomplete([ResolutionIncompleteReason::Cancelled]),
    ])
}

/// One candidate page's decoded identities, checked against each other.
///
/// This used to be a staging area for the operation rebaser: every identity a
/// page decoded was registered there when the page published, so that a later
/// reader could map the runtime ID back to its storage coordinate. A runtime
/// ID now names its own mount, and a persisted node, path or stack variable
/// carries its local key in its own last eight bytes, so there is nothing to
/// hand on. What is left is worth keeping on its own: one coordinate of one
/// mount names one identity, and a page that decodes the same coordinate
/// twice with different identities has read inconsistent rows.
pub(super) struct IdentityStage<'names> {
    /// Where a persisted shared semantic's stored digest becomes the id the
    /// heap holds. It is the request's own memoized table, so a name repeated
    /// across a batch's rows is one seek.
    names: &'names dyn crate::analyzer::resolution::SharedNameInterner,
    semantics:
        BTreeMap<(SelectedResolutionMountOrdinal, ResolutionLocalKey), ResolutionSemanticIdentity>,
    nodes: BTreeMap<(SelectedResolutionMountOrdinal, ResolutionLocalKey), ResolutionNodeIdentity>,
    paths: BTreeMap<(SelectedResolutionMountOrdinal, ResolutionLocalKey), ResolutionPathIdentity>,
    variables: BTreeMap<
        (SelectedResolutionMountOrdinal, ResolutionLocalKey),
        ResolutionStackVariableIdentity,
    >,
}

impl<'names> IdentityStage<'names> {
    pub(super) fn new(names: &'names dyn crate::analyzer::resolution::SharedNameInterner) -> Self {
        Self {
            names,
            semantics: BTreeMap::new(),
            nodes: BTreeMap::new(),
            paths: BTreeMap::new(),
            variables: BTreeMap::new(),
        }
    }

    pub(super) fn semantic(
        &mut self,
        mount: &SelectedResolutionMountRecord,
        key: i64,
        space: String,
        digest: [u8; 32],
    ) -> StoreResult<SemanticId> {
        let key = ResolutionLocalKey::new(key);
        let identity = match space.as_str() {
            "fragment_local" => ResolutionSemanticIdentity::fragment_local(digest),
            "shared" => ResolutionSemanticIdentity::shared(self.names.intern(digest)),
            _ => {
                return Err(invalid_fact(format!(
                    "unknown resolution semantic identity space {space:?}"
                )));
            }
        };
        insert_staged_identity(
            &mut self.semantics,
            (mount.ordinal(), key),
            identity,
            "semantic",
        )?;
        // A row's storage-local key is the position the identity occupies in
        // its blob's catalog, and a local runtime id is the mount ordinal and
        // that position. So the key the row already carries *is* the id, and
        // the identity the row also carries is evidence rather than input.
        Ok(identity.mounted(mount.ordinal().get(), local_key_u32(key)?))
    }

    pub(super) fn node(
        &mut self,
        mount: &SelectedResolutionMountRecord,
        key: i64,
        digest: [u8; 32],
    ) -> StoreResult<BindingNodeId> {
        let key = ResolutionLocalKey::new(key);
        let identity = ResolutionNodeIdentity::new(digest);
        insert_staged_identity(&mut self.nodes, (mount.ordinal(), key), identity, "node")?;
        Ok(BindingNodeId::local(
            mount.ordinal().get(),
            local_key_u32(key)?,
        ))
    }

    pub(super) fn path(
        &mut self,
        mount: &SelectedResolutionMountRecord,
        key: i64,
        digest: [u8; 32],
    ) -> StoreResult<PartialPathId> {
        let key = ResolutionLocalKey::new(key);
        let identity = ResolutionPathIdentity::new(digest);
        insert_staged_identity(&mut self.paths, (mount.ordinal(), key), identity, "path")?;
        Ok(PartialPathId::local(
            mount.ordinal().get(),
            local_key_u32(key)?,
        ))
    }

    fn variable(
        &mut self,
        mount: &SelectedResolutionMountRecord,
        key: i64,
        digest: [u8; 32],
    ) -> StoreResult<StackVariableId> {
        let key = ResolutionLocalKey::new(key);
        let identity = ResolutionStackVariableIdentity::new(digest);
        insert_staged_identity(
            &mut self.variables,
            (mount.ordinal(), key),
            identity,
            "stack variable",
        )?;
        Ok(StackVariableId::local(
            mount.ordinal().get(),
            local_key_u32(key)?,
        ))
    }
}

/// One storage-local key as the catalog position it is.
fn local_key_u32(key: ResolutionLocalKey) -> StoreResult<u32> {
    u32::try_from(key.get()).map_err(|_| {
        invalid_fact(format!(
            "a persisted local key is a catalog position and fits u32: {key:?}"
        ))
    })
}

fn insert_staged_identity<Key, Identity>(
    identities: &mut BTreeMap<Key, Identity>,
    key: Key,
    identity: Identity,
    label: &str,
) -> StoreResult<()>
where
    Key: Copy + Ord + std::fmt::Debug,
    Identity: Copy + Eq + std::fmt::Debug,
{
    if let Some(previous) = identities.insert(key, identity)
        && previous != identity
    {
        return Err(invalid_fact(format!(
            "selected resolution {label} coordinate {key:?} has conflicting identities {previous:?} and {identity:?}"
        )));
    }
    Ok(())
}

#[derive(Debug)]
struct RawSemanticSite {
    mount: SelectedResolutionMountOrdinal,
    namespace: String,
    role: String,
    semantic_key: i64,
    semantic_space: String,
    semantic_digest: [u8; 32],
    node_key: i64,
    node_digest: [u8; 32],
}

impl RawSemanticSite {
    fn from_row(row: &Row<'_>, base: usize) -> StoreResult<Self> {
        Ok(Self {
            mount: mount_ordinal(row, base, "semantic site mount")?,
            namespace: row.get(base + 2)?,
            role: row.get(base + 3)?,
            semantic_key: nonnegative_i64(row, base + 4, "semantic site semantic key")?,
            semantic_space: row.get(base + 5)?,
            semantic_digest: required_digest(row, base + 6, "semantic site identity digest")?,
            node_key: nonnegative_i64(row, base + 7, "semantic site node key")?,
            node_digest: required_digest(row, base + 8, "semantic site node digest")?,
        })
    }
}

enum CompletionRead {
    Exhausted(ResolutionCompletion),
    Cancelled(ResolutionCompletion),
}

impl CompletionRead {
    fn completion(&self) -> &ResolutionCompletion {
        match self {
            Self::Exhausted(completion) | Self::Cancelled(completion) => completion,
        }
    }

    fn is_cancelled(&self) -> bool {
        matches!(self, Self::Cancelled(_))
    }
}

#[derive(Debug)]
struct RawCompletionReason {
    position: i64,
    kind: String,
    cyclic_path_key: Option<i64>,
    cyclic_path_digest: Option<[u8; 32]>,
    semantic_key: Option<i64>,
    semantic_space: Option<String>,
    semantic_digest: Option<[u8; 32]>,
    boundary_status: Option<String>,
}

impl RawCompletionReason {
    fn from_gap_row(row: &Row<'_>, base: usize) -> StoreResult<Self> {
        Ok(Self {
            position: nonnegative_i64(row, base, "gap key")?,
            kind: row.get(base + 1)?,
            cyclic_path_key: optional_nonnegative_i64(row, base + 2, "cyclic path key")?,
            cyclic_path_digest: optional_digest(row, base + 3, "cyclic path digest")?,
            semantic_key: optional_nonnegative_i64(row, base + 4, "reason semantic key")?,
            semantic_space: row.get(base + 5)?,
            semantic_digest: optional_digest(row, base + 6, "reason semantic digest")?,
            boundary_status: row.get(base + 7)?,
        })
    }

    fn mount(
        self,
        mount: &SelectedResolutionMountRecord,
        identities: &mut IdentityStage<'_>,
    ) -> StoreResult<ResolutionIncompleteReason> {
        let path = mount_optional_path(
            identities,
            mount,
            self.cyclic_path_key,
            self.cyclic_path_digest,
        )?;
        let semantic = mount_optional_semantic(
            identities,
            mount,
            self.semantic_key,
            self.semantic_space,
            self.semantic_digest,
        )?;
        incomplete_reason_from_parts(&self.kind, path, semantic, self.boundary_status.as_deref())
    }
}

struct RawCompletionBatchRow {
    mount: SelectedResolutionMountOrdinal,
    mount_ordinal: usize,
    reason: RawCompletionReason,
}

/// One SQL-grouped root completion reason. The source row count is retained
/// so the reader can prove that aggregation did not amplify or invent rows
/// relative to the sealed per-mount candidate count.
struct RawRootCandidateCompletionRow {
    mount: SelectedResolutionMountOrdinal,
    reason: RawCompletionReason,
    reason_count: usize,
    is_fragment_scope: bool,
}

impl RawRootCandidateCompletionRow {
    fn from_row(row: &Row<'_>) -> StoreResult<Self> {
        let scope = row.get::<_, String>(10)?;
        let is_fragment_scope = match scope.as_str() {
            "fragment" => true,
            "endpoint" => false,
            _ => {
                return Err(invalid_fact(format!(
                    "root candidate completion returned unknown coverage scope {scope:?}"
                )));
            }
        };
        Ok(Self {
            mount: mount_ordinal(row, 0, "root candidate completion mount")?,
            reason: RawCompletionReason::from_gap_row(row, 1)?,
            reason_count: usize_from_nonnegative(row, 9, "root candidate completion row count")?,
            is_fragment_scope,
        })
    }
}

impl RawCompletionBatchRow {
    fn from_row(row: &Row<'_>) -> StoreResult<Self> {
        Ok(Self {
            mount: mount_ordinal(row, 1, "selected gap batch mount")?,
            mount_ordinal: usize_from_nonnegative(row, 10, "selected gap batch ordinal")?,
            reason: RawCompletionReason::from_gap_row(row, 2)?,
        })
    }
}

fn completion_from_set(reasons: BTreeSet<ResolutionIncompleteReason>) -> ResolutionCompletion {
    if reasons.is_empty() {
        ResolutionCompletion::Complete
    } else {
        ResolutionCompletion::Incomplete(reasons.into_iter().collect::<Vec<_>>().into())
    }
}

fn namespace_from_label(label: &str) -> StoreResult<ResolutionNamespace> {
    ResolutionNamespace::from_label(label)
        .ok_or_else(|| invalid_fact(format!("unknown resolution namespace {label:?}")))
}

fn mount_optional_path(
    identities: &mut IdentityStage<'_>,
    mount: &SelectedResolutionMountRecord,
    key: Option<i64>,
    digest: Option<[u8; 32]>,
) -> StoreResult<Option<PartialPathId>> {
    match (key, digest) {
        (None, None) => Ok(None),
        (Some(key), Some(digest)) => identities.path(mount, key, digest).map(Some),
        values => Err(invalid_fact(format!(
            "partial path key and digest disagree: {values:?}"
        ))),
    }
}

fn mount_optional_semantic(
    identities: &mut IdentityStage<'_>,
    mount: &SelectedResolutionMountRecord,
    key: Option<i64>,
    space: Option<String>,
    digest: Option<[u8; 32]>,
) -> StoreResult<Option<SemanticId>> {
    match (key, space, digest) {
        (None, None, None) => Ok(None),
        (Some(key), Some(space), Some(digest)) => {
            identities.semantic(mount, key, space, digest).map(Some)
        }
        values => Err(invalid_fact(format!(
            "semantic key and identity descriptor disagree: {values:?}"
        ))),
    }
}

fn boundary_node_from_key(key: i64) -> StoreResult<BindingNodeId> {
    if key != BindingNodeId::UNIVERSAL_ROOT_BOUNDARY_KEY {
        return Err(invalid_fact(format!(
            "unknown resolution boundary node key {key}"
        )));
    }
    Ok(BindingNodeId::universal_root())
}

fn incomplete_reason_from_parts(
    kind: &str,
    path: Option<PartialPathId>,
    semantic: Option<SemanticId>,
    boundary_status: Option<&str>,
) -> StoreResult<ResolutionIncompleteReason> {
    let kind = ResolutionCompletionReasonKind::from_label(kind)
        .ok_or_else(|| invalid_fact(format!("unknown completion reason kind {kind:?}")))?;
    match (kind, path, semantic, boundary_status) {
        (ResolutionCompletionReasonKind::CyclicExpansion, Some(path), None, None) => {
            Ok(ResolutionIncompleteReason::CyclicExpansion(path))
        }
        (ResolutionCompletionReasonKind::InconsistentPrecedence, None, Some(semantic), None) => {
            Ok(ResolutionIncompleteReason::InconsistentPrecedence(semantic))
        }
        (ResolutionCompletionReasonKind::OpenBoundary, None, Some(semantic), Some(status)) => {
            let status = BoundaryStatus::from_label(status).ok_or_else(|| {
                invalid_fact(format!("unknown resolution boundary status {status:?}"))
            })?;
            Ok(ResolutionIncompleteReason::OpenBoundary { semantic, status })
        }
        (ResolutionCompletionReasonKind::UnsupportedSemantic, None, Some(semantic), None) => {
            Ok(ResolutionIncompleteReason::UnsupportedSemantic(semantic))
        }
        _ => Err(invalid_fact(format!(
            "completion reason {kind:?} has inconsistent local payload"
        ))),
    }
}

/// Is one selected mount inside a root read's mount scope?
///
/// `RustRootHalfMounts::new` sorts and deduplicates the ordinals it collects,
/// so membership is a binary search. The linear `contains` this replaces was
/// evaluated once per unconditional reason, once per boundary branch row and
/// once per candidate position, making a scoped read quadratic in its scope.
fn scope_admits(
    scope: &[SelectedResolutionMountOrdinal],
    mount: SelectedResolutionMountOrdinal,
) -> bool {
    debug_assert!(
        scope.is_sorted(),
        "a root read's mount scope is sorted and deduplicated: {scope:?}"
    );
    scope.binary_search(&mount).is_ok()
}

/// One root read's mount scope as the JSON array `json_each` binds.
fn scope_ordinal_array(scope: &[SelectedResolutionMountOrdinal]) -> String {
    use std::fmt::Write as _;
    let mut array = String::with_capacity(scope.len() * 8 + 2);
    array.push('[');
    for (index, ordinal) in scope.iter().enumerate() {
        let separator = if index == 0 { "" } else { "," };
        write!(array, "{separator}{}", ordinal.get()).expect("writing to a String cannot fail");
    }
    array.push(']');
    array
}

fn mount_ordinal(
    row: &Row<'_>,
    column: usize,
    description: &str,
) -> StoreResult<SelectedResolutionMountOrdinal> {
    let value = nonnegative_i64(row, column, description)?;
    let value = u32::try_from(value)
        .map_err(|_| invalid_fact(format!("{description} is outside u32: {value}")))?;
    Ok(SelectedResolutionMountOrdinal::new(value))
}

/// One candidate gap header identity column, as the 32-byte digest the schema
/// requires. The `CHECK` constraint holds it on write; this states the same
/// width at the read boundary so a corrupt cache reports the column and the
/// mount instead of passing a short slice into identity construction.
/// One candidate gap header row's reason, as the row states it.
///
/// A local runtime id is its mount's ordinal and the position the identity
/// occupies in that mount's catalog. The header row carries that position in
/// `reason_semantic_key`, so a reader that has the row and the mount has the
/// reason, with nothing to open and nothing to translate.
fn gap_reason_semantic(
    row: &Row<'_>,
    column: usize,
    ordinal: SelectedResolutionMountOrdinal,
    description: &str,
) -> StoreResult<SemanticId> {
    let key = nonnegative_i64(row, column, description)?;
    let key = u32::try_from(key).map_err(|_| {
        invalid_fact(format!(
            "{description} key for mount {ordinal:?} does not fit a local key: {key}"
        ))
    })?;
    Ok(SemanticId::local(ordinal.get(), key))
}

fn gap_identity_digest(
    digest: &[u8],
    ordinal: SelectedResolutionMountOrdinal,
    description: &str,
) -> StoreResult<[u8; 32]> {
    digest.try_into().map_err(|_| {
        invalid_fact(format!(
            "{description} identity for mount {ordinal:?} is {} bytes, not 32",
            digest.len()
        ))
    })
}

fn nonnegative_i64(row: &Row<'_>, column: usize, description: &str) -> StoreResult<i64> {
    let value = row.get::<_, i64>(column)?;
    if value < 0 {
        return Err(invalid_fact(format!(
            "{description} cannot be negative: {value}"
        )));
    }
    Ok(value)
}

fn usize_from_nonnegative(row: &Row<'_>, column: usize, description: &str) -> StoreResult<usize> {
    let value = nonnegative_i64(row, column, description)?;
    usize::try_from(value)
        .map_err(|_| invalid_fact(format!("{description} does not fit usize: {value}")))
}

fn optional_nonnegative_i64(
    row: &Row<'_>,
    column: usize,
    description: &str,
) -> StoreResult<Option<i64>> {
    let value = row.get::<_, Option<i64>>(column)?;
    if value.is_some_and(|value| value < 0) {
        return Err(invalid_fact(format!(
            "{description} cannot be negative: {value:?}"
        )));
    }
    Ok(value)
}

fn required_digest(row: &Row<'_>, column: usize, description: &str) -> StoreResult<[u8; 32]> {
    let value = row.get::<_, Vec<u8>>(column)?;
    value.try_into().map_err(|value: Vec<u8>| {
        invalid_fact(format!(
            "{description} must contain 32 bytes, found {}",
            value.len()
        ))
    })
}

fn optional_digest(
    row: &Row<'_>,
    column: usize,
    description: &str,
) -> StoreResult<Option<[u8; 32]>> {
    row.get::<_, Option<Vec<u8>>>(column)?
        .map(|value| {
            value.try_into().map_err(|value: Vec<u8>| {
                invalid_fact(format!(
                    "{description} must contain 32 bytes, found {}",
                    value.len()
                ))
            })
        })
        .transpose()
}

fn invalid_fact(message: impl Into<String>) -> StoreError {
    StoreError::new(format!(
        "invalid selected resolution fact: {}",
        message.into()
    ))
}

fn ensure_selected_interior(row: &Row<'_>, column: usize, operation: &str) -> StoreResult<()> {
    if row.get::<_, Option<i64>>(column)?.is_none() {
        return Err(StoreError::stale_resolution(format!(
            "selected resolution interior changed during {operation}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod root_prefix_tests {
    use super::*;

    fn request(symbols: Vec<SemanticId>) -> BatchCandidateRequest {
        BatchCandidateRequest::new(
            0,
            EndpointSignature::new_scoped(
                BindingNodeId::universal_root(),
                StackPattern::new(
                    symbols
                        .into_iter()
                        .map(PartialScopedSymbol::unscoped)
                        .collect::<Vec<_>>(),
                    None,
                ),
                StackPattern::new(Vec::<BindingNodeId>::new(), None),
            ),
        )
    }

    #[test]
    fn root_prefix_uses_stored_alias_and_keeps_unmapped_open_prefix() {
        #[derive(Debug)]
        struct AliasedNames;
        impl crate::analyzer::resolution::SharedNameInterner for AliasedNames {
            fn intern(&self, _: [u8; 32]) -> SharedNameId {
                unimplemented!()
            }
            fn to_persisted(&self, name: SharedNameId) -> Option<SharedNameId> {
                (name == SharedNameId::per_request(7)).then(|| SharedNameId::interned(42))
            }
        }
        let token = CancellationToken::new();
        for (symbols, complete) in [
            (
                vec![SemanticId::shared_name(SharedNameId::per_request(7))],
                1,
            ),
            (
                vec![
                    SemanticId::shared_name(SharedNameId::per_request(7)),
                    SemanticId::shared_name(SharedNameId::per_request(8)),
                ],
                0,
            ),
        ] {
            let encoded = root_candidate_request(
                &AliasedNames,
                0,
                &request(symbols),
                SelectedResolutionMountOrdinal::new(7),
                &token,
            )
            .unwrap();
            let value: serde_json::Value = serde_json::from_str(&encoded).unwrap();
            assert_eq!(value[1], "[[null,42,0]]");
            assert_eq!(value[3], complete);
            assert_eq!(
                value[4].as_array().unwrap().len(),
                if complete == 1 { 1 } else { 2 }
            );
        }
    }

    #[test]
    fn root_prefix_offsets_preserve_empty_foreign_and_context_boundaries() {
        let mount = SelectedResolutionMountOrdinal::new(7);
        let cancellation = CancellationToken::new();
        for foreign in [SemanticId::local(8, 12), SemanticId::operation_local(12)] {
            let req = request(vec![SemanticId::local(7, 1), foreign]);
            let encoded = root_candidate_request(
                crate::analyzer::resolution::test_shared_names(),
                3,
                &req,
                mount,
                &cancellation,
            )
            .unwrap();
            let value: serde_json::Value = serde_json::from_str(&encoded).unwrap();
            assert_eq!(value, serde_json::json!([3, "[[1,null,0]]", 0, 0, [1, 11]]));
        }
        let empty = root_candidate_request(
            crate::analyzer::resolution::test_shared_names(),
            0,
            &request(vec![]),
            mount,
            &cancellation,
        )
        .unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&empty).unwrap(),
            serde_json::json!([0, "[]", 0, 1, []])
        );
        let complete = root_candidate_request(
            crate::analyzer::resolution::test_shared_names(),
            0,
            &request(vec![SemanticId::local(7, 1)]),
            mount,
            &cancellation,
        )
        .unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&complete).unwrap(),
            serde_json::json!([0, "[[1,null,0]]", 0, 1, [1]])
        );
    }

    #[test]
    fn root_prefix_preparation_is_linear_and_observes_cancellation() {
        let mount = SelectedResolutionMountOrdinal::new(7);
        let cancellation = CancellationToken::new();
        let mut sizes = Vec::new();
        for length in [1024, 2048, 4096] {
            let req = request((0..length).map(|key| SemanticId::local(7, key)).collect());
            let encoded = root_candidate_request(
                crate::analyzer::resolution::test_shared_names(),
                0,
                &req,
                mount,
                &cancellation,
            )
            .unwrap();
            let value: serde_json::Value = serde_json::from_str(&encoded).unwrap();
            assert_eq!(value[4].as_array().unwrap().len(), length as usize);
            assert!(encoded.len() < length as usize * 24);
            sizes.push(encoded.len());
        }
        assert!(sizes[2] < sizes[0] * 5, "{sizes:?}");
        cancellation.cancel();
        assert!(
            root_candidate_request(
                crate::analyzer::resolution::test_shared_names(),
                0,
                &request(vec![]),
                mount,
                &cancellation
            )
            .is_none()
        );
        assert!(
            root_candidate_request(
                crate::analyzer::resolution::test_shared_names(),
                0,
                &request(vec![SemanticId::local(7, 0)]),
                mount,
                &cancellation
            )
            .is_none()
        );
    }

    #[test]
    fn root_prefix_production_batch_matches_admission_oracle_after_endpoint_decode() {
        use brokk_bifrost_core::cache_gc::PlannerStatisticsState;
        let mount = SelectedResolutionMountOrdinal::new(7);
        let cancellation = CancellationToken::new();
        let alphabet = [(0, false), (1, false), (10, true), (-1, false), (-10, true)];
        let mut sequences = vec![Vec::new()];
        for length in 1..=3 {
            for number in 0usize..alphabet.len().pow(length) {
                let mut number = number;
                sequences.push(
                    (0..length)
                        .map(|_| {
                            let cell = alphabet[number % alphabet.len()];
                            number /= alphabet.len();
                            cell
                        })
                        .collect(),
                );
            }
        }
        let endpoint = |sequence: &Vec<(i64, bool)>, tail: bool| {
            EndpointSignature::new_scoped(
                BindingNodeId::universal_root(),
                StackPattern::new(
                    sequence
                        .iter()
                        .map(|&(id, scoped)| {
                            let id = if id < 0 {
                                SemanticId::shared_name(SharedNameId::interned(-id))
                            } else {
                                SemanticId::local(7, u32::try_from(id).unwrap())
                            };
                            if scoped {
                                PartialScopedSymbol::scoped(
                                    id,
                                    StackPattern::new(Vec::<BindingNodeId>::new(), None),
                                )
                            } else {
                                PartialScopedSymbol::unscoped(id)
                            }
                        })
                        .collect::<Vec<_>>(),
                    tail.then(|| StackVariableId::local(7, 0)),
                ),
                StackPattern::new(Vec::<BindingNodeId>::new(), None),
            )
        };
        let mut candidates = sequences
            .iter()
            .flat_map(|sequence| [false, true].map(|tail| endpoint(sequence, tail)))
            .collect::<Vec<_>>();
        candidates.push(candidates[0].clone()); // Equal endpoints retain distinct path identities.
        let mut requests = candidates
            .iter()
            .cloned()
            .enumerate()
            .map(|(i, e)| BatchCandidateRequest::new(i, e))
            .collect::<Vec<_>>();
        for foreign in [SemanticId::local(8, 1), SemanticId::operation_local(1)] {
            for sequence in &sequences {
                let mut symbols = endpoint(sequence, false).symbols().fixed().to_vec();
                symbols.push(PartialScopedSymbol::unscoped(foreign));
                requests.push(BatchCandidateRequest::new(
                    requests.len(),
                    EndpointSignature::new_scoped(
                        BindingNodeId::universal_root(),
                        StackPattern::new(symbols, None),
                        StackPattern::new(Vec::<BindingNodeId>::new(), None),
                    ),
                ));
            }
        }
        let nonroot_endpoint = EndpointSignature::new_scoped(
            BindingNodeId::local(7, 0),
            StackPattern::new(
                vec![PartialScopedSymbol::unscoped(SemanticId::shared_name(
                    SharedNameId::interned(1),
                ))],
                None,
            ),
            StackPattern::new(Vec::<BindingNodeId>::new(), None),
        );
        let context = PathBodyContext {
            fragment: BindingFragmentId::at_ordinal(7),
        };
        for state in PlannerStatisticsState::BOTH {
            let store = super::super::AnalyzerStore::open_ephemeral().unwrap();
            let conn = store.conn.lock().unwrap();
            // The fixture isolates path reads; schema seal/FK laws have separate core fixtures.
            conn.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
            for (path, candidate) in candidates.iter().enumerate() {
                let mut key = RootKeyBuilder::default();
                let symbols = candidate
                    .symbols()
                    .fixed()
                    .iter()
                    .map(|symbol| {
                        let signed = if let Some(id) = symbol.symbol().shared_name_id() {
                            let id = i64::from(id.get());
                            key.push(None, Some(id), symbol.scopes().is_some());
                            -id
                        } else {
                            let id = i64::from(symbol.symbol().local_key().unwrap());
                            key.push(Some(id), None, symbol.scopes().is_some());
                            id
                        };
                        if symbol.scopes().is_some() {
                            serde_json::json!([signed, [], null])
                        } else {
                            serde_json::json!(signed)
                        }
                    })
                    .collect::<Vec<_>>();
                let tail = candidate.symbols().tail().map(|_| 0);
                let body =
                    serde_json::json!([[], null, [], null, symbols, tail, [], null, [], [], []])
                        .to_string();
                conn.execute("INSERT INTO resolution_paths(blob_id,path,start_node,start_lead_scoped,end_node,end_lead_scoped,body,end_fixed_key,end_open_tail) VALUES(1,?1,-1,0,-1,0,jsonb(?2),?3,?4)", params![path as i64, body, key.finish().0, i64::from(tail.is_some())]).unwrap();
            }
            conn.execute("INSERT INTO resolution_paths(blob_id,path,start_node,start_lead_scoped,end_node,end_lead_identity,end_lead_scoped,body) VALUES(1,1000000,-1,0,0,1,0,jsonb('[[],null,[],null,[-1],null,[],null,[],[],[]]'))", []).unwrap();
            state.install(&conn);
            for batch in requests.chunks(MAX_SOURCE_ROWS_PER_BATCH - 2) {
                let encoded = format!(
                    "[{}]",
                    batch
                        .iter()
                        .enumerate()
                        .map(|(ordinal, request)| root_candidate_request(
                            crate::analyzer::resolution::test_shared_names(),
                            ordinal,
                            request,
                            mount,
                            &cancellation
                        )
                        .unwrap())
                        .collect::<Vec<_>>()
                        .join(",")
                );
                let mut statement = conn
                    .prepare(RESOLUTION_REVERSE_CANDIDATE_MATCH_SQL)
                    .unwrap();
                assert_eq!(statement.parameter_count(), 5);
                let keyed = format!("[[{},0,1,null,0]]", batch.len());
                let open = format!("[[{},0]]", batch.len());
                let whole = format!("[[{},0]]", batch.len() + 1);
                let mut rows = statement
                    .query(params![1, keyed, open, whole, encoded])
                    .unwrap();
                let mut actual = Vec::new();
                while let Some(row) = rows.next().unwrap() {
                    let ordinal: usize = row.get(0).unwrap();
                    let path: usize = row.get(1).unwrap();
                    let cells: String = row.get(4).unwrap();
                    let decoded = decode_selected_endpoint(
                        &context,
                        row.get(3).unwrap(),
                        &parse_endpoint_cells(&cells),
                    );
                    if ordinal < batch.len() {
                        assert!(
                            batch[ordinal].admits_candidate(&decoded),
                            "{state}: {ordinal} {path}"
                        );
                    } else {
                        assert!(ordinal <= batch.len() + 1);
                        assert_eq!(decoded, nonroot_endpoint);
                        assert_eq!(path, 1000000);
                    }
                    actual.push((ordinal, path));
                }
                actual.sort_unstable();
                let mut expected = batch
                    .iter()
                    .enumerate()
                    .flat_map(|(ordinal, request)| {
                        candidates
                            .iter()
                            .enumerate()
                            .filter_map(move |(path, candidate)| {
                                request
                                    .admits_candidate(candidate)
                                    .then_some((ordinal, path))
                            })
                    })
                    .collect::<Vec<_>>();
                expected.extend([(batch.len(), 1000000), (batch.len() + 1, 1000000)]);
                assert_eq!(actual, expected, "{state}");
            }
        }
    }

    #[test]
    fn root_prefix_sql_work_ignores_unrelated_rows_and_cancels_long_seeks() {
        use brokk_bifrost_core::cache_gc::PlannerStatisticsState;
        let mount = SelectedResolutionMountOrdinal::new(7);
        let cancellation = CancellationToken::new();
        let short_request = request(vec![SemanticId::shared_name(SharedNameId::interned(1)); 3]);
        for state in PlannerStatisticsState::BOTH {
            let store = super::super::AnalyzerStore::open_ephemeral().unwrap();
            let conn = store.conn.lock().unwrap();
            conn.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
            let insert = |path: i64, last: i64| {
                let mut key = RootKeyBuilder::default();
                for id in [1, 1, last] {
                    key.push(None, Some(id), false);
                }
                let body = serde_json::json!([
                    [],
                    null,
                    [],
                    null,
                    [-1, -1, -last],
                    null,
                    [],
                    null,
                    [],
                    [],
                    []
                ])
                .to_string();
                conn.execute("INSERT INTO resolution_paths(blob_id,path,start_node,start_lead_scoped,end_node,end_lead_identity,end_lead_scoped,body,end_fixed_key,end_open_tail) VALUES(1,?1,-1,0,-1,1,0,jsonb(?2),?3,0)", params![path, body, key.finish().0]).unwrap();
            };
            insert(0, 1);
            state.install(&conn);
            let measure = |count: usize| {
                let array = format!(
                    "[{}]",
                    (0..count)
                        .map(|ordinal| root_candidate_request(
                            crate::analyzer::resolution::test_shared_names(),
                            ordinal,
                            &short_request,
                            mount,
                            &cancellation
                        )
                        .unwrap())
                        .collect::<Vec<_>>()
                        .join(",")
                );
                let mut statement = conn
                    .prepare(RESOLUTION_REVERSE_CANDIDATE_MATCH_SQL)
                    .unwrap();
                let rows = statement
                    .query_map(params![1, "[]", "[]", "[]", array], |row| {
                        Ok((
                            row.get::<_, usize>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, String>(4)?,
                        ))
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap();
                assert_eq!(rows.len(), count);
                assert!(
                    rows.iter()
                        .all(|(_, path, body)| *path == 0 && body == "[[-1,-1,-1],null,[],null]")
                );
                statement.get_status(rusqlite::StatementStatus::VmStep)
            };
            let before = [1, 16, 256].map(measure);
            for path in 1..=4096 {
                insert(path, path + 1000);
            }
            state.install(&conn);
            let after = [1, 16, 256].map(measure);
            // A matching row that is no longer the index's final row adds
            // one boundary check per request, not a scan of unrelated rows.
            for ((before, after), requests) in before.into_iter().zip(after).zip([1, 16, 256]) {
                assert!(
                    after <= before + requests,
                    "{state}: unrelated rows added unbounded work: {before} -> {after}"
                );
            }
            eprintln!("root prefix {state} VM work for batches 1/16/256: {after:?}");
            let long = request(vec![
                SemanticId::shared_name(SharedNameId::interned(1));
                4096
            ]);
            let encoded = format!(
                "[{}]",
                root_candidate_request(
                    crate::analyzer::resolution::test_shared_names(),
                    0,
                    &long,
                    mount,
                    &cancellation
                )
                .unwrap()
            );
            let stopped = CancellationToken::new();
            let result = with_resolution_read_progress_handler(&conn, &stopped, |conn| {
                stopped.cancel();
                let mut statement = conn.prepare(RESOLUTION_REVERSE_CANDIDATE_MATCH_SQL)?;
                let mut rows = statement.query(params![1, "[]", "[]", "[]", encoded])?;
                while rows.next()?.is_some() {}
                Ok(())
            });
            assert!(result.unwrap_err().to_string().contains("interrupted"));
            assert_eq!(
                conn.query_row("SELECT 1", [], |row| row.get::<_, i64>(0))
                    .unwrap(),
                1
            );
        }
    }
}

impl crate::analyzer::resolution::SelectedContextPathSource
    for SelectedResolutionLexicalSource<'_, '_>
{
    fn visit_context_forward_additions(
        &self,
        context: crate::analyzer::resolution::SelectedContextPathToken,
        requests: &[BatchCandidateRequest],
        completion: BatchCandidateCompletionOutcome,
        maximum_page_rows: usize,
        cancellation: &CancellationToken,
        session: Option<&ResolutionSession>,
        visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
    ) -> StoreResult<BatchCandidateCompletionOutcome> {
        self.visit_context_additions(
            context,
            requests,
            completion,
            maximum_page_rows,
            cancellation,
            session,
            visitor,
            stage::CONTEXT_FORWARD_CANDIDATES_SQL,
        )
    }

    fn visit_context_reverse_additions(
        &self,
        context: crate::analyzer::resolution::SelectedContextPathToken,
        requests: &[BatchCandidateRequest],
        completion: BatchCandidateCompletionOutcome,
        maximum_page_rows: usize,
        cancellation: &CancellationToken,
        session: Option<&ResolutionSession>,
        visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
    ) -> StoreResult<BatchCandidateCompletionOutcome> {
        self.visit_context_additions(
            context,
            requests,
            completion,
            maximum_page_rows,
            cancellation,
            session,
            visitor,
            stage::CONTEXT_REVERSE_CANDIDATES_SQL,
        )
    }

    fn context_paths(
        &self,
        context: crate::analyzer::resolution::SelectedContextPathToken,
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<(CandidatePathIdentity, PartialPath)>>> {
        stage::context_paths(self.selection, context, cancellation)
    }

    fn hydrate_context_paths(
        &self,
        context: crate::analyzer::resolution::SelectedContextPathToken,
        candidates: &[CandidatePathIdentity],
        cancellation: &CancellationToken,
    ) -> StoreResult<Option<Vec<(CandidatePathIdentity, PartialPath)>>> {
        stage::hydrate_context_paths(self.selection, context, candidates, cancellation)
    }
}

impl SelectedResolutionLexicalSource<'_, '_> {
    #[allow(clippy::too_many_arguments)]
    fn visit_context_additions(
        &self,
        context: crate::analyzer::resolution::SelectedContextPathToken,
        requests: &[BatchCandidateRequest],
        completion: BatchCandidateCompletionOutcome,
        maximum_page_rows: usize,
        cancellation: &CancellationToken,
        session: Option<&ResolutionSession>,
        visitor: &mut dyn FnMut(&[BatchCandidateMatch]) -> StoreResult<bool>,
        sql: &str,
    ) -> StoreResult<BatchCandidateCompletionOutcome> {
        assert!((1..=MAX_SOURCE_ROWS_PER_BATCH).contains(&maximum_page_rows));
        assert_eq!(requests.len(), completion.branch_completions().len());
        if cancellation.is_cancelled()
            || completion
                .unconditional_completion()
                .contains_reason(ResolutionIncompleteReason::Cancelled)
        {
            return candidate_completion_after_visit(
                requests.len(),
                completion,
                CandidatePageVisit::Cancelled,
                cancellation,
            );
        }
        let Some(rows) =
            stage::context_candidate_rows(self.selection, context, requests, sql, cancellation)?
        else {
            return candidate_completion_after_visit(
                requests.len(),
                completion,
                CandidatePageVisit::Cancelled,
                cancellation,
            );
        };
        let mut page = Vec::with_capacity(maximum_page_rows);
        for (ordinal, identity) in rows {
            // The former context cursor charges only offered rows. Unlike the
            // stage aggregate, budget exhaustion discards its pending page
            // and adds cancellation to the supplied once-read base coverage.
            if cancellation.is_cancelled() || session.is_some_and(|session| !session.scope_step()) {
                return candidate_completion_after_visit(
                    requests.len(),
                    completion,
                    CandidatePageVisit::Cancelled,
                    cancellation,
                );
            }
            page.push(BatchCandidateMatch::new(identity, ordinal));
            if page.len() == maximum_page_rows {
                let keep_going = visitor(&page)?;
                if cancellation.is_cancelled() {
                    return candidate_completion_after_visit(
                        requests.len(),
                        completion,
                        CandidatePageVisit::Cancelled,
                        cancellation,
                    );
                }
                if !keep_going {
                    return Ok(completion);
                }
                page.clear();
            }
        }
        if !page.is_empty() && !cancellation.is_cancelled() {
            visitor(&page)?;
        }
        candidate_completion_after_visit(
            requests.len(),
            completion,
            CandidatePageVisit::Exhausted,
            cancellation,
        )
    }
}

#[cfg(test)]
mod stage_completion_cache_tests {
    use super::*;
    use crate::analyzer::store::resolution_selection::tests::SelectionFixture;

    #[test]
    fn stage_suppression_preserves_factored_boxes_and_refreshes_after_clear() {
        let fixture = SelectionFixture::new(1);
        let selection = fixture.open_ready(&[]);
        let shared = SemanticId::shared_name(SharedNameId::per_request(701));
        let other_shared = SemanticId::shared_name(SharedNameId::per_request(702));
        let closed = ResolutionIncompleteReason::UnsupportedSemantic(shared);
        let survivor = ResolutionIncompleteReason::UnsupportedSemantic(other_shared);
        let mut reasons = (0..256)
            .map(|key| ResolutionIncompleteReason::UnsupportedSemantic(SemanticId::local(0, key)))
            .chain([closed, survivor])
            .collect::<Vec<_>>();
        reasons.sort_unstable();
        let whole = ResolutionCompletion::Incomplete(CompletionReasons::shared_from_canonical(
            reasons.clone().into_boxed_slice(),
        ));
        selection.with_owned_temp_write(|connection| {
            connection.execute("INSERT INTO temp.selected_resolution_stage_producers(host_ordinal,bridge_identity,content_digest) VALUES(0,?1,?2)", params![[171u8;32].as_slice(),[172u8;32].as_slice()])?;
            connection.execute("INSERT INTO temp.selected_resolution_stage_closed_reasons(producer_id,semantic_shared) VALUES(?1,?2)",params![connection.last_insert_rowid(),shared.shared_name_id().unwrap().get()])?;
            Ok(())
        }).unwrap();
        let source = SelectedResolutionLexicalSource::new_on_demand(&selection);
        // Supply the same factored ordinary box that the tier-1 reader publishes.
        source.unconditional_candidate_reasons[0]
            .set(UnconditionalCandidateBox {
                whole: whole.clone(),
                positions: vec![0; reasons.len()].into_boxed_slice(),
            })
            .unwrap();
        let cancellation = CancellationToken::default();
        for _ in 0..64 {
            let (answer, cancelled) = source
                .lazy_candidate_completion(
                    CandidateDirection::Forward,
                    &[],
                    None,
                    None,
                    &cancellation,
                )
                .unwrap();
            assert!(!cancelled);
            assert!(!answer.unconditional_completion().contains_reason(closed));
            assert!(answer.unconditional_completion().contains_reason(survivor));
            let ResolutionCompletion::Incomplete(kept) = answer.unconditional_completion() else {
                panic!("unclosed ordinary evidence remains");
            };
            assert!(kept.is_shared(), "suppression preserves the factored base");
            assert_eq!(kept.len(), reasons.len() - 1);
        }
        let authority = source
            .ordinary_completion_suppression
            .borrow()
            .as_ref()
            .unwrap()
            .authority;
        super::super::resolution_stage::SelectedResolutionStage::new(&selection)
            .clear_facts()
            .unwrap();
        assert_ne!(authority, selection.candidate_coverage_fingerprint());
        let (answer, cancelled) = source
            .lazy_candidate_completion(CandidateDirection::Forward, &[], None, None, &cancellation)
            .unwrap();
        assert!(!cancelled);
        assert_eq!(answer.unconditional_completion(), &whole);
        assert_eq!(
            source
                .ordinary_completion_suppression
                .borrow()
                .as_ref()
                .unwrap()
                .authority,
            selection.candidate_coverage_fingerprint()
        );

        let before_commit = selection.candidate_coverage_fingerprint();
        let fragment = BindingFragmentId::at_ordinal(0);
        let lowered =
            crate::analyzer::resolution::LoweredResolutionFragment::selected_macro_head_bridge(
                fragment,
                SemanticId::operation_local(9101),
                BindingNodeId::operation_local(9102),
                BindingNodeId::operation_local(9103),
                PartialPathId::operation_local(9104),
            );
        let host = selection
            .persisted_mount_record(SelectedResolutionMountOrdinal::new(0))
            .unwrap()
            .unwrap();
        assert!(matches!(
            super::super::resolution_stage::SelectedResolutionStage::new(&selection)
                .insert_generated_bridge(
                    &host,
                    [173; 32],
                    &lowered,
                    None,
                    &[],
                    &[shared],
                    &cancellation
                )
                .unwrap(),
            super::super::resolution_stage::SelectedResolutionStageOutcome::Ready
        ));
        assert_ne!(before_commit, selection.candidate_coverage_fingerprint());
        let (answer, cancelled) = source
            .lazy_candidate_completion(CandidateDirection::Forward, &[], None, None, &cancellation)
            .unwrap();
        assert!(!cancelled);
        assert!(!answer.unconditional_completion().contains_reason(closed));
        assert!(answer.unconditional_completion().contains_reason(survivor));
        let cold = SelectedResolutionLexicalSource::new_on_demand(&selection);
        cold.unconditional_candidate_reasons[0]
            .set(UnconditionalCandidateBox {
                whole,
                positions: vec![0; reasons.len()].into_boxed_slice(),
            })
            .unwrap();
        cancellation.cancel();
        let (answer, cancelled) = cold
            .lazy_candidate_completion(CandidateDirection::Forward, &[], None, None, &cancellation)
            .unwrap();
        assert!(cancelled);
        assert!(answer.unconditional_completion().contains_reason(survivor));
        assert!(
            answer
                .unconditional_completion()
                .contains_reason(ResolutionIncompleteReason::Cancelled)
        );
        assert!(
            cold.ordinary_completion_suppression.borrow().is_none(),
            "an interrupted suppression read cannot publish a cache entry"
        );
    }
}
