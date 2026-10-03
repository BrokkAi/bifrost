//! The `resolution_paths` and `resolution_identities` recipe rows: how a
//! partial path is encoded on the way in and decoded on the way out.
//!
//! Milestone 6's checkpoint (lane PK) ports one reader question,
//! `hydrate_candidate_paths`, from the in-heap interior to keyed rows, and
//! `lookup_semantic_recipes` beside it. This module is the one place that
//! knows the body encoding of milestone 5's draft section 4, so the writer in
//! `store/resolution.rs`, the reader in `store/resolution_lexical.rs` and the
//! measurement loader in `schema_loader.rs` all speak the same encoding.
//!
//! The body is a positional JSONB array and is decoded by exactly one Rust
//! decoder; no SQL reads inside it. Its positions are
//!
//! ```text
//! [start_symbols, start_symbol_tail, start_scopes, start_scope_tail,
//!  end_symbols, end_symbol_tail, end_scopes, end_scope_tail,
//!  precedence, witness, completion]
//! ```
//!
//! A symbol is a signed semantic (`>= 0` a blob-local semantic key, `< 0`
//! minus a `resolution_identities.id`), or `[semantic, scopes, scope_tail]`
//! when it is scoped. A tail is a stack variable number local to the path, or
//! null. A node key is a blob-local node key, or `-1` for the universal root.
//!
//! ## Interning happens at write time, so the body is built in two steps
//!
//! A shared name's integer id is a store fact: it exists only inside the
//! writer's transaction, and the per-blob producer that encodes a path cannot
//! know it. So the encoder emits [`PathBodyToken`]s, with every shared name a
//! slot in [`PreparedPathRows::shared`], and the writer renders the tokens to
//! JSON text once it has interned that slot list. Rendering is a walk over the
//! tokens; nothing parses or rewrites text.

use std::fmt::Write as _;

use brokk_bifrost_core::analyzer::Language;
use brokk_bifrost_core::analyzer::resolution_facts::{
    ALL_RESOLUTION_CALLABLE_RECEIVER_ORIGINS, ALL_RESOLUTION_NAMESPACES, ALL_RESOLUTION_SITE_KINDS,
    ResolutionCallableReceiverOrigin, ResolutionNamespace, ResolutionSiteKind,
};
use brokk_bifrost_core::analyzer::structural::resolution::{
    ALL_BOUNDARY_STATUSES, ALL_PRECEDENCE_TIERS, ALL_REJECTION_REASONS,
    ALL_RESOLUTION_COMPLETION_REASON_KINDS, ALL_RESOLUTION_GAP_ORIGIN_KINDS, BoundaryStatus,
    CandidateOutcome, PrecedenceTier,
};

use crate::analyzer::resolution::{
    BindingFragmentId, BindingNodeId, EndpointSignature, LoweredCandidateDirection,
    LoweredCoverageGap, LoweredSemanticRole, LoweredSemanticSite, LoweringCoverageFrontier,
    LoweringGapOrigin, PartialPath, PartialPathId, PartialScopedSymbol, PrecedenceStep,
    ResolutionCompletion, ResolutionIdentityCatalog, ResolutionIncompleteReason,
    ResolutionLookupSemanticRecipe, SemanticId, SharedNameId, StackPattern, StackVariableId,
    WitnessStep,
};
use crate::hash::HashMap;

use super::ResolutionLocalKeys;

// ---------------------------------------------------------------------------
// The two statements this checkpoint adds
// ---------------------------------------------------------------------------

/// Question 19, `hydrate_candidate_paths`: the bodies of one blob's paths, by
/// key, in one statement for the whole call's share of that blob.
///
/// A primary-key seek over `resolution_paths(blob_id, path)`, so it needs no
/// `INDEXED BY` and no index of its own. The keys arrive as one JSON array
/// because the caller already holds every one of them (milestone 6's rule).
pub(crate) const RESOLUTION_PATHS_BY_KEY_SQL: &str = "SELECT path, start_node, end_node, json(body) FROM resolution_paths \
     WHERE blob_id = ?1 AND path IN (SELECT value FROM json_each(?2))";

// Questions #11 to #14, the forward candidate match, and #15 to #18, the
// reverse one. The two statements differ only in which end's columns they
// seek by and which index they name.
//
// One statement per blob per call, whatever the batch holds, because the
// three request shapes the in-memory candidate index distinguishes are the
// three arms of this `UNION ALL` and each arm takes its own JSON array of
// requests:
//
// * `?2` the requests that fix a first cell: they seek their own lead bucket,
//   `(node, lead identity or lead local, scoped)`;
// * `?3` the same requests again: they also take the open bucket, the paths
//   whose indexed endpoint fixes no symbol at all, which `CandidateNodeIndex`
//   makes every keyed request walk;
// * `?4` the requests that fix nothing: their fixed prefix is empty, so they
//   share a decidable cell with no stored endpoint and take the whole
//   `(blob_id, node)` prefix, which is `extend_all_buckets`.
//
// Each element is the positional array `[request ordinal, node, lead
// identity, lead local, lead scoped]`; the third arm reads only the first two
// positions.
//
// The body travels with the key because the lead cell is not the whole
// admission test: `endpoint_admits_candidate` decides every cell of the
// shared fixed prefix and the two tail counts, and the index can key only the
// first cell. Returning the key alone would emit a superset of the interior's
// matches, which is sound but changes how much work every later stage does.
// The match returns the endpoint admission decides on, not the whole path
// body. `endpoint_admits_candidate` reads one endpoint and rejects almost
// every row a bucket offers: on tract's reverse root bucket it admits about
// one row of every hundred and seventy. Returning the body made every rejected
// row pay a JSONB-to-text conversion of the precedence, witness and completion
// positions as well, and a `serde_json` parse of all eleven. The four cells of
// one endpoint are what the test needs; the admitted rows are hydrated by key
// through `RESOLUTION_PATHS_BY_KEY_SQL`, which is one seek each.

/// The forward arm: `start_node` and the `start_lead_*` columns, over
/// `resolution_paths_forward`.
pub(crate) const RESOLUTION_FORWARD_CANDIDATE_MATCH_SQL: &str = "\
SELECT r.value ->> 0, p.path, p.start_node, p.end_node, json_extract(p.body, '$[0]', '$[1]', '$[2]', '$[3]') \
FROM json_each(?2) AS r \
CROSS JOIN resolution_paths AS p INDEXED BY resolution_paths_forward \
  ON p.blob_id = ?1 \
 AND p.start_node = r.value ->> 1 \
 AND p.start_lead_identity IS r.value ->> 2 \
 AND p.start_lead_local IS r.value ->> 3 \
 AND p.start_lead_scoped = r.value ->> 4 \
UNION ALL \
SELECT r.value ->> 0, p.path, p.start_node, p.end_node, json_extract(p.body, '$[0]', '$[1]', '$[2]', '$[3]') \
FROM json_each(?3) AS r \
CROSS JOIN resolution_paths AS p INDEXED BY resolution_paths_forward \
  ON p.blob_id = ?1 \
 AND p.start_node = r.value ->> 1 \
 AND p.start_lead_identity IS NULL \
 AND p.start_lead_local IS NULL \
UNION ALL \
SELECT r.value ->> 0, p.path, p.start_node, p.end_node, json_extract(p.body, '$[0]', '$[1]', '$[2]', '$[3]') \
FROM json_each(?4) AS r \
CROSS JOIN resolution_paths AS p INDEXED BY resolution_paths_forward \
  ON p.blob_id = ?1 \
 AND p.start_node = r.value ->> 1";

/// One reverse batch: non-root lead buckets and complete root-prefix seeks.
///
/// Bind 5 carries [ordinal, canonical key, requested tail, fully representable,
/// proper-prefix byte offsets]. Canonical cells are ASCII, so SQLite character
/// offsets equal byte offsets. Each shorter key is transient inside its seek;
/// Rust never materializes the quadratic collection of proper-prefix strings.
pub(crate) const RESOLUTION_REVERSE_CANDIDATE_MATCH_SQL: &str = "\
SELECT r.value ->> 0, p.path, p.start_node, p.end_node, json_extract(p.body, '$[4]', '$[5]', '$[6]', '$[7]') \
FROM json_each(?2) AS r \
CROSS JOIN resolution_paths AS p INDEXED BY resolution_paths_reverse \
  ON p.blob_id = ?1 \
 AND p.end_node = r.value ->> 1 \
 AND p.end_lead_identity IS r.value ->> 2 \
 AND p.end_lead_local IS r.value ->> 3 \
 AND p.end_lead_scoped = r.value ->> 4 \
UNION ALL \
SELECT r.value ->> 0, p.path, p.start_node, p.end_node, json_extract(p.body, '$[4]', '$[5]', '$[6]', '$[7]') \
FROM json_each(?3) AS r \
CROSS JOIN resolution_paths AS p INDEXED BY resolution_paths_reverse \
  ON p.blob_id = ?1 \
 AND p.end_node = r.value ->> 1 \
 AND p.end_lead_identity IS NULL \
 AND p.end_lead_local IS NULL \
UNION ALL \
SELECT r.value ->> 0, p.path, p.start_node, p.end_node, json_extract(p.body, '$[4]', '$[5]', '$[6]', '$[7]') \
FROM json_each(?4) AS r \
CROSS JOIN resolution_paths AS p INDEXED BY resolution_paths_reverse \
  ON p.blob_id = ?1 \
 AND p.end_node = r.value ->> 1 \
UNION ALL \
SELECT r.value ->> 0, p.path, p.start_node, p.end_node, json_extract(p.body, '$[4]', '$[5]', '$[6]', '$[7]') \
FROM json_each(?5) AS r \
CROSS JOIN resolution_paths AS p INDEXED BY resolution_paths_reverse_root_prefix \
  ON p.blob_id = ?1 AND p.end_node = -1 \
 AND p.end_fixed_key = r.value ->> 1 COLLATE BINARY \
WHERE r.value ->> 2 = 0 AND r.value ->> 3 = 1 \
UNION ALL \
SELECT r.value ->> 0, p.path, p.start_node, p.end_node, json_extract(p.body, '$[4]', '$[5]', '$[6]', '$[7]') \
FROM json_each(?5) AS r \
CROSS JOIN json_each(r.value -> 4) AS boundary \
CROSS JOIN resolution_paths AS p INDEXED BY resolution_paths_reverse_root_prefix \
  ON p.blob_id = ?1 AND p.end_node = -1 \
 AND p.end_fixed_key = substr(r.value ->> 1, 1, boundary.value) || ']' COLLATE BINARY \
 AND p.end_open_tail = 1 \
UNION ALL \
SELECT r.value ->> 0, p.path, p.start_node, p.end_node, json_extract(p.body, '$[4]', '$[5]', '$[6]', '$[7]') \
FROM json_each(?5) AS r \
CROSS JOIN resolution_paths AS p INDEXED BY resolution_paths_reverse_root_prefix \
  ON p.blob_id = ?1 AND p.end_node = -1 \
 AND p.end_fixed_key >= substr(r.value ->> 1, 1, length(r.value ->> 1) - 1) COLLATE BINARY \
 AND p.end_fixed_key < CASE WHEN length(r.value ->> 1) = 2 THEN char(92) \
     ELSE substr(r.value ->> 1, 1, length(r.value ->> 1) - 2) || '^' END COLLATE BINARY \
WHERE r.value ->> 2 = 1 AND r.value ->> 3 = 1";

/// Question #67, `root_terminal_paths`: the universal-root-terminated paths of
/// one blob that end in one shared name.
///
/// The planner is not given statistics on a cache that has not been
/// `ANALYZE`d, so the partial index is named (lane LD's finding, which the
/// gap-header reads already act on).
pub(crate) const RESOLUTION_ROOT_TERMINAL_PATHS_SQL: &str = "SELECT path FROM resolution_paths INDEXED BY resolution_paths_root_terminal \
     WHERE blob_id = ?1 AND root_terminal = ?2 ORDER BY path";

/// Questions #5, #6 and #10: one blob's site rows, by key, in one statement
/// for the whole call.
///
/// A primary-key seek over `resolution_sites(blob_id, site)`, so it needs no
/// `INDEXED BY` and no index of its own. Site, semantic and node are one
/// number (lane NB), so this one statement answers "is this node a reference
/// or a definition" and "which node does this definition own" alike.
pub(crate) const RESOLUTION_SITES_BY_KEY_SQL: &str = "SELECT site, role, namespace, site_kind, \
     start_byte, end_byte, unqualified, owner, receiver_origin, go_spelling_namespace, go_definition_namespaces, go_package_qualifier \
     FROM resolution_sites \
     WHERE blob_id = ?1 AND site IN (SELECT value FROM json_each(?2))";

/// Question 66, `lookup_recipe`: the recipe columns of a batch of shared
/// names, keyed by the id a shared `SemanticId` carries.
pub(crate) const RESOLUTION_IDENTITY_RECIPES_SQL: &str = "SELECT id, semantic_language, namespace, spelling \
     FROM resolution_identities \
     WHERE id IN (SELECT value FROM json_each(?1))";

pub(crate) const fn import_route_kind_label(
    kind: brokk_bifrost_core::analyzer::resolution_facts::ResolutionImportRouteKind,
) -> &'static str {
    use brokk_bifrost_core::analyzer::resolution_facts::ResolutionImportRouteKind::*;
    match kind {
        SingleType => "single_type",
        TypeOnDemand => "type_on_demand",
        SingleStatic => "single_static",
        StaticOnDemand => "static_on_demand",
    }
}

// ---------------------------------------------------------------------------
// Vocabulary codes
// ---------------------------------------------------------------------------

/// The integer code of one enumeration value: its declaration position in the
/// vocabulary that owns it. One rule for every enumeration, so nothing here
/// invents a numbering of its own.
pub(crate) fn code<T: PartialEq + Copy>(all: &[T], value: T) -> i64 {
    let index = all
        .iter()
        .position(|candidate| *candidate == value)
        .expect("an enumeration value belongs to its own vocabulary");
    i64::try_from(index).expect("a vocabulary position fits an integer")
}

pub(crate) fn from_code<T: Copy>(all: &[T], value: i64, vocabulary: &str) -> T {
    let index = usize::try_from(value)
        .unwrap_or_else(|_| panic!("a stored {vocabulary} code cannot be negative: {value}"));
    *all.get(index)
        .unwrap_or_else(|| panic!("stored {vocabulary} code {value} is outside its vocabulary"))
}

pub(crate) fn language_code(language: Language) -> i64 {
    code(&Language::ALL, language)
}

fn language_from_code(value: i64) -> Language {
    from_code(&Language::ALL, value, "language")
}

pub(crate) fn namespace_code(namespace: ResolutionNamespace) -> i64 {
    code(ALL_RESOLUTION_NAMESPACES, namespace)
}

pub(crate) fn namespace_from_code(value: i64) -> ResolutionNamespace {
    from_code(ALL_RESOLUTION_NAMESPACES, value, "resolution namespace")
}

pub(crate) fn site_kind_code(kind: ResolutionSiteKind) -> i64 {
    code(ALL_RESOLUTION_SITE_KINDS, kind)
}

pub(crate) fn receiver_origin_code(origin: ResolutionCallableReceiverOrigin) -> i64 {
    code(ALL_RESOLUTION_CALLABLE_RECEIVER_ORIGINS, origin)
}

/// `0` a reference, `1` a definition.
pub(crate) const fn semantic_role_code(role: LoweredSemanticRole) -> i64 {
    match role {
        LoweredSemanticRole::Reference => 0,
        LoweredSemanticRole::Definition => 1,
    }
}

/// `0` selected, otherwise one more than the rejection reason's code.
pub(crate) fn candidate_outcome_code(outcome: CandidateOutcome) -> i64 {
    match outcome {
        CandidateOutcome::Selected => 0,
        CandidateOutcome::Rejected(reason) => 1 + code(ALL_REJECTION_REASONS, reason),
    }
}

fn candidate_outcome_from_code(value: i64) -> CandidateOutcome {
    match value {
        0 => CandidateOutcome::Selected,
        other => CandidateOutcome::Rejected(from_code(
            ALL_REJECTION_REASONS,
            other - 1,
            "candidate rejection reason",
        )),
    }
}

/// The universal root is not a node of any blob.
pub(super) fn node_key(keys: &ResolutionLocalKeys, node: BindingNodeId) -> i64 {
    if node == BindingNodeId::universal_root() {
        -1
    } else {
        keys.node(node)
    }
}

// ---------------------------------------------------------------------------
// What the writer carries from preparation into its transaction
// ---------------------------------------------------------------------------

/// One element of an encoded path body.
///
/// `Shared` is a position in [`PreparedPathRows::shared`] rather than an id,
/// because the id does not exist until the writer interns the digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PathBodyToken {
    Open,
    Close,
    Null,
    Int(i64),
    Shared(u32),
}

/// One `resolution_paths` row, with every shared name still a slot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PreparedPathRow {
    pub(crate) path: i64,
    pub(crate) start_node: i64,
    pub(crate) start_lead_local: Option<i64>,
    pub(crate) start_lead_shared: Option<u32>,
    pub(crate) start_lead_scoped: bool,
    pub(crate) end_node: i64,
    pub(crate) end_lead_local: Option<i64>,
    pub(crate) end_lead_shared: Option<u32>,
    pub(crate) end_lead_scoped: bool,
    pub(crate) root_terminal: Option<u32>,
    pub(crate) root_endpoint: Option<PreparedRootEndpoint>,
    pub(crate) body: Vec<PathBodyToken>,
}

/// A root endpoint still names shared identities by the writer's intern slots.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PreparedRootEndpoint {
    pub(crate) symbols: Vec<(PathBodyToken, bool)>,
    pub(crate) open_tail: bool,
}

/// Canonical SQL-readable cells and their boundaries, built in one linear pass.
///
/// Boundary 1 denotes the empty prefix. After each cell, its boundary excludes
/// the outer closing bracket. The reader drops the final boundary only when
/// the complete request is representable, keeping equal and shorter seeks
/// disjoint. A foreign or context-local cutoff retains that final boundary.
pub(crate) struct RootKeyBuilder {
    text: String,
    boundaries: Vec<usize>,
}

impl Default for RootKeyBuilder {
    fn default() -> Self {
        Self {
            text: String::from("["),
            boundaries: vec![1],
        }
    }
}

impl RootKeyBuilder {
    pub(crate) fn push(&mut self, local: Option<i64>, shared: Option<i64>, scoped: bool) {
        if self.boundaries.len() > 1 {
            self.text.push(',');
        }
        match (local, shared) {
            (Some(local), None) => {
                assert!(local >= 0, "a root key's local identity is nonnegative");
                write!(self.text, "[{local},null,{}]", i64::from(scoped))
                    .expect("writing canonical cells to a String is infallible");
            }
            (None, Some(shared)) => {
                assert!(shared > 0, "a root key's shared identity is positive");
                write!(self.text, "[null,{shared},{}]", i64::from(scoped))
                    .expect("writing canonical cells to a String is infallible");
            }
            _ => panic!("a root key cell has exactly one identity: {local:?}, {shared:?}"),
        }
        self.boundaries.push(self.text.len());
    }

    pub(crate) fn finish(mut self) -> (String, Vec<usize>) {
        self.text.push(']');
        (self.text, self.boundaries)
    }
}

/// One `resolution_sites` row (milestone 5 draft section 3, port block 2).
///
/// Site, semantic and node are one number (lane NB), so `site` is the whole
/// key. Everything after `namespace` is the reference site metadata, which a
/// definition row does not carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PreparedSiteRow {
    pub(crate) site: i64,
    pub(crate) role: i64,
    pub(crate) namespace: i64,
    pub(crate) site_kind: Option<i64>,
    pub(crate) start_byte: Option<i64>,
    pub(crate) end_byte: Option<i64>,
    pub(crate) unqualified: Option<i64>,
    pub(crate) owner: Option<i64>,
    pub(crate) receiver_origin: Option<i64>,
    pub(crate) go_spelling_namespace: Option<i64>,
    pub(crate) go_definition_namespaces: Option<u8>,
    pub(crate) go_package_qualifier: bool,
}

/// One `resolution_identities` recipe row.
///
/// Every lookup recipe is a shared identity (`local_identity.rs`, `finish`),
/// so the recipe belongs on the store-wide name and not on the blob.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PreparedLookupRecipeRow {
    pub(crate) identity_digest: [u8; 32],
    pub(crate) semantic_language: i64,
    pub(crate) namespace: i64,
    pub(crate) spelling: String,
}

/// A blob's path rows and the shared names they name, in first-use order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct PreparedPathRows {
    pub(crate) shared: Vec<[u8; 32]>,
    pub(crate) rows: Vec<PreparedPathRow>,
}

/// The shared names one blob's rows mention, as slots.
///
/// Shared with `typed_rows`, which interns the same way for the same reason:
/// a name's id is a store fact that the per-blob producer cannot know.
#[derive(Default)]
pub(super) struct SharedNames {
    digests: Vec<[u8; 32]>,
    slots: HashMap<[u8; 32], u32>,
}

impl SharedNames {
    pub(super) fn into_digests(self) -> Vec<[u8; 32]> {
        self.digests
    }

    pub(super) fn slot(&mut self, digest: [u8; 32]) -> u32 {
        if let Some(&slot) = self.slots.get(&digest) {
            return slot;
        }
        let slot = u32::try_from(self.digests.len()).expect("a blob's shared names fit u32");
        self.digests.push(digest);
        self.slots.insert(digest, slot);
        slot
    }
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

/// Every path of one blob, encoded.
pub(super) fn prepare_path_rows(
    keys: &ResolutionLocalKeys,
    identities: &ResolutionIdentityCatalog,
    paths: &[(PartialPathId, PartialPath)],
) -> PreparedPathRows {
    let mut shared = SharedNames::default();
    let mut rows = Vec::with_capacity(paths.len());
    for (path_id, path) in paths {
        let path_key = keys.path(*path_id);
        assert_eq!(
            PartialPathId::local(
                identities.fragment().ordinal(),
                u32::try_from(path_key).expect("a catalog position fits u32"),
            ),
            *path_id,
            "a persisted path's key must be the one its mounted id carries"
        );
        let mut variables: Vec<(StackVariableId, i64)> = Vec::new();
        let body = path_body(&mut shared, keys, identities, path, &mut variables);
        let start = endpoint_lead(&mut shared, keys, identities, path.start());
        let end = endpoint_lead(&mut shared, keys, identities, path.end());
        let root_terminal = root_terminal_identity(&mut shared, identities, path);
        let root_endpoint =
            (path.end().node() == BindingNodeId::universal_root()).then(|| PreparedRootEndpoint {
                symbols: path
                    .end()
                    .symbols()
                    .fixed()
                    .iter()
                    .map(|symbol| {
                        (
                            signed_semantic(&mut shared, keys, identities, symbol.symbol()),
                            symbol.scopes().is_some(),
                        )
                    })
                    .collect(),
                open_tail: path.end().symbols().tail().is_some(),
            });
        rows.push(PreparedPathRow {
            path: path_key,
            start_node: node_key(keys, path.start().node()),
            start_lead_local: start.0,
            start_lead_shared: start.1,
            start_lead_scoped: start.2,
            end_node: node_key(keys, path.end().node()),
            end_lead_local: end.0,
            end_lead_shared: end.1,
            end_lead_scoped: end.2,
            root_terminal,
            root_endpoint,
            body,
        });
    }
    PreparedPathRows {
        shared: shared.digests,
        rows,
    }
}

// ---------------------------------------------------------------------------
// Coverage gaps (milestone 6, port block 3)
// ---------------------------------------------------------------------------

/// One `resolution_gaps` row, with the lookup name still a slot.
///
/// The three key columns after `blob_id` are the question a reader asks:
/// `covers` says which frontier the gap qualifies, `subject` names the
/// reference, endpoint node or type frontier it is about, and `lookup` names
/// the shared lookup a candidate branch is keyed on. `gap` is the gap's own
/// local semantic key: it is unique within the blob, so it orders the group,
/// and it is also the identity a reverse gap-exclusion plan names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PreparedGapRow {
    pub(crate) covers: i64,
    pub(crate) subject: i64,
    /// A slot in [`PreparedGapRows::shared`]; `None` is the stored 0, "every
    /// lookup".
    pub(crate) lookup: Option<u32>,
    pub(crate) gap: i64,
    pub(crate) reason: i64,
}

/// One `resolution_gap_reasons` row: where a reason came from (question 60).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PreparedGapReasonRow {
    pub(crate) reason: i64,
    pub(crate) site: i64,
    pub(crate) origin: i64,
}

/// A blob's gap rows, the one provenance row per distinct reason, and the
/// shared lookup names the candidate rows name, in first-use order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct PreparedGapRows {
    pub(crate) shared: Vec<[u8; 32]>,
    pub(crate) rows: Vec<PreparedGapRow>,
    pub(crate) reasons: Vec<PreparedGapReasonRow>,
}

/// `covers`, as the DDL comment lists it.
pub(crate) const COVERS_FRAGMENT: i64 = 0;
pub(crate) const COVERS_ENUMERATION: i64 = 1;
pub(crate) const COVERS_FORWARD_INVENTORY: i64 = 2;
pub(crate) const COVERS_REVERSE_INVENTORY: i64 = 3;
pub(crate) const COVERS_REFERENCE: i64 = 4;
pub(crate) const COVERS_FORWARD_ENDPOINT: i64 = 5;
pub(crate) const COVERS_REVERSE_ENDPOINT: i64 = 6;
pub(crate) const COVERS_TYPE_FRONTIER: i64 = 7;

/// One candidate direction's endpoint `covers` code.
pub(crate) const fn covers_candidate_endpoint(direction: LoweredCandidateDirection) -> i64 {
    match direction {
        LoweredCandidateDirection::Forward => COVERS_FORWARD_ENDPOINT,
        LoweredCandidateDirection::Reverse => COVERS_REVERSE_ENDPOINT,
    }
}

/// One candidate direction's fragment-wide inventory `covers` code.
pub(crate) const fn covers_candidate_inventory(direction: LoweredCandidateDirection) -> i64 {
    match direction {
        LoweredCandidateDirection::Forward => COVERS_FORWARD_INVENTORY,
        LoweredCandidateDirection::Reverse => COVERS_REVERSE_INVENTORY,
    }
}

/// A gap origin is its `ResolutionGapOriginKind`, which is in bijection with
/// `LoweringGapOrigin` (`kind` and `from_kind` are total and mutually
/// inverse), so the stored code is a position in an existing vocabulary and
/// this invents no numbering of its own.
pub(crate) fn gap_origin_code(origin: LoweringGapOrigin) -> i64 {
    code(ALL_RESOLUTION_GAP_ORIGIN_KINDS, origin.kind())
}

pub(crate) fn gap_origin_from_code(value: i64) -> LoweringGapOrigin {
    LoweringGapOrigin::from_kind(from_code(
        ALL_RESOLUTION_GAP_ORIGIN_KINDS,
        value,
        "resolution gap origin kind",
    ))
}

/// Every coverage gap of one blob, encoded.
///
/// One row per gap, plus one provenance row per distinct reason. A reason can
/// carry several gaps (853,835 gap rows name 312,129 distinct reasons on
/// tract) and its provenance is a function of the reason, which the interior
/// holds the same way and this asserts here.
///
/// A gap is not a catalog semantic (#3737). Its `gap` key is its position in
/// the fragment's digest-ordered gap list, dense from zero and below the
/// `1 << 31` floor the selected stage allocates its own gap keys from, so a
/// blob cannot repeat one and no catalog row exists per gap.
pub(super) fn prepare_gap_rows(
    keys: &ResolutionLocalKeys,
    identities: &ResolutionIdentityCatalog,
    gaps: &[LoweredCoverageGap],
) -> PreparedGapRows {
    assert!(
        gaps.len() <= 1 << 31,
        "a blob's gap ordinals stay below the stage allocation floor: {}",
        gaps.len()
    );
    let mut shared = SharedNames::default();
    let mut rows = Vec::with_capacity(gaps.len());
    let mut provenance: HashMap<i64, PreparedGapReasonRow> = HashMap::default();
    let mut reasons = Vec::new();
    for (gap_key, gap) in gaps.iter().enumerate() {
        let (covers, subject, lookup) = match gap.frontier() {
            LoweringCoverageFrontier::Fragment => (COVERS_FRAGMENT, 0, None),
            LoweringCoverageFrontier::Enumeration => (COVERS_ENUMERATION, 0, None),
            LoweringCoverageFrontier::CandidateInventory { direction } => {
                (covers_candidate_inventory(direction), 0, None)
            }
            LoweringCoverageFrontier::Reference { semantic, .. } => {
                (COVERS_REFERENCE, keys.semantic(semantic), None)
            }
            LoweringCoverageFrontier::Candidate {
                direction,
                endpoint,
                lookup,
            } => (
                covers_candidate_endpoint(direction),
                node_key(keys, endpoint),
                lookup.map(|semantic| shared.slot(shared_lookup_digest(identities, semantic))),
            ),
            LoweringCoverageFrontier::Type { frontier } => {
                (COVERS_TYPE_FRONTIER, keys.semantic(frontier), None)
            }
        };
        let reason = keys.semantic(gap.reason_semantic());
        rows.push(PreparedGapRow {
            covers,
            subject,
            lookup,
            gap: i64::try_from(gap_key).expect("a gap ordinal fits i64"),
            reason,
        });
        let row = PreparedGapReasonRow {
            reason,
            site: i64::from(gap.site().get()),
            origin: gap_origin_code(gap.origin()),
        };
        match provenance.insert(reason, row) {
            None => reasons.push(row),
            Some(previous) => assert_eq!(
                previous, row,
                "one gap reason retains one exact lowering provenance"
            ),
        }
    }
    PreparedGapRows {
        shared: shared.digests,
        rows,
        reasons,
    }
}

/// A candidate-endpoint gap's lookup is always a shared lookup recipe: both
/// production constructions bind it from `lookup_semantic`, and the catalog's
/// `finish` asserts every lookup recipe is `Shared` (lane ID, confirmed). The
/// invariant is stated where it is established, so no local-lookup value can
/// reach a row and no reader needs a branch for one.
fn shared_lookup_digest(identities: &ResolutionIdentityCatalog, semantic: SemanticId) -> [u8; 32] {
    let identity = identities
        .semantic_identity(semantic)
        .expect("a candidate gap lookup is registered in the identity catalog");
    let name = identity
        .shared_name()
        .expect("a candidate-endpoint gap lookup is always a shared lookup recipe");
    identities.shared_name_digest(name)
}

/// Every lookup recipe of one blob's catalog, as store-wide rows.
pub(super) fn prepare_lookup_recipe_rows(
    identities: &ResolutionIdentityCatalog,
) -> Vec<PreparedLookupRecipeRow> {
    identities
        .lookup_recipes()
        .iter()
        .map(|(semantic, recipe)| {
            let identity = identities
                .semantic_identity(*semantic)
                .expect("a catalog recipe's semantic is in its own catalog");
            let name = identity
                .shared_name()
                .expect("every lookup recipe is a shared identity");
            PreparedLookupRecipeRow {
                identity_digest: identities.shared_name_digest(name),
                semantic_language: language_code(
                    Language::from_config_label(recipe.semantic_language())
                        .expect("a recipe's semantic language is a configured language"),
                ),
                namespace: namespace_code(recipe.namespace()),
                spelling: recipe.spelling().to_owned(),
            }
        })
        .collect()
}

/// Every reference and definition site of one blob, encoded.
///
/// `keys` is the same dense numbering every other family uses, and
/// `prepare_lexical_rows` has already asserted that a site's number is its
/// semantic's key and its node's key, so nothing is re-derived here.
pub(super) fn prepare_site_rows(
    keys: &ResolutionLocalKeys,
    sites: &[LoweredSemanticSite],
) -> Vec<PreparedSiteRow> {
    sites
        .iter()
        .map(|site| {
            let metadata = site.published_site_metadata();
            let owner = site
                .reference_owner()
                .map(|owner| owner.map_or(-1, |semantic| keys.semantic(semantic)));
            PreparedSiteRow {
                site: i64::from(site.site().get()),
                role: semantic_role_code(site.role()),
                namespace: namespace_code(site.namespace()),
                site_kind: metadata.map(|metadata| site_kind_code(metadata.site_kind())),
                start_byte: metadata.map(|metadata| {
                    i64::try_from(metadata.start_byte()).expect("a source offset fits an integer")
                }),
                end_byte: metadata.map(|metadata| {
                    i64::try_from(metadata.end_byte()).expect("a source offset fits an integer")
                }),
                unqualified: metadata.map(|metadata| i64::from(metadata.unqualified())),
                owner,
                receiver_origin: site.callable_receiver_origin().map(receiver_origin_code),
                go_spelling_namespace: metadata
                    .and_then(|row| row.go_spelling_namespace())
                    .map(namespace_code),
                go_definition_namespaces: site.go_definition_namespaces().map(|set| set.bits()),
                go_package_qualifier: metadata.is_some_and(|row| row.go_package_qualifier()),
            }
        })
        .collect()
}

/// One symbol inside a path body: `>= 0` a local semantic key, `< 0` minus the
/// interned id of a shared name.
fn signed_semantic(
    shared: &mut SharedNames,
    keys: &ResolutionLocalKeys,
    identities: &ResolutionIdentityCatalog,
    semantic: SemanticId,
) -> PathBodyToken {
    let identity = identities
        .semantic_identity(semantic)
        .expect("an emitted semantic is in its blob's catalog");
    match identity.shared_name() {
        None => PathBodyToken::Int(keys.semantic(semantic)),
        Some(name) => PathBodyToken::Shared(shared.slot(identities.shared_name_digest(name))),
    }
}

/// `(lead_local, lead_shared, lead_scoped)` for one endpoint.
fn endpoint_lead(
    shared: &mut SharedNames,
    keys: &ResolutionLocalKeys,
    identities: &ResolutionIdentityCatalog,
    endpoint: &EndpointSignature,
) -> (Option<i64>, Option<u32>, bool) {
    let Some(symbol) = endpoint.symbols().fixed().first() else {
        return (None, None, false);
    };
    let scoped = symbol.scopes().is_some();
    match signed_semantic(shared, keys, identities, symbol.symbol()) {
        PathBodyToken::Int(local) => (Some(local), None, scoped),
        PathBodyToken::Shared(slot) => (None, Some(slot), scoped),
        other => unreachable!("a signed semantic is one of two tokens, not {other:?}"),
    }
}

/// The shared name a reverse path terminating at the universal root with three
/// or more fixed symbols ends in.
fn root_terminal_identity(
    shared: &mut SharedNames,
    identities: &ResolutionIdentityCatalog,
    path: &PartialPath,
) -> Option<u32> {
    if path.end().node() != BindingNodeId::universal_root() {
        return None;
    }
    let fixed = path.end().symbols().fixed();
    if fixed.len() < 3 {
        return None;
    }
    let terminal = fixed
        .last()
        .expect("a three-symbol stack has a last symbol");
    let identity = identities
        .semantic_identity(terminal.symbol())
        .expect("a terminal symbol is in the catalog");
    identity
        .shared_name()
        .map(|name| shared.slot(identities.shared_name_digest(name)))
}

/// The per-path number of one stack variable, in order of first appearance in
/// the body's serialization order.
fn variable_number(variables: &mut Vec<(StackVariableId, i64)>, variable: StackVariableId) -> i64 {
    if let Some((_, number)) = variables.iter().find(|(known, _)| *known == variable) {
        return *number;
    }
    let number = i64::try_from(variables.len()).expect("a path's variables fit an integer");
    variables.push((variable, number));
    number
}

fn push_option(out: &mut Vec<PathBodyToken>, value: Option<i64>) {
    out.push(value.map_or(PathBodyToken::Null, PathBodyToken::Int));
}

/// `[start_symbols, start_symbol_tail, start_scopes, start_scope_tail,
/// end_symbols, end_symbol_tail, end_scopes, end_scope_tail, precedence,
/// witness, completion]`.
fn path_body(
    shared: &mut SharedNames,
    keys: &ResolutionLocalKeys,
    identities: &ResolutionIdentityCatalog,
    path: &PartialPath,
    variables: &mut Vec<(StackVariableId, i64)>,
) -> Vec<PathBodyToken> {
    let mut out = Vec::new();
    out.push(PathBodyToken::Open);
    for endpoint in [path.start(), path.end()] {
        out.push(PathBodyToken::Open);
        for symbol in endpoint.symbols().fixed() {
            let signed = signed_semantic(shared, keys, identities, symbol.symbol());
            match symbol.scopes() {
                None => out.push(signed),
                Some(scopes) => {
                    out.push(PathBodyToken::Open);
                    out.push(signed);
                    out.push(PathBodyToken::Open);
                    for scope in scopes.fixed() {
                        out.push(PathBodyToken::Int(node_key(keys, *scope)));
                    }
                    out.push(PathBodyToken::Close);
                    push_option(
                        &mut out,
                        scopes
                            .tail()
                            .map(|variable| variable_number(variables, variable)),
                    );
                    out.push(PathBodyToken::Close);
                }
            }
        }
        out.push(PathBodyToken::Close);
        push_option(
            &mut out,
            endpoint
                .symbols()
                .tail()
                .map(|variable| variable_number(variables, variable)),
        );
        out.push(PathBodyToken::Open);
        for scope in endpoint.scopes().fixed() {
            out.push(PathBodyToken::Int(node_key(keys, *scope)));
        }
        out.push(PathBodyToken::Close);
        push_option(
            &mut out,
            endpoint
                .scopes()
                .tail()
                .map(|variable| variable_number(variables, variable)),
        );
    }
    out.push(PathBodyToken::Open);
    for step in path.precedence() {
        let signed = signed_semantic(shared, keys, identities, step.semantic);
        out.push(PathBodyToken::Open);
        out.push(PathBodyToken::Int(code(ALL_PRECEDENCE_TIERS, step.tier)));
        out.push(PathBodyToken::Int(i64::from(step.ordinal)));
        out.push(signed);
        out.push(PathBodyToken::Close);
    }
    out.push(PathBodyToken::Close);
    out.push(PathBodyToken::Open);
    for step in path.witness() {
        match step {
            WitnessStep::Node(node) => out.push(PathBodyToken::Int(node_key(keys, *node))),
            WitnessStep::Candidate { semantic, outcome } => {
                let signed = signed_semantic(shared, keys, identities, *semantic);
                out.push(PathBodyToken::Open);
                out.push(PathBodyToken::Int(1));
                out.push(signed);
                out.push(PathBodyToken::Int(candidate_outcome_code(*outcome)));
                out.push(PathBodyToken::Close);
            }
            WitnessStep::Boundary { semantic, status } => {
                let signed = signed_semantic(shared, keys, identities, *semantic);
                out.push(PathBodyToken::Open);
                out.push(PathBodyToken::Int(2));
                out.push(signed);
                out.push(PathBodyToken::Int(code(ALL_BOUNDARY_STATUSES, *status)));
                out.push(PathBodyToken::Close);
            }
        }
    }
    out.push(PathBodyToken::Close);
    write_completion(&mut out, keys, path.completion());
    out.push(PathBodyToken::Close);
    out
}

fn write_completion(
    out: &mut Vec<PathBodyToken>,
    keys: &ResolutionLocalKeys,
    completion: &ResolutionCompletion,
) {
    out.push(PathBodyToken::Open);
    if let ResolutionCompletion::Incomplete(reasons) = completion {
        for reason in reasons.iter() {
            out.push(PathBodyToken::Open);
            out.push(PathBodyToken::Int(code(
                ALL_RESOLUTION_COMPLETION_REASON_KINDS,
                reason.kind(),
            )));
            match reason {
                ResolutionIncompleteReason::CyclicExpansion(path) => {
                    out.push(PathBodyToken::Int(keys.path(*path)));
                }
                ResolutionIncompleteReason::InconsistentPrecedence(semantic)
                | ResolutionIncompleteReason::UnsupportedSemantic(semantic) => {
                    out.push(PathBodyToken::Int(keys.semantic(*semantic)));
                }
                ResolutionIncompleteReason::OpenBoundary { semantic, status } => {
                    out.push(PathBodyToken::Int(keys.semantic(*semantic)));
                    out.push(PathBodyToken::Int(code(ALL_BOUNDARY_STATUSES, *status)));
                }
                other => panic!("a lowered completion cannot carry {other:?}"),
            }
            out.push(PathBodyToken::Close);
        }
    }
    out.push(PathBodyToken::Close);
}

/// Render an encoded body to the JSON text the writer wraps in `jsonb(...)`,
/// with each shared slot replaced by minus the id the writer interned for it.
pub(crate) fn render_path_body(body: &[PathBodyToken], shared_ids: &[i64]) -> String {
    let mut out = String::with_capacity(body.len() * 3);
    for token in body {
        if !out.is_empty() && !out.ends_with('[') && *token != PathBodyToken::Close {
            out.push(',');
        }
        match token {
            PathBodyToken::Open => out.push('['),
            PathBodyToken::Close => out.push(']'),
            PathBodyToken::Null => out.push_str("null"),
            PathBodyToken::Int(value) => out.push_str(&value.to_string()),
            PathBodyToken::Shared(slot) => {
                let id = shared_ids[usize::try_from(*slot).expect("a slot fits usize")];
                assert!(id > 0, "an interned identity id is positive: {id}");
                out.push('-');
                out.push_str(&id.to_string());
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

/// What a body's integers mean in one blob, for the reader that turns rows
/// back into the engine's own `PartialPath`.
///
/// Everything here is a property of one blob and lives for one hydration call.
/// The catalog is the interior's own `Catalog` page, which every measured
/// route already opens. A shared name needs nothing here at all any more: the
/// body's `-id` **is** the identity, so the decoder builds the `SemanticId`
/// from it and the second statement that used to fetch those names' digests is
/// gone. `node`, `path` and `variable` below lose their catalog the same way
/// when milestone 4's stage 1b shrinks the other four identities.
pub(crate) struct PathBodyContext {
    pub(crate) fragment: BindingFragmentId,
}

impl PathBodyContext {
    fn semantic(&self, signed: i64) -> SemanticId {
        if signed < 0 {
            return SemanticId::shared_name(SharedNameId::interned(-signed));
        }
        SemanticId::local(
            self.fragment.ordinal(),
            u32::try_from(signed).expect("stored local semantic fits u32"),
        )
    }

    fn node(&self, key: i64) -> BindingNodeId {
        if key == -1 {
            return BindingNodeId::universal_root();
        }
        BindingNodeId::local(
            self.fragment.ordinal(),
            u32::try_from(key).expect("stored local node fits u32"),
        )
    }

    fn path(&self, key: i64) -> PartialPathId {
        PartialPathId::local(
            self.fragment.ordinal(),
            u32::try_from(key).expect("stored local path fits u32"),
        )
    }

    /// A body's stack variables are numbered per path, so a number is the
    /// storage-local key of an alpha-equivalent variable of this blob. The
    /// engine renames a path's variables before every composition
    /// (`EndpointSignature::can_concatenate_with_poll`), so the numbering that
    /// survives a round trip is a choice of representative and not a fact.
    fn variable(&self, number: i64) -> StackVariableId {
        StackVariableId::local(
            self.fragment.ordinal(),
            u32::try_from(number).expect("a path-local variable number fits u32"),
        )
    }
}

/// One JSON element of a body, as `serde_json` hands it over.
type Element = serde_json::Value;

fn array<'value>(value: &'value Element, what: &str) -> &'value [Element] {
    value
        .as_array()
        .unwrap_or_else(|| panic!("a stored path body's {what} is an array, got {value}"))
}

fn integer(value: &Element, what: &str) -> i64 {
    value
        .as_i64()
        .unwrap_or_else(|| panic!("a stored path body's {what} is an integer, got {value}"))
}

fn optional_integer(value: &Element, what: &str) -> Option<i64> {
    if value.is_null() {
        return None;
    }
    Some(integer(value, what))
}

/// One stored path body, parsed once.
pub(crate) struct ParsedPathBody(Vec<Element>);

pub(crate) fn parse_path_body(body: &str) -> ParsedPathBody {
    let document: Element =
        serde_json::from_str(body).expect("a stored path body is the JSON this module wrote");
    let cells = array(&document, "body").to_vec();
    assert_eq!(cells.len(), 11, "a stored path body has eleven positions");
    ParsedPathBody(cells)
}

/// Rebuild one path row's `PartialPath`.
///
/// The two endpoint nodes are the row's own key columns: they are what
/// stitching seeks by, so they are columns and not body positions.
pub(crate) fn decode_path_row(
    context: &PathBodyContext,
    start_node: i64,
    end_node: i64,
    body: &ParsedPathBody,
) -> PartialPath {
    let cells = &body.0;
    let start = decode_endpoint(context, context.node(start_node), &cells[0..4]);
    let end = decode_endpoint(context, context.node(end_node), &cells[4..8]);
    let precedence = array(&cells[8], "precedence")
        .iter()
        .map(|step| {
            let step = array(step, "precedence step");
            assert_eq!(step.len(), 3, "a precedence step has three positions");
            PrecedenceStep {
                tier: from_code::<PrecedenceTier>(
                    ALL_PRECEDENCE_TIERS,
                    integer(&step[0], "precedence tier"),
                    "precedence tier",
                ),
                ordinal: u32::try_from(integer(&step[1], "precedence ordinal"))
                    .expect("a precedence ordinal fits u32"),
                semantic: context.semantic(integer(&step[2], "precedence semantic")),
            }
        })
        .collect::<Vec<_>>();
    let witness = array(&cells[9], "witness")
        .iter()
        .map(|step| decode_witness_step(context, step))
        .collect::<Vec<_>>();
    PartialPath::new(
        start,
        end,
        precedence,
        witness,
        decode_completion(context, &cells[10]),
    )
}

/// The four positions of one endpoint, as the candidate match selects them.
///
/// The match decides admission on one endpoint and rejects almost every row a
/// bucket offers, so it reads those four positions and never the rest of the
/// path. The whole body is read only where a path is needed, by
/// `hydrate_candidate_paths`.
pub(crate) struct ParsedEndpointCells(Vec<Element>);

pub(crate) fn parse_endpoint_cells(cells: &str) -> ParsedEndpointCells {
    let document: Element =
        serde_json::from_str(cells).expect("a selected endpoint is the JSON this module wrote");
    let cells = array(&document, "endpoint cells").to_vec();
    assert_eq!(cells.len(), 4, "an endpoint has four positions");
    ParsedEndpointCells(cells)
}

/// One endpoint, for a candidate match's admission test.
pub(crate) fn decode_selected_endpoint(
    context: &PathBodyContext,
    node: i64,
    cells: &ParsedEndpointCells,
) -> EndpointSignature {
    decode_endpoint(context, context.node(node), &cells.0)
}

fn decode_witness_step(context: &PathBodyContext, step: &Element) -> WitnessStep {
    if let Some(node) = step.as_i64() {
        return WitnessStep::Node(context.node(node));
    }
    let step = array(step, "witness step");
    assert_eq!(step.len(), 3, "a keyed witness step has three positions");
    let semantic = context.semantic(integer(&step[1], "witness semantic"));
    match integer(&step[0], "witness kind") {
        1 => WitnessStep::Candidate {
            semantic,
            outcome: candidate_outcome_from_code(integer(&step[2], "candidate outcome")),
        },
        2 => WitnessStep::Boundary {
            semantic,
            status: from_code::<BoundaryStatus>(
                ALL_BOUNDARY_STATUSES,
                integer(&step[2], "boundary status"),
                "boundary status",
            ),
        },
        other => panic!("a stored witness step cannot be of kind {other}"),
    }
}

fn decode_endpoint(
    context: &PathBodyContext,
    node: BindingNodeId,
    cells: &[Element],
) -> EndpointSignature {
    let symbols = array(&cells[0], "symbol stack")
        .iter()
        .map(|symbol| decode_symbol(context, symbol))
        .collect::<Vec<_>>();
    let symbol_tail =
        optional_integer(&cells[1], "symbol tail").map(|number| context.variable(number));
    let scopes = array(&cells[2], "scope stack")
        .iter()
        .map(|scope| context.node(integer(scope, "scope")))
        .collect::<Vec<_>>();
    let scope_tail =
        optional_integer(&cells[3], "scope tail").map(|number| context.variable(number));
    EndpointSignature::new_scoped(
        node,
        StackPattern::new(symbols, symbol_tail),
        StackPattern::new(scopes, scope_tail),
    )
}

fn decode_symbol(context: &PathBodyContext, symbol: &Element) -> PartialScopedSymbol {
    if let Some(signed) = symbol.as_i64() {
        return PartialScopedSymbol::unscoped(context.semantic(signed));
    }
    let cells = array(symbol, "scoped symbol");
    assert_eq!(cells.len(), 3, "a scoped symbol has three positions");
    let scopes = array(&cells[1], "symbol scope stack")
        .iter()
        .map(|scope| context.node(integer(scope, "symbol scope")))
        .collect::<Vec<_>>();
    let tail =
        optional_integer(&cells[2], "symbol scope tail").map(|number| context.variable(number));
    PartialScopedSymbol::scoped(
        context.semantic(integer(&cells[0], "scoped symbol semantic")),
        StackPattern::new(scopes, tail),
    )
}

fn decode_completion(context: &PathBodyContext, cells: &Element) -> ResolutionCompletion {
    let reasons = array(cells, "completion");
    if reasons.is_empty() {
        return ResolutionCompletion::Complete;
    }
    ResolutionCompletion::incomplete(reasons.iter().map(|reason| {
        let reason = array(reason, "completion reason");
        let kind = from_code(
            ALL_RESOLUTION_COMPLETION_REASON_KINDS,
            integer(&reason[0], "completion reason kind"),
            "completion reason kind",
        );
        decode_incomplete_reason(context, kind, &reason[1..])
    }))
}

fn decode_incomplete_reason(
    context: &PathBodyContext,
    kind: brokk_bifrost_core::analyzer::structural::resolution::ResolutionCompletionReasonKind,
    rest: &[Element],
) -> ResolutionIncompleteReason {
    use brokk_bifrost_core::analyzer::structural::resolution::ResolutionCompletionReasonKind as Kind;
    match kind {
        Kind::CyclicExpansion => ResolutionIncompleteReason::CyclicExpansion(
            context.path(integer(&rest[0], "cyclic expansion path")),
        ),
        Kind::InconsistentPrecedence => ResolutionIncompleteReason::InconsistentPrecedence(
            context.semantic(integer(&rest[0], "inconsistent precedence semantic")),
        ),
        Kind::UnsupportedSemantic => ResolutionIncompleteReason::UnsupportedSemantic(
            context.semantic(integer(&rest[0], "unsupported semantic")),
        ),
        Kind::OpenBoundary => ResolutionIncompleteReason::OpenBoundary {
            semantic: context.semantic(integer(&rest[0], "open boundary semantic")),
            status: from_code(
                ALL_BOUNDARY_STATUSES,
                integer(&rest[1], "open boundary status"),
                "boundary status",
            ),
        },
    }
}

/// One recipe row, decoded into the value the engine holds.
pub(crate) fn decode_lookup_recipe(
    semantic_language: i64,
    namespace: i64,
    spelling: &str,
) -> ResolutionLookupSemanticRecipe {
    ResolutionLookupSemanticRecipe::new(
        language_from_code(semantic_language),
        namespace_from_code(namespace),
        spelling,
    )
}
