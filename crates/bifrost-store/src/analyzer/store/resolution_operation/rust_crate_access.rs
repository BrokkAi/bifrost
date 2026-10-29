use super::placement_access::{
    PlacementKey, PlacementRead, certified_predecessor_or_selected_mount, read_placements,
};
use super::rust_privacy::complete_access_source_read;
use super::*;
use crate::analyzer::resolution::{
    DeclarationAccessDecision, DeclarationAccessRequest, DeclarationAccessRow, FactPageVisitor,
    LoweredRustDeclarationAuthority, LoweredRustReferenceContext, ReasonOwnerRow,
    SelectedDeclarationAccessSource, SelectedTypedFactSource, SelectedTypedRow,
    TypedFactReadOutcome, TypedFactRequest,
};

pub(crate) const REASON_OWNERS_SQL: &str = "SELECT gap.reason, authority.semantic_key
FROM resolution_gap_reasons AS gap
CROSS JOIN resolution_sites AS site
  ON site.blob_id=gap.blob_id AND site.site=gap.site AND site.role=1
CROSS JOIN resolution_rust_declaration_authorities AS authority
  ON authority.blob_id=site.blob_id AND authority.source_site=site.site
WHERE gap.blob_id=?1
  AND gap.reason IN (SELECT value FROM json_each(?2))
ORDER BY gap.reason";

/// Configuration activity of a caller blob across its selected Cargo routes.
/// Only `Inactive` is sufficient evidence to exclude a caller from analysis.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub enum RustBlobActivity {
    Active,
    Inactive,
    Unknown,
}

pub(crate) const BLOB_PLACEMENT_ACTIVITY: &str = "WITH route_evidence AS MATERIALIZED (
 SELECT unit.workspace_id, unit.generation, json_extract(gap.detail, '$.path') AS path,
        MIN(gap.gap_kind='inactive_placement'
            AND json_extract(gap.detail, '$.activation')=0) AS inactive
 FROM selected_rust_unit_summaries AS unit
 CROSS JOIN main.rust_resolution_unit_summary_contexts AS context
  ON context.summary_id=unit.summary_id AND context.target_kind<>'detached'
 CROSS JOIN main.rust_resolution_unit_summary_gaps AS gap
  ON gap.summary_id=unit.summary_id
 AND gap.gap_kind IN ('inactive_placement','unknown_activation','unplaced_module','duplicate_placement')
 GROUP BY unit.workspace_id, unit.generation, path
)
SELECT requested.value,
 CASE WHEN EXISTS (
  SELECT 1 FROM selected_rust_container_placements AS placement
  CROSS JOIN main.rust_resolution_unit_summary_contexts AS context
   ON context.summary_id=placement.summary_id AND context.target_kind<>'detached'
  WHERE placement.placement_blob=requested.value
   AND NOT EXISTS (
    SELECT 1 FROM main.rust_resolution_unit_summary_gaps AS gap
    WHERE gap.summary_id=placement.summary_id AND gap.gap_kind='unknown_activation'
     AND (gap.subject=placement.container_path
      OR substr(placement.container_path,1,length(gap.subject)+2)=gap.subject || '::')
   )
 ) THEN 1
 WHEN EXISTS (
  SELECT 1 FROM temp.selected_resolution_mounts AS mount
  JOIN route_evidence AS evidence
   ON evidence.workspace_id=mount.workspace_id AND evidence.generation=mount.generation
  AND evidence.path=mount.persisted_relative_path
  WHERE mount.blob_id=requested.value AND evidence.inactive=1
 ) AND NOT EXISTS (
  SELECT 1 FROM temp.selected_resolution_mounts AS mount
  JOIN route_evidence AS evidence
   ON evidence.workspace_id=mount.workspace_id AND evidence.generation=mount.generation
  AND evidence.path=mount.persisted_relative_path
  WHERE mount.blob_id=requested.value AND evidence.inactive IS NOT 1
 ) THEN 0 ELSE -1 END
FROM json_each(?1) AS requested ORDER BY requested.key";

impl SelectedResolutionOperation<'_, '_> {
    /// Read one verdict per input blob, preserving input order and duplicates.
    /// The batch and its evidence live only for this query; detached placements
    /// cannot prove activity or override positive Cargo inactivity evidence.
    #[doc(hidden)]
    pub fn rust_blob_placement_activity(
        &self,
        blobs: &[i64],
    ) -> Result<Vec<(i64, super::RustBlobActivity)>> {
        let requested = serde_json::to_string(blobs).expect("blob ids serialize");
        let rows = self
            .ready
            .inventory
            .connection()
            .prepare_cached(BLOB_PLACEMENT_ACTIVITY)?
            .query_map([requested], |row| {
                let activation: i64 = row.get(1)?;
                debug_assert!((-1..=1).contains(&activation));
                let activity = match activation {
                    1 => RustBlobActivity::Active,
                    0 => RustBlobActivity::Inactive,
                    _ => RustBlobActivity::Unknown,
                };
                Ok((row.get(0)?, activity))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }
}

#[derive(Debug)]
#[doc(hidden)]
pub struct RustCrateAccessPolicy {
    pub(super) crate_keys: Vec<[u8; 32]>,
    pub(super) base_blobs: Vec<(BindingFragmentId, i64)>,
    /// The policy names itself with one identity the context minted for it.
    /// It belongs to no file, and it used to be a digest of the policy's own
    /// crate keys; the request's table numbers that digest now.
    pub(super) identity: SemanticId,
}

impl RustCrateAccessPolicy {
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn new(
        crate_keys: Vec<[u8; 32]>,
        base_blobs: Vec<(BindingFragmentId, i64)>,
        identity: SemanticId,
    ) -> Self {
        Self {
            crate_keys,
            base_blobs,
            identity,
        }
    }
}

#[derive(Debug)]
pub(super) struct RustCrateSetAccessPolicy {
    pub(super) crate_keys: Vec<[u8; 32]>,
    pub(super) base_blobs: Vec<(BindingFragmentId, i64)>,
    /// See [`RustCrateAccessPolicy::identity`].
    pub(super) identity: SemanticId,
}

trait RustAccessDecisionSource: Send + Sync {
    fn identity(&self) -> SemanticId;
    fn decide(
        &self,
        facts: &dyn SelectedTypedFactSource,
        reference: Option<&SelectedTypedRow<LoweredRustReferenceContext>>,
        definition: Option<&SelectedTypedRow<LoweredRustDeclarationAuthority>>,
    ) -> Result<DeclarationAccessDecision>;
}

/// Rust declaration-authority rows are keyed by a declaration in one source
/// fragment. A shared name is a lookup recipe, not a concrete declaration.
fn local_rust_authority_definition(definition: SemanticId) -> Option<SemanticId> {
    definition.local_key().map(|_| definition)
}

pub(super) fn site_cfg_activation(
    atoms: &BTreeSet<String>,
    detached: bool,
    condition: &brokk_bifrost_core::analyzer::rust_facts::RustCfgCondition,
) -> (
    brokk_bifrost_rust::selected_context::RustSelectedActivation,
    bool,
    Option<brokk_bifrost_rust::cfg::RustCfgSiteAssignment>,
) {
    if detached {
        brokk_bifrost_rust::cfg::detached_site_cfg_activation(atoms, condition)
    } else {
        brokk_bifrost_rust::cfg::crate_site_cfg_activation(atoms, condition)
    }
}

fn site_cfg_context<'a>(
    rows: impl IntoIterator<Item = (&'a BTreeSet<String>, bool)>,
    condition: &brokk_bifrost_core::analyzer::rust_facts::RustCfgCondition,
) -> (
    brokk_bifrost_rust::selected_context::RustSelectedActivation,
    bool,
    Option<brokk_bifrost_rust::cfg::RustCfgSiteAssignment>,
) {
    use brokk_bifrost_rust::selected_context::RustSelectedActivation;

    let mut selected = None;
    for (atoms, detached) in rows {
        let context = site_cfg_activation(atoms, detached, condition);
        if selected
            .as_ref()
            .is_some_and(|previous| previous != &context)
        {
            return (RustSelectedActivation::Unknown, false, None);
        }
        selected = Some(context);
    }
    selected.unwrap_or((RustSelectedActivation::Unknown, false, None))
}

impl<T: RustAccessDecisionSource> SelectedDeclarationAccessSource for T {
    fn qualify_selection_path(
        &self,
        facts: &dyn SelectedTypedFactSource,
        reference: SemanticId,
        path: &mut PartialPath,
        cancellation: &CancellationToken,
    ) -> Result<Option<bool>> {
        facts.qualify_selection_path(reference, path, cancellation)
    }

    fn identity(&self) -> SemanticId {
        RustAccessDecisionSource::identity(self)
    }

    fn declaration_activation(
        &self,
        facts: &dyn SelectedTypedFactSource,
        definition: SemanticId,
        cancellation: &CancellationToken,
        session: Option<&ResolutionSession>,
    ) -> Result<Option<(DeclarationAccessDecision, Option<SemanticId>)>> {
        let Some(definition) = local_rust_authority_definition(definition) else {
            return Ok(Some((DeclarationAccessDecision::Allowed, None)));
        };
        let mut authority = None;
        let mut collect = |rows: &[SelectedTypedRow<LoweredRustDeclarationAuthority>]| {
            for row in rows {
                assert_eq!(row.row().definition(), definition);
                assert!(
                    authority.replace(row.clone()).is_none(),
                    "one target owns one item authority"
                );
            }
            Ok(!cancellation.is_cancelled())
        };
        let mut visitor = match session {
            Some(session) => FactPageVisitor::with_maximum_rows_in_session(
                &mut collect,
                MAX_SOURCE_ROWS_PER_BATCH,
                session,
            ),
            None => FactPageVisitor::new(&mut collect),
        };
        let outcome = facts.visit_rust_declaration_authority_pages(
            TypedFactRequest::new(&[definition]),
            cancellation,
            &mut visitor,
        )?;
        if complete_access_source_read(outcome, cancellation, "Rust target activation")?.is_some() {
            return Ok(None);
        }
        let Some(authority) = authority else {
            return Ok(Some((DeclarationAccessDecision::Allowed, None)));
        };
        Ok(Some((
            self.decide(facts, None, Some(&authority))?,
            authority.row().activation_reason(),
        )))
    }

    fn visit_access_pages(
        &self,
        facts: &dyn SelectedTypedFactSource,
        requests: TypedFactRequest<DeclarationAccessRequest>,
        cancellation: &CancellationToken,
        visitor: &mut FactPageVisitor<'_, DeclarationAccessRow>,
    ) -> Result<TypedFactReadOutcome> {
        if cancellation.is_cancelled() {
            return Ok(TypedFactReadOutcome::cancelled(
                ResolutionCompletion::Complete,
            ));
        }
        if requests.is_empty() {
            return Ok(TypedFactReadOutcome::exhausted(
                ResolutionCompletion::Complete,
            ));
        }

        let mut references = BTreeSet::new();
        let mut definitions = BTreeSet::new();
        for request in requests.as_slice() {
            if cancellation.is_cancelled() {
                return Ok(TypedFactReadOutcome::cancelled(
                    ResolutionCompletion::Complete,
                ));
            }
            references.insert(request.reference);
            definitions.insert(request.definition);
        }
        let references = references.into_iter().collect::<Vec<_>>();
        let definitions = definitions
            .into_iter()
            .filter_map(local_rust_authority_definition)
            .collect::<Vec<_>>();

        let mut reference_rows = BTreeMap::new();
        let mut collect_references = |rows: &[SelectedTypedRow<LoweredRustReferenceContext>]| {
            for row in rows {
                if cancellation.is_cancelled() {
                    return Ok(false);
                }
                let key = row.row().reference();
                if reference_rows.insert(key, row.clone()).is_some() {
                    return Err(StoreError::corrupt(format!(
                        "selected Rust reference context returned duplicate semantic: {key:?}"
                    )));
                }
            }
            Ok(true)
        };
        let reference_outcome = if let Some(session) = visitor.resolution_session() {
            let mut nested_visitor = FactPageVisitor::with_maximum_rows_in_session(
                &mut collect_references,
                MAX_SOURCE_ROWS_PER_BATCH,
                session,
            );
            facts.visit_rust_reference_context_pages(
                TypedFactRequest::new(&references),
                cancellation,
                &mut nested_visitor,
            )?
        } else {
            let mut nested_visitor = FactPageVisitor::with_maximum_rows(
                &mut collect_references,
                MAX_SOURCE_ROWS_PER_BATCH,
            );
            facts.visit_rust_reference_context_pages(
                TypedFactRequest::new(&references),
                cancellation,
                &mut nested_visitor,
            )?
        };
        if let Some(outcome) =
            complete_access_source_read(reference_outcome, cancellation, "Rust reference context")?
        {
            return Ok(outcome);
        }

        let mut definition_rows = BTreeMap::new();
        let mut collect_definitions = |rows: &[SelectedTypedRow<
            LoweredRustDeclarationAuthority,
        >]| {
            for row in rows {
                if cancellation.is_cancelled() {
                    return Ok(false);
                }
                let key = row.row().definition();
                if definition_rows.insert(key, row.clone()).is_some() {
                    return Err(StoreError::corrupt(format!(
                        "selected Rust declaration authority returned duplicate semantic: {key:?}"
                    )));
                }
            }
            Ok(true)
        };
        let definition_outcome = if let Some(session) = visitor.resolution_session() {
            let mut nested_visitor = FactPageVisitor::with_maximum_rows_in_session(
                &mut collect_definitions,
                MAX_SOURCE_ROWS_PER_BATCH,
                session,
            );
            facts.visit_rust_declaration_authority_pages(
                TypedFactRequest::new(&definitions),
                cancellation,
                &mut nested_visitor,
            )?
        } else {
            let mut nested_visitor = FactPageVisitor::with_maximum_rows(
                &mut collect_definitions,
                MAX_SOURCE_ROWS_PER_BATCH,
            );
            facts.visit_rust_declaration_authority_pages(
                TypedFactRequest::new(&definitions),
                cancellation,
                &mut nested_visitor,
            )?
        };
        if let Some(outcome) = complete_access_source_read(
            definition_outcome,
            cancellation,
            "Rust declaration authority",
        )? {
            return Ok(outcome);
        }

        let mut page = Vec::with_capacity(MAX_SOURCE_ROWS_PER_BATCH);
        for request in requests.as_slice() {
            if cancellation.is_cancelled() {
                return Ok(TypedFactReadOutcome::cancelled(
                    ResolutionCompletion::Complete,
                ));
            }
            let reference = reference_rows.get(&request.reference).ok_or_else(|| {
                StoreError::corrupt(format!(
                    "selected Rust access source omitted requested reference context: requests={:?}, received={:?}",
                    requests.as_slice(),
                    reference_rows.keys().collect::<Vec<_>>(),
                ))
            })?;
            let definition = definition_rows.get(&request.definition);
            let decision = self.decide(facts, Some(reference), definition)?;
            page.push(DeclarationAccessRow {
                request: *request,
                decision,
                activation_reason: definition
                    .and_then(|definition| definition.row().activation_reason()),
                visibility_applies: false,
                subclass_access: None,
            });
            if page.len() == MAX_SOURCE_ROWS_PER_BATCH {
                if !visitor.visit_page(&page)? {
                    if cancellation.is_cancelled() {
                        return Ok(TypedFactReadOutcome::cancelled(
                            ResolutionCompletion::Complete,
                        ));
                    }
                    return Ok(TypedFactReadOutcome::stopped(
                        ResolutionCompletion::Complete,
                    ));
                }
                page.clear();
            }
        }
        if !page.is_empty() && !visitor.visit_page(&page)? {
            if cancellation.is_cancelled() {
                return Ok(TypedFactReadOutcome::cancelled(
                    ResolutionCompletion::Complete,
                ));
            }
            return Ok(TypedFactReadOutcome::stopped(
                ResolutionCompletion::Complete,
            ));
        }
        Ok(if cancellation.is_cancelled() {
            TypedFactReadOutcome::cancelled(ResolutionCompletion::Complete)
        } else {
            TypedFactReadOutcome::exhausted(ResolutionCompletion::Complete)
        })
    }

    fn visit_reason_owners(
        &self,
        facts: &dyn SelectedTypedFactSource,
        reasons: TypedFactRequest<SemanticId>,
        cancellation: &CancellationToken,
        visitor: &mut FactPageVisitor<'_, ReasonOwnerRow>,
    ) -> Result<TypedFactReadOutcome> {
        let maximum_rows = visitor.maximum_rows().min(MAX_SOURCE_ROWS_PER_BATCH);
        let session = visitor.resolution_session();
        let mut adapt = |page: &[(SemanticId, SemanticId)]| {
            let rows = page
                .iter()
                .map(|&(reason, definition)| ReasonOwnerRow { reason, definition })
                .collect::<Vec<_>>();
            visitor.visit_page(&rows)
        };
        let mut typed_visitor = match session {
            Some(session) => {
                FactPageVisitor::with_maximum_rows_in_session(&mut adapt, maximum_rows, session)
            }
            None => FactPageVisitor::with_maximum_rows(&mut adapt, maximum_rows),
        };
        facts.visit_rust_reason_owners(reasons, cancellation, &mut typed_visitor)
    }
}

// Seek the blob's materialized placements before scanning its dependency
// closure. Driving from graph used to repeat all module alignment per crate.
pub(crate) const PLACEMENTS: &str =
    "SELECT placement.topology_id, placement.container_path, json(context.cfg_atoms)
FROM selected_rust_container_placements AS placement
CROSS JOIN selected_rust_unit_closure AS graph
  ON graph.root_unit_key=?1 AND graph.topology_id=placement.topology_id
CROSS JOIN main.rust_resolution_unit_summary_contexts AS context
  ON context.summary_id=graph.summary_id
WHERE placement.placement_blob=?2 AND placement.module_declaration IS ?3";

/// The module placements of a blob in the crate being resolved only, with the
/// same columns as [`PLACEMENTS`]. See `reference_placements`.
pub(super) const REFERENCE_PLACEMENTS: &str = "SELECT placement.topology_id,
 placement.container_path, json(context.cfg_atoms)
FROM selected_rust_container_placements AS placement
CROSS JOIN selected_rust_unit_summaries AS unit
  ON unit.topology_id=placement.topology_id
CROSS JOIN main.rust_resolution_unit_summary_contexts AS context
  ON context.summary_id=unit.summary_id
WHERE unit.unit_key=?1 AND placement.placement_blob=?2
  AND placement.module_declaration IS ?3";

pub(super) const MEMBERSHIPS: &str =
    "SELECT graph.topology_id, json(context.cfg_atoms), context.target_kind
FROM selected_rust_unit_closure AS graph
CROSS JOIN main.rust_resolution_unit_summary_contexts AS context
  ON context.summary_id=graph.summary_id
WHERE graph.root_unit_key=?1 AND EXISTS (
 SELECT 1 FROM main.resolution_unit_summary_members AS member
  INDEXED BY resolution_unit_summary_members_blob
 WHERE member.summary_id=graph.summary_id AND member.blob_id=?2
)";

pub(super) const VISIBILITY: &str = "SELECT CASE WHEN ?5='public' THEN 1
 WHEN ?1<>?3 THEN 0 WHEN ?5='crate' THEN 1
 WHEN ?5 IN ('private','self') THEN (?2=?4 OR substr(?2,1,length(?4)+2)=?4 || '::')
 ELSE (?2=cr_restriction(?5,?4,?6) OR substr(?2,1,length(cr_restriction(?5,?4,?6))+2)=cr_restriction(?5,?4,?6) || '::') END
 FROM selected_rust_unit_summaries AS unit
 CROSS JOIN main.rust_unit_summary_containers AS container
  ON container.summary_id=unit.summary_id
 WHERE unit.topology_id=?3 AND container.module_path=?4";

type CratePlacement = (i64, String, BTreeSet<String>);
type CrateMembership = (i64, BTreeSet<String>, String);

/// One crate stage's answers from [`PLACEMENTS`] and [`MEMBERSHIPS`], keyed by
/// their bound parameters.
///
/// Both statements rebuild the dependency closure of the stage's crate before
/// they look up one blob. On the whole tract graph they ran 757,326 times for
/// 24 s, asking the same few blobs of the crate again for every access
/// decision. The rows they read (selected unit summaries, shared dependency
/// rows, Rust placements and contexts, and the blob's module scopes) do not
/// change while a stage runs.
///
/// Only a crate stage holds one, with the export memo beside it: see
/// `rust_crate_rows::CrateStageMemos`. Outside a crate stage the decisions run
/// the statements directly.
#[derive(Default)]
pub(crate) struct CrateAccessMemo {
    placements: super::placement_access::PlacementMemo<CratePlacement>,
    reference_placements: super::placement_access::PlacementMemo<CratePlacement>,
    memberships: super::placement_access::PlacementMemo<CrateMembership>,
    /// Whether a definition, by mount ordinal and semantic key, declares a
    /// module (`rust_crate_rows::MODULE_DEFINITIONS`). Every projection round
    /// asks it again for the same targets: on the whole tract graph the
    /// statement ran 1,295,894 times for 17.3 s. A definition's declaration
    /// kind does not change while a stage runs.
    pub(super) module_definitions: HashMap<(u32, i64), bool>,
}

fn definition_placements(
    selection: &super::super::resolution_selection::SelectedResolutionMountInventory<'_>,
    crate_key: [u8; 32],
    base_blobs: &[(BindingFragmentId, i64)],
    fragment: BindingFragmentId,
    declaration: Option<SourceDeclarationId>,
) -> Result<Vec<CratePlacement>> {
    placement_rows(
        selection,
        crate_key,
        base_blobs,
        fragment,
        declaration,
        PLACEMENTS,
        |memo| &mut memo.placements,
    )
}

fn reference_placements(
    selection: &super::super::resolution_selection::SelectedResolutionMountInventory<'_>,
    crate_key: [u8; 32],
    base_blobs: &[(BindingFragmentId, i64)],
    fragment: BindingFragmentId,
    declaration: Option<SourceDeclarationId>,
) -> Result<Vec<CratePlacement>> {
    let own = placement_rows(
        selection,
        crate_key,
        base_blobs,
        fragment,
        declaration,
        REFERENCE_PLACEMENTS,
        |memo| &mut memo.reference_placements,
    )?;
    if !own.is_empty() {
        return Ok(own);
    }
    definition_placements(selection, crate_key, base_blobs, fragment, declaration)
}

#[allow(clippy::too_many_arguments)]
fn placement_rows(
    selection: &super::super::resolution_selection::SelectedResolutionMountInventory<'_>,
    crate_key: [u8; 32],
    base_blobs: &[(BindingFragmentId, i64)],
    fragment: BindingFragmentId,
    declaration: Option<SourceDeclarationId>,
    sql: &'static str,
    memo_rows: fn(
        &mut CrateAccessMemo,
    ) -> &mut super::placement_access::PlacementMemo<CratePlacement>,
) -> Result<Vec<CratePlacement>> {
    let Some(subject) = certified_predecessor_or_selected_mount(selection, base_blobs, fragment)?
    else {
        return Ok(Vec::new());
    };
    let key = PlacementKey {
        language: Language::Rust,
        unit_digest: crate_key,
        subject,
        declaration: declaration.map(SourceDeclarationId::get),
    };
    read_placements(
        selection,
        &key,
        PlacementRead {
            sql,
            bind: |key: &PlacementKey| {
                vec![
                    key.unit_digest.to_vec().into(),
                    key.subject.blob.into(),
                    key.declaration.map(i64::from).into(),
                ]
            },
            decode: |row: &rusqlite::Row<'_>| {
                let atoms: String = row.get(2)?;
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    serde_json::from_str(&atoms)
                        .map_err(|error| StoreError::corrupt(error.to_string()))?,
                ))
            },
        },
        selection
            .crate_access_memo()
            .borrow_mut()
            .as_mut()
            .map(memo_rows),
    )
}

pub(crate) fn access(
    selection: &super::super::resolution_selection::SelectedResolutionMountInventory<'_>,
    crate_key: [u8; 32],
    base_blobs: &[(BindingFragmentId, i64)],
    reference: Option<&SelectedTypedRow<LoweredRustReferenceContext>>,
    definition: Option<&SelectedTypedRow<LoweredRustDeclarationAuthority>>,
) -> Result<Option<DeclarationAccessDecision>> {
    use brokk_bifrost_core::analyzer::rust_facts::RustCfgCondition;
    use brokk_bifrost_rust::selected_context::RustSelectedActivation;
    let references = reference
        .map(|row| {
            reference_placements(
                selection,
                crate_key,
                base_blobs,
                row.fragment(),
                row.row().module_declaration(),
            )
        })
        .transpose()?
        .unwrap_or_default();
    let definitions = definition
        .map(|row| {
            definition_placements(
                selection,
                crate_key,
                base_blobs,
                row.fragment(),
                row.row().module_declaration(),
            )
        })
        .transpose()?
        .unwrap_or_default();
    if (reference.is_some() && references.is_empty())
        || (reference.is_none() && definition.is_some() && definitions.is_empty())
    {
        return Ok(None);
    }
    // A definition-only check is declaration self-activation (including the
    // reverse-usage preflight). Its own cfg is the premise until concrete
    // reference sites are checked below with their site cfgs.
    let site_condition = reference
        .map(|row| row.row().cfg_condition())
        .or_else(|| definition.map(|row| row.row().cfg_condition()))
        .expect("Rust access has a reference or declaration cfg");
    let site_rows = if reference.is_some() {
        &references
    } else {
        &definitions
    };
    let (site_activation, _, assignment) = site_cfg_context(
        site_rows.iter().map(|(_, _, atoms)| (atoms, false)),
        site_condition,
    );
    match site_activation {
        RustSelectedActivation::Unknown => {
            return Ok(Some(DeclarationAccessDecision::UnknownActivation));
        }
        RustSelectedActivation::Inactive => {
            return Ok(Some(DeclarationAccessDecision::InactiveActivation));
        }
        RustSelectedActivation::Active => (),
    }
    let activation = |rows: &[CratePlacement], condition: &RustCfgCondition| {
        let mut active = false;
        for (_, _, atoms) in rows {
            let selected = brokk_bifrost_rust::cfg::crate_activation_under_site_cfg(
                atoms,
                condition,
                assignment.as_ref(),
            );
            match selected {
                RustSelectedActivation::Unknown => return RustSelectedActivation::Unknown,
                RustSelectedActivation::Active => active = true,
                RustSelectedActivation::Inactive => (),
            }
        }
        if active || (rows.is_empty() && condition == &RustCfgCondition::Always) {
            RustSelectedActivation::Active
        } else if rows.is_empty() {
            RustSelectedActivation::Unknown
        } else {
            RustSelectedActivation::Inactive
        }
    };
    for state in [
        reference.map(|row| activation(&references, row.row().cfg_condition())),
        definition.map(|row| activation(&definitions, row.row().cfg_condition())),
    ]
    .into_iter()
    .flatten()
    {
        match state {
            RustSelectedActivation::Unknown => {
                return Ok(Some(DeclarationAccessDecision::UnknownActivation));
            }
            RustSelectedActivation::Inactive => {
                return Ok(Some(DeclarationAccessDecision::InactiveActivation));
            }
            RustSelectedActivation::Active => (),
        }
    }
    finish_access(
        selection.connection(),
        reference,
        definition,
        &references,
        &definitions,
    )
}

pub(crate) fn set_access(
    selection: &super::super::resolution_selection::SelectedResolutionMountInventory<'_>,
    crate_key: [u8; 32],
    base_blobs: &[(BindingFragmentId, i64)],
    reference: Option<&SelectedTypedRow<LoweredRustReferenceContext>>,
    definition: Option<&SelectedTypedRow<LoweredRustDeclarationAuthority>>,
) -> Result<Option<DeclarationAccessDecision>> {
    use brokk_bifrost_core::analyzer::rust_facts::RustCfgCondition;
    use brokk_bifrost_rust::selected_context::RustSelectedActivation;
    let conn = selection.connection();
    let memberships = |fragment| {
        let Some(subject) =
            certified_predecessor_or_selected_mount(selection, base_blobs, fragment)?
        else {
            return Ok(Vec::new());
        };
        let key = PlacementKey {
            language: Language::Rust,
            unit_digest: crate_key,
            subject,
            declaration: None,
        };
        read_placements(
            selection,
            &key,
            PlacementRead {
                sql: MEMBERSHIPS,
                bind: |key: &PlacementKey| {
                    vec![key.unit_digest.to_vec().into(), key.subject.blob.into()]
                },
                decode: |row: &rusqlite::Row<'_>| {
                    let atoms: String = row.get(1)?;
                    Ok((
                        row.get(0)?,
                        serde_json::from_str(&atoms)
                            .map_err(|error| StoreError::corrupt(error.to_string()))?,
                        row.get(2)?,
                    ))
                },
            },
            selection
                .crate_access_memo()
                .borrow_mut()
                .as_mut()
                .map(|memo| &mut memo.memberships),
        )
    };
    let references = reference
        .map(|row| {
            reference_placements(
                selection,
                crate_key,
                base_blobs,
                row.fragment(),
                row.row().module_declaration(),
            )
        })
        .transpose()?
        .unwrap_or_default();
    let definitions = definition
        .map(|row| {
            definition_placements(
                selection,
                crate_key,
                base_blobs,
                row.fragment(),
                row.row().module_declaration(),
            )
        })
        .transpose()?
        .unwrap_or_default();
    let reference_memberships = reference
        .map(|row| memberships(row.fragment()))
        .transpose()?
        .unwrap_or_default();
    let definition_memberships = definition
        .map(|row| memberships(row.fragment()))
        .transpose()?
        .unwrap_or_default();
    if (reference.is_some() && reference_memberships.is_empty())
        || (reference.is_none() && definition.is_some() && definition_memberships.is_empty())
    {
        return Ok(None);
    }
    // A definition-only check is declaration self-activation (including the
    // reverse-usage preflight). Its own cfg is the premise until concrete
    // reference sites are checked below with their site cfgs.
    let site_condition = reference
        .map(|row| row.row().cfg_condition())
        .or_else(|| definition.map(|row| row.row().cfg_condition()))
        .expect("Rust access has a reference or declaration cfg");
    let site_rows = if reference.is_some() {
        &reference_memberships
    } else {
        &definition_memberships
    };
    let (site_activation, _, assignment) = site_cfg_context(
        site_rows
            .iter()
            .map(|(_, atoms, kind)| (atoms, kind == "detached")),
        site_condition,
    );
    match site_activation {
        RustSelectedActivation::Unknown => {
            return Ok(Some(DeclarationAccessDecision::UnknownActivation));
        }
        RustSelectedActivation::Inactive => {
            return Ok(Some(DeclarationAccessDecision::InactiveActivation));
        }
        RustSelectedActivation::Active => (),
    }
    let activation = |rows: &[CrateMembership], condition: &RustCfgCondition| {
        let mut active = false;
        for (_, atoms, kind) in rows {
            let state = if kind == "detached" {
                brokk_bifrost_rust::cfg::detached_activation_under_site_cfg(
                    atoms,
                    condition,
                    assignment.as_ref(),
                )
            } else {
                brokk_bifrost_rust::cfg::crate_activation_under_site_cfg(
                    atoms,
                    condition,
                    assignment.as_ref(),
                )
            };
            match state {
                RustSelectedActivation::Unknown => return RustSelectedActivation::Unknown,
                RustSelectedActivation::Active => active = true,
                RustSelectedActivation::Inactive => (),
            }
        }
        if active || (rows.is_empty() && condition == &RustCfgCondition::Always) {
            RustSelectedActivation::Active
        } else if rows.is_empty() {
            RustSelectedActivation::Unknown
        } else {
            RustSelectedActivation::Inactive
        }
    };
    for state in [
        reference.map(|row| activation(&reference_memberships, row.row().cfg_condition())),
        definition.map(|row| activation(&definition_memberships, row.row().cfg_condition())),
    ]
    .into_iter()
    .flatten()
    {
        match state {
            RustSelectedActivation::Unknown => {
                return Ok(Some(DeclarationAccessDecision::UnknownActivation));
            }
            RustSelectedActivation::Inactive => {
                return Ok(Some(DeclarationAccessDecision::InactiveActivation));
            }
            RustSelectedActivation::Active => (),
        }
    }
    finish_access(conn, reference, definition, &references, &definitions)
}

fn finish_access(
    conn: &rusqlite::Connection,
    reference: Option<&SelectedTypedRow<LoweredRustReferenceContext>>,
    definition: Option<&SelectedTypedRow<LoweredRustDeclarationAuthority>>,
    references: &[CratePlacement],
    definitions: &[CratePlacement],
) -> Result<Option<DeclarationAccessDecision>> {
    use brokk_bifrost_core::analyzer::rust_facts::encode_rust_visibility;
    let (Some(_), Some(definition)) = (reference, definition) else {
        return Ok(Some(DeclarationAccessDecision::Allowed));
    };
    let Some(visibility) = definition.row().visibility() else {
        return Ok(Some(DeclarationAccessDecision::Unknown));
    };
    let visibility = encode_rust_visibility(visibility);
    // Share all-placement reduction as SQL when a second language adopts shared placements (milestone 2b slices 5 and 7), not as callbacks.
    let mut allowed = false;
    let mut denied = false;
    let mut unknown = false;
    let mut reaches_statement = conn.prepare_cached(VISIBILITY)?;
    for (target, path, _) in definitions {
        let parent: Option<String> = conn
            .prepare_cached(super::rust_crate_context::PARENT)?
            .query_row(rusqlite::params![target, path], |row| row.get(0))
            .optional()?;
        for (requester, request_path, _) in references {
            let reaches: Option<bool> = reaches_statement.query_row(
                rusqlite::params![requester, request_path, target, path, visibility, parent],
                |row| row.get(0),
            )?;
            match reaches {
                Some(true) => allowed = true,
                Some(false) => denied = true,
                None => unknown = true,
            }
        }
    }
    if unknown {
        return Ok(Some(DeclarationAccessDecision::Unknown));
    }
    Ok(Some(match (allowed, denied) {
        (true, false) => DeclarationAccessDecision::Allowed,
        (false, true) => DeclarationAccessDecision::Denied,
        _ => DeclarationAccessDecision::Unknown,
    }))
}

impl RustAccessDecisionSource for RustCrateAccessPolicy {
    fn identity(&self) -> SemanticId {
        self.identity
    }

    fn decide(
        &self,
        facts: &dyn SelectedTypedFactSource,
        reference: Option<&SelectedTypedRow<LoweredRustReferenceContext>>,
        definition: Option<&SelectedTypedRow<LoweredRustDeclarationAuthority>>,
    ) -> Result<DeclarationAccessDecision> {
        let mut decision = None;
        for key in &self.crate_keys {
            let Some(next) =
                facts.rust_crate_access(*key, &self.base_blobs, reference, definition)?
            else {
                continue;
            };
            // One selected placement supplies positive authority for this exact
            // reference/definition pair. A file compiled into more than one
            // Cargo target has one placement per target, and a placement that
            // cannot reach the definition does not revoke one that can --
            // otherwise every reference in a lib/bin shared file is unprovable.
            // `RustCrateSetAccessPolicy` below takes the same reading.
            if next == DeclarationAccessDecision::Allowed {
                return Ok(DeclarationAccessDecision::Allowed);
            }
            decision = Some(match decision {
                Some(previous) if previous != next => DeclarationAccessDecision::Unknown,
                _ => next,
            });
        }
        Ok(decision.unwrap_or_else(|| {
            if reference.is_none() {
                if definition.is_some_and(|definition| {
                    definition.row().cfg_condition()
                        == &brokk_bifrost_core::analyzer::rust_facts::RustCfgCondition::Always
                }) {
                    DeclarationAccessDecision::Allowed
                } else {
                    DeclarationAccessDecision::Unknown
                }
            } else {
                // No crate this point request names places the reference's
                // module, so the reference is outside the request's crate set.
                // Rows say that exactly: a decoy of the same name in an
                // unrelated Cargo target is denied here, not unknown. The
                // crate-set policy below, which certifies absence, keeps the
                // conservative reading instead.
                DeclarationAccessDecision::Denied
            }
        }))
    }
}

impl RustAccessDecisionSource for RustCrateSetAccessPolicy {
    fn identity(&self) -> SemanticId {
        self.identity
    }

    fn decide(
        &self,
        facts: &dyn SelectedTypedFactSource,
        reference: Option<&SelectedTypedRow<LoweredRustReferenceContext>>,
        definition: Option<&SelectedTypedRow<LoweredRustDeclarationAuthority>>,
    ) -> Result<DeclarationAccessDecision> {
        let mut decisions = Vec::new();
        for key in &self.crate_keys {
            if let Some(next) =
                facts.rust_crate_set_access(*key, &self.base_blobs, reference, definition)?
            {
                decisions.push(next);
            }
        }
        if decisions.contains(&DeclarationAccessDecision::UnknownActivation) {
            return Ok(DeclarationAccessDecision::UnknownActivation);
        }
        if !decisions.is_empty()
            && decisions
                .iter()
                .all(|decision| *decision == DeclarationAccessDecision::InactiveActivation)
        {
            return Ok(DeclarationAccessDecision::InactiveActivation);
        }
        decisions.retain(|decision| *decision != DeclarationAccessDecision::InactiveActivation);
        if decisions.contains(&DeclarationAccessDecision::Allowed) {
            return Ok(DeclarationAccessDecision::Allowed);
        }
        let Some(first) = decisions.first().copied() else {
            if reference.is_none() {
                return Ok(if definition.is_some_and(|definition| {
                    definition.row().cfg_condition() == &brokk_bifrost_core::analyzer::rust_facts::RustCfgCondition::Always
                }) {
                    DeclarationAccessDecision::Allowed
                } else {
                    DeclarationAccessDecision::UnknownActivation
                });
            }
            // No crate in this set places the reference's module, so the
            // reference is outside the set. That is an exact exclusion from
            // rows -- a decoy of the same name in an unrelated Cargo target --
            // and it is not the undecided cfg atom that keeps absence
            // uncertain, which arrives above as `UnknownActivation`.
            return Ok(DeclarationAccessDecision::Denied);
        };
        Ok(if decisions.iter().all(|decision| *decision == first) {
            first
        } else {
            DeclarationAccessDecision::Unknown
        })
    }
}

/// Qualify only source-owned Rust import choices. The import token marks
/// the rank it guards in the path trace. It already carries source provenance
/// in the catalog, so no workspace inventory or answer cache is needed.
pub(crate) fn qualify_import_path(
    selection: &super::super::resolution_selection::SelectedResolutionMountInventory<'_>,
    reference: SemanticId,
    path: &mut PartialPath,
    cancellation: &CancellationToken,
) -> Result<Option<bool>> {
    use crate::analyzer::resolution::SelectedSemanticMount;
    use brokk_bifrost_rust::selected_context::RustSelectedActivation;
    let reference_mount = match selection.mount_rebaser().borrow().semantic_mount(reference) {
        SelectedSemanticMount::FragmentLocal(mount) => mount,
        SelectedSemanticMount::Shared(_) => return Ok(Some(true)),
    };
    let conn = selection.connection();
    let mut groups: Vec<(SelectedResolutionMountOrdinal, Vec<u32>)> = Vec::new();
    for step in path.precedence() {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let mount = match selection
            .mount_rebaser()
            .borrow()
            .semantic_mount(step.semantic)
        {
            SelectedSemanticMount::FragmentLocal(mount) => mount,
            SelectedSemanticMount::Shared(_) => continue,
        };
        // Selected stage choices can belong to a mount without having a
        // blob-local catalog key. The source lookup cannot match those.
        let Some(key) = step.semantic.local_key() else {
            continue;
        };
        if let Some((_, keys)) = groups
            .iter_mut()
            .find(|(ordinal, _)| *ordinal == mount.ordinal())
        {
            keys.push(key);
        } else {
            groups.push((mount.ordinal(), vec![key]));
        }
    }
    let mut conditional = Vec::new();
    for (ordinal, keys) in groups {
        let owner = selection.mount_record_by_ordinal(ordinal)?;
        if owner.semantic_language() != Language::Rust {
            continue;
        }
        // Probe the catalog before expanding a token's source route. The
        // uncorrelated existence check also rules out an unconditional-only
        // blob once for the entire batch. Use the same cfg projection as
        // source_rust_import_targets, including its legacy source-less rows.
        let import_keys = conn
            .prepare_cached(
                "SELECT token.local_key
             FROM resolution_semantic_catalog token
             WHERE token.blob_id=?1
               AND token.local_key IN (SELECT value FROM json_each(?2))
               AND token.import_source_site IS NOT NULL
               AND EXISTS (
                SELECT 1 FROM rust_import_targets imported
                LEFT JOIN source_rust_import_contexts context
                  ON context.blob_id=imported.blob_id
                 AND context.declaration_occurrence_id=imported.source_context_occurrence_id
                WHERE imported.blob_id=?1
                  AND CASE WHEN imported.source_context_occurrence_id IS NULL
                       THEN imported.cfg_condition ELSE context.cfg_condition END<>'always')
             ORDER BY token.local_key",
            )?
            .query_map(
                rusqlite::params![
                    owner.blob_id(),
                    serde_json::to_string(&keys).expect("local keys serialize")
                ],
                |row| row.get::<_, u32>(0),
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        // Preserve path order even though the batched catalog probe is keyed.
        for key in keys {
            if cancellation.is_cancelled() {
                return Ok(None);
            }
            if import_keys.binary_search(&key).is_err() {
                continue;
            }
            let token = SemanticId::local(ordinal.get(), key);
            let condition: Option<(String, u32)> = conn
                .prepare_cached(
                    "SELECT imports.cfg_condition, json_extract(route.body, '$[8][2][2]')
                 FROM resolution_semantic_catalog token
                 CROSS JOIN source_rust_import_targets imports ON imports.blob_id=token.blob_id
                 CROSS JOIN source_occurrence_arenas occurrence
                   ON occurrence.blob_id=imports.blob_id
                 CROSS JOIN resolution_node_catalog scope
                   ON scope.blob_id=imports.blob_id AND scope.source_scope=imports.native_scope
                 CROSS JOIN resolution_paths route
                   ON route.blob_id=scope.blob_id AND route.start_node=scope.local_key
                  AND route.end_node=-1 AND route.root_terminal IS NOT NULL
                  AND json_extract(route.body, '$[4][#-2]')=token.local_key
                 WHERE token.blob_id=?1 AND token.local_key=?2
                   AND token.import_source_site IS NOT NULL
                   AND json_extract(occurrence.spans, '$[' || imports.declaration_occurrence_id || '][0]')<=token.import_start_byte
                   AND json_extract(occurrence.spans, '$[' || imports.declaration_occurrence_id || '][1]')>=token.import_end_byte
                 LIMIT 1",
                )?
                .query_row(rusqlite::params![owner.blob_id(), token.local_key()], |row| {
                    Ok((row.get(0)?, row.get(1)?))
                })
                .optional()?;
            let Some((condition, choice_key)) = condition else {
                continue;
            };
            let condition =
                brokk_bifrost_core::analyzer::rust_facts::decode_rust_cfg_condition(&condition)
                    .expect("stored import cfg condition");
            if condition == brokk_bifrost_core::analyzer::rust_facts::RustCfgCondition::Always {
                continue;
            }
            conditional.push((token, choice_key, condition));
        }
    }
    if conditional.is_empty() {
        return Ok(Some(true));
    }
    // Most paths have no conditional import. Only those that do need the
    // reference premise and selected crate contexts, once per call.
    let record = selection.mount_record_by_ordinal(reference_mount.ordinal())?;
    if record.semantic_language() != Language::Rust {
        return Ok(Some(true));
    }
    let site: Option<String> = conn
        .prepare_cached(
            "SELECT json(cfg_condition) FROM resolution_rust_reference_contexts
         WHERE blob_id=?1 AND semantic_key=?2",
        )?
        .query_row(
            rusqlite::params![record.blob_id(), reference.local_key()],
            |row| row.get(0),
        )
        .optional()?;
    let Some(site) = site else {
        return Ok(Some(true));
    };
    let site = super::super::resolution_prepare::rust_authority::decode_cfg(&site);
    let contexts = conn
        .prepare_cached(
            "SELECT DISTINCT json(context.cfg_atoms), context.target_kind
         FROM selected_rust_container_placements placement
         CROSS JOIN main.rust_resolution_unit_summary_contexts context
           ON context.summary_id=placement.summary_id
         WHERE placement.placement_blob=?1",
        )?
        .query_map([record.blob_id()], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let contexts = contexts
        .into_iter()
        .map(|(atoms, kind)| {
            let atoms = serde_json::from_str::<BTreeSet<String>>(&atoms)
                .map_err(|error| StoreError::corrupt(error.to_string()))?;
            Ok((atoms, kind == "detached"))
        })
        .collect::<Result<Vec<_>>>()?;
    for (token, choice_key, condition) in conditional {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        let mut activation = None;
        for (atoms, detached) in &contexts {
            let (_, _, premise) = site_cfg_activation(atoms, *detached, &site);
            let selected = if *detached {
                brokk_bifrost_rust::cfg::detached_activation_under_site_cfg(
                    atoms,
                    &condition,
                    premise.as_ref(),
                )
            } else {
                brokk_bifrost_rust::cfg::crate_activation_under_site_cfg(
                    atoms,
                    &condition,
                    premise.as_ref(),
                )
            };
            activation = Some(match activation {
                Some(previous) if previous != selected => RustSelectedActivation::Unknown,
                _ => selected,
            });
        }
        match activation.unwrap_or(RustSelectedActivation::Unknown) {
            RustSelectedActivation::Inactive => return Ok(Some(false)),
            RustSelectedActivation::Active => {}
            RustSelectedActivation::Unknown => {
                // Unknown named imports can bind, but cannot prove shadowing
                // of the glob alternative. Their own route gap stays live.
                // Joined paths deduplicate repeated choice points. Find the
                // source choice by identity rather than relying on adjacency.
                let choice = SemanticId::local(
                    token.ordinal().expect("an import token is fragment-local"),
                    choice_key,
                );
                for step in &mut path.precedence {
                    if step.semantic == choice {
                        step.ordinal = 1;
                    }
                }
                path.completion = path.completion.combine(&ResolutionCompletion::incomplete([
                    ResolutionIncompleteReason::UnsupportedSemantic(token),
                ]));
            }
        }
    }
    Ok(Some(true))
}
