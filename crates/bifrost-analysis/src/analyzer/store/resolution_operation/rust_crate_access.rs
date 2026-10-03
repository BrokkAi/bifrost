use super::rust_privacy::complete_access_source_read;
use super::*;
use crate::analyzer::resolution::{
    DeclarationAccessDecision, DeclarationAccessRequest, DeclarationAccessRow, FactPageVisitor,
    LoweredRustDeclarationAuthority, LoweredRustReferenceContext, SelectedDeclarationAccessSource,
    SelectedTypedFactSource, SelectedTypedRow, TypedFactReadOutcome, TypedFactRequest,
};

#[derive(Debug)]
pub(super) struct RustCrateAccessPolicy {
    pub(super) crate_keys: Vec<[u8; 32]>,
    pub(super) base_blobs: Vec<(BindingFragmentId, i64)>,
    /// The policy names itself with one identity the context minted for it.
    /// It belongs to no file, and it used to be a digest of the policy's own
    /// crate keys; the request's table numbers that digest now.
    pub(super) identity: SemanticId,
}

#[derive(Debug)]
pub(super) struct RustCrateSetAccessPolicy {
    pub(super) crate_keys: Vec<[u8; 32]>,
    pub(super) base_blobs: Vec<(BindingFragmentId, i64)>,
    /// See [`RustCrateAccessPolicy::identity`].
    pub(super) identity: SemanticId,
}

trait RustAccessDecisionSource: Send + Sync {
    fn access_identity(&self) -> SemanticId;
    fn decide(
        &self,
        facts: &dyn SelectedTypedFactSource,
        reference: Option<&SelectedTypedRow<LoweredRustReferenceContext>>,
        definition: Option<&SelectedTypedRow<LoweredRustDeclarationAuthority>>,
    ) -> Result<DeclarationAccessDecision>;
}

impl<T: RustAccessDecisionSource> SelectedDeclarationAccessSource for T {
    fn identity(&self) -> SemanticId {
        self.access_identity()
    }

    fn declaration_activation(
        &self,
        facts: &dyn SelectedTypedFactSource,
        definition: SemanticId,
        cancellation: &CancellationToken,
        session: Option<&ResolutionSession>,
    ) -> Result<Option<(DeclarationAccessDecision, Option<SemanticId>)>> {
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
        let definitions = definitions.into_iter().collect::<Vec<_>>();

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
}

pub(super) const PLACEMENTS: &str = "WITH RECURSIVE graph(topology_id) AS (
 SELECT topology_id FROM selected_rust_crates WHERE crate_key=?1
 UNION SELECT target.topology_id FROM graph
 CROSS JOIN rust_crate_dependencies AS dependency USING(topology_id)
 CROSS JOIN selected_rust_crates AS target ON target.crate_key=dependency.dependency_crate_key
) SELECT source.topology_id,source.container_path,json(topology.cfg_atoms)
FROM source_rust_module_scopes AS scope
CROSS JOIN rust_crate_container_sources AS source ON source.blob_id=scope.blob_id AND source.scope_ordinal=scope.ordinal
CROSS JOIN rust_crate_topologies AS topology ON topology.topology_id=source.topology_id
WHERE scope.blob_id=?2 AND scope.declaration_id IS ?3
AND source.topology_id IN (SELECT topology_id FROM graph)";

/// The module placements of a blob in the crate being resolved only, with the
/// same columns as [`PLACEMENTS`]. See `reference_placements`.
pub(super) const REFERENCE_PLACEMENTS: &str = "SELECT source.topology_id,source.container_path,json(topology.cfg_atoms)
FROM source_rust_module_scopes AS scope
CROSS JOIN rust_crate_container_sources AS source ON source.blob_id=scope.blob_id AND source.scope_ordinal=scope.ordinal
CROSS JOIN rust_crate_topologies AS topology ON topology.topology_id=source.topology_id
WHERE scope.blob_id=?2 AND scope.declaration_id IS ?3
AND source.topology_id IN (SELECT topology_id FROM selected_rust_crates WHERE crate_key=?1)";

pub(super) const MEMBERSHIPS: &str = "WITH RECURSIVE graph(topology_id) AS (
 SELECT topology_id FROM selected_rust_crates WHERE crate_key=?1
 UNION SELECT target.topology_id FROM graph
 CROSS JOIN rust_crate_dependencies AS dependency USING(topology_id)
 CROSS JOIN selected_rust_crates AS target ON target.crate_key=dependency.dependency_crate_key
) SELECT DISTINCT source.topology_id,json(topology.cfg_atoms),topology.target_kind
FROM rust_crate_container_sources AS source
CROSS JOIN rust_crate_topologies AS topology ON topology.topology_id=source.topology_id
WHERE source.blob_id=?2 AND source.topology_id IN (SELECT topology_id FROM graph)";

pub(super) const VISIBILITY: &str = "SELECT CASE WHEN ?5='public' THEN 1
 WHEN ?1<>?3 THEN 0 WHEN ?5='crate' THEN 1
 WHEN ?5 IN ('private','self') THEN (?2=?4 OR substr(?2,1,length(?4)+2)=?4 || '::')
 ELSE (?2=cr_restriction(?5,?4,?6) OR substr(?2,1,length(cr_restriction(?5,?4,?6))+2)=cr_restriction(?5,?4,?6) || '::') END FROM rust_crate_containers WHERE topology_id=?3 AND container_path=?4";

// Visibility and activation use persisted crate placement even when the
// selected canonical artifact is a content-mounted overlay. Its native facts
// still come from the selected blob; only placement uses this base identity.
fn placement_blob(
    selection: &super::super::resolution_selection::SelectedResolutionMountInventory<'_>,
    base_blobs: &[(BindingFragmentId, i64)],
    fragment: BindingFragmentId,
) -> Result<Option<i64>> {
    if let Some((_, blob)) = base_blobs.iter().find(|(id, _)| *id == fragment) {
        return Ok(Some(*blob));
    }
    Ok(selection
        .mount_record_for_fragment(fragment)?
        .map(|mount| mount.blob_id()))
}

type CratePlacement = (i64, String, BTreeSet<String>);
type CrateMembership = (i64, BTreeSet<String>, String);
type PlacementMemo = HashMap<([u8; 32], i64, Option<u32>), Vec<CratePlacement>>;

/// One crate stage's answers from [`PLACEMENTS`] and [`MEMBERSHIPS`], keyed by
/// their bound parameters.
///
/// Both statements rebuild the dependency closure of the stage's crate before
/// they look up one blob. On the whole tract graph they ran 757,326 times for
/// 24 s, asking the same few blobs of the crate again for every access
/// decision. The rows they read (crate rows, the selection's crates and the
/// blobs' module scopes) do not change while a stage runs.
///
/// Only a crate stage holds one, with the export memo beside it: see
/// `rust_crate_rows::CrateStageMemos`. Outside a crate stage the decisions run
/// the statements directly.
#[derive(Default)]
pub(crate) struct CrateAccessMemo {
    placements: PlacementMemo,
    reference_placements: PlacementMemo,
    memberships: HashMap<([u8; 32], i64), Vec<CrateMembership>>,
    /// Whether a definition, by mount ordinal and semantic key, declares a
    /// module (`rust_crate_rows::MODULE_DEFINITIONS`). Every projection round
    /// asks it again for the same targets: on the whole tract graph the
    /// statement ran 1,295,894 times for 17.3 s. A definition's declaration
    /// kind does not change while a stage runs.
    pub(super) module_definitions: HashMap<(u32, i64), bool>,
}

/// Where a definition's blob stands in the crate or any crate it depends on.
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

/// Where a reference's blob stands for the crate being resolved.
///
/// A blob placed in that crate is compiled there, so only those placements
/// count, even when a dependency mounts the same file too (a bench target and
/// its package library can share one). A blob the crate does not place, such
/// as a dependency's re-export binder reached from this crate, stands where the
/// dependency closure places it, as a definition does.
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

fn placement_rows(
    selection: &super::super::resolution_selection::SelectedResolutionMountInventory<'_>,
    crate_key: [u8; 32],
    base_blobs: &[(BindingFragmentId, i64)],
    fragment: BindingFragmentId,
    declaration: Option<SourceDeclarationId>,
    sql: &'static str,
    memo_rows: fn(&mut CrateAccessMemo) -> &mut PlacementMemo,
) -> Result<Vec<CratePlacement>> {
    use rusqlite::params;
    let Some(blob) = placement_blob(selection, base_blobs, fragment)? else {
        return Ok(Vec::new());
    };
    let key = (crate_key, blob, declaration.map(SourceDeclarationId::get));
    if let Some(rows) = selection
        .crate_access_memo()
        .borrow_mut()
        .as_mut()
        .and_then(|memo| memo_rows(memo).get(&key).cloned())
    {
        return Ok(rows);
    }
    let rows = selection
        .connection()
        .prepare_cached(sql)?
        .query_map(
            params![
                crate_key.as_slice(),
                blob,
                declaration.map(SourceDeclarationId::get)
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )?
        .map(|row| {
            let (topology, path, atoms) = row?;
            Ok((
                topology,
                path,
                serde_json::from_str(&atoms)
                    .map_err(|error| StoreError::corrupt(error.to_string()))?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    if let Some(memo) = selection.crate_access_memo().borrow_mut().as_mut() {
        memo_rows(memo).insert(key, rows.clone());
    }
    Ok(rows)
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
    let activation = |rows: &[CratePlacement], condition: &RustCfgCondition| {
        let mut active = false;
        for (_, _, atoms) in rows {
            match brokk_bifrost_rust::cfg::crate_activation(atoms, condition) {
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
    use rusqlite::params;
    let conn = selection.connection();
    let memberships = |fragment| -> Result<Vec<CrateMembership>> {
        let blob = placement_blob(selection, base_blobs, fragment)?;
        let Some(blob) = blob else {
            return Ok(Vec::new());
        };
        if let Some(rows) = selection
            .crate_access_memo()
            .borrow()
            .as_ref()
            .and_then(|memo| memo.memberships.get(&(crate_key, blob)))
        {
            return Ok(rows.clone());
        }
        let rows = conn
            .prepare_cached(MEMBERSHIPS)?
            .query_map(params![crate_key.as_slice(), blob], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?
            .map(|row| {
                let (topology, atoms, kind) = row?;
                Ok((
                    topology,
                    serde_json::from_str(&atoms)
                        .map_err(|error| StoreError::corrupt(error.to_string()))?,
                    kind,
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        if let Some(memo) = selection.crate_access_memo().borrow_mut().as_mut() {
            memo.memberships.insert((crate_key, blob), rows.clone());
        }
        Ok(rows)
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
    let activation = |rows: &[CrateMembership], condition: &RustCfgCondition| {
        let mut active = false;
        for (_, atoms, kind) in rows {
            let state = if kind == "detached" {
                brokk_bifrost_rust::cfg::detached_activation(atoms, condition)
            } else {
                brokk_bifrost_rust::cfg::crate_activation(atoms, condition)
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
    use rusqlite::params;
    let (Some(_), Some(definition)) = (reference, definition) else {
        return Ok(Some(DeclarationAccessDecision::Allowed));
    };
    let Some(visibility) = definition.row().visibility() else {
        return Ok(Some(DeclarationAccessDecision::Unknown));
    };
    let visibility = encode_rust_visibility(visibility);
    let mut allowed = false;
    let mut denied = false;
    let mut unknown = false;
    let mut reaches_statement = conn.prepare_cached(VISIBILITY)?;
    for (target, path, _) in definitions {
        let parent: Option<String> = conn
            .prepare_cached(super::rust_crate_context::PARENT)?
            .query_row(params![target, path], |row| row.get(0))
            .optional()?;
        for (requester, request_path, _) in references {
            let reaches: Option<bool> = reaches_statement.query_row(
                params![requester, request_path, target, path, visibility, parent],
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
    fn access_identity(&self) -> SemanticId {
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
    fn access_identity(&self) -> SemanticId {
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
