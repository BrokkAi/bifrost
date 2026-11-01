//! Dormant C# compilation placements and access on the shared readers.
use super::placement_access::{
    PlacementKey, PlacementMemo, PlacementRead, PlacementSubject, read_placements,
};
use super::unit_access::{UnitAccess, UnitAccessMemo, UnitAccessRules, read_unit_access};
use super::*;
use crate::analyzer::store::resolution_selection::SelectedResolutionMountInventory;
use crate::analyzer::store::{
    WorkspaceSnapshotId,
    csharp_compilation::{CSharpCompilationView, SelectedCSharpMembership},
};
use rusqlite::types::Value;

pub const PLACEMENT_SQL: &str = "SELECT compilation.compilation_id, compilation.project_path
    FROM csharp_compilations AS compilation
    JOIN csharp_compilation_selections AS selected ON selected.set_id = compilation.set_id
    JOIN temp.selected_workspace_revisions AS revision
      ON revision.workspace_id = selected.workspace_id AND revision.lang = selected.lang
     AND revision.generation = selected.generation AND revision.revision = selected.revision
    WHERE compilation.compilation_id = ?1 AND selected.lang = 'csharp'";

/// Configuration reads are not yet ledgered, so this is an operational reason.
pub const ACCESS_UNKNOWN: &str = "csharp-compilation-access-unknown";

#[derive(Clone, Debug)]
pub struct CSharpUnitPlacement {
    pub compilation_id: i64,
    pub project_path: Option<String>,
    key: PlacementKey,
}

/// One selected query. The shared memo caps bound retention; drop this reader
/// with the request. Returned placements are results of that query.
pub struct CSharpUnitReader<'a, 'selection> {
    selection: &'a SelectedResolutionMountInventory<'selection>,
    compilations: Option<CSharpCompilationView<'a>>,
    identities: &'a SelectedContextIdentities,
    placements: PlacementMemo<CSharpUnitPlacement>,
    access: UnitAccessMemo,
}

impl<'a, 'selection> CSharpUnitReader<'a, 'selection> {
    pub fn new(
        selection: &'a SelectedResolutionMountInventory<'selection>,
        snapshot: &'a WorkspaceSnapshotId,
        identities: &'a SelectedContextIdentities,
    ) -> Result<Self> {
        Ok(Self {
            selection,
            compilations: CSharpCompilationView::selected(selection.connection(), snapshot)?,
            identities,
            placements: Default::default(),
            access: Default::default(),
        })
    }

    /// The subject uses the selected C# mount ordinal, unique per workspace path.
    /// None preserves unknown membership; a proven empty set remains empty.
    pub(super) fn using_metadata(
        &self,
        placement: &CSharpUnitPlacement,
    ) -> Result<Option<super::super::csharp_compilation::CSharpCompilationMetadata>> {
        self.compilations
            .as_ref()
            .map(|view| view.metadata(placement.project_path.as_deref()))
            .transpose()
            .map(Option::flatten)
    }

    pub(super) fn compilation_membership(
        &self,
        rel_path: &str,
    ) -> Result<SelectedCSharpMembership> {
        match &self.compilations {
            Some(view) => view.selected_compilations_of(self.selection, rel_path),
            None => Ok(SelectedCSharpMembership::NotSelected),
        }
    }

    pub(super) fn open_inventories(
        &self,
        placement: &CSharpUnitPlacement,
    ) -> Result<Vec<super::super::csharp_compilation::CSharpOpenInventory>> {
        match &self.compilations {
            Some(view) => view.open_inventories(placement.compilation_id),
            None => Err(StoreError::corrupt("C# placement has no compilation view")),
        }
    }

    pub(super) fn inventory_gaps(
        &self,
        placement: &CSharpUnitPlacement,
    ) -> Result<Vec<super::super::csharp_compilation::CSharpCompilationGap>> {
        match &self.compilations {
            Some(view) => view.inventory_gaps(placement.compilation_id),
            None => Err(StoreError::corrupt("C# placement has no compilation view")),
        }
    }

    pub fn placements(&mut self, rel_path: &str) -> Result<Option<Vec<CSharpUnitPlacement>>> {
        let ids = match self.compilation_membership(rel_path)? {
            SelectedCSharpMembership::Proven(membership) => membership.proven,
            SelectedCSharpMembership::Unproven { .. } => return Ok(None),
            SelectedCSharpMembership::NotSelected => return Ok(None),
        };
        let Some(mount) = self.selection.mount_record_for_path("csharp", rel_path)? else {
            return Ok(None);
        };
        let path = mount.ordinal().get() as usize;
        let mut placements = Vec::new();
        for compilation_id in ids {
            let mut hash = CanonicalHasher::new(b"bifrost-csharp-placement-unit:v1");
            hash.field("selection", &self.selection.scope_identity());
            hash.field("compilation", &compilation_id.to_le_bytes());
            let key = PlacementKey {
                language: Language::CSharp,
                unit_digest: hash.finish(),
                subject: PlacementSubject {
                    blob: None,
                    path: Some(path),
                    file_version: None,
                },
                declaration: None,
            };
            let rows = read_placements(
                self.selection,
                &key,
                PlacementRead {
                    sql: PLACEMENT_SQL,
                    bind: |_: &PlacementKey| vec![Value::Integer(compilation_id)],
                    decode: |row: &rusqlite::Row<'_>| {
                        Ok(CSharpUnitPlacement {
                            compilation_id: row.get(0)?,
                            project_path: row.get(1)?,
                            key,
                        })
                    },
                },
                Some(&mut self.placements),
            )?;
            // Missing selected metadata is unknown, never a negative proof.
            if rows.is_empty() {
                return Ok(None);
            }
            placements.extend(rows);
        }
        Ok(Some(placements))
    }

    /// Unit-access evidence in the caller's selected identity arena.
    pub(super) fn read_access(
        &mut self,
        callers: Option<&[CSharpUnitPlacement]>,
        targets: Option<&[CSharpUnitPlacement]>,
    ) -> Result<UnitAccess> {
        let callers = callers.unwrap_or_default();
        let targets = targets.unwrap_or_default();
        let rules = CSharpAccessRules {
            compilations: self.compilations.as_ref(),
            identities: self.identities,
            callers,
            targets,
        };
        let access = read_unit_access(
            self.selection,
            &rules,
            &callers.iter().map(|p| p.key).collect::<Vec<_>>(),
            &targets.iter().map(|p| p.key).collect::<Vec<_>>(),
            Some(&mut self.access),
        )?;
        Ok(access)
    }

    /// Render shared evidence for the schema-to-reader test boundary.
    pub fn access(
        &mut self,
        callers: Option<&[CSharpUnitPlacement]>,
        targets: Option<&[CSharpUnitPlacement]>,
    ) -> Result<CSharpUnitAccess> {
        let access = self.read_access(callers, targets)?;
        Ok(match access {
            UnitAccess::Visible => CSharpUnitAccess::Visible,
            UnitAccess::NotVisible => CSharpUnitAccess::NotVisible,
            UnitAccess::Unknown(reason) => {
                let (kind, evidence) = self
                    .identities
                    .named_reason(reason)
                    .expect("C# access names its reason");
                CSharpUnitAccess::Unknown {
                    kind,
                    evidence: evidence.to_string(),
                }
            }
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum CSharpUnitAccess {
    Visible,
    NotVisible,
    Unknown {
        kind: &'static str,
        evidence: String,
    },
}

struct CSharpAccessRules<'a> {
    compilations: Option<&'a CSharpCompilationView<'a>>,
    identities: &'a SelectedContextIdentities,
    callers: &'a [CSharpUnitPlacement],
    targets: &'a [CSharpUnitPlacement],
}

impl CSharpAccessRules<'_> {
    fn unknown_for(
        &self,
        callers: &[CSharpUnitPlacement],
        targets: &[CSharpUnitPlacement],
    ) -> SemanticId {
        let callers: Vec<_> = callers
            .iter()
            .map(|p| (&p.project_path, p.compilation_id))
            .collect();
        let targets: Vec<_> = targets
            .iter()
            .map(|p| (&p.project_path, p.compilation_id))
            .collect();
        let evidence = format!(
            "C# compilation visibility is unknown or disagrees: callers {callers:?}, targets {targets:?}"
        );
        let mut hash = CanonicalHasher::new(b"bifrost-csharp-compilation-access-unknown:v1");
        hash.field("evidence", evidence.as_bytes());
        self.identities
            .named_semantic(hash.finish(), ACCESS_UNKNOWN, &evidence)
    }
}

impl UnitAccessRules for CSharpAccessRules<'_> {
    fn exact_relation(
        &self,
        caller: &PlacementKey,
        target: &PlacementKey,
    ) -> Result<Option<UnitAccess>> {
        let caller = self
            .callers
            .iter()
            .find(|p| p.key == *caller)
            .expect("caller placement");
        let target = self
            .targets
            .iter()
            .find(|p| p.key == *target)
            .expect("target placement");
        let Some(compilations) = self.compilations else {
            return Ok(None);
        };
        let visible = compilations.visible_closure(caller.compilation_id)?;
        if visible.binary_search(&target.compilation_id).is_ok() {
            return Ok(Some(UnitAccess::Visible));
        }
        let (reached, complete) = compilations.referenced_closure(caller.compilation_id)?;
        Ok(
            (complete && reached.binary_search(&target.compilation_id).is_err())
                .then_some(UnitAccess::NotVisible),
        )
    }

    fn unknown_reason(&self, caller: &PlacementKey, target: &PlacementKey) -> Result<SemanticId> {
        let caller = self
            .callers
            .iter()
            .find(|p| p.key == *caller)
            .expect("caller placement");
        let target = self
            .targets
            .iter()
            .find(|p| p.key == *target)
            .expect("target placement");
        Ok(self.unknown_for(std::slice::from_ref(caller), std::slice::from_ref(target)))
    }

    fn combine(&self, answers: &[(PlacementKey, PlacementKey, UnitAccess)]) -> UnitAccess {
        // First any visible target instance counts for each caller compilation;
        // then all caller compilations must agree. Agreement over every raw
        // caller-target pair would reject a caller seeing one instance of a
        // multiply placed target. This mirrors CSharpAnalyzer::compilation_visibility
        // in bifrost-csharp-analysis/src/analyzer/csharp/compilation.rs:963-989.
        let mut agreed = None;
        for caller in self.callers {
            let mut instance = UnitAccess::NotVisible;
            let mut found = false;
            for (_, _, access) in answers.iter().filter(|(key, _, _)| *key == caller.key) {
                found = true;
                match access {
                    UnitAccess::Visible => {
                        instance = UnitAccess::Visible;
                        break;
                    }
                    UnitAccess::Unknown(_) => {
                        instance = UnitAccess::Unknown(self.unknown_for(self.callers, self.targets))
                    }
                    UnitAccess::NotVisible => {}
                }
            }
            if !found || agreed.is_some_and(|previous| previous != instance) {
                return UnitAccess::Unknown(self.unknown_for(self.callers, self.targets));
            }
            agreed = Some(instance);
        }
        agreed.unwrap_or_else(|| UnitAccess::Unknown(self.unknown_for(self.callers, self.targets)))
    }
}

// Read A is trial-only. Read B replaces this function with compilation-keyed
// extent and coverage reads without changing the returned inventory contract.
pub const GLOBAL_USING_CANDIDATES: &str = "SELECT DISTINCT v.rel_path
 FROM main.resolution_compilation_imports g
 CROSS JOIN main.blobs b ON b.id=g.blob_id
 CROSS JOIN main.workspace_file_versions v INDEXED BY idx_workspace_file_versions_snapshot_blob
 ON v.workspace_id=?1 AND v.lang='csharp' AND v.generation=?2 AND v.blob_oid=b.blob_oid
 WHERE v.valid_from<=?3 AND (v.valid_until IS NULL OR v.valid_until>?3) AND v.input_kind='source'
 AND NOT EXISTS(SELECT 1 FROM temp.selected_resolution_overlay_masks x
 WHERE x.storage_language='csharp' AND x.persisted_relative_path=v.rel_path)
 UNION SELECT m.persisted_relative_path FROM temp.selected_resolution_mounts m
 JOIN main.resolution_compilation_imports g ON g.blob_id=m.blob_id
 WHERE m.storage_language='csharp' AND m.file_version_id IS NULL";
pub const GLOBAL_USING_SITES: &str = "SELECT g.import_site,s.local_name
 FROM main.resolution_compilation_imports g
 LEFT JOIN main.resolution_import_selectors s ON s.blob_id=g.blob_id AND s.site=g.import_site
 WHERE g.blob_id=?1 ORDER BY g.import_site";
pub const GLOBAL_USING_COVERAGE: &str = "SELECT l.expected_unmasked_mount_count,
 (SELECT count(*) FROM temp.selected_resolution_mounts m WHERE m.storage_language='csharp' AND m.file_version_id IS NOT NULL),
 (SELECT coalesce(sum(x.expected_transient_replacement_count),0) FROM temp.selected_resolution_overlay_masks x WHERE x.storage_language='csharp'),
 (SELECT count(*) FROM temp.selected_resolution_mounts m WHERE m.storage_language='csharp' AND m.file_version_id IS NULL),
 (SELECT json_group_array(m.persisted_relative_path) FROM temp.selected_resolution_mounts m
  WHERE m.storage_language='csharp' AND EXISTS(SELECT 1 FROM main.resolution_gaps gap
   WHERE gap.blob_id=m.blob_id AND gap.covers=1))
 FROM temp.selected_resolution_languages l WHERE l.storage_language='csharp'";

pub(super) struct CSharpGlobalUsingRoute {
    pub fragment: BindingFragmentId,
    pub alias: Option<String>,
    pub route: super::imports::ImportRoute,
}
pub(super) struct CSharpGlobalUsings {
    pub routes: Vec<CSharpGlobalUsingRoute>,
    pub completion: crate::analyzer::resolution::ResolutionCompletion,
}
impl CSharpUnitReader<'_, '_> {
    pub(super) fn global_usings(
        &mut self,
        snapshot: &WorkspaceSnapshotId,
        placement: &CSharpUnitPlacement,
        cancellation: &CancellationToken,
        session: &brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession,
    ) -> Result<Option<CSharpGlobalUsings>> {
        use crate::analyzer::resolution::{ResolutionCompletion, ResolutionIncompleteReason};
        let conn = self.selection.connection();
        let mut missing = Vec::new();
        let counts = conn
            .prepare_cached(GLOBAL_USING_COVERAGE)?
            .query_row([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, String>(4)?,
                ))
            })?;
        if counts.0 != counts.1 || counts.2 != counts.3 {
            missing.push(format!(
                "source publications: expected/installed persisted {}/{}, transient {}/{}",
                counts.0, counts.1, counts.2, counts.3
            ));
        }
        if !self
            .compilations
            .as_ref()
            .map(|view| view.inventory_gaps(placement.compilation_id))
            .transpose()?
            .is_some_and(|gaps| gaps.is_empty())
        {
            let gaps = self.inventory_gaps(placement)?;
            missing.push(format!("compilation inventory is open: {gaps:?}"));
        }
        let changed: bool = conn
            .prepare_cached(super::super::csharp_compilation::SELECTED_CONFIGURATION_MASK_SQL)?
            .query_row(
                rusqlite::params![
                    snapshot.workspace_id.as_str(),
                    snapshot.generation.0,
                    snapshot.revision
                ],
                |row| row.get(0),
            )?;
        if changed {
            missing.push(
                "configuration inputs are replaced; derived membership is unavailable".into(),
            );
        }
        // A published fragment with incomplete enumeration does not certify
        // zero global directives. In particular an unsupported using target can
        // have a gap and no marker; retain that source's inventory obligation.
        let uncertain: Vec<String> = serde_json::from_str(&counts.4).map_err(|error| {
            StoreError::corrupt(format!("invalid global-using coverage paths: {error}"))
        })?;
        for path in uncertain {
            if cancellation.is_cancelled() || !session.scope_step() {
                return Ok(None);
            }
            if let Some(view) = self.compilations.as_ref() {
                match view.selected_compilations_of(self.selection, &path)? {
                    SelectedCSharpMembership::Proven(membership) => {
                        if !membership
                            .open
                            .iter()
                            .any(|open| open.compilation_id == placement.compilation_id)
                            && !membership.proven.contains(&placement.compilation_id)
                        {
                            continue;
                        }
                    }
                    SelectedCSharpMembership::Unproven { .. } => {}
                    SelectedCSharpMembership::NotSelected => {}
                }
            }
            missing.push(format!("source marker enumeration incomplete: {path}"));
        }
        let mut routes = Vec::new();
        let mut statement = conn.prepare_cached(GLOBAL_USING_CANDIDATES)?;
        let mut rows = statement.query(rusqlite::params![
            snapshot.workspace_id.as_str(),
            snapshot.generation.0,
            snapshot.revision
        ])?;
        while let Some(row) = rows.next()? {
            if cancellation.is_cancelled() || !session.scope_step() {
                return Ok(None);
            }
            let path: String = row.get(0)?;
            let Some(mount) = self.selection.mount_record_for_path("csharp", &path)? else {
                missing.push(format!("source publication unavailable: {path}"));
                continue;
            };
            let Some(view) = self.compilations.as_ref() else {
                continue;
            };
            let ids = match view.selected_compilations_of(self.selection, &path)? {
                SelectedCSharpMembership::Proven(membership) => {
                    if membership
                        .open
                        .iter()
                        .any(|open| open.compilation_id == placement.compilation_id)
                    {
                        missing.push(format!("membership open: {path}: {:?}", membership.open));
                    }
                    membership.proven
                }
                SelectedCSharpMembership::Unproven { .. } => {
                    missing.push(format!("membership unavailable: {path}"));
                    continue;
                }
                SelectedCSharpMembership::NotSelected => {
                    missing.push(format!("membership unavailable: {path}"));
                    continue;
                }
            };
            if !ids.contains(&placement.compilation_id) {
                continue;
            }
            // A candidate blob merely discovers a path. Only its selected mount
            // authorizes the publication/parse variant used to hydrate a route.
            let mut sites = conn.prepare_cached(GLOBAL_USING_SITES)?;
            for site in sites.query_map([mount.blob_id()], |row| {
                Ok((row.get::<_, u32>(0)?, row.get::<_, Option<String>>(1)?))
            })? {
                if cancellation.is_cancelled() || !session.scope_step() {
                    return Ok(None);
                }
                let (site, alias) = site?;
                let route = super::imports::route_at_site(conn, mount.blob_id(), site)?
                    .ok_or_else(|| {
                        StoreError::corrupt("global using marker lacks its root import")
                    })?;
                // Root bound_name is the target demand; the selector owns the
                // local alias spelling, as the shared named-scope reader does.
                if route.kind == "named" && alias.is_none() {
                    return Err(StoreError::corrupt("global alias lacks its named selector"));
                }
                routes.push(CSharpGlobalUsingRoute {
                    fragment: mount.fragment_id(),
                    alias,
                    route,
                });
            }
        }
        missing.sort_unstable();
        missing.dedup();
        let completion = if missing.is_empty() {
            ResolutionCompletion::Complete
        } else {
            let mut hash = CanonicalHasher::new(b"csharp-global-using-inventory:v1");
            hash.field("selection", &self.selection.scope_identity());
            hash.field("compilation", &placement.compilation_id.to_le_bytes());
            for item in &missing {
                hash.field("missing", item.as_bytes());
            }
            let reason = self.identities.named_semantic(
                hash.finish(),
                "csharp_compilation_usings_incomplete",
                &format!("compilation {:?}: {missing:?}", placement.project_path),
            );
            ResolutionCompletion::incomplete([ResolutionIncompleteReason::UnsupportedSemantic(
                reason,
            )])
        };
        Ok(Some(CSharpGlobalUsings { routes, completion }))
    }
}
