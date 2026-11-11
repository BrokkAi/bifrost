//! Dormant C# compilation placements and access on the shared readers.
use super::placement_access::{
    PlacementKey, PlacementMemo, PlacementRead, PlacementSubject, read_placements,
};
use super::unit_access::{UnitAccess, UnitAccessMemo, UnitAccessRules, read_unit_access};
use super::*;
use crate::analyzer::store::resolution_selection::SelectedResolutionMountInventory;
use crate::analyzer::store::{
    WorkspaceSnapshotId,
    csharp_compilation::{CSharpCompilationView, CertifiedCSharpHandle, SelectedCSharpMembership},
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
        certified: &CertifiedCSharpHandle,
        identities: &'a SelectedContextIdentities,
    ) -> Result<Self> {
        Ok(Self {
            selection,
            compilations: Some(CSharpCompilationView::certified(
                selection.connection(),
                snapshot,
                certified,
            )),
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
            .map(|view| view.metadata(placement.compilation_id))
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

// A coverage row counts only for a compilation of a set at the current
// derivation version: a row left by an older derivation proves nothing.
pub const SELECTED_GLOBAL_USING_COVERAGE: &str =
    "SELECT v.membership_complete,v.publications_expected,
 v.publications_installed,json(v.reasons)
 FROM temp.selected_csharp_compilation_using_coverage v
 JOIN main.csharp_compilations c ON c.compilation_id=v.compilation_id
 JOIN main.csharp_compilation_sets s ON s.set_id=c.set_id AND s.derivation_version=?2
 WHERE v.compilation_id=?1";
// The extent holds only installed publications of selected members; the reader
// checks each row's blob against the selected mount, and coverage proves the
// publication counts. Joining the member view would build an automatic index.
pub const SELECTED_GLOBAL_USING_SITES: &str =
    "SELECT e.rel_path,e.blob_id,e.import_site,s.local_name
 FROM temp.selected_csharp_global_using_extent e
 LEFT JOIN main.resolution_import_selectors s ON s.blob_id=e.blob_id AND s.site=e.import_site
 WHERE e.compilation_id=?1";

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
    #[cfg(feature = "test-support")]
    pub fn global_usings_for_test(
        &mut self,
        compilation_id: i64,
        project_path: Option<String>,
        cancellation: &CancellationToken,
        session: &brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession,
    ) -> Result<Option<(usize, crate::analyzer::resolution::ResolutionCompletion)>> {
        let placement = CSharpUnitPlacement {
            compilation_id,
            project_path,
            key: PlacementKey {
                language: Language::CSharp,
                unit_digest: [0; 32],
                subject: PlacementSubject {
                    blob: None,
                    path: None,
                    file_version: None,
                },
                declaration: None,
            },
        };
        Ok(self
            .global_usings(&placement, cancellation, session)?
            .map(|answer| (answer.routes.len(), answer.completion)))
    }

    pub(super) fn global_usings(
        &mut self,
        placement: &CSharpUnitPlacement,
        cancellation: &CancellationToken,
        session: &brokk_bifrost_core::analyzer::usages::resolution_session::ResolutionSession,
    ) -> Result<Option<CSharpGlobalUsings>> {
        use crate::analyzer::resolution::{ResolutionCompletion, ResolutionIncompleteReason};
        let conn = self.selection.connection();
        let mut missing = Vec::new();
        let coverage = conn
            .prepare_cached(SELECTED_GLOBAL_USING_COVERAGE)?
            .query_row(
                rusqlite::params![
                    placement.compilation_id,
                    super::super::csharp_compilation::DERIVATION_VERSION
                ],
                |row| {
                    Ok((
                        row.get::<_, bool>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )
            .optional()?;
        // Completeness comes from the coverage row alone, never from the absence
        // of extent rows. Its `metadata` reason is native demand's obligation.
        match coverage {
            Some((membership, expected, installed, reasons)) => {
                if !membership {
                    let gaps = self.inventory_gaps(placement)?;
                    missing.push(format!("compilation inventory is open: {gaps:?}"));
                }
                if expected != installed {
                    missing.push(format!(
                        "source publications: expected/installed {expected}/{installed}"
                    ));
                }
                let reasons: Vec<serde_json::Value> =
                    serde_json::from_str(&reasons).map_err(|error| {
                        StoreError::corrupt(format!(
                            "invalid global-using coverage reasons: {error}"
                        ))
                    })?;
                for reason in &reasons {
                    if reason["kind"] != "source_enumeration" {
                        continue;
                    }
                    let paths = reason["paths"].as_array().ok_or_else(|| {
                        StoreError::corrupt("source enumeration reason lacks its paths")
                    })?;
                    for path in paths {
                        missing.push(format!(
                            "source marker enumeration incomplete: {}",
                            path.as_str().ok_or_else(|| {
                                StoreError::corrupt("source enumeration path is not text")
                            })?
                        ));
                    }
                }
            }
            None => missing.push("selected compilation coverage row missing".into()),
        }
        let mut routes = Vec::new();
        let mut sites = conn
            .prepare_cached(SELECTED_GLOBAL_USING_SITES)?
            .query_map([placement.compilation_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, u32>(2)?,
                    row.get::<_, Option<String>>(3)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        sites.sort_unstable();
        for (path, blob, site, alias) in sites {
            if cancellation.is_cancelled() || !session.scope_step() {
                return Ok(None);
            }
            let Some(mount) = self.selection.mount_record_for_path("csharp", &path)? else {
                missing.push(format!("selected source mount unavailable: {path}"));
                continue;
            };
            if mount.blob_id() != blob {
                missing.push(format!("selected source publication differs: {path}"));
                continue;
            }
            let route = super::imports::route_at_site(conn, blob, site)?
                .ok_or_else(|| StoreError::corrupt("global using extent lacks its root import"))?;
            if route.kind == "named" && alias.is_none() {
                return Err(StoreError::corrupt("global alias lacks its named selector"));
            }
            routes.push(CSharpGlobalUsingRoute {
                fragment: mount.fragment_id(),
                alias,
                route,
            });
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
