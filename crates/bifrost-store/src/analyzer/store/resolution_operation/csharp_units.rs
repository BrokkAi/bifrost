//! Dormant C# compilation placements and access on the shared readers.
use super::placement_access::{
    PlacementKey, PlacementMemo, PlacementRead, PlacementSubject, read_placements,
};
use super::unit_access::{UnitAccess, UnitAccessMemo, UnitAccessRules, read_unit_access};
use super::*;
use crate::analyzer::store::resolution_selection::SelectedResolutionMountInventory;
use crate::analyzer::store::{WorkspaceSnapshotId, csharp_compilation::CSharpCompilationView};
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
    pub fn placements(&mut self, rel_path: &str) -> Result<Option<Vec<CSharpUnitPlacement>>> {
        let Some(compilations) = self.compilations.as_ref() else {
            return Ok(None);
        };
        let Some(ids) = compilations.compilations_of(rel_path)? else {
            return Ok(None);
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
