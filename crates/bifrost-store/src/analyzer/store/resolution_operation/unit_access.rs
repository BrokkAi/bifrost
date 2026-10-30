//! Query-local access between selected compilation-unit placements.
use super::placement_access::PlacementKey;
use super::*;
use crate::analyzer::store::resolution_selection::SelectedResolutionMountInventory;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum UnitAccess {
    Visible,
    NotVisible,
    Unknown(SemanticId),
}

impl UnitAccess {
    /// Incoming route completion is never memoized with the pair evidence.
    pub(super) fn completion(
        self,
        incoming: &ResolutionCompletion,
    ) -> Option<ResolutionCompletion> {
        match self {
            Self::NotVisible => None,
            Self::Visible => Some(incoming.clone()),
            Self::Unknown(reason) => Some(incoming.combine(&ResolutionCompletion::incomplete([
                ResolutionIncompleteReason::UnsupportedSemantic(reason),
            ]))),
        }
    }
}

/// A language's unit-access relation. The reader calls `exact_relation`, then
/// `upgrade_unknown`, then `unknown_reason` only when both declined, so a
/// successful proof mints no named reason.
pub(super) trait UnitAccessRules {
    /// The language's exact relation for one caller and target placement, read
    /// from its static SQL. None means the exact relation cannot decide.
    fn exact_relation(
        &self,
        caller: &PlacementKey,
        target: &PlacementKey,
    ) -> Result<Option<UnitAccess>>;

    /// A second proof that may decide a pair the exact relation could not.
    fn upgrade_unknown(
        &self,
        _caller: &PlacementKey,
        _target: &PlacementKey,
    ) -> Result<Option<UnitAccess>> {
        Ok(None)
    }

    /// The named reason for a pair that neither proof decided.
    fn unknown_reason(&self, caller: &PlacementKey, target: &PlacementKey) -> Result<SemanticId>;

    fn combine(&self, answers: &[(PlacementKey, PlacementKey, UnitAccess)]) -> UnitAccess;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct UnitAccessKey {
    caller: PlacementKey,
    target: PlacementKey,
    scope: [u8; 32],
    stage_epoch: (u64, u64),
}

// Insert-stop, with no eviction: misses beyond the cap still read SQL.
const UNIT_ACCESS_MEMO_ENTRY_CAP: usize = 65_536;

#[derive(Default)]
pub(super) struct UnitAccessMemo {
    rows: HashMap<UnitAccessKey, UnitAccess>,
}

impl UnitAccessMemo {
    pub(super) fn entry_count(&self) -> usize {
        self.rows.len()
    }
}

/// Read one caller/target product and let the language combine the answers.
/// If both subjects have equal languages and carry equal paths, the pair is Visible without SQL or a
/// memo entry. File versions and blobs are ignored: the workspace path identifies
/// the same file even when its endpoints carry different selected versions.
/// Path indexes from different languages are not comparable (PlacementSubject.path).
/// All retained pair evidence is capped and dies with the operation or stage.
pub(super) fn read_unit_access<R: UnitAccessRules>(
    selection: &SelectedResolutionMountInventory<'_>,
    rules: &R,
    callers: &[PlacementKey],
    targets: &[PlacementKey],
    mut memo: Option<&mut UnitAccessMemo>,
) -> Result<UnitAccess> {
    let mut answers = Vec::new();
    for caller in callers {
        for target in targets {
            let key = UnitAccessKey {
                caller: *caller,
                target: *target,
                scope: selection.scope_identity(),
                stage_epoch: selection.staged_read_epoch(),
            };
            let access = if caller.language == target.language
                && caller.subject.path.is_some()
                && caller.subject.path == target.subject.path
            {
                UnitAccess::Visible
            } else if let Some(access) = memo.as_ref().and_then(|memo| memo.rows.get(&key)) {
                *access
            } else {
                let access = if let Some(access) = rules.exact_relation(caller, target)? {
                    access
                } else if let Some(access) = rules.upgrade_unknown(caller, target)? {
                    access
                } else {
                    UnitAccess::Unknown(rules.unknown_reason(caller, target)?)
                };
                if let Some(memo) = memo.as_mut()
                    && memo.rows.len() < UNIT_ACCESS_MEMO_ENTRY_CAP
                {
                    memo.rows.insert(key, access);
                }
                access
            };
            answers.push((*caller, *target, access));
        }
    }
    Ok(rules.combine(&answers))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::store::resolution_selection::tests::qualifier_completion_gap_fixture;
    use crate::analyzer::store::resolution_selection::{
        SelectedResolutionLanguage, SelectedResolutionMountInventoryOutcome,
    };
    #[test]
    fn unit_access_same_language_path_shortcut_skips_the_relation() {
        use super::super::placement_access::PlacementSubject;
        use super::super::selected_sql_trace::{
            begin_production_selected_sql_trace_on_connection,
            finish_production_selected_sql_trace_on_connection,
        };
        struct Rules(std::cell::Cell<usize>);
        impl UnitAccessRules for Rules {
            fn exact_relation(
                &self,
                _: &PlacementKey,
                _: &PlacementKey,
            ) -> Result<Option<UnitAccess>> {
                self.0.set(self.0.get() + 1);
                Ok(Some(UnitAccess::NotVisible))
            }
            fn unknown_reason(
                &self,
                _: &PlacementKey,
                _: &PlacementKey,
            ) -> Result<crate::analyzer::resolution::SemanticId> {
                unreachable!("exact relation decides")
            }
            fn combine(&self, answers: &[(PlacementKey, PlacementKey, UnitAccess)]) -> UnitAccess {
                assert_eq!(answers.len(), 1);
                answers[0].2
            }
        }
        let (store, workspace, snapshots) = qualifier_completion_gap_fixture();
        let cancellation = CancellationToken::new();
        let languages = [SelectedResolutionLanguage::new("go", Language::Go)];
        let SelectedResolutionMountInventoryOutcome::Ready(selection) = store
            .open_selected_resolution_mount_inventory(
                &workspace,
                &snapshots,
                &languages,
                &[],
                &cancellation,
            )
            .unwrap()
        else {
            panic!("published inventory");
        };
        let caller = PlacementKey {
            language: Language::Java,
            unit_digest: [1; 32],
            subject: PlacementSubject {
                path: Some(0),
                blob: Some(1),
                file_version: Some(1),
            },
            declaration: None,
        };
        let target = PlacementKey {
            unit_digest: [2; 32],
            subject: PlacementSubject {
                path: Some(0),
                blob: Some(2),
                file_version: Some(2),
            },
            ..caller
        };
        let rules = Rules(std::cell::Cell::new(0));
        begin_production_selected_sql_trace_on_connection(selection.connection());
        assert_eq!(
            read_unit_access(&selection, &rules, &[caller], &[target], None).unwrap(),
            UnitAccess::Visible
        );
        let cost = finish_production_selected_sql_trace_on_connection(selection.connection());
        assert!(cost.statements.is_empty(), "{cost:?}");
        assert_eq!(rules.0.get(), 0);
        let foreign = PlacementKey {
            language: Language::CSharp,
            ..target
        };
        assert_eq!(
            read_unit_access(&selection, &rules, &[caller], &[foreign], None).unwrap(),
            UnitAccess::NotVisible
        );
        assert_eq!(
            rules.0.get(),
            1,
            "foreign path indexes cannot authorize access"
        );
    }
}
