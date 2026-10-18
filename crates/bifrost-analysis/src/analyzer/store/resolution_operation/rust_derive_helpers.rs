//! Source-owned conditional gaps, closed on demand.
//!
//! Inactive item-macro inputs use the same exact reason-closure mechanism as
//! derive helpers. Only predicates false in every selected membership close;
//! active or unknown predicates retain the original frontier.
//!
//! A Rust item that carries a derive may carry a bare attribute that is really
//! an inert helper of that derive (`#[serde(..)]`). The producer cannot tell
//! that from an attribute macro that replaces the item, so it leaves an open
//! binder gap on the declaration site. The gap closes when every helper name
//! at every placement of the declaration has no workspace macro, no external
//! binding, and both inventories are closed (`DERIVE_HELPER_CONDITIONS`).
//!
//! The decision costs a few point-target queries for each helper name and
//! placement, so a request decides only what its lookups reach. A reader that
//! is about to consult closed reasons names the mounts or the reasons it will
//! read, and calls one of the `decide_*` methods first. The answers are the
//! rows of `temp.selected_resolution_stage_closed_reasons`; the set of what
//! was already decided lives and dies with the inventory, which one request
//! owns, and `SelectedResolutionStage::clear_facts` resets it with the rows.

use super::rust_crate_context;
use crate::CancellationToken;
use crate::analyzer::resolution::{
    LoweringGapOrigin, ResolutionCompletion, ResolutionIncompleteReason,
    SelectedResolutionMountOrdinal, SemanticId,
};
use crate::analyzer::store::Result;
use crate::analyzer::store::resolution_prepare::resolution_rows::{
    gap_origin_code, namespace_code,
};
use crate::analyzer::store::resolution_selection::SelectedResolutionMountInventory;
use crate::analyzer::store::resolution_stage::{
    SelectedResolutionStage, SelectedResolutionStageOutcome,
};
use crate::hash::{HashMap, HashSet};
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;
use brokk_bifrost_core::analyzer::structural::resolution::ResolutionGapOriginKind;

/// What one request has already decided: whole mounts, and single gap reasons
/// of mounts not decided as a whole. A reason that is no candidate at all is
/// recorded too, so a reader that meets it again does not ask again.
#[derive(Default)]
pub(in crate::analyzer::store) struct DeriveHelperDecisions {
    /// Set by the Rust route that prepares macro frontiers. Another language
    /// holds no derive-helper gaps, and its readers must not pay for the
    /// query that finds none.
    enabled: bool,
    mounts: HashSet<u32>,
    reasons: HashSet<(u32, u32)>,
}

impl DeriveHelperDecisions {
    pub(in crate::analyzer::store) fn clear(&mut self) {
        self.mounts.clear();
        self.reasons.clear();
    }

    fn contains(&self, mount: u32, reason: Option<u32>) -> bool {
        self.mounts.contains(&mount)
            || reason.is_some_and(|reason| self.reasons.contains(&(mount, reason)))
    }
}

impl SelectedResolutionMountInventory<'_> {
    /// Let this operation's readers decide derive-helper gaps on demand.
    pub(in crate::analyzer::store) fn enable_derive_helper_decisions(&self) {
        self.derive_helper_decisions().borrow_mut().enabled = true;
    }

    /// Decide every derive-helper gap of `mounts`. `false` means cancelled.
    pub(in crate::analyzer::store) fn decide_derive_helpers_of_mounts(
        &self,
        mounts: impl IntoIterator<Item = u32>,
        cancellation: &CancellationToken,
    ) -> Result<bool> {
        self.decide_derive_helpers(mounts.into_iter().map(|mount| (mount, None)), cancellation)
    }

    /// Decide the derive-helper gaps behind the gap reasons a lookup returned.
    /// A semantic that is not a local reason of a mount is no candidate.
    /// `false` means cancelled.
    pub(in crate::analyzer::store) fn decide_derive_helpers_of_semantics(
        &self,
        semantics: impl IntoIterator<Item = SemanticId>,
        cancellation: &CancellationToken,
    ) -> Result<bool> {
        self.decide_derive_helpers(
            semantics
                .into_iter()
                .filter_map(|semantic| Some((semantic.ordinal()?, Some(semantic.local_key()?)))),
            cancellation,
        )
    }

    /// Decide the derive-helper gaps behind the reasons of `completions`.
    /// `false` means cancelled.
    pub(in crate::analyzer::store) fn decide_derive_helpers_of_completions<'a>(
        &self,
        completions: impl IntoIterator<Item = &'a ResolutionCompletion>,
        cancellation: &CancellationToken,
    ) -> Result<bool> {
        self.decide_derive_helpers_of_semantics(
            completions
                .into_iter()
                .flat_map(|completion| match completion {
                    ResolutionCompletion::Complete => None,
                    ResolutionCompletion::Incomplete(reasons) => Some(reasons.iter()),
                })
                .flatten()
                .filter_map(|reason| match reason {
                    ResolutionIncompleteReason::UnsupportedSemantic(semantic) => Some(*semantic),
                    _ => None,
                }),
            cancellation,
        )
    }

    fn decide_derive_helpers(
        &self,
        reached: impl Iterator<Item = (u32, Option<u32>)>,
        cancellation: &CancellationToken,
    ) -> Result<bool> {
        if !self.derive_helper_decisions().borrow().enabled {
            return Ok(true);
        }
        let mut undecided = {
            let decisions = self.derive_helper_decisions().borrow();
            reached
                .filter(|&(mount, reason)| !decisions.contains(mount, reason))
                .collect::<Vec<_>>()
        };
        if undecided.is_empty() {
            return Ok(true);
        }
        undecided.sort_unstable();
        undecided.dedup();
        let connection = self.connection();
        let origin = gap_origin_code(LoweringGapOrigin::from_kind(
            ResolutionGapOriginKind::UnsupportedScopeOrBinder,
        ));
        let rows = connection
            .prepare_cached(rust_crate_context::DERIVE_HELPER_CONDITIONS)?
            .query_map(
                rusqlite::params![
                    origin,
                    serde_json::to_string(&undecided).expect("reached mounts serialize")
                ],
                |row| {
                    Ok((
                        row.get::<_, u32>(0)?,
                        row.get::<_, u32>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                },
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        // Rows arrive ordered by mount and reason; one declaration placed in
        // several modules closes only when every helper name at every
        // placement proves absent from macro lookup.
        let mut decided: Vec<(u32, u32, bool)> = Vec::new();
        // The answer depends on the module and the helper name, not on the
        // declaration, and declarations of one module share both.
        let mut proven_names: HashMap<(i64, String, String), bool> = HashMap::default();
        for (ordinal, reason, helper, topology, path) in rows {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            let proven = match helper.as_ref() {
                None => true,
                Some(helper) => match proven_names.get(&(topology, path.clone(), helper.clone())) {
                    Some(&proven) => proven,
                    None => {
                        let proven =
                            helper_absent_from_macro_lookup(connection, topology, &path, helper)?;
                        proven_names.insert((topology, path, helper.clone()), proven);
                        proven
                    }
                },
            };
            match decided.last_mut() {
                Some((last_ordinal, last_reason, all))
                    if (*last_ordinal, *last_reason) == (ordinal, reason) =>
                {
                    *all &= proven;
                }
                _ => decided.push((ordinal, reason, proven)),
            }
        }
        let stage = SelectedResolutionStage::new(self);
        for group in decided.chunk_by(|left, right| left.0 == right.0) {
            let ordinal = group[0].0;
            let reasons = group
                .iter()
                .filter(|(_, _, proven)| *proven)
                .map(|(_, reason, _)| (i64::from(ordinal) << 32) + i64::from(*reason))
                .collect::<Vec<_>>();
            if reasons.is_empty() {
                continue;
            }
            let host = self
                .persisted_mount_record(SelectedResolutionMountOrdinal::new(ordinal))?
                .expect("a derive-helper condition's mount is selected");
            match stage.close_derive_helper_reasons(&host, &reasons, cancellation)? {
                SelectedResolutionStageOutcome::Ready => {}
                SelectedResolutionStageOutcome::Cancelled => return Ok(false),
                SelectedResolutionStageOutcome::Unavailable(_)
                | SelectedResolutionStageOutcome::Stale(_) => {
                    unreachable!("a closure publication is cancelled or ready")
                }
            }
        }
        let mut decisions = self.derive_helper_decisions().borrow_mut();
        for (mount, reason) in undecided {
            match reason {
                None => {
                    decisions.mounts.insert(mount);
                }
                Some(reason) => {
                    decisions.reasons.insert((mount, reason));
                }
            }
        }
        Ok(true)
    }
}

/// Whether `helper`, looked up as a macro from module `path` of `topology`,
/// has no workspace macro, no external binding, and meets no open inventory.
fn helper_absent_from_macro_lookup(
    connection: &rusqlite::Connection,
    topology: i64,
    path: &str,
    helper: &str,
) -> Result<bool> {
    let workspace_macro = connection
        .prepare_cached(rust_crate_context::EXPORT)?
        .exists(rusqlite::params![
            topology, path, "macro", helper, topology, path
        ])?;
    let external_binding = !workspace_macro
        && connection
            .prepare_cached(rust_crate_context::EXTERNAL_BINDING)?
            .exists(rusqlite::params![
                topology,
                path,
                "macro",
                helper,
                topology,
                path,
                namespace_code(ResolutionNamespace::Macro),
            ])?;
    let open_inventory = !workspace_macro
        && !external_binding
        && connection
            .prepare_cached(rust_crate_context::OPEN_INVENTORY)?
            .exists(rusqlite::params![
                topology, path, "macro", helper, topology, path
            ])?;
    let unindexed_scope = !workspace_macro
        && !external_binding
        && !open_inventory
        && connection
            .prepare_cached(rust_crate_context::UNINDEXED_SCOPE)?
            .exists(rusqlite::params![
                topology, path, "macro", helper, topology, path
            ])?;
    Ok(!workspace_macro && !external_binding && !open_inventory && !unindexed_scope)
}
