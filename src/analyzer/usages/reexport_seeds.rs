//! Cross-file re-export seed resolution shared by the Go and JS/TS usage graphs.
//!
//! Both languages model a file's exports as an [`ExportIndex`] plus pre-built
//! re-export edge maps, then resolve a target symbol to the set of `(file, name)`
//! seeds reachable through named and star re-export chains. The walk operates only
//! on the shared [`model`](crate::analyzer::usages::model) types and
//! [`ImportEdge`]s, so it lives here instead of being duplicated per language. The
//! per-language resolvers stay thin: they build the maps with language-specific
//! module resolution, then delegate the chain walk and edge matching to these
//! functions.

use crate::analyzer::ProjectFile;
use crate::analyzer::usages::model::{ExportEntry, ExportIndex};
use crate::analyzer::usages::{ImportEdge, ImportEdgeKind};
use crate::hash::HashMap;
use std::collections::{BTreeSet, VecDeque};

/// Export seeds for `target_short` in `target_file`, following named and star
/// re-export chains across files. Member-qualified targets (a `target_name` containing
/// `.`) only match the owner export when `owner_seed_allowed` (the analyzer reports that
/// owner as the declaration's parent); otherwise they must match the full `target_name`.
/// Languages without member exports pass `target_name == target_short` (or
/// `owner_seed_allowed = true`), reducing to plain short-name matching.
pub(crate) fn seeds_for_target(
    exports_by_file: &HashMap<ProjectFile, ExportIndex>,
    reexport_edges: &HashMap<(ProjectFile, String), Vec<(ProjectFile, String)>>,
    star_reexports: &HashMap<ProjectFile, Vec<ProjectFile>>,
    target_file: &ProjectFile,
    target_short: &str,
    target_name: &str,
    owner_seed_allowed: bool,
) -> BTreeSet<(ProjectFile, String)> {
    let mut seeds: BTreeSet<(ProjectFile, String)> = BTreeSet::new();
    if let Some(exports) = exports_by_file.get(target_file) {
        for (exported_name, entry) in &exports.exports_by_name {
            let local = match entry {
                ExportEntry::Local { local_name } => Some(local_name.as_str()),
                ExportEntry::Default { local_name } => local_name.as_deref(),
                ExportEntry::ReexportedNamed { .. } => None,
            };
            if let Some(local_name) = local
                && export_local_matches_target(
                    local_name,
                    target_short,
                    target_name,
                    owner_seed_allowed,
                )
            {
                seeds.insert((target_file.clone(), exported_name.clone()));
            }
        }
    }
    let mut frontier: VecDeque<(ProjectFile, String)> = seeds.iter().cloned().collect();
    while let Some(seed) = frontier.pop_front() {
        if let Some(reexports) = reexport_edges.get(&seed) {
            for next in reexports {
                if seeds.insert(next.clone()) {
                    frontier.push_back(next.clone());
                }
            }
        }
        if let Some(star_files) = star_reexports.get(&seed.0) {
            for star_file in star_files {
                let next = (star_file.clone(), seed.1.clone());
                if seeds.insert(next.clone()) {
                    frontier.push_back(next);
                }
            }
        }
    }
    seeds
}

/// The import edges in `importer` that bind one of the `seeds`.
pub(crate) fn matching_edges_for_importer(
    importer_reverse: &HashMap<ProjectFile, Vec<ImportEdge>>,
    importer: &ProjectFile,
    seeds: &BTreeSet<(ProjectFile, String)>,
) -> Vec<ImportEdge> {
    let mut matches = Vec::new();
    for (target_file, _) in seeds {
        let Some(edges) = importer_reverse.get(target_file) else {
            continue;
        };
        matches.extend(
            edges
                .iter()
                .filter(|edge| &edge.importer == importer && edge_matches_seed(edge, seeds))
                .cloned(),
        );
    }
    matches
}

/// Whether an export's local name identifies the target. For a member-qualified target
/// (`target_name` contains `.`) where owner-name seeding is disallowed, the export's local
/// name must equal the full `target_name`; otherwise the short name suffices.
pub(crate) fn export_local_matches_target(
    local_name: &str,
    target_short: &str,
    target_name: &str,
    owner_seed_allowed: bool,
) -> bool {
    if target_name.contains('.') && !owner_seed_allowed {
        local_name == target_name || module_qualified_member_matches(local_name, target_name)
    } else {
        local_name == target_short
    }
}

fn module_qualified_member_matches(local_name: &str, target_name: &str) -> bool {
    if !target_name.contains(".js.") {
        return false;
    }
    let Some((_, local_member)) = local_name.rsplit_once('.') else {
        return false;
    };
    let Some((_, target_member)) = target_name.rsplit_once('.') else {
        return false;
    };
    local_member == target_member
}

/// Whether `edge` binds one of the `seeds`, accounting for each import kind.
pub(crate) fn edge_matches_seed(
    edge: &ImportEdge,
    seeds: &BTreeSet<(ProjectFile, String)>,
) -> bool {
    match &edge.kind {
        ImportEdgeKind::Named(name) => seeds.contains(&(edge.target_file.clone(), name.clone())),
        ImportEdgeKind::Default => {
            seeds.contains(&(edge.target_file.clone(), "default".to_string()))
        }
        ImportEdgeKind::Namespace => seeds.iter().any(|(file, _)| file == &edge.target_file),
        ImportEdgeKind::CommonJsRequire(export_name) => {
            seeds.contains(&(edge.target_file.clone(), export_name.clone()))
        }
    }
}
