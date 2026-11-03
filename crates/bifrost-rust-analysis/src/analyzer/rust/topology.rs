//! The Cargo build model as project topology (#9055).
//!
//! Cargo `dependency_evidence` names the package that declares a dependency by
//! the id of a `BuildProject` entity (`member_entity`). This reader publishes
//! those same entities, one `Target` per package, and the file ownership that
//! lets a code row reach them, so a policy can join
//! call site -> `file-of` -> `target-of` -> `build_project_id` = `declared_by`.
//!
//! Ownership comes from the stored Rust unit summaries, not from paths. A
//! summary's members are the files its Cargo target's module tree reaches
//! (`mod`, `#[path]` and `include!` placements), and the summary records the
//! manifest that declares the target. The owner is the package: a file that a
//! package's library and one of its test targets both compile is owned, while a
//! file two packages compile is ambiguous. A file only a detached unit holds,
//! outside every Cargo target, is unresolved rather than unclaimed; that
//! includes the files of a target shape the Cargo inventory cannot enumerate,
//! which gets no unit of its own. Source sets and target dependencies stay
//! unsupported.

use std::path::{Path, PathBuf};

use brokk_bifrost_analysis::analyzer::IAnalyzer;
use brokk_bifrost_analysis::analyzer::languages::BuildModelProvider;
use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;
use brokk_bifrost_analysis::analyzer::store::rust_unit_summaries::RustCargoFileOwnerRow;
use brokk_bifrost_analysis::analyzer::topology::{
    FileOwnership, FileOwnershipState, TopologyAxis, TopologyCompleteness, TopologyEntity,
    TopologyEntityKind, TopologySupport, WorkspaceTopology,
};
use brokk_bifrost_core::hash::HashMap;

use super::RustAnalyzer;
use super::file_dependency_evidence::member_entity;

static CARGO_TOPOLOGY_SUPPORT: TopologySupport = TopologySupport::NONE
    .supported(TopologyAxis::BuildProjects)
    .supported(TopologyAxis::Targets)
    .supported(TopologyAxis::FileOwnership);

pub(crate) struct CargoBuildModel;

pub(crate) static CARGO_BUILD_MODEL: CargoBuildModel = CargoBuildModel;

impl BuildModelProvider for CargoBuildModel {
    fn support(&self) -> &'static TopologySupport {
        &CARGO_TOPOLOGY_SUPPORT
    }

    fn topology(&self, analyzer: &dyn IAnalyzer) -> Option<WorkspaceTopology> {
        let rust = resolve_analyzer::<RustAnalyzer>(analyzer)?;
        let snapshots = rust.inner.selected_workspace_snapshots();
        match rust
            .analyzer_store()
            .rust_cargo_file_owner_rows(snapshots.as_ref())
        {
            Ok(rows) if rows.is_empty() => None,
            Ok(rows) => Some(cargo_topology(rows)),
            Err(error) => {
                rust.inner.record_store_error(
                    error.context("reading live Rust summary members for Cargo topology"),
                );
                let mut topology = WorkspaceTopology::incomplete(CARGO_TOPOLOGY_SUPPORT.clone());
                topology.mark_provider_failed();
                Some(topology)
            }
        }
    }
}

fn cargo_topology(rows: Vec<RustCargoFileOwnerRow>) -> WorkspaceTopology {
    // File -> directories of the manifests whose targets compile it.
    let mut claims: HashMap<PathBuf, Vec<PathBuf>> = HashMap::default();
    for row in rows {
        let packages = claims.entry(PathBuf::from(row.rel_path)).or_default();
        if let Some(manifest) = row.manifest_rel_path {
            let directory = Path::new(&manifest)
                .parent()
                .expect("a Cargo manifest path names its file")
                .to_path_buf();
            if !packages.contains(&directory) {
                packages.push(directory);
            }
        }
    }

    let mut directories: Vec<&PathBuf> = claims.values().flatten().collect();
    directories.sort();
    directories.dedup();
    let mut entities = Vec::with_capacity(directories.len() * 2);
    for directory in directories {
        let project = member_entity(directory);
        entities.push(TopologyEntity {
            kind: TopologyEntityKind::Target,
            name: project.name.clone(),
            owner: Some(project.name.clone()),
            root: project.root.clone(),
            provenance: project.provenance.clone(),
            completeness: TopologyCompleteness::Complete,
        });
        entities.push(project);
    }
    entities.sort_by(|left, right| (left.kind, &left.name).cmp(&(right.kind, &right.name)));

    let mut ownership: Vec<FileOwnership> = claims
        .into_iter()
        .map(|(file, packages)| match packages.as_slice() {
            [] => FileOwnership::unowned(file, FileOwnershipState::Unresolved),
            [directory] => FileOwnership {
                target: Some(member_entity(directory).name),
                source_set: None,
                file,
                state: FileOwnershipState::Owned,
            },
            _ => FileOwnership::unowned(file, FileOwnershipState::Ambiguous),
        })
        .collect();
    ownership.sort_by(|left, right| left.file.cmp(&right.file));

    WorkspaceTopology::new(
        entities,
        Vec::new(),
        ownership,
        CARGO_TOPOLOGY_SUPPORT.clone(),
        TopologyCompleteness::Complete,
    )
}
