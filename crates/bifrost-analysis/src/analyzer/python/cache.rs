use super::*;
use crate::analyzer::usages::{ExportEntry, ReexportStar};
use std::mem::size_of;
use std::sync::Arc;

#[derive(Clone, Eq, Hash, PartialEq)]
pub(super) struct PythonUsageEdgesKey {
    caller_nodes: Arc<[String]>,
    callee_targets: Arc<[String]>,
}

impl PythonUsageEdgesKey {
    pub(super) fn new(nodes: &HashSet<String>, targets: &HashSet<String>) -> Self {
        Self {
            caller_nodes: sorted_names(nodes),
            callee_targets: sorted_names(targets),
        }
    }
}

pub(super) fn weight_code_unit_vec(_key: &CodeUnit, value: &Arc<Vec<CodeUnit>>) -> u32 {
    let size = value
        .iter()
        .map(|item| item.fq_name().len() + size_of::<CodeUnit>())
        .sum::<usize>()
        + size_of::<Vec<CodeUnit>>();
    size.min(u32::MAX as usize) as u32
}

pub(super) fn weight_export_index(_key: &ProjectFile, value: &Arc<ExportIndex>) -> u32 {
    let exports_size = value
        .exports_by_name
        .iter()
        .map(|(name, entry)| {
            name.len()
                + match entry {
                    ExportEntry::Local { local_name } => local_name.len(),
                    ExportEntry::ReexportedNamed {
                        module_specifier,
                        imported_name,
                    } => module_specifier.len() + imported_name.len(),
                    ExportEntry::Default { local_name } => {
                        local_name.as_deref().map_or(0, str::len)
                    }
                }
                + size_of::<ExportEntry>()
        })
        .sum::<usize>();
    let reexport_stars_size = value
        .reexport_stars
        .iter()
        .map(|star| star.module_specifier.len() + size_of::<ReexportStar>())
        .sum::<usize>();
    (exports_size + reexport_stars_size + size_of::<ExportIndex>()).min(u32::MAX as usize) as u32
}

pub(super) fn weight_python_usage_edges(
    key: &PythonUsageEdgesKey,
    edges: &Arc<crate::analyzer::usages::inverted_edges::UsageEdges>,
) -> u32 {
    let key_bytes = names_weight(&key.caller_nodes) + names_weight(&key.callee_targets);
    let edge_bytes = edges
        .edges
        .iter()
        .map(|((caller, callee), sites)| {
            caller.len()
                + callee.len()
                + sites
                    .iter()
                    .map(|site| {
                        size_of::<crate::analyzer::usages::inverted_edges::CallSite>()
                            + site.path.len()
                    })
                    .sum::<usize>()
        })
        .sum::<usize>();
    let summary_bytes = edges
        .truncated
        .keys()
        .chain(edges.unproven_inbound.keys())
        .map(|name| size_of::<String>() + name.len() + size_of::<usize>())
        .sum::<usize>();
    (key_bytes + edge_bytes + summary_bytes).clamp(1, u32::MAX as usize) as u32
}

fn sorted_names(names: &HashSet<String>) -> Arc<[String]> {
    let mut sorted_names = names.iter().cloned().collect::<Vec<_>>();
    sorted_names.sort_unstable();
    sorted_names.into()
}

fn names_weight(names: &Arc<[String]>) -> usize {
    size_of::<Arc<[String]>>()
        + names
            .iter()
            .map(|item| size_of::<String>() + item.len())
            .sum::<usize>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::usages::inverted_edges::UsageEdges;
    use crate::analyzer::{IAnalyzer, Language, ProjectFile, TestProject};
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn usage_edges_are_reused_per_target_set_and_reset_on_update() {
        let root = tempfile::tempdir().expect("temporary project root");
        let file = ProjectFile::new(root.path(), "module.py");
        file.write("def target(): pass\n")
            .expect("write Python fixture");
        let analyzer = PythonAnalyzer::new(Arc::new(TestProject::new(
            root.path().to_path_buf(),
            Language::Python,
        )));
        let nodes = HashSet::from_iter(["module.target".to_string(), "module.other".to_string()]);
        let first_targets = HashSet::from_iter(["module.target".to_string()]);
        let second_targets = HashSet::from_iter(["module.target".to_string()]);
        let builds = AtomicUsize::new(0);

        let first = analyzer.usage_edges_for_targets(&nodes, &first_targets, || {
            builds.fetch_add(1, Ordering::Relaxed);
            UsageEdges::default()
        });
        let second = analyzer.usage_edges_for_targets(&nodes, &second_targets, || {
            panic!("warm Python usage graph must reuse the cached edges")
        });

        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(1, builds.load(Ordering::Relaxed));

        let different_targets = HashSet::from_iter(["module.other".to_string()]);
        analyzer.usage_edges_for_targets(&nodes, &different_targets, || {
            builds.fetch_add(1, Ordering::Relaxed);
            UsageEdges::default()
        });
        assert_eq!(
            2,
            builds.load(Ordering::Relaxed),
            "different callee targets need a separately resolved graph"
        );

        let updated = analyzer.update(&std::collections::BTreeSet::from([file]));
        updated.usage_edges_for_targets(&nodes, &first_targets, || {
            builds.fetch_add(1, Ordering::Relaxed);
            UsageEdges::default()
        });
        assert_eq!(3, builds.load(Ordering::Relaxed));
    }
}
