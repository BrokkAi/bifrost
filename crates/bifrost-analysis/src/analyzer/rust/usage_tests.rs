//! The Rust usage-vocabulary tests that need a live analyzer.
//!
//! The value types and the seed/reference entry points live in
//! [`brokk_bifrost_rust::usage`]; these tests exercise them over a real
//! workspace, so they stay on the analysis side.

#[cfg(test)]
mod tests {
    use crate::analyzer::rust::RustAnalyzer;
    use crate::analyzer::{AnalyzerQueryScope, QueryScope};
    use crate::analyzer::{CodeUnit, CodeUnitIndex};
    use crate::analyzer::{CodeUnitType, Language, ProjectFile, TestProject};
    use brokk_bifrost_rust::usage::RustReferenceResolution;
    use brokk_bifrost_rust::usage::{Domain, ModuleKey, RustSymbolIdentity, RustSymbolNamespace};
    use brokk_bifrost_rust::usage_queries::RustUsageQueries;
    use brokk_bifrost_rust::usage_walks::RustUsageWalks;
    use std::collections::BTreeSet;
    #[test]
    fn rust_domains_intersect_without_cross_crate_or_sibling_widening() {
        let crate_a = "workspace.a.src".to_string();
        let crate_b = "workspace.b.src".to_string();
        let parent = Domain::Module(ModuleKey {
            crate_root: crate_a.clone(),
            components: vec!["parent".to_string()],
        });
        let child = Domain::Module(ModuleKey {
            crate_root: crate_a.clone(),
            components: vec!["parent".to_string(), "child".to_string()],
        });
        let sibling = Domain::Module(ModuleKey {
            crate_root: crate_a.clone(),
            components: vec!["sibling".to_string()],
        });

        assert_eq!(Some(child.clone()), parent.intersect(&child));
        assert_eq!(
            Some(child.clone()),
            Domain::Crate(crate_a.clone()).intersect(&child)
        );
        assert_eq!(None, parent.intersect(&sibling));
        assert_eq!(
            None,
            Domain::Crate(crate_a).intersect(&Domain::Crate(crate_b))
        );
        assert_eq!(Some(child.clone()), Domain::Public.intersect(&child));
    }

    #[test]
    fn fallback_binding_identity_remains_an_exact_root() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        let analyzer = analyzer_for(&root);
        let source = ProjectFile::new(root, "src/db.rs");
        let target = CodeUnit::new(
            source.clone(),
            CodeUnitType::Function,
            "crate.src.db",
            "get_connection",
        );
        let roots = BTreeSet::from([target.clone()]);
        let scope = AnalyzerQueryScope::new(&analyzer);
        let walks = RustUsageWalks::new(&analyzer, scope.token());
        let seeds = walks
            .binding_seeds_while(&analyzer, &roots, &|| true)
            .expect("an uncancelled walk answers");
        let resolution = RustReferenceResolution::Exact(RustSymbolIdentity {
            file: source,
            module: ModuleKey::new(target.source(), target.package_name()),
            name: target.identifier().to_string(),
            namespace: RustSymbolNamespace::Value,
        });

        assert_eq!(
            walks.exact_root_for_resolution(&resolution, &seeds),
            Some(target)
        );
    }

    fn analyzer_for(root: &std::path::Path) -> RustAnalyzer {
        RustAnalyzer::from_project(TestProject::new(root.to_path_buf(), Language::Rust))
    }

    /// The store-backed name lookup must offer every declaring file for a
    /// shared short name, with each identity's own visibility domain.
    ///
    /// The v1 index answered this from `identities_by_name`, a map over every
    /// declaration in the workspace. Its replacement asks the store's indexed
    /// short-name lookup for candidate files and verifies each against that
    /// file's own declaration facts, so what this pins is that the candidate
    /// set misses no file and that verification drops no identity. The
    /// associated function `Shared::helper` is the false positive the
    /// verification exists to reject: it carries the right short name and no
    /// module-scope identity.
    #[test]
    fn identities_named_covers_every_declaring_file_for_a_shared_name() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        ProjectFile::new(root.clone(), "src/lib.rs")
            .write(
                "pub mod worker;\n\
                 pub mod util;\n\
                 pub struct Shared;\n\
                 pub fn helper() {}\n",
            )
            .expect("write lib.rs");
        ProjectFile::new(root.clone(), "src/worker.rs")
            .write(
                "pub struct Shared(pub u8);\n\
                 impl Shared {\n    \
                     pub fn helper(&self) {}\n\
                 }\n",
            )
            .expect("write worker.rs");
        ProjectFile::new(root.clone(), "src/util.rs")
            .write(
                "fn helper() {}\n\
                 mod inner {\n    \
                     pub(crate) struct Shared;\n\
                 }\n",
            )
            .expect("write util.rs");
        let analyzer = analyzer_for(&root);
        let queries = RustUsageQueries::new(&analyzer);

        let mut rendered: Vec<String> = ["Shared", "helper", "worker", "util", "inner"]
            .into_iter()
            .flat_map(|name| queries.identities_named(name))
            .map(|(identity, domains)| render_identity(&identity, &domains))
            .collect();
        rendered.sort();

        assert_eq!(
            rendered,
            vec![
                "src/lib.rs crate Shared Type = [Public]",
                "src/lib.rs crate Shared Value = [Public]",
                "src/lib.rs crate helper Value = [Public]",
                "src/lib.rs crate util Module = [Public]",
                "src/lib.rs crate worker Module = [Public]",
                "src/util.rs crate::util helper Value = [Module(crate::util)]",
                "src/util.rs crate::util inner Module = [Module(crate::util)]",
                "src/util.rs crate::util::inner Shared Type = [Crate]",
                "src/util.rs crate::util::inner Shared Value = [Crate]",
                "src/worker.rs crate::worker Shared Type = [Public]",
                "src/worker.rs crate::worker Shared Value = [Public]",
            ]
        );
    }

    /// Path-independent rendering of one identity and its domains: the fixture
    /// lives under a temporary root, so neither the absolute path nor the
    /// crate-root package name may reach an assertion. Every identity here is
    /// in the one crate, so the crate root renders as the literal `crate`.
    fn render_identity(identity: &RustSymbolIdentity, domains: &[Domain]) -> String {
        let render_module = |module: &ModuleKey| {
            std::iter::once("crate")
                .chain(module.components.iter().map(String::as_str))
                .collect::<Vec<_>>()
                .join("::")
        };
        let render_domain = |domain: &Domain| match domain {
            Domain::Public => "Public".to_string(),
            Domain::Crate(_) => "Crate".to_string(),
            Domain::Module(module) => format!("Module({})", render_module(module)),
        };
        format!(
            "{} {} {} {:?} = [{}]",
            crate::path_utils::rel_path_string(&identity.file),
            render_module(&identity.module),
            identity.name,
            identity.namespace,
            domains
                .iter()
                .map(render_domain)
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
    #[test]
    fn dbg_visibility_probe() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        ProjectFile::new(root.clone(), "src/lib.rs")
            .write("pub mod util;\n")
            .expect("write lib.rs");
        ProjectFile::new(root.clone(), "src/util.rs")
            .write("fn helper() {}\nmod inner {\n    pub struct Shared;\n}\n")
            .expect("write util.rs");
        let analyzer = analyzer_for(&root);
        let util = ProjectFile::new(root.clone(), "src/util.rs");
        for d in analyzer.declarations(&util) {
            let scope = AnalyzerQueryScope::new(&analyzer);
            let vis = brokk_bifrost_rust::graph_support::rust_declaration_visibility(
                &analyzer,
                scope.token(),
                &d,
            );
            println!(
                "DBG {} kind={:?} vis={:?} parent={:?}",
                d.fq_name(),
                d.kind(),
                vis,
                analyzer.structural_parent_of(&d).map(|p| p.fq_name())
            );
        }
    }
}
