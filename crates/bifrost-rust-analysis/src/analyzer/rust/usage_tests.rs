//! The Rust usage-vocabulary tests that need a live analyzer.
//!
//! The value types and the seed/reference entry points live in
//! [`brokk_bifrost_rust::usage`]; these tests exercise them over a real
//! workspace, so they stay on the analysis side.

#[cfg(test)]
mod tests {

    use brokk_bifrost_core::analyzer::model::CodeUnit;

    use crate::analyzer::rust::RustAnalyzer;

    use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

    use brokk_bifrost_core::analyzer::query_token::QueryScope;

    use brokk_bifrost_core::analyzer::model::CodeUnitType;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use crate::test_support::rust_analyzer;
    use brokk_bifrost_rust::usage::RustReferenceResolution;
    use brokk_bifrost_rust::usage::{Domain, ModuleKey, RustSymbolIdentity, RustSymbolNamespace};
    use brokk_bifrost_rust::usage_queries::RustUsageQueries;
    use brokk_bifrost_rust::usage_walks::RustUsageWalks;
    use std::collections::BTreeSet;
    #[test]
    fn fallback_binding_identity_remains_an_exact_root() {
        // The caller-supplied root lacks an indexed identity, but its file
        // still needs a real canonical publication. A nonexistent source is
        // unavailable, not proof that the file has no declaration identities.
        let fixture = crate::inline_project::InlineTestProject::with_language(Language::Rust)
            .file("src/db.rs", "")
            .build();
        let analyzer = RustAnalyzer::new(fixture.project_dyn());
        let source = fixture.file("src/db.rs");
        let target = CodeUnit::new(
            source.clone(),
            CodeUnitType::Function,
            "crate.src.db",
            "get_connection",
        );
        let roots = BTreeSet::from([target.clone()]);
        let scope = AnalyzerQueryScope::new(&analyzer);
        let walks = RustUsageWalks::new(&analyzer, scope.token())
            .expect("Cargo routes available for the fixture");
        let seeds = walks
            .binding_seeds_while(&analyzer, &roots, &|| true)
            .expect("available fixture binding facts")
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
    #[cfg_attr(not(scheduled_tests), ignore = "scheduled-only")]
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
        let analyzer = rust_analyzer(&root);
        let queries = RustUsageQueries::new(&analyzer);

        let mut rendered: Vec<String> = ["Shared", "helper", "worker", "util", "inner"]
            .into_iter()
            .flat_map(|name| {
                queries
                    .identities_named(name)
                    .expect("uncancelled fixture identity lookup")
            })
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
            brokk_bifrost_core::path_utils::rel_path_string(&identity.file),
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
}
