//! The analyzer-owned half of Rust's type hierarchy: the `TypeHierarchyProvider`
//! capability impl and the `OnceLock` cells behind it.
//!
//! The index itself and every predicate it is built from live in
//! [`brokk_bifrost_rust::hierarchy`] and [`brokk_bifrost_rust::graph_support`].

use crate::analyzer::type_relations::TypeRelation;
use crate::analyzer::{CodeUnit, TypeHierarchyProvider};
use crate::hash::HashSet;
use brokk_bifrost_rust::graph_support::{
    is_rust_enum_declaration, is_rust_struct_declaration, is_rust_trait_declaration,
    is_rust_type_alias_declaration,
};
use brokk_bifrost_rust::hierarchy::RustHierarchyIndex;

use super::RustAnalyzer;

impl TypeHierarchyProvider for RustAnalyzer {
    fn get_direct_ancestors(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        if !self.supports_type_hierarchy(code_unit) || is_rust_trait_declaration(self, code_unit) {
            return Vec::new();
        }

        self.hierarchy_index()
            .direct_ancestors
            .get(code_unit)
            .cloned()
            .unwrap_or_default()
    }

    fn get_direct_descendants(&self, code_unit: &CodeUnit) -> HashSet<CodeUnit> {
        if !self.supports_type_hierarchy(code_unit) || !is_rust_trait_declaration(self, code_unit) {
            return HashSet::default();
        }

        self.hierarchy_index()
            .direct_descendants
            .get(code_unit)
            .cloned()
            .unwrap_or_default()
    }

    fn supports_type_hierarchy(&self, code_unit: &CodeUnit) -> bool {
        is_rust_trait_declaration(self, code_unit)
            || is_rust_struct_declaration(self, code_unit)
            || is_rust_enum_declaration(self, code_unit)
            || is_rust_type_alias_declaration(self, code_unit)
    }
}
impl RustAnalyzer {
    pub fn hierarchy_index(&self) -> &RustHierarchyIndex {
        self.hierarchy_index
            .get_or_init(|| RustHierarchyIndex::build(self))
    }

    pub fn type_relations(&self) -> &[TypeRelation] {
        self.type_relations
            .get_or_init(|| self.hierarchy_index().relations.clone())
            .as_slice()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::type_relations::TypeRelationKind;
    use crate::analyzer::{CodeUnitIndex, IAnalyzer, Language};
    use crate::test_support::AnalyzerFixture;

    fn analyzer_with_files(files: &[(&str, &str)]) -> (AnalyzerFixture, RustAnalyzer) {
        let fixture = AnalyzerFixture::new_for_language(Language::Rust, files);
        let analyzer = RustAnalyzer::from_project(fixture.test_project().clone());
        (fixture, analyzer)
    }

    fn definition(analyzer: &RustAnalyzer, fq_name: &str) -> CodeUnit {
        analyzer
            .get_definitions(fq_name)
            .into_iter()
            .next()
            .unwrap_or_else(|| panic!("missing definition for {fq_name}"))
    }

    fn has_trait_implementation_relation(analyzer: &RustAnalyzer, from: &str, to: &str) -> bool {
        analyzer.type_relations().iter().any(|relation| {
            relation.from.fq_name() == from
                && relation.to.fq_name() == to
                && relation.kind == TypeRelationKind::TraitImplementation
        })
    }

    #[test]
    fn warm_query_indexes_builds_hierarchy_and_usage_indexes_ahead_of_demand() {
        let (_fixture, analyzer) = analyzer_with_files(&[(
            "src/lib.rs",
            r#"
trait Runnable {}
pub struct Worker;
impl Runnable for Worker {}
"#,
        )]);

        assert!(!analyzer.query_indexes_warm());
        assert!(analyzer.hierarchy_index.get().is_none());
        assert!(!analyzer.usage_index.is_ready());

        analyzer.warm_query_indexes();

        assert!(analyzer.query_indexes_warm());
        assert!(analyzer.hierarchy_index.get().is_some());
        assert!(analyzer.usage_index.is_ready());

        let runnable = definition(&analyzer, "Runnable");
        let worker = definition(&analyzer, "Worker");
        assert_eq!(analyzer.get_direct_ancestors(&worker), vec![runnable]);
    }

    #[test]
    fn rust_type_relations_record_same_file_trait_implementation() {
        let (_fixture, analyzer) = analyzer_with_files(&[(
            "src/lib.rs",
            r#"
trait Runnable {}
struct Worker;
impl Runnable for Worker {}
"#,
        )]);

        let runnable = definition(&analyzer, "Runnable");
        let worker = definition(&analyzer, "Worker");

        assert!(has_trait_implementation_relation(
            &analyzer, "Worker", "Runnable"
        ));
        assert_eq!(
            analyzer.get_direct_ancestors(&worker),
            vec![runnable.clone()]
        );
        assert!(analyzer.get_direct_descendants(&runnable).contains(&worker));
    }

    #[test]
    fn rust_type_relations_record_imported_trait_implementation() {
        let (_fixture, analyzer) = analyzer_with_files(&[
            ("src/contracts.rs", "pub trait Runnable {}"),
            (
                "src/worker.rs",
                r#"
use crate::contracts::Runnable;
pub struct Worker;
impl Runnable for Worker {}
"#,
            ),
        ]);

        let runnable = definition(&analyzer, "contracts.Runnable");
        let worker = definition(&analyzer, "worker.Worker");

        assert!(has_trait_implementation_relation(
            &analyzer,
            "worker.Worker",
            "contracts.Runnable"
        ));
        assert_eq!(
            analyzer.get_direct_ancestors(&worker),
            vec![runnable.clone()]
        );
        assert!(analyzer.get_direct_descendants(&runnable).contains(&worker));
    }
}
