use super::*;
use crate::analyzer::type_relations::{TypeRelation, TypeRelationKind};
use crate::analyzer::usages::scala_graph::{ScalaNameResolver, ScalaProjectTypes};
use std::sync::Arc;

impl TypeHierarchyProvider for ScalaAnalyzer {
    fn get_direct_ancestors(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        if let Some(cached) = self.direct_ancestors.get(code_unit) {
            return (*cached).clone();
        }

        let ancestors = self.resolve_direct_ancestors(code_unit);
        self.direct_ancestors
            .insert(code_unit.clone(), Arc::new(ancestors.clone()));
        ancestors
    }

    fn get_direct_descendants(&self, code_unit: &CodeUnit) -> HashSet<CodeUnit> {
        self.direct_descendant_index
            .get_or_init(|| self.build_direct_descendant_index())
            .descendants(code_unit)
    }
}

impl ScalaAnalyzer {
    fn build_direct_descendant_index(&self) -> DirectDescendantIndex {
        let _scope = crate::profiling::scope("ScalaAnalyzer::build_direct_descendant_index");
        let file_states = self.bulk_file_states(self.analyzed_files(), BulkFileStateSource::Omit);
        let mut candidates = Vec::new();
        let mut seen = HashSet::default();
        for state in file_states.values() {
            for candidate in state
                .definition_lookup_units
                .iter()
                .chain(&state.declarations)
                .filter(|candidate| candidate.is_class())
            {
                if seen.insert(candidate.clone()) {
                    candidates.push(candidate.clone());
                }
            }
        }

        let (ancestors_by_owner, _) = self
            .project_types()
            .resolve_direct_ancestors_from_file_states(&file_states);
        for (owner, ancestors) in &ancestors_by_owner {
            self.direct_ancestors
                .insert(owner.clone(), Arc::new(ancestors.clone()));
        }
        build_direct_descendant_index_from_candidates(candidates, |candidate| {
            ancestors_by_owner
                .get(candidate)
                .cloned()
                .unwrap_or_default()
        })
    }

    #[allow(dead_code)]
    pub(crate) fn type_relations(&self) -> &[TypeRelation] {
        self.type_relations
            .get_or_init(|| self.collect_type_relations())
            .as_slice()
    }

    #[allow(dead_code)]
    fn collect_type_relations(&self) -> Vec<TypeRelation> {
        let types = self.project_types();
        let traits = self.scala_trait_fqns();
        self.all_declarations()
            .filter(|unit| unit.is_class())
            .flat_map(|unit| self.resolve_direct_ancestor_relations(&unit, &types, &traits))
            .collect()
    }

    fn resolve_direct_ancestors(&self, code_unit: &CodeUnit) -> Vec<CodeUnit> {
        let types = self.project_types();
        self.resolve_direct_ancestor_units(code_unit, &types)
    }

    fn resolve_direct_ancestor_units(
        &self,
        code_unit: &CodeUnit,
        types: &ScalaProjectTypes,
    ) -> Vec<CodeUnit> {
        if !code_unit.is_class() {
            return Vec::new();
        }

        let Some(facts) = self.forward_owner_facts(code_unit) else {
            return Vec::new();
        };
        let resolver = ScalaNameResolver::for_file_types(self, code_unit, types);
        let mut ancestors = Vec::new();
        let mut seen = HashSet::default();
        for path in facts.supertype_lookup_paths {
            let Some(fqn) =
                types.resolve_type_in_hierarchy_context(self, &resolver, path.segments())
            else {
                continue;
            };
            if !seen.insert(fqn.clone()) {
                continue;
            }
            if let crate::analyzer::usages::scala_graph::namespace::ScalaTypeNamespaceResolution::Resolved(definition) =
                types.exact_type_declaration_for_owner_context(&fqn, code_unit)
            {
                ancestors.push(definition);
            }
        }
        ancestors
    }

    fn resolve_direct_ancestor_relations(
        &self,
        code_unit: &CodeUnit,
        types: &ScalaProjectTypes,
        traits: &HashSet<String>,
    ) -> Vec<TypeRelation> {
        let owner_is_trait = traits.contains(&code_unit.fq_name());
        self.resolve_direct_ancestor_units(code_unit, types)
            .into_iter()
            .map(|ancestor| {
                let kind = self.relation_kind(owner_is_trait, &ancestor, traits);
                TypeRelation {
                    from: code_unit.clone(),
                    to: ancestor,
                    kind,
                }
            })
            .collect()
    }

    fn relation_kind(
        &self,
        owner_is_trait: bool,
        ancestor: &CodeUnit,
        traits: &HashSet<String>,
    ) -> TypeRelationKind {
        if !owner_is_trait && traits.contains(&ancestor.fq_name()) {
            TypeRelationKind::TraitImplementation
        } else {
            TypeRelationKind::NominalInheritance
        }
    }

    pub(crate) fn is_scala_trait_declaration(&self, code_unit: &CodeUnit) -> bool {
        code_unit.is_class()
            && self
                .forward_owner_facts(code_unit)
                .map(|facts| facts.is_trait)
                .unwrap_or_else(|| self.inner.is_scala_trait(code_unit))
    }

    fn scala_trait_fqns(&self) -> HashSet<String> {
        self.inner
            .scala_traits()
            .into_iter()
            .map(|unit| unit.fq_name())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::Language;
    use crate::test_support::AnalyzerFixture;

    fn analyzer_with_files(files: &[(&str, &str)]) -> (AnalyzerFixture, ScalaAnalyzer) {
        let fixture = AnalyzerFixture::new_for_language(Language::Scala, files);
        let analyzer = ScalaAnalyzer::from_project(fixture.test_project().clone());
        (fixture, analyzer)
    }

    #[test]
    fn scala_type_relations_distinguish_trait_mixins_from_nominal_inheritance() {
        let (_fixture, analyzer) = analyzer_with_files(&[
            (
                "Types.scala",
                r#"
package app
import lib.External
class Base
trait Runnable
trait Logged
trait Derived extends Logged
class Worker extends Base with Runnable with External
object Singleton extends Runnable
"#,
            ),
            (
                "lib/Types.scala",
                r#"
package lib
trait External
"#,
            ),
        ]);

        let relations = analyzer.type_relations();
        assert!(relations.iter().any(|relation| {
            relation.from.fq_name() == "app.Worker"
                && relation.to.fq_name() == "app.Base"
                && relation.kind == TypeRelationKind::NominalInheritance
        }));
        assert!(relations.iter().any(|relation| {
            relation.from.fq_name() == "app.Worker"
                && relation.to.fq_name() == "app.Runnable"
                && relation.kind == TypeRelationKind::TraitImplementation
        }));
        assert!(relations.iter().any(|relation| {
            relation.from.fq_name() == "app.Singleton$"
                && relation.to.fq_name() == "app.Runnable"
                && relation.kind == TypeRelationKind::TraitImplementation
        }));
        assert!(relations.iter().any(|relation| {
            relation.from.fq_name() == "app.Worker"
                && relation.to.fq_name() == "lib.External"
                && relation.kind == TypeRelationKind::TraitImplementation
        }));
        assert!(relations.iter().any(|relation| {
            relation.from.fq_name() == "app.Derived"
                && relation.to.fq_name() == "app.Logged"
                && relation.kind == TypeRelationKind::NominalInheritance
        }));
    }
}
