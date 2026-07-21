use super::*;
use crate::analyzer::ImportInfo;
use crate::analyzer::type_relations::{TypeRelation, TypeRelationKind};
use crate::analyzer::usages::scala_graph::{ScalaNameResolver, ScalaProjectTypes};
use std::sync::Arc;

#[derive(Clone)]
struct ScalaHierarchyOwnerContext {
    supertype_lookup_paths: Vec<ScalaSupertypeLookupPath>,
    imports: Vec<ImportInfo>,
}

enum ScalaHierarchyPackageResolution {
    NoMatch,
    Resolved(String),
    AuthoritativeMiss,
}

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
        let mut contexts = HashMap::default();
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
                if let Some(context) = hierarchy_owner_context_from_state(state, candidate) {
                    contexts.insert(candidate.clone(), context);
                }
            }
        }

        let types = self.project_types_from_file_states(file_states);
        let mut ancestors_by_owner = HashMap::default();
        for candidate in &candidates {
            let ancestors = contexts
                .get(candidate)
                .map(|context| {
                    self.resolve_direct_ancestor_units_with_context(candidate, &types, context)
                })
                .unwrap_or_default();
            self.direct_ancestors
                .insert(candidate.clone(), Arc::new(ancestors.clone()));
            ancestors_by_owner.insert(candidate.clone(), ancestors);
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

        let Some(state) = self.inner.fetch_file_state(code_unit.source()) else {
            return Vec::new();
        };
        let Some(context) = hierarchy_owner_context_from_state(&state, code_unit) else {
            return Vec::new();
        };
        self.resolve_direct_ancestor_units_with_context(code_unit, types, &context)
    }

    fn resolve_direct_ancestor_units_with_context(
        &self,
        code_unit: &CodeUnit,
        types: &ScalaProjectTypes,
        context: &ScalaHierarchyOwnerContext,
    ) -> Vec<CodeUnit> {
        let mut ancestors = Vec::new();
        let mut seen = HashSet::default();
        for path in &context.supertype_lookup_paths {
            let fallback_package = [code_unit.package_name().to_string()];
            let package_prefixes = if path.package_prefixes().is_empty() {
                fallback_package.as_slice()
            } else {
                path.package_prefixes()
            };
            let resolver = ScalaNameResolver::for_file_with_package_context(
                self,
                Some(code_unit.source()),
                package_prefixes,
                &context.imports,
                types,
            );
            let non_wildcard_imports = context
                .imports
                .iter()
                .filter(|import| !import.is_wildcard)
                .cloned()
                .collect::<Vec<_>>();
            let wildcard_baseline =
                (non_wildcard_imports.len() != context.imports.len()).then(|| {
                    ScalaNameResolver::for_file_with_package_context(
                        self,
                        Some(code_unit.source()),
                        package_prefixes,
                        &non_wildcard_imports,
                        types,
                    )
                });
            let Some(fqn) = self.resolve_hierarchy_supertype_path(
                types,
                &resolver,
                wildcard_baseline.as_ref(),
                path,
                package_prefixes,
                &context.imports,
            ) else {
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

    fn resolve_hierarchy_supertype_path(
        &self,
        types: &ScalaProjectTypes,
        resolver: &ScalaNameResolver,
        wildcard_baseline: Option<&ScalaNameResolver>,
        path: &ScalaSupertypeLookupPath,
        package_prefixes: &[String],
        imports: &[ImportInfo],
    ) -> Option<String> {
        let segments = path.segments();
        if let [root, _, ..] = segments
            && !hierarchy_import_claims_root(imports, root, resolver, wildcard_baseline)
        {
            match self.resolve_enclosing_package_supertype(package_prefixes, segments) {
                ScalaHierarchyPackageResolution::Resolved(fqn) => return Some(fqn),
                ScalaHierarchyPackageResolution::AuthoritativeMiss => return None,
                ScalaHierarchyPackageResolution::NoMatch => {}
            }
        }
        types.resolve_type_in_hierarchy_context(self, resolver, segments)
    }

    fn resolve_enclosing_package_supertype(
        &self,
        package_prefixes: &[String],
        segments: &[String],
    ) -> ScalaHierarchyPackageResolution {
        let Some((root, rest)) = segments.split_first() else {
            return ScalaHierarchyPackageResolution::NoMatch;
        };
        if rest.is_empty() || root == "_root_" {
            return ScalaHierarchyPackageResolution::NoMatch;
        }
        for package in scala_enclosing_package_root_candidates(package_prefixes, root) {
            if package == *root {
                continue;
            }
            if !self.inner.forward_package_exists(&package) {
                continue;
            }
            let qualified = std::iter::once(package.as_str())
                .chain(rest.iter().map(String::as_str))
                .collect::<Vec<_>>()
                .join(".");
            let mut declarations = self
                .inner
                .definitions(&qualified)
                .filter(CodeUnit::is_class)
                .collect::<Vec<_>>();
            declarations.sort();
            declarations.dedup();
            let ordinary = declarations
                .iter()
                .filter(|unit| !unit.short_name().ends_with('$'))
                .cloned()
                .collect::<Vec<_>>();
            let selected = if ordinary.is_empty() {
                declarations
            } else {
                ordinary
            };
            return match selected.as_slice() {
                [definition] => ScalaHierarchyPackageResolution::Resolved(definition.fq_name()),
                [] | [_, _, ..] => ScalaHierarchyPackageResolution::AuthoritativeMiss,
            };
        }
        ScalaHierarchyPackageResolution::NoMatch
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

fn hierarchy_owner_context_from_state(
    state: &FileState,
    owner: &CodeUnit,
) -> Option<ScalaHierarchyOwnerContext> {
    let raw_supertypes = state.raw_supertypes.get(owner)?;
    let supertype_lookup_paths = state
        .supertype_lookup_paths
        .get(owner)?
        .iter()
        .map(|path| ScalaSupertypeLookupPath::decode(path))
        .collect::<Option<Vec<_>>>()?;
    if raw_supertypes.len() != supertype_lookup_paths.len() {
        return None;
    }
    let reference_byte = state
        .ranges
        .get(owner)
        .into_iter()
        .flatten()
        .map(|range| range.start_byte)
        .min()
        .unwrap_or(usize::MAX);
    let fallback_package = [owner.package_name().to_string()];
    let package_prefixes = supertype_lookup_paths
        .first()
        .map(ScalaSupertypeLookupPath::package_prefixes)
        .filter(|prefixes| !prefixes.is_empty())
        .unwrap_or(fallback_package.as_slice());
    let imports = state
        .imports
        .iter()
        .filter(|import| scala_import_visible_at(import, package_prefixes, &[], reference_byte))
        .cloned()
        .collect();
    Some(ScalaHierarchyOwnerContext {
        supertype_lookup_paths,
        imports,
    })
}

fn hierarchy_import_claims_root(
    imports: &[ImportInfo],
    root: &str,
    resolver: &ScalaNameResolver,
    wildcard_baseline: Option<&ScalaNameResolver>,
) -> bool {
    imports.iter().any(|import| {
        !import.is_wildcard
            && import
                .identifier
                .as_deref()
                .is_some_and(|visible| visible == root)
    }) || wildcard_baseline.is_some_and(|baseline| {
        (resolver.resolve(root), resolver.resolve_object(root))
            != (baseline.resolve(root), baseline.resolve_object(root))
    })
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
