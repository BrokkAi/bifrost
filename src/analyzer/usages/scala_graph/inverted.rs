//! Whole-workspace inverted edge builder for Scala.
//!
//! Walks each file once and resolves every reference to the callee fqn it names,
//! via the shared [`build_edges`] driver. Scala has no single `resolve_type_name`
//! primitive, so name->fqn resolution is rebuilt here by mirroring the forward
//! scanner's [`Visibility`](super::resolver): a per-file [`NameResolver`] maps a
//! source-visible type/object name to the analyzer's own fqn, honoring the file's
//! package and its imports. A [`LocalInferenceEngine`] seeded with typed params
//! and `val x = new Foo()` lets a method call's receiver be typed:
//!
//! - a type reference (`x: Foo`, `new Foo`, `def f(): Foo`) resolves to the type;
//! - `recv.method(..)` types `recv` to `Owner`, giving `Owner.method`;
//! - `this`/an unqualified `method(..)` attributes to the enclosing class.
//!
//! Scala object fqns keep their `$` object-encoding suffix (`example.Helpers$`,
//! method `example.Helpers$.help`), so type/object fqns come straight from the
//! analyzer's declarations rather than being rebuilt from `package.name` text —
//! a string-rebuilt name would drop the `$` and silently match no node. The
//! enclosing class is taken from a per-file class-range index (the analyzer's own
//! fqns) so `this`/unqualified calls attribute to the right class (and the right
//! `$`-encoded object). Receivers needing return-type inference (method chains)
//! are an unhandled recall gap, not a wrong edge.

use super::resolver::{
    preferred_scala_type, scala_builtin_type_name, scala_extension_receiver_matches_resolved,
    scala_literal_type_name, scala_normalized_fq_name,
};
use super::shared::ScalaEdgeGraph;
use super::syntax::{
    ScalaCallableParameterList, ScalaImportContextIndex, ScalaMethodValueContext,
    ScalaPackageContextIndex, ScalaParameterListKind, ScalaQualifiedStableTypeRole,
    ScalaSourceFacts, call_arities_for_reference, enclosing_template_declarations,
    is_bare_companion_method_value_reference, is_constructor_like_reference, is_declaration_name,
    is_extractor_reference, is_infix_pattern_operator, is_scala_class_reference,
    is_scala_object_reference, is_terminal_stable_field_reference, node_text, parenthesized_arity,
    qualified_stable_type_reference, resolve_stable_object_expression,
    scala_import_is_visible_at_byte, scala_source_facts, stable_identifier_reference,
    template_direct_term_member_named, template_self_type,
};
use crate::analyzer::scala::{
    ScalaAdapter, ScalaExplicitImportFacts, ScalaExplicitImportTier, ScalaExportSelector,
    ScalaSupertypeLookupPath, ScalaWildcardOwnerFacts, resolve_scala_explicit_import_tier,
    resolve_scala_wildcard_import_environment, scala_class_parameter_field_keyword,
    scala_import_path, scala_normalize_full_name, scala_simple_type_name,
    scala_supertype_lookup_nodes, scala_type_lookup_segments,
};
use crate::analyzer::tree_sitter_analyzer::FileState;
use crate::analyzer::usage_facts::CallableFacts;
use crate::analyzer::usages::common::{TreeWalkAction, walk_tree_iterative};
use crate::analyzer::usages::inverted_edges::{
    ClassRangeIndex, EdgeCollector, UsageEdgeBuildOutput, build_edge_output,
    build_file_declarations_from_state, classify_reference_node, first_precise,
    parse_source_and_collect_with_declarations,
};
use crate::analyzer::usages::local_inference::{LocalInferenceConfig, LocalInferenceEngine};
use crate::analyzer::{
    CallableArity, CodeUnit, GlobalUsageDefinitionIndex, Range, UsageFactsIndex,
};
use crate::analyzer::{
    IAnalyzer, ImportAnalysisProvider, ProjectFile, ScalaAnalyzer, TypeHierarchyProvider,
};
use crate::hash::{HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock};
use tree_sitter::Node;

type PackageTypeEntries = Arc<Vec<(String, CodeUnit)>>;
type CachedScalaSourceFacts = Arc<ScalaSourceFacts>;
type ScalaSourceFactsCell = Arc<OnceLock<CachedScalaSourceFacts>>;
pub(crate) type CachedCallableAlternatives = Arc<Vec<CallableAlternative>>;
type CallableAlternativesCell = Arc<OnceLock<CachedCallableAlternatives>>;
type ExtensionOwnerMemberKey = (String, String);
type ExtensionMethodEntries = Arc<Vec<ExtensionMethod>>;
type OverrideTargetEntries = Arc<Vec<String>>;

#[derive(Clone)]
struct ScalaExportEdge {
    exporter_fqn: String,
    source_owner_fqn: String,
    selectors: Vec<ScalaExportSelector>,
}

type ExportedMemberBindings = HashMap<String, HashSet<String>>;

pub(super) enum MemberReturnResolution {
    NoMatch,
    Unresolved,
    Resolved(String),
}

pub(super) enum BareMemberResolution {
    NoMatch,
    Unresolved,
    Resolved(Vec<CodeUnit>),
}

pub(super) enum FieldResolution {
    NoMatch,
    Unresolved,
    Resolved(ResolvedField),
}

pub(super) struct ResolvedField {
    pub(super) declaration: CodeUnit,
    pub(super) declared_type: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum TypeApplicationRole {
    ExplicitConstructor,
    BareApplication,
    Extractor,
}

pub(super) struct TypeApplicationResolution {
    pub(super) type_target: Option<CodeUnit>,
    pub(super) callable_targets: Vec<CodeUnit>,
}

/// Every class/object/trait/enum the project declares, indexed for the per-file
/// name->fqn rebuild. Built once and shared across all files' scans.
pub(crate) struct ProjectTypes {
    index: Arc<GlobalUsageDefinitionIndex>,
    facts: Arc<UsageFactsIndex>,
    direct_ancestors_by_owner: Option<HashMap<String, Vec<CodeUnit>>>,
    direct_ancestors_by_unit: Option<HashMap<CodeUnit, Vec<CodeUnit>>>,
    scala_trait_fqns: Option<HashSet<String>>,
    package_types_by_package: Mutex<HashMap<String, PackageTypeEntries>>,
    package_objects_by_package: Mutex<HashMap<String, PackageTypeEntries>>,
    nested_types_by_owner: Mutex<HashMap<String, PackageTypeEntries>>,
    nested_objects_by_owner: Mutex<HashMap<String, PackageTypeEntries>>,
    source_facts_by_file: Mutex<HashMap<ProjectFile, ScalaSourceFactsCell>>,
    bulk_file_states: Option<HashMap<ProjectFile, FileState>>,
    callable_alternatives_by_unit: Mutex<HashMap<CodeUnit, CallableAlternativesCell>>,
    extension_methods_by_owner_member:
        Mutex<HashMap<ExtensionOwnerMemberKey, ExtensionMethodEntries>>,
    override_targets_by_method: Mutex<HashMap<String, OverrideTargetEntries>>,
    exported_member_bindings_by_owner: Mutex<HashMap<String, Vec<(String, String)>>>,
}

impl ProjectTypes {
    pub(crate) fn build(scala: &ScalaAnalyzer) -> Self {
        let index = scala.global_usage_definition_index_shared();
        Self {
            index,
            facts: scala.usage_facts_index_shared(),
            direct_ancestors_by_owner: None,
            direct_ancestors_by_unit: None,
            scala_trait_fqns: None,
            package_types_by_package: Mutex::new(HashMap::default()),
            package_objects_by_package: Mutex::new(HashMap::default()),
            nested_types_by_owner: Mutex::new(HashMap::default()),
            nested_objects_by_owner: Mutex::new(HashMap::default()),
            source_facts_by_file: Mutex::new(HashMap::default()),
            bulk_file_states: None,
            callable_alternatives_by_unit: Mutex::new(HashMap::default()),
            extension_methods_by_owner_member: Mutex::new(HashMap::default()),
            override_targets_by_method: Mutex::new(HashMap::default()),
            exported_member_bindings_by_owner: Mutex::new(HashMap::default()),
        }
    }

    pub(crate) fn build_from_file_states(file_states: HashMap<ProjectFile, FileState>) -> Self {
        let mut declarations = Vec::new();
        let mut seen = HashSet::default();
        for state in file_states.values() {
            for unit in state
                .definition_lookup_units
                .iter()
                .chain(&state.declarations)
            {
                if !unit.is_file_scope() && seen.insert(unit.clone()) {
                    declarations.push(unit.clone());
                }
            }
        }
        let index = Arc::new(GlobalUsageDefinitionIndex::from_declarations(
            declarations.iter(),
            scala_normalize_full_name,
            scala_simple_type_name,
        ));
        let facts = Arc::new(UsageFactsIndex::build_from_declarations(
            &index,
            declarations.iter(),
            |unit| {
                file_states
                    .get(unit.source())
                    .and_then(|state| state.signatures.get(unit).and_then(|values| values.first()))
                    .cloned()
                    .or_else(|| unit.signature().map(str::to_string))
            },
            |unit| {
                file_states
                    .get(unit.source())
                    .and_then(|state| {
                        state
                            .signature_metadata
                            .get(unit)
                            .and_then(|values| values.first())
                    })
                    .cloned()
            },
            &ScalaAdapter,
        ));
        let mut types = Self {
            index,
            facts,
            direct_ancestors_by_owner: Some(HashMap::default()),
            direct_ancestors_by_unit: Some(HashMap::default()),
            scala_trait_fqns: Some(
                file_states
                    .values()
                    .flat_map(|state| state.scala_traits.iter().map(CodeUnit::fq_name))
                    .collect(),
            ),
            package_types_by_package: Mutex::new(HashMap::default()),
            package_objects_by_package: Mutex::new(HashMap::default()),
            nested_types_by_owner: Mutex::new(HashMap::default()),
            nested_objects_by_owner: Mutex::new(HashMap::default()),
            source_facts_by_file: Mutex::new(HashMap::default()),
            bulk_file_states: Some(file_states),
            callable_alternatives_by_unit: Mutex::new(HashMap::default()),
            extension_methods_by_owner_member: Mutex::new(HashMap::default()),
            override_targets_by_method: Mutex::new(HashMap::default()),
            exported_member_bindings_by_owner: Mutex::new(HashMap::default()),
        };
        let direct_ancestors_by_unit = types.resolve_direct_ancestors_from_file_states(
            types
                .bulk_file_states
                .as_ref()
                .expect("bulk Scala file states were just installed"),
        );
        let direct_ancestors_by_owner = direct_ancestors_by_unit
            .iter()
            .map(|(owner, ancestors)| (owner.fq_name(), ancestors.clone()))
            .collect();
        types.direct_ancestors_by_owner = Some(direct_ancestors_by_owner);
        types.direct_ancestors_by_unit = Some(direct_ancestors_by_unit);
        types
    }

    fn bulk_file_state(&self, file: &ProjectFile) -> Option<&FileState> {
        self.bulk_file_states.as_ref()?.get(file)
    }

    fn export_infos_for_owner(
        &self,
        scala: &ScalaAnalyzer,
        owner: &CodeUnit,
    ) -> Vec<crate::analyzer::scala::ScalaExportInfo> {
        match &self.bulk_file_states {
            Some(states) => states
                .get(owner.source())
                .and_then(|state| state.scala_exports.get(owner))
                .cloned()
                .unwrap_or_default(),
            None => scala.export_infos_for_owner(owner),
        }
    }

    fn imports_for_export_owner(
        &self,
        scala: &ScalaAnalyzer,
        owner: &CodeUnit,
    ) -> Vec<crate::analyzer::ImportInfo> {
        match &self.bulk_file_states {
            Some(states) => states
                .get(owner.source())
                .map(|state| state.imports.clone())
                .unwrap_or_default(),
            None => scala.import_info_of(owner.source()),
        }
    }

    fn direct_member_bindings(&self, owner_fqn: &str) -> ExportedMemberBindings {
        let mut bindings = ExportedMemberBindings::default();
        for child in self.index.fqn_direct_children(owner_fqn) {
            if child.is_function() || child.is_field() {
                let visible_name = child
                    .short_name()
                    .rsplit('.')
                    .next()
                    .unwrap_or(child.short_name())
                    .to_string();
                bindings
                    .entry(visible_name)
                    .or_default()
                    .insert(child.fq_name());
            }
        }
        bindings
    }

    /// Resolve the original declarations exposed as members of `exporter`.
    ///
    /// Export aliases are compiler-generated declarations and therefore do
    /// not appear in the source declaration index. Build their bindings from
    /// parser-recorded export facts instead. Discovery is iterative and the
    /// propagation is a finite monotonic fixed point, so malformed export
    /// cycles terminate without losing valid aliases on another path.
    pub(crate) fn exported_member_bindings(
        &self,
        scala: &ScalaAnalyzer,
        exporter: &CodeUnit,
    ) -> Vec<(String, String)> {
        let exporter_fqn = exporter.fq_name();
        if let Some(cached) = self
            .exported_member_bindings_by_owner
            .lock()
            .expect("Scala export binding cache poisoned")
            .get(&exporter_fqn)
            .cloned()
        {
            return cached;
        }

        let mut queue = vec![exporter.clone()];
        let mut visited = HashSet::default();
        let mut owners = HashMap::<String, CodeUnit>::default();
        let mut edges = Vec::new();
        while let Some(current) = queue.pop() {
            let current_fqn = current.fq_name();
            if !visited.insert(current_fqn.clone()) {
                continue;
            }
            owners.insert(current_fqn.clone(), current.clone());
            let imports = self.imports_for_export_owner(scala, &current);
            for export in self.export_infos_for_owner(scala, &current) {
                if export.owner_path.is_empty() {
                    continue;
                }
                // Export qualifier paths are elaborated before aliases in the
                // same owner. Excluding member bindings here enforces that
                // path-before-alias rule while retaining ordinary import and
                // package precedence.
                let visible_imports =
                    visible_imports_at_byte(&imports, Some(export.declaration_start_byte));
                let resolver = NameResolver::for_file_with_facts_impl(
                    scala,
                    Some(current.source()),
                    &[current.package_name().to_string()],
                    &visible_imports,
                    self,
                    false,
                );
                let Some(source_owner_fqn) = self.resolve_qualified_stable_type_at(
                    scala,
                    &resolver,
                    &export.owner_path,
                    true,
                    None,
                ) else {
                    continue;
                };
                let normalized = scala_normalized_fq_name(&source_owner_fqn);
                let Some(source_owner) = self.object_by_normalized_fqn(scala, &normalized).cloned()
                else {
                    continue;
                };
                let source_owner_fqn = source_owner.fq_name();
                edges.push(ScalaExportEdge {
                    exporter_fqn: current_fqn.clone(),
                    source_owner_fqn: source_owner_fqn.clone(),
                    selectors: export.selectors,
                });
                if !visited.contains(&source_owner_fqn) {
                    queue.push(source_owner);
                }
            }
        }

        let mut bindings_by_owner = owners
            .keys()
            .map(|owner_fqn| (owner_fqn.clone(), self.direct_member_bindings(owner_fqn)))
            .collect::<HashMap<_, _>>();
        loop {
            let mut changed = false;
            for edge in &edges {
                let Some(source_bindings) = bindings_by_owner.get(&edge.source_owner_fqn).cloned()
                else {
                    continue;
                };
                let destination = bindings_by_owner
                    .entry(edge.exporter_fqn.clone())
                    .or_default();
                let named_sources = edge
                    .selectors
                    .iter()
                    .filter_map(|selector| match selector {
                        ScalaExportSelector::Named { source_name, .. } => Some(source_name.clone()),
                        ScalaExportSelector::Wildcard | ScalaExportSelector::GivenWildcard => None,
                    })
                    .collect::<HashSet<_>>();
                for selector in &edge.selectors {
                    match selector {
                        ScalaExportSelector::Named {
                            source_name,
                            visible_name,
                        } => {
                            let Some(visible_name) = visible_name else {
                                continue;
                            };
                            let Some(candidates) = source_bindings.get(source_name) else {
                                continue;
                            };
                            let target = destination.entry(visible_name.clone()).or_default();
                            let previous = target.len();
                            target.extend(candidates.iter().cloned());
                            changed |= target.len() != previous;
                        }
                        ScalaExportSelector::Wildcard => {
                            for (visible_name, candidates) in &source_bindings {
                                if named_sources.contains(visible_name) {
                                    continue;
                                }
                                let target = destination.entry(visible_name.clone()).or_default();
                                let previous = target.len();
                                target.extend(candidates.iter().cloned());
                                changed |= target.len() != previous;
                            }
                        }
                        // Given exports have distinct eligibility rules. Do
                        // not expose them as ordinary term-member bindings.
                        ScalaExportSelector::GivenWildcard => {}
                    }
                }
            }
            if !changed {
                break;
            }
        }

        let flattened_by_owner = bindings_by_owner
            .into_iter()
            .map(|(owner_fqn, bindings)| {
                let mut flattened = bindings
                    .into_iter()
                    .flat_map(|(visible_name, candidates)| {
                        candidates
                            .into_iter()
                            .map(move |candidate| (visible_name.clone(), candidate))
                    })
                    .collect::<Vec<_>>();
                flattened.sort();
                flattened.dedup();
                (owner_fqn, flattened)
            })
            .collect::<Vec<_>>();
        let result = flattened_by_owner
            .iter()
            .find(|(owner_fqn, _)| owner_fqn == &exporter_fqn)
            .map(|(_, bindings)| bindings.clone())
            .unwrap_or_default();
        let mut cache = self
            .exported_member_bindings_by_owner
            .lock()
            .expect("Scala export binding cache poisoned");
        for (owner_fqn, bindings) in flattened_by_owner {
            cache.entry(owner_fqn).or_insert(bindings);
        }
        result
    }

    pub(crate) fn resolve_direct_ancestors_from_file_states(
        &self,
        file_states: &HashMap<ProjectFile, FileState>,
    ) -> HashMap<CodeUnit, Vec<CodeUnit>> {
        let mut ancestors_by_owner = HashMap::default();
        for (file, state) in file_states {
            if state.supertype_lookup_paths.is_empty() {
                continue;
            }
            let lookup_paths_by_owner = state
                .supertype_lookup_paths
                .iter()
                .filter_map(|(owner, encoded)| {
                    let paths = encoded
                        .iter()
                        .map(|path| ScalaSupertypeLookupPath::decode(path))
                        .collect::<Option<Vec<_>>>()?;
                    Some((owner.clone(), paths))
                })
                .collect::<HashMap<_, _>>();
            let mut required_names_by_package = HashMap::<String, HashSet<String>>::default();
            for (owner, paths) in &lookup_paths_by_owner {
                required_names_by_package
                    .entry(owner.package_name().to_string())
                    .or_default()
                    .extend(
                        paths
                            .iter()
                            .filter_map(|path| path.segments().first().cloned()),
                    );
            }
            let resolvers_by_package = required_names_by_package
                .into_iter()
                .map(|(package, required_names)| {
                    let resolver = NameResolver::for_type_hierarchy_file(
                        Some(file),
                        Some(&package),
                        &state.imports,
                        self,
                        &required_names,
                    );
                    (package, resolver)
                })
                .collect::<HashMap<_, _>>();
            let parent_by_child = state
                .children
                .iter()
                .flat_map(|(parent, children)| children.iter().map(move |child| (child, parent)))
                .collect::<HashMap<_, _>>();
            for (owner, lookup_paths) in lookup_paths_by_owner {
                if !owner.is_class() {
                    continue;
                }
                let Some(resolver) = resolvers_by_package.get(owner.package_name()) else {
                    continue;
                };
                let mut ancestors = Vec::new();
                let mut seen = HashSet::default();
                for path in lookup_paths {
                    let Some(fqn) = self.resolve_type_in_owner_context(
                        resolver,
                        path.segments(),
                        &owner,
                        state,
                        &parent_by_child,
                    ) else {
                        continue;
                    };
                    if !seen.insert(fqn.clone()) {
                        continue;
                    }
                    if let Some(definition) =
                        self.type_by_normalized_fqn(&scala_normalized_fq_name(&fqn))
                    {
                        ancestors.push(definition.clone());
                    }
                }
                if !ancestors.is_empty() {
                    ancestors_by_owner.insert(owner.clone(), ancestors);
                }
            }
        }
        ancestors_by_owner
    }

    pub(super) fn direct_ancestors_for_owner(
        &self,
        scala: &ScalaAnalyzer,
        owner_fqn: &str,
    ) -> Vec<CodeUnit> {
        if let Some(ancestors_by_owner) = &self.direct_ancestors_by_owner {
            return ancestors_by_owner
                .get(owner_fqn)
                .cloned()
                .unwrap_or_default();
        }
        scala
            .definitions(owner_fqn)
            .find(|unit| unit.is_class())
            .map(|owner| scala.get_direct_ancestors(&owner))
            .unwrap_or_default()
    }

    fn direct_ancestors_for_declaration(
        &self,
        scala: &ScalaAnalyzer,
        owner: &CodeUnit,
    ) -> Vec<CodeUnit> {
        if let Some(ancestors_by_unit) = &self.direct_ancestors_by_unit {
            return ancestors_by_unit.get(owner).cloned().unwrap_or_default();
        }
        scala.get_direct_ancestors(owner)
    }

    fn direct_field_ancestors_for_owner(
        &self,
        scala: &ScalaAnalyzer,
        owner_fqn: &str,
    ) -> Vec<CodeUnit> {
        if let Some(ancestors_by_owner) = &self.direct_ancestors_by_owner {
            return ancestors_by_owner
                .get(owner_fqn)
                .cloned()
                .unwrap_or_default();
        }
        scala
            .definitions(owner_fqn)
            .find(|unit| unit.is_class())
            .map(|owner| scala.get_direct_ancestors(&owner))
            .unwrap_or_default()
    }

    pub(super) fn field_for_owner_member(
        &self,
        scala: &ScalaAnalyzer,
        owner_fqn: &str,
        member: &str,
    ) -> FieldResolution {
        let mut level = vec![owner_fqn.to_string()];
        let mut seen = HashSet::default();
        while !level.is_empty() {
            let mut matches = Vec::new();
            let mut next = Vec::new();
            for owner in level {
                if !seen.insert(owner.clone()) {
                    continue;
                }
                matches.extend(
                    self.members_for_exact_owner_name(&owner, member)
                        .into_iter()
                        .filter(|unit| unit.is_field() && !scala.is_type_alias(unit))
                        .cloned(),
                );
                next.extend(
                    self.direct_field_ancestors_for_owner(scala, &owner)
                        .into_iter()
                        .map(|ancestor| ancestor.fq_name()),
                );
            }
            if !matches.is_empty() {
                let mut unique = HashSet::default();
                matches.retain(|field| unique.insert(field.clone()));
                if matches.len() != 1 {
                    return FieldResolution::Unresolved;
                }
                let declaration = matches.pop().expect("one exact Scala field");
                let declared_type = self.field_declared_type(scala, &declaration);
                return FieldResolution::Resolved(ResolvedField {
                    declaration,
                    declared_type,
                });
            }
            level = next;
        }
        FieldResolution::NoMatch
    }

    pub(super) fn stable_type_member_for_owner(
        &self,
        scala: &ScalaAnalyzer,
        owner_fqn: &str,
        member: &str,
    ) -> FieldResolution {
        let mut level = vec![owner_fqn.to_string()];
        let mut seen = HashSet::default();
        while !level.is_empty() {
            let mut matches = Vec::new();
            let mut next = Vec::new();
            for owner in level {
                if !seen.insert(owner.clone()) {
                    continue;
                }
                matches.extend(
                    self.members_for_exact_owner_name(&owner, member)
                        .into_iter()
                        .filter(|unit| unit.is_field())
                        .cloned(),
                );
                next.extend(
                    self.direct_field_ancestors_for_owner(scala, &owner)
                        .into_iter()
                        .map(|ancestor| ancestor.fq_name()),
                );
            }
            if !matches.is_empty() {
                let type_members = matches
                    .iter()
                    .filter(|field| scala.is_type_alias(field))
                    .cloned()
                    .collect::<Vec<_>>();
                if !type_members.is_empty() {
                    matches = type_members;
                }
                let mut unique = HashSet::default();
                matches.retain(|field| unique.insert(field.clone()));
                if matches.len() != 1 {
                    return FieldResolution::Unresolved;
                }
                return FieldResolution::Resolved(ResolvedField {
                    declaration: matches.pop().expect("one exact Scala stable type member"),
                    declared_type: None,
                });
            }
            level = next;
        }
        FieldResolution::NoMatch
    }

    fn field_declared_type(&self, scala: &ScalaAnalyzer, declaration: &CodeUnit) -> Option<String> {
        let source_facts = self.source_facts_for_file(scala, declaration.source());
        let resolver = NameResolver::for_file_types(scala, declaration, self);
        let mut resolved = HashSet::default();
        for range in self.declaration_ranges_for(scala, declaration) {
            if let Some(path) = source_facts
                .field_type_paths_by_range
                .get(&(range.start_byte, range.end_byte))
                && let Some(field_type) = self.resolve_type_in_declaration_context(&resolver, path)
            {
                resolved.insert(field_type);
            }
        }
        match resolved.len() {
            1 => return resolved.into_iter().next(),
            2.. => return None,
            0 => {}
        }
        self.facts
            .fact_for_declaration(declaration)
            .and_then(|facts| facts.return_type_fqn.clone())
    }

    pub(super) fn is_scala_trait_declaration(
        &self,
        scala: &ScalaAnalyzer,
        code_unit: &CodeUnit,
    ) -> bool {
        if let Some(traits) = &self.scala_trait_fqns {
            return traits.contains(&code_unit.fq_name());
        }
        scala.is_scala_trait_declaration(code_unit)
    }

    fn method_declarations_for_owner_member(
        &self,
        scala: &ScalaAnalyzer,
        owner_fqn: &str,
        member: &str,
        call_arities: Option<&[usize]>,
    ) -> Vec<CodeUnit> {
        let members = self.members_for_exact_owner_name(owner_fqn, member);
        self.method_declarations_for_members(scala, &members, call_arities)
    }

    fn method_declarations_for_members(
        &self,
        scala: &ScalaAnalyzer,
        members: &[&CodeUnit],
        call_arities: Option<&[usize]>,
    ) -> Vec<CodeUnit> {
        let candidates = members
            .iter()
            .filter(|method| method.is_function())
            .filter_map(|method| {
                self.facts.fact_for_declaration(method).map(|facts| {
                    (
                        *method,
                        facts,
                        self.callable_alternatives_for(scala, method),
                    )
                })
            })
            .collect::<Vec<_>>();
        let callable_count = candidates
            .iter()
            .map(|(_, _, alternatives)| alternatives.len().max(1))
            .sum::<usize>();
        let unique_callable = callable_count == 1;
        candidates
            .iter()
            .filter(|(_, facts, alternatives)| {
                method_call_shape_matches(facts, alternatives, call_arities, unique_callable)
            })
            .map(|(method, _, _)| (*method).clone())
            .collect()
    }

    fn imported_member_targets(
        &self,
        scala: &ScalaAnalyzer,
        member_fqn: &str,
        call_arities: Option<&[usize]>,
    ) -> Vec<String> {
        let members = self
            .index
            .by_fqn(member_fqn)
            .iter()
            .filter(|unit| unit.is_function())
            .collect::<Vec<_>>();
        self.method_declarations_for_members(scala, &members, call_arities)
            .into_iter()
            .map(|method| method.fq_name())
            .collect()
    }

    pub(super) fn bare_member_declarations_for_owner(
        &self,
        scala: &ScalaAnalyzer,
        owner: &CodeUnit,
        member: &str,
        call_arities: Option<&[usize]>,
    ) -> BareMemberResolution {
        if !owner.is_class() {
            return BareMemberResolution::NoMatch;
        }
        let mut owners = vec![owner.clone()];
        let mut seen = HashSet::default();
        while !owners.is_empty() {
            let mut matched = Vec::new();
            let mut next = Vec::new();
            for owner in owners {
                if !seen.insert(owner.clone()) {
                    continue;
                }
                let members = self
                    .members_for_exact_owner_name(&owner.fq_name(), member)
                    .into_iter()
                    .filter(|unit| unit.source() == owner.source())
                    .collect::<Vec<_>>();
                if members
                    .iter()
                    .any(|member| self.member_blocks_callable_lookup(scala, member))
                {
                    return BareMemberResolution::Unresolved;
                }
                matched.extend(self.method_declarations_for_members(scala, &members, call_arities));
                next.extend(self.direct_ancestors_for_declaration(scala, &owner));
            }
            if !matched.is_empty() {
                let mut unique = HashSet::default();
                matched.retain(|method| unique.insert(method.clone()));
                return BareMemberResolution::Resolved(matched);
            }
            owners = next;
        }
        BareMemberResolution::NoMatch
    }

    /// Resolve only ordinary methods declared by a class or object owner.
    ///
    /// This intentionally does not broaden trait-default or extension-method
    /// handling.  Each breadth level is one semantic tier: fields, trait
    /// declarations, or methods from multiple class owners make that tier
    /// unresolved instead of allowing traversal order to choose a target.
    pub(super) fn ordinary_class_member_declarations_for_owner(
        &self,
        scala: &ScalaAnalyzer,
        owner: &CodeUnit,
        member: &str,
        call_arities: Option<&[usize]>,
    ) -> BareMemberResolution {
        if !owner.is_class() {
            return BareMemberResolution::NoMatch;
        }
        self.ordinary_class_member_declarations_for_owners(
            scala,
            std::slice::from_ref(owner),
            member,
            call_arities,
        )
    }

    pub(super) fn ordinary_class_member_declarations_for_owners(
        &self,
        scala: &ScalaAnalyzer,
        direct_owners: &[CodeUnit],
        member: &str,
        call_arities: Option<&[usize]>,
    ) -> BareMemberResolution {
        let mut owners = direct_owners.to_vec();
        let mut seen = HashSet::default();
        while !owners.is_empty() {
            let mut matched = Vec::new();
            let mut declaring_owners = HashSet::default();
            let mut blocked = false;
            let mut next = Vec::new();
            for owner in owners {
                if !seen.insert(owner.clone()) {
                    continue;
                }
                if call_arities.is_none()
                    && self
                        .exact_nested_object(scala, &owner.fq_name(), member)
                        .is_some()
                {
                    blocked = true;
                }
                let members = self
                    .members_for_exact_owner_name(&owner.fq_name(), member)
                    .into_iter()
                    .filter(|unit| unit.source() == owner.source())
                    .collect::<Vec<_>>();
                if members
                    .iter()
                    .any(|member| self.member_blocks_callable_lookup(scala, member))
                {
                    blocked = true;
                }
                let methods = self.method_declarations_for_members(scala, &members, call_arities);
                if !methods.is_empty() {
                    if self.is_scala_trait_declaration(scala, &owner) {
                        if methods
                            .iter()
                            .any(|method| !self.is_abstract_scala_method(scala, method))
                        {
                            blocked = true;
                        }
                    } else if methods
                        .iter()
                        .any(|method| self.extension_method_for_unit(scala, method).is_some())
                    {
                        blocked = true;
                    } else {
                        declaring_owners.insert(owner.clone());
                        matched.extend(methods);
                    }
                }
                next.extend(self.direct_ancestors_for_declaration(scala, &owner));
            }
            if blocked || declaring_owners.len() > 1 {
                return BareMemberResolution::Unresolved;
            }
            if !matched.is_empty() {
                let mut unique = HashSet::default();
                matched.retain(|method| unique.insert(method.clone()));
                return BareMemberResolution::Resolved(matched);
            }
            owners = next;
        }
        BareMemberResolution::NoMatch
    }

    fn is_abstract_scala_method(&self, scala: &ScalaAnalyzer, method: &CodeUnit) -> bool {
        let ranges = self.declaration_ranges_for(scala, method);
        !ranges.is_empty()
            && ranges.iter().all(|range| {
                self.source_facts_for_file(scala, method.source())
                    .abstract_callable_ranges
                    .contains(&(range.start_byte, range.end_byte))
            })
    }

    fn member_blocks_callable_lookup(&self, scala: &ScalaAnalyzer, member: &CodeUnit) -> bool {
        member.is_field() && !scala.is_type_alias(member)
            || member.is_class() && self.type_is_stable_owner(scala, member)
    }

    pub(super) fn callable_parameter_function_arity(
        &self,
        scala: &ScalaAnalyzer,
        method: &CodeUnit,
        call_arities: &[usize],
        parameter_list: usize,
        parameter_index: usize,
    ) -> Option<usize> {
        let alternatives = self.callable_alternatives_for(scala, method);
        let mut resolved = None;
        for alternative in alternatives.iter().filter(|alternative| {
            callable_shape_matches(&alternative.shape, Some(call_arities), true)
        }) {
            let arity = alternative
                .parameter_function_arities
                .get(parameter_list)
                .and_then(|parameters| parameters.get(parameter_index))
                .copied()
                .flatten()?;
            if resolved.is_some_and(|resolved| resolved != arity) {
                return None;
            }
            resolved = Some(arity);
        }
        resolved
    }

    /// Resolve the callable selected for a receiver's static owner.
    ///
    /// Scala mixin linearization gives the rightmost parent and its ancestry
    /// precedence over parents to its left. Abstract inherited trait contracts
    /// remain a fallback only when the linearization supplies no concrete
    /// implementation.
    fn effective_method_declarations_for_owner(
        &self,
        scala: &ScalaAnalyzer,
        owner_fqn: &str,
        member: &str,
        call_arities: Option<&[usize]>,
    ) -> BareMemberResolution {
        let mut declarations = self
            .index
            .by_fqn(owner_fqn)
            .iter()
            .filter(|owner| owner.is_class());
        let Some(owner) = declarations.next() else {
            return BareMemberResolution::NoMatch;
        };
        if declarations.next().is_some() {
            return BareMemberResolution::Unresolved;
        }

        let root_owner = owner.clone();
        let mut abstract_trait_fallback = None;
        for owner in self.linearized_owners(scala, &root_owner) {
            if call_arities.is_none()
                && self
                    .exact_nested_object(scala, &owner.fq_name(), member)
                    .is_some()
            {
                return BareMemberResolution::Unresolved;
            }
            let members = self
                .members_for_exact_owner_name(&owner.fq_name(), member)
                .into_iter()
                .filter(|unit| unit.source() == owner.source())
                .collect::<Vec<_>>();
            if members
                .iter()
                .any(|member| self.member_blocks_callable_lookup(scala, member))
            {
                return BareMemberResolution::Unresolved;
            }
            let methods = self.method_declarations_for_members(scala, &members, call_arities);
            if !methods.is_empty() {
                let inherited_abstract_trait = owner != root_owner
                    && self.is_scala_trait_declaration(scala, &owner)
                    && methods
                        .iter()
                        .all(|method| self.is_abstract_scala_method(scala, method));
                if inherited_abstract_trait {
                    abstract_trait_fallback.get_or_insert(methods);
                } else {
                    return BareMemberResolution::Resolved(methods);
                }
            }
        }
        abstract_trait_fallback.map_or(
            BareMemberResolution::NoMatch,
            BareMemberResolution::Resolved,
        )
    }

    /// Compute Scala's duplicate-eliding parent linearization without Rust
    /// recursion. For `C extends L with R`, the parent suffix is
    /// `L(R) ⊕ L(L)`: identities repeated by the later/left linearization are
    /// removed from the earlier/right one before the lists are joined.
    fn linearized_owners(&self, scala: &ScalaAnalyzer, root: &CodeUnit) -> Vec<CodeUnit> {
        let mut completed = HashMap::<CodeUnit, Vec<CodeUnit>>::default();
        let mut visiting = HashSet::default();
        let mut stack = vec![(root.clone(), false)];

        while let Some((owner, expanded)) = stack.pop() {
            if completed.contains_key(&owner) {
                continue;
            }
            if expanded {
                visiting.remove(&owner);
                let mut suffix = Vec::new();
                for parent in self
                    .direct_ancestors_for_declaration(scala, &owner)
                    .into_iter()
                    .rev()
                {
                    let Some(parent_linearization) = completed.get(&parent) else {
                        // A missing entry denotes a cyclic edge that was not
                        // rescheduled while its owner was already active.
                        continue;
                    };
                    let parent_owners = parent_linearization.iter().collect::<HashSet<_>>();
                    suffix.retain(|existing| !parent_owners.contains(existing));
                    suffix.extend(parent_linearization.iter().cloned());
                }
                let mut linearization = Vec::with_capacity(1 + suffix.len());
                linearization.push(owner.clone());
                linearization.extend(suffix);
                completed.insert(owner, linearization);
                continue;
            }
            if !visiting.insert(owner.clone()) {
                continue;
            }
            stack.push((owner.clone(), true));
            for parent in self.direct_ancestors_for_declaration(scala, &owner) {
                if !completed.contains_key(&parent) && !visiting.contains(&parent) {
                    stack.push((parent, false));
                }
            }
        }

        completed.remove(root).unwrap_or_else(|| vec![root.clone()])
    }

    pub(crate) fn member_return_type(
        &self,
        scala: &ScalaAnalyzer,
        resolver: &NameResolver,
        member_fqn: &str,
    ) -> Option<String> {
        let mut resolved_return = None;
        let mut matched = false;
        for unit in self
            .index
            .by_fqn(member_fqn)
            .iter()
            .filter(|unit| unit.is_function())
        {
            let alternatives = self.callable_alternatives_for(scala, unit);
            if alternatives.is_empty() {
                let return_type = self
                    .facts
                    .fact_for_declaration(unit)
                    .and_then(|facts| facts.return_type_fqn.clone())?;
                if resolved_return
                    .as_ref()
                    .is_some_and(|resolved| resolved != &return_type)
                {
                    return None;
                }
                resolved_return = Some(return_type);
                matched = true;
                continue;
            }
            for alternative in alternatives.iter() {
                let return_type = alternative
                    .return_type
                    .as_deref()
                    .and_then(|return_type| self.resolve_type_text(resolver, return_type))?;
                if resolved_return
                    .as_ref()
                    .is_some_and(|resolved| resolved != &return_type)
                {
                    return None;
                }
                resolved_return = Some(return_type);
                matched = true;
            }
        }
        matched.then_some(resolved_return).flatten()
    }

    pub(super) fn member_return_type_for_owner_member(
        &self,
        scala: &ScalaAnalyzer,
        resolver: &NameResolver,
        owner_fqn: &str,
        member: &str,
        call_arities: Option<&[usize]>,
    ) -> Option<String> {
        let members = self.members_for_exact_owner_name(owner_fqn, member);
        self.member_return_type_for_members(scala, resolver, &members, call_arities)
    }

    fn member_return_type_for_members(
        &self,
        scala: &ScalaAnalyzer,
        resolver: &NameResolver,
        members: &[&CodeUnit],
        call_arities: Option<&[usize]>,
    ) -> Option<String> {
        let candidates = members
            .iter()
            .filter(|method| method.is_function())
            .filter_map(|method| {
                self.facts.fact_for_declaration(method).map(|facts| {
                    (
                        *method,
                        facts,
                        self.callable_alternatives_for(scala, method),
                    )
                })
            })
            .collect::<Vec<_>>();
        let callable_count = candidates
            .iter()
            .map(|(_, _, alternatives)| alternatives.len().max(1))
            .sum::<usize>();
        let unique_callable = callable_count == 1;
        let mut resolved_return = None;
        let mut matched = false;
        for (_, facts, alternatives) in candidates {
            if alternatives.is_empty() {
                if !method_call_shape_matches(facts, &[], call_arities, unique_callable) {
                    continue;
                }
                let return_type = facts.return_type_fqn.clone()?;
                if resolved_return
                    .as_ref()
                    .is_some_and(|resolved| resolved != &return_type)
                {
                    return None;
                }
                resolved_return = Some(return_type);
                matched = true;
                continue;
            }
            for alternative in alternatives.iter().filter(|alternative| {
                callable_shape_matches(&alternative.shape, call_arities, unique_callable)
            }) {
                let return_type = alternative
                    .return_type
                    .as_deref()
                    .and_then(|return_type| self.resolve_type_text(resolver, return_type))?;
                if resolved_return
                    .as_ref()
                    .is_some_and(|resolved| resolved != &return_type)
                {
                    return None;
                }
                resolved_return = Some(return_type);
                matched = true;
            }
        }
        matched.then_some(resolved_return).flatten()
    }

    pub(super) fn unqualified_member_return_type(
        &self,
        scala: &ScalaAnalyzer,
        resolver: &NameResolver,
        owner: &CodeUnit,
        member: &str,
        call_arities: Option<&[usize]>,
    ) -> MemberReturnResolution {
        if !owner.is_class() {
            return MemberReturnResolution::NoMatch;
        }
        self.unqualified_member_return_type_for_owners(
            scala,
            resolver,
            std::slice::from_ref(owner),
            member,
            call_arities,
        )
    }

    pub(super) fn unqualified_member_return_type_for_owners(
        &self,
        scala: &ScalaAnalyzer,
        resolver: &NameResolver,
        direct_owners: &[CodeUnit],
        member: &str,
        call_arities: Option<&[usize]>,
    ) -> MemberReturnResolution {
        let mut level = direct_owners.to_vec();

        let mut seen = HashSet::default();
        let mut saw_member = false;
        while !level.is_empty() {
            let mut matched_return = None;
            let mut matched = false;
            let mut next = Vec::new();
            for owner in level {
                if !seen.insert(owner.clone()) {
                    continue;
                }
                let owner_fqn = owner.fq_name();
                if call_arities.is_none()
                    && self
                        .exact_nested_object(scala, &owner_fqn, member)
                        .is_some()
                {
                    return MemberReturnResolution::Unresolved;
                }
                let members = self
                    .members_for_exact_owner_name(&owner_fqn, member)
                    .into_iter()
                    .filter(|unit| unit.source() == owner.source())
                    .collect::<Vec<_>>();
                saw_member |= !members.is_empty();
                if members
                    .iter()
                    .any(|unit| self.member_blocks_callable_lookup(scala, unit))
                {
                    return MemberReturnResolution::Unresolved;
                }
                if !self
                    .method_declarations_for_members(scala, &members, call_arities)
                    .is_empty()
                {
                    matched = true;
                    let Some(return_type) = self.member_return_type_for_members(
                        scala,
                        resolver,
                        &members,
                        call_arities,
                    ) else {
                        return MemberReturnResolution::Unresolved;
                    };
                    if matched_return
                        .as_ref()
                        .is_some_and(|resolved| resolved != &return_type)
                    {
                        return MemberReturnResolution::Unresolved;
                    }
                    matched_return = Some(return_type);
                }
                next.extend(self.direct_ancestors_for_declaration(scala, &owner));
            }
            if matched {
                return matched_return
                    .map(MemberReturnResolution::Resolved)
                    .unwrap_or(MemberReturnResolution::Unresolved);
            }
            level = next;
        }
        if saw_member {
            MemberReturnResolution::Unresolved
        } else {
            MemberReturnResolution::NoMatch
        }
    }

    fn members_for_exact_owner_name<'a>(&'a self, owner: &str, member: &str) -> Vec<&'a CodeUnit> {
        let mut members =
            self.index
                .members_for_owner_name(owner, &scala_normalized_fq_name(owner), member);
        if self.index.fqn_exists(owner) {
            members.retain(|unit| owner_fqn(unit).as_deref() == Some(owner));
        }
        members
    }

    fn package_types_in(&self, package: &str) -> PackageTypeEntries {
        if let Some(types) = self
            .package_types_by_package
            .lock()
            .expect("package type cache poisoned")
            .get(package)
            .cloned()
        {
            return types;
        }
        let mut values = Vec::new();
        for ((candidate_package, simple), units) in self.index.package_types() {
            if candidate_package != package {
                continue;
            }
            let package_level = units
                .iter()
                .filter(|unit| unit.is_class() && is_package_level_type(unit))
                .collect::<Vec<_>>();
            let ordinary = package_level
                .iter()
                .copied()
                .filter(|unit| !unit.short_name().ends_with('$'))
                .collect::<Vec<_>>();
            let selected = if ordinary.is_empty() {
                package_level
            } else {
                ordinary
            };
            for unit in selected {
                values.push((simple.clone(), unit.clone()));
            }
        }
        let values = Arc::new(values);
        self.package_types_by_package
            .lock()
            .expect("package type cache poisoned")
            .insert(package.to_string(), values.clone());
        values
    }

    fn type_by_normalized_fqn(&self, normalized_fqn: &str) -> Option<&CodeUnit> {
        preferred_scala_type(
            self.index
                .by_normalized_fqn(normalized_fqn)
                .iter()
                .filter(|unit| unit.is_class()),
        )
    }

    fn object_by_normalized_fqn(
        &self,
        scala: &ScalaAnalyzer,
        normalized_fqn: &str,
    ) -> Option<&CodeUnit> {
        let units = self.index.by_normalized_fqn(normalized_fqn);
        units
            .iter()
            .find(|unit| unit.is_class() && unit.short_name().ends_with('$'))
            .or_else(|| {
                preferred_scala_type(
                    units
                        .iter()
                        .filter(|unit| unit.is_class())
                        .filter(|unit| self.type_accepts_object_roles(scala, unit)),
                )
            })
    }

    fn unique_type_by_normalized_fqn(&self, normalized_fqn: &str) -> Option<&CodeUnit> {
        let classes = self
            .index
            .by_normalized_fqn(normalized_fqn)
            .iter()
            .filter(|unit| unit.is_class())
            .collect::<Vec<_>>();
        let ordinary = classes
            .iter()
            .copied()
            .filter(|unit| !unit.short_name().ends_with('$'))
            .collect::<Vec<_>>();
        let selected = if ordinary.is_empty() {
            classes
        } else {
            ordinary
        };
        let [resolved] = selected.as_slice() else {
            return None;
        };
        Some(*resolved)
    }

    fn unique_object_by_normalized_fqn(
        &self,
        scala: &ScalaAnalyzer,
        normalized_fqn: &str,
    ) -> Option<&CodeUnit> {
        let units = self.index.by_normalized_fqn(normalized_fqn);
        let explicit = units
            .iter()
            .filter(|unit| unit.is_class() && unit.short_name().ends_with('$'))
            .collect::<Vec<_>>();
        if let [resolved] = explicit.as_slice() {
            return Some(*resolved);
        }
        if !explicit.is_empty() {
            return None;
        }
        let accepting = units
            .iter()
            .filter(|unit| unit.is_class() && self.type_accepts_object_roles(scala, unit))
            .collect::<Vec<_>>();
        let [resolved] = accepting.as_slice() else {
            return None;
        };
        Some(*resolved)
    }

    fn explicit_import_tier(
        &self,
        path: &str,
        package_prefixes: &[String],
    ) -> Option<ScalaExplicitImportTier> {
        resolve_scala_explicit_import_tier(path, package_prefixes, |candidate| {
            let normalized = scala_normalized_fq_name(candidate);
            ScalaExplicitImportFacts {
                declaration: !self.index.by_normalized_fqn(&normalized).is_empty(),
                package: self.index.package_exists(&normalized),
            }
        })
    }

    fn explicit_import_class_declarations(
        &self,
        candidate: &str,
    ) -> (Vec<CodeUnit>, Vec<CodeUnit>) {
        let normalized = scala_normalized_fq_name(candidate);
        let classes = self
            .index
            .by_normalized_fqn(&normalized)
            .iter()
            .filter(|unit| unit.is_class())
            .collect::<Vec<_>>();
        let ordinary = classes
            .iter()
            .copied()
            .filter(|unit| !unit.short_name().ends_with('$'))
            .cloned()
            .collect::<Vec<_>>();
        let type_declarations = if ordinary.is_empty() {
            classes.iter().map(|unit| (*unit).clone()).collect()
        } else {
            ordinary
        };
        let object_declarations = classes
            .iter()
            .copied()
            .filter(|unit| unit.short_name().ends_with('$'))
            .cloned()
            .collect::<Vec<_>>();
        (type_declarations, object_declarations)
    }

    pub(super) fn exact_nested_object(
        &self,
        scala: &ScalaAnalyzer,
        owner_fqn: &str,
        member: &str,
    ) -> Option<String> {
        let candidate = format!("{owner_fqn}.{member}$");
        let mut matches = self
            .index
            .by_fqn(&candidate)
            .iter()
            .filter(|unit| unit.is_class() && self.type_accepts_object_roles(scala, unit));
        let resolved = matches.next()?.fq_name();
        matches.next().is_none().then_some(resolved)
    }

    pub(super) fn exact_nested_type(&self, owner_fqn: &str, member: &str) -> Option<String> {
        let candidate = format!("{owner_fqn}.{member}");
        let mut matches = self
            .index
            .by_fqn(&candidate)
            .iter()
            .filter(|unit| unit.is_class());
        let resolved = matches.next()?.fq_name();
        matches.next().is_none().then_some(resolved)
    }

    fn resolve_type_text(&self, resolver: &NameResolver, type_text: &str) -> Option<String> {
        resolver
            .resolve(type_text)
            .or_else(|| {
                self.type_by_normalized_fqn(&scala_normalized_fq_name(type_text))
                    .map(CodeUnit::fq_name)
            })
            .or_else(|| scala_builtin_type_name(type_text).map(str::to_string))
    }

    pub(crate) fn resolve_type_in_declaration_context(
        &self,
        resolver: &NameResolver,
        segments: &[String],
    ) -> Option<String> {
        let (first, rest) = segments.split_first()?;
        if rest.is_empty() {
            return resolver
                .resolve(first)
                .or_else(|| scala_builtin_type_name(first).map(str::to_string));
        }

        let mut resolved_roots = HashSet::default();
        resolved_roots.extend(resolver.resolve(first));
        resolved_roots.extend(resolver.resolve_object(first));
        if !resolved_roots.is_empty() {
            let mut candidates = resolved_roots;
            for segment in rest {
                let mut nested_candidates = HashSet::default();
                for owner in candidates {
                    let candidate = format!("{owner}.{segment}");
                    if let Some(nested) = preferred_scala_type(
                        self.index
                            .by_fqn(&candidate)
                            .iter()
                            .filter(|unit| unit.is_class()),
                    ) {
                        nested_candidates.insert(nested.fq_name());
                        continue;
                    }
                    let object_candidate = format!("{candidate}$");
                    if let Some(nested) = preferred_scala_type(
                        self.index
                            .by_fqn(&object_candidate)
                            .iter()
                            .filter(|unit| unit.is_class()),
                    ) {
                        nested_candidates.insert(nested.fq_name());
                    }
                }
                if nested_candidates.is_empty() {
                    return None;
                }
                candidates = nested_candidates;
            }
            return (candidates.len() == 1)
                .then(|| candidates.into_iter().next())
                .flatten();
        }

        if let Some(package) = resolver.resolve_package(self, first) {
            let qualified = std::iter::once(package.as_str())
                .chain(rest.iter().map(String::as_str))
                .collect::<Vec<_>>()
                .join(".");
            return self
                .unique_type_by_normalized_fqn(&scala_normalized_fq_name(&qualified))
                .map(CodeUnit::fq_name);
        }

        if resolver.has_type_or_object_or_package_binding(first)
            || !self.has_package_prefix(segments)
        {
            return None;
        }
        let qualified = segments.join(".");
        self.unique_type_by_normalized_fqn(&scala_normalized_fq_name(&qualified))
            .map(CodeUnit::fq_name)
    }

    pub(super) fn resolve_qualified_stable_type_at(
        &self,
        scala: &ScalaAnalyzer,
        resolver: &NameResolver,
        segments: &[String],
        terminal_object: bool,
        lexical_root: Option<String>,
    ) -> Option<String> {
        let (first, rest) = segments.split_first()?;
        if rest.is_empty() {
            return if terminal_object {
                resolver.resolve_object(first)
            } else {
                resolver.resolve(first)
            };
        }

        if let Some(mut owner) = lexical_root.or_else(|| resolver.resolve_stable_object_root(first))
        {
            for segment in &rest[..rest.len() - 1] {
                owner = self.exact_nested_object(scala, &owner, segment)?;
            }
            let terminal = rest.last()?;
            if terminal_object {
                return self.exact_nested_object(scala, &owner, terminal);
            }
            return self.exact_nested_type(&owner, terminal);
        }

        if let Some(package) = resolver.resolve_package(self, first) {
            let qualified = std::iter::once(package.as_str())
                .chain(rest.iter().map(String::as_str))
                .collect::<Vec<_>>()
                .join(".");
            let normalized = scala_normalized_fq_name(&qualified);
            return if terminal_object {
                self.unique_object_by_normalized_fqn(scala, &normalized)
                    .map(CodeUnit::fq_name)
            } else {
                self.unique_type_by_normalized_fqn(&normalized)
                    .map(CodeUnit::fq_name)
            };
        }

        if resolver.has_type_or_object_or_package_binding(first)
            || !self.has_package_prefix(segments)
        {
            return None;
        }
        let normalized = scala_normalized_fq_name(&segments.join("."));
        if terminal_object {
            return self
                .object_by_normalized_fqn(scala, &normalized)
                .map(CodeUnit::fq_name);
        }
        self.type_by_normalized_fqn(&normalized)
            .map(CodeUnit::fq_name)
    }

    fn resolve_type_in_callable_declaration_context(
        &self,
        scala: &ScalaAnalyzer,
        resolver: &NameResolver,
        declaration: &CodeUnit,
        segments: &[String],
    ) -> Option<String> {
        let (first, rest) = segments.split_first()?;
        let mut scope = scala
            .structural_parent_of(declaration)
            .or_else(|| scala.parent_of(declaration));
        let mut seen = HashSet::default();
        while let Some(owner) = scope {
            if !seen.insert(owner.clone()) {
                break;
            }
            let lexical_root = (owner.is_class() && scala_simple_type_name(&owner) == *first)
                .then(|| {
                    self.type_by_normalized_fqn(&scala_normalized_fq_name(&owner.fq_name()))
                        .map(CodeUnit::fq_name)
                })
                .flatten()
                .or_else(|| self.exact_nested_type(&owner.fq_name(), first));
            if let Some(mut resolved) = lexical_root {
                let mut complete = true;
                for segment in rest {
                    let candidate = format!("{resolved}.{segment}");
                    let Some(nested) = preferred_scala_type(
                        self.index
                            .by_fqn(&candidate)
                            .iter()
                            .filter(|unit| unit.is_class()),
                    ) else {
                        complete = false;
                        break;
                    };
                    resolved = nested.fq_name();
                }
                if complete {
                    return Some(resolved);
                }
            }
            scope = scala
                .structural_parent_of(&owner)
                .or_else(|| scala.parent_of(&owner));
        }
        self.resolve_type_in_declaration_context(resolver, segments)
    }

    fn resolve_type_in_owner_context(
        &self,
        resolver: &NameResolver,
        segments: &[String],
        owner: &CodeUnit,
        state: &FileState,
        parent_by_child: &HashMap<&CodeUnit, &CodeUnit>,
    ) -> Option<String> {
        let (first, rest) = segments.split_first()?;
        let mut scope = parent_by_child.get(owner).copied();
        while let Some(parent) = scope {
            let lexical = state
                .children
                .get(parent)
                .into_iter()
                .flatten()
                .filter(|unit| unit.is_class() && scala_simple_type_name(unit) == *first)
                .collect::<Vec<_>>();
            if !lexical.is_empty() {
                let ordinary = lexical
                    .iter()
                    .copied()
                    .filter(|unit| !unit.short_name().ends_with('$'))
                    .map(CodeUnit::fq_name)
                    .collect::<HashSet<_>>();
                let candidates = if ordinary.is_empty() {
                    lexical.into_iter().map(CodeUnit::fq_name).collect()
                } else {
                    ordinary
                };
                return (candidates.len() == 1)
                    .then(|| self.resolve_nested_type_segments(candidates, rest))
                    .flatten();
            }
            scope = parent_by_child.get(parent).copied();
        }
        if resolver.has_type_or_object_binding(first) {
            return self.resolve_type_in_declaration_context(resolver, segments);
        }
        if let Some(relative) = self.resolve_package_relative_type(&state.package_name, segments) {
            return Some(relative);
        }
        self.resolve_type_in_declaration_context(resolver, segments)
    }

    fn resolve_package_relative_type(
        &self,
        package_name: &str,
        segments: &[String],
    ) -> Option<String> {
        if package_name.is_empty() || segments.is_empty() {
            return None;
        }
        let normalized =
            scala_normalized_fq_name(&format!("{package_name}.{}", segments.join(".")));
        let candidates = self
            .index
            .by_normalized_fqn(&normalized)
            .iter()
            .filter(|unit| unit.is_class())
            .collect::<Vec<_>>();
        let ordinary = candidates
            .iter()
            .copied()
            .filter(|unit| !unit.short_name().ends_with('$'))
            .collect::<Vec<_>>();
        let preferred = if ordinary.is_empty() {
            candidates
        } else {
            ordinary
        };
        (preferred.len() == 1).then(|| preferred[0].fq_name())
    }

    fn resolve_nested_type_segments(
        &self,
        mut candidates: HashSet<String>,
        segments: &[String],
    ) -> Option<String> {
        for segment in segments {
            let mut nested_candidates = HashSet::default();
            for owner in candidates {
                for candidate in [format!("{owner}.{segment}"), format!("{owner}.{segment}$")] {
                    nested_candidates.extend(
                        self.index
                            .by_fqn(&candidate)
                            .iter()
                            .filter(|unit| unit.is_class())
                            .map(CodeUnit::fq_name),
                    );
                }
            }
            if nested_candidates.is_empty() {
                return None;
            }
            candidates = nested_candidates;
        }
        (candidates.len() == 1)
            .then(|| candidates.into_iter().next())
            .flatten()
    }

    fn has_package_prefix(&self, segments: &[String]) -> bool {
        (1..segments.len()).any(|end| self.index.package_exists(&segments[..end].join(".")))
    }

    fn package_objects_in(&self, scala: &ScalaAnalyzer, package: &str) -> PackageTypeEntries {
        if let Some(objects) = self
            .package_objects_by_package
            .lock()
            .expect("package object cache poisoned")
            .get(package)
            .cloned()
        {
            return objects;
        }

        let mut values = Vec::new();
        for ((candidate_package, simple), units) in self.index.package_types() {
            if candidate_package != package {
                continue;
            }
            let exact = units
                .iter()
                .filter(|unit| {
                    unit.is_class()
                        && is_package_level_type(unit)
                        && unit.short_name().ends_with('$')
                })
                .collect::<Vec<_>>();
            if !exact.is_empty() {
                for unit in exact {
                    values.push((simple.clone(), unit.clone()));
                }
                continue;
            }
            for unit in units.iter().filter(|unit| {
                unit.is_class()
                    && is_package_level_type(unit)
                    && self.type_accepts_object_roles(scala, unit)
            }) {
                values.push((simple.clone(), unit.clone()));
            }
        }
        let values = Arc::new(values);
        self.package_objects_by_package
            .lock()
            .expect("package object cache poisoned")
            .insert(package.to_string(), values.clone());
        values
    }

    fn nested_types_in(&self, scala: &ScalaAnalyzer, normalized_owner: &str) -> PackageTypeEntries {
        if let Some(types) = self
            .nested_types_by_owner
            .lock()
            .expect("nested Scala type cache poisoned")
            .get(normalized_owner)
            .cloned()
        {
            return types;
        }
        let mut grouped: HashMap<String, Vec<CodeUnit>> = HashMap::default();
        for owner in self
            .index
            .by_normalized_fqn(normalized_owner)
            .iter()
            .filter(|unit| unit.is_class() && self.type_is_stable_owner(scala, unit))
        {
            for unit in self
                .index
                .fqn_direct_children(&owner.fq_name())
                .into_iter()
                .filter(|unit| unit.is_class())
            {
                grouped
                    .entry(scala_simple_type_name(&unit))
                    .or_default()
                    .push(unit);
            }
        }
        let mut values = Vec::new();
        for (simple, units) in grouped {
            let ordinary = units
                .iter()
                .filter(|unit| !unit.short_name().ends_with('$'))
                .collect::<Vec<_>>();
            let selected = if ordinary.is_empty() {
                units.iter().collect::<Vec<_>>()
            } else {
                ordinary
            };
            values.extend(
                selected
                    .into_iter()
                    .map(|unit| (simple.clone(), unit.clone())),
            );
        }
        let values = Arc::new(values);
        self.nested_types_by_owner
            .lock()
            .expect("nested Scala type cache poisoned")
            .insert(normalized_owner.to_string(), values.clone());
        values
    }

    fn nested_objects_in(
        &self,
        scala: &ScalaAnalyzer,
        normalized_owner: &str,
    ) -> PackageTypeEntries {
        if let Some(types) = self
            .nested_objects_by_owner
            .lock()
            .expect("nested Scala object cache poisoned")
            .get(normalized_owner)
            .cloned()
        {
            return types;
        }
        let mut values = Vec::new();
        for owner in self
            .index
            .by_normalized_fqn(normalized_owner)
            .iter()
            .filter(|unit| unit.is_class() && self.type_is_stable_owner(scala, unit))
        {
            for unit in self
                .index
                .fqn_direct_children(&owner.fq_name())
                .into_iter()
                .filter(|unit| unit.is_class() && self.type_accepts_object_roles(scala, unit))
            {
                values.push((scala_simple_type_name(&unit), unit));
            }
        }
        let values = Arc::new(values);
        self.nested_objects_by_owner
            .lock()
            .expect("nested Scala object cache poisoned")
            .insert(normalized_owner.to_string(), values.clone());
        values
    }

    fn member_by_normalized_fqn(&self, normalized_fqn: &str) -> Option<&CodeUnit> {
        self.index
            .by_normalized_fqn(normalized_fqn)
            .iter()
            .find(|unit| unit.is_function() || unit.is_field())
    }

    fn exact_field(&self, scala: &ScalaAnalyzer, owner_fqn: &str, member: &str) -> Option<String> {
        let field_fqn = format!("{owner_fqn}.{member}");
        let fields = self
            .index
            .by_fqn(&field_fqn)
            .iter()
            .filter(|unit| unit.is_field() && !scala.is_type_alias(unit))
            .collect::<Vec<_>>();
        (fields.len() == 1).then(|| fields[0].fq_name())
    }

    pub(super) fn constructor_call_shape_matches(
        &self,
        scala: &ScalaAnalyzer,
        type_fqn: &str,
        call_arities: Option<&[usize]>,
    ) -> bool {
        let Some(call_arities) = call_arities else {
            return false;
        };
        let Some(target) = self.type_by_normalized_fqn(&scala_normalized_fq_name(type_fqn)) else {
            return false;
        };
        self.constructor_target_call_shape_matches(scala, target, Some(call_arities))
    }

    pub(super) fn constructor_target_call_shape_matches(
        &self,
        scala: &ScalaAnalyzer,
        target: &CodeUnit,
        call_arities: Option<&[usize]>,
    ) -> bool {
        let Some(call_arities) = call_arities else {
            return false;
        };
        let alternatives = self.callable_alternatives_for(scala, target);
        if alternatives.is_empty() {
            return callable_shape_matches(
                &[ScalaCallableParameterList::explicit(CallableArity::exact(
                    0,
                ))],
                Some(call_arities),
                false,
            );
        }
        alternatives.iter().any(|alternative| {
            callable_shape_matches(&alternative.shape, Some(call_arities), false)
        })
    }

    pub(super) fn callable_alternatives_for(
        &self,
        scala: &ScalaAnalyzer,
        target: &CodeUnit,
    ) -> CachedCallableAlternatives {
        let cell = self
            .callable_alternatives_by_unit
            .lock()
            .expect("Scala callable-alternative cache poisoned")
            .entry(target.clone())
            .or_insert_with(|| Arc::new(OnceLock::new()))
            .clone();
        cell.get_or_init(|| {
            let source_facts = self.source_facts_for_file(scala, target.source());
            let declaration_resolver = NameResolver::for_file_types(scala, target, self);
            let ranges = self.declaration_ranges_for(scala, target);
            let mut exact = ranges
                .iter()
                .filter_map(|range| {
                    source_facts
                        .callable_alternatives_by_range
                        .get(&(range.start_byte, range.end_byte))
                        .map(|facts| CallableAlternative {
                            shape: facts.shape.clone(),
                            parameter_function_arities: facts.parameter_function_arities.clone(),
                            extension_receiver_type: facts
                                .extension_receiver_type_path
                                .as_deref()
                                .and_then(|segments| {
                                    self.resolve_type_in_callable_declaration_context(
                                        scala,
                                        &declaration_resolver,
                                        target,
                                        segments,
                                    )
                                }),
                            return_type: facts.return_type_path.as_deref().and_then(|segments| {
                                self.resolve_type_in_callable_declaration_context(
                                    scala,
                                    &declaration_resolver,
                                    target,
                                    segments,
                                )
                            }),
                        })
                })
                .collect::<Vec<_>>();
            if let Some(case_class) = self.exact_case_class_for_companion_apply(scala, target) {
                for constructor in self.callable_alternatives_for(scala, &case_class).iter() {
                    if exact
                        .iter()
                        .any(|alternative| alternative.shape == constructor.shape)
                    {
                        continue;
                    }
                    let mut synthetic = constructor.clone();
                    synthetic.extension_receiver_type = None;
                    synthetic.return_type = Some(case_class.fq_name());
                    exact.push(synthetic);
                }
            }
            if !exact.is_empty() {
                return Arc::new(exact);
            }
            let mut fallback = self
                .signature_metadata_for(scala, target)
                .into_iter()
                .filter_map(|metadata| {
                    metadata.callable_arity().map(|arity| CallableAlternative {
                        shape: vec![ScalaCallableParameterList::explicit(arity)],
                        parameter_function_arities: Vec::new(),
                        extension_receiver_type: None,
                        return_type: None,
                    })
                })
                .collect::<Vec<_>>();
            if fallback.is_empty()
                && let Some(arity) = self.facts.fact_for_declaration(target).and_then(|facts| {
                    facts
                        .callable_arity
                        .or_else(|| facts.arity.map(CallableArity::exact))
                })
            {
                fallback.push(CallableAlternative {
                    shape: vec![ScalaCallableParameterList::explicit(arity)],
                    parameter_function_arities: Vec::new(),
                    extension_receiver_type: None,
                    return_type: self
                        .facts
                        .fact_for_declaration(target)
                        .and_then(|facts| facts.return_type_fqn.clone()),
                });
            }
            Arc::new(fallback)
        })
        .clone()
    }

    fn exact_case_class_for_companion_apply(
        &self,
        scala: &ScalaAnalyzer,
        target: &CodeUnit,
    ) -> Option<CodeUnit> {
        if !target.is_function() || target.short_name().rsplit('.').next() != Some("apply") {
            return None;
        }
        let companion = scala.structural_parent_of(target)?;
        if !companion.is_class() || !companion.short_name().ends_with('$') {
            return None;
        }
        let structural_parent = scala.structural_parent_of(&companion);
        let mut candidates = self
            .index
            .by_normalized_fqn(&scala_normalized_fq_name(&companion.fq_name()))
            .iter()
            .filter(|candidate| {
                candidate.is_class()
                    && !candidate.short_name().ends_with('$')
                    && candidate.source() == companion.source()
                    && scala.structural_parent_of(candidate) == structural_parent
                    && self.is_case_class(scala, candidate)
            });
        let candidate = candidates.next()?.clone();
        candidates.next().is_none().then_some(candidate)
    }

    pub(super) fn type_accepts_object_roles(
        &self,
        scala: &ScalaAnalyzer,
        target: &CodeUnit,
    ) -> bool {
        if self.type_is_stable_owner(scala, target) {
            return true;
        }
        let source_facts = self.source_facts_for_file(scala, target.source());
        self.declaration_ranges_for(scala, target)
            .iter()
            .any(|range| {
                source_facts
                    .case_class_ranges
                    .contains(&(range.start_byte, range.end_byte))
            })
    }

    pub(super) fn type_is_stable_owner(&self, scala: &ScalaAnalyzer, target: &CodeUnit) -> bool {
        if target.short_name().ends_with('$') {
            return true;
        }
        let source_facts = self.source_facts_for_file(scala, target.source());
        self.declaration_ranges_for(scala, target)
            .iter()
            .any(|range| {
                source_facts
                    .stable_owner_ranges
                    .contains(&(range.start_byte, range.end_byte))
            })
    }

    pub(super) fn exact_companion_objects(
        &self,
        scala: &ScalaAnalyzer,
        target: &CodeUnit,
    ) -> Vec<CodeUnit> {
        let target_parent = scala.structural_parent_of(target);
        self.index
            .by_normalized_fqn(&scala_normalized_fq_name(&target.fq_name()))
            .iter()
            .filter(|candidate| {
                candidate.is_class()
                    && *candidate != target
                    && candidate.source() == target.source()
                    && candidate.short_name().ends_with('$')
                    && scala.structural_parent_of(candidate) == target_parent
            })
            .cloned()
            .collect()
    }

    pub(super) fn class_accepts_extractor_role(
        &self,
        scala: &ScalaAnalyzer,
        target: &CodeUnit,
    ) -> bool {
        self.is_case_class(scala, target)
            || self
                .exact_companion_objects(scala, target)
                .iter()
                .any(|companion| {
                    ["unapply", "unapplySeq"].iter().any(|member| {
                        self.members_for_exact_owner_name(&companion.fq_name(), member)
                            .iter()
                            .any(|unit| unit.is_function())
                    })
                })
    }

    pub(super) fn class_application_matches(
        &self,
        scala: &ScalaAnalyzer,
        resolver: &NameResolver,
        target: &CodeUnit,
        call_arities: Option<&[usize]>,
    ) -> bool {
        if self.class_companion_apply_call_matches(scala, resolver, target, call_arities) {
            return true;
        }
        if self
            .exact_companion_objects(scala, target)
            .iter()
            .any(|companion| {
                !self
                    .method_declarations_for_owner_member(
                        scala,
                        &companion.fq_name(),
                        "apply",
                        call_arities,
                    )
                    .is_empty()
            })
        {
            return false;
        }
        self.constructor_call_shape_matches(scala, &target.fq_name(), call_arities)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn resolve_type_application(
        &self,
        scala: &ScalaAnalyzer,
        resolver: &NameResolver,
        class_fqn: Option<&str>,
        object_fqn: Option<&str>,
        name: &str,
        call_arities: Option<&[usize]>,
        role: TypeApplicationRole,
    ) -> TypeApplicationResolution {
        let type_candidates = class_fqn
            .map(|fqn| {
                self.index
                    .by_fqn(fqn)
                    .iter()
                    .filter(|unit| unit.is_class() && !unit.short_name().ends_with('$'))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let type_target = (type_candidates.len() == 1).then(|| type_candidates[0].clone());
        if role == TypeApplicationRole::Extractor {
            let extractor_owners = if !type_candidates.is_empty() {
                type_candidates
                    .iter()
                    .flat_map(|target| self.exact_companion_objects(scala, target))
                    .map(|companion| companion.fq_name())
                    .collect::<Vec<_>>()
            } else {
                object_fqn.into_iter().map(str::to_string).collect()
            };
            let mut callable_targets = extractor_owners
                .iter()
                .flat_map(|companion| {
                    ["unapply", "unapplySeq"]
                        .into_iter()
                        .flat_map(move |member| {
                            self.method_declarations_for_owner_member(
                                scala, companion, member, None,
                            )
                        })
                })
                .collect::<Vec<_>>();
            for target in &type_candidates {
                callable_targets.extend(
                    self.method_declarations_for_owner_member(
                        scala,
                        &target.fq_name(),
                        name,
                        call_arities,
                    )
                    .into_iter()
                    .filter(CodeUnit::is_synthetic),
                );
            }
            let mut seen = HashSet::default();
            callable_targets.retain(|target| seen.insert(target.clone()));
            return TypeApplicationResolution {
                type_target: type_target
                    .filter(|target| self.class_accepts_extractor_role(scala, target)),
                callable_targets,
            };
        }

        if role == TypeApplicationRole::ExplicitConstructor {
            let callable_targets = type_candidates
                .iter()
                .flat_map(|target| {
                    self.method_declarations_for_owner_member(
                        scala,
                        &target.fq_name(),
                        name,
                        call_arities,
                    )
                })
                .filter(CodeUnit::is_synthetic)
                .collect();
            let type_target = type_target.filter(|target| {
                self.is_scala_trait_declaration(scala, target)
                    || self.constructor_target_call_shape_matches(scala, target, call_arities)
            });
            return TypeApplicationResolution {
                type_target,
                callable_targets,
            };
        }

        let apply_owners = if !type_candidates.is_empty() {
            type_candidates
                .iter()
                .flat_map(|target| self.exact_companion_objects(scala, target))
                .map(|companion| companion.fq_name())
                .collect::<Vec<_>>()
        } else {
            object_fqn.into_iter().map(str::to_string).collect()
        };
        let mut apply_targets = apply_owners
            .iter()
            .flat_map(|owner| {
                self.method_declarations_for_owner_member(scala, owner, "apply", call_arities)
            })
            .collect::<Vec<_>>();
        if !apply_targets.is_empty() {
            for target in type_candidates.iter().filter(|target| {
                self.is_case_class(scala, target)
                    || owner_fqn(target).is_some_and(|owner| owner.ends_with('$'))
            }) {
                apply_targets.extend(
                    self.method_declarations_for_owner_member(
                        scala,
                        &target.fq_name(),
                        name,
                        call_arities,
                    )
                    .into_iter()
                    .filter(CodeUnit::is_synthetic),
                );
            }
            if !type_candidates.is_empty() {
                let mut seen = HashSet::default();
                apply_targets.retain(|target| seen.insert(target.clone()));
            }
            return TypeApplicationResolution {
                type_target: type_target.filter(|target| {
                    self.class_application_matches(scala, resolver, target, call_arities)
                }),
                callable_targets: apply_targets,
            };
        }

        let callable_targets = type_candidates
            .iter()
            .flat_map(|target| {
                self.method_declarations_for_owner_member(
                    scala,
                    &target.fq_name(),
                    name,
                    call_arities,
                )
            })
            .filter(CodeUnit::is_synthetic)
            .collect();
        TypeApplicationResolution {
            type_target: type_target.filter(|target| {
                self.class_application_matches(scala, resolver, target, call_arities)
            }),
            callable_targets,
        }
    }

    pub(super) fn class_accepts_apply_role(
        &self,
        scala: &ScalaAnalyzer,
        target: &CodeUnit,
    ) -> bool {
        self.is_case_class(scala, target)
            || self
                .exact_companion_objects(scala, target)
                .iter()
                .any(|companion| {
                    self.members_for_exact_owner_name(&companion.fq_name(), "apply")
                        .iter()
                        .any(|unit| unit.is_function())
                })
    }

    pub(super) fn class_companion_apply_call_matches(
        &self,
        scala: &ScalaAnalyzer,
        resolver: &NameResolver,
        target: &CodeUnit,
        call_arities: Option<&[usize]>,
    ) -> bool {
        if self.is_case_class(scala, target)
            && self.constructor_call_shape_matches(scala, &target.fq_name(), call_arities)
        {
            return true;
        }
        self.exact_companion_objects(scala, target)
            .iter()
            .any(|companion| {
                self.member_return_type_for_owner_member(
                    scala,
                    resolver,
                    &companion.fq_name(),
                    "apply",
                    call_arities,
                )
                .is_some_and(|return_type| {
                    scala_normalized_fq_name(&return_type)
                        == scala_normalized_fq_name(&target.fq_name())
                })
            })
    }

    pub(super) fn class_companion_apply_method_value_matches(
        &self,
        scala: &ScalaAnalyzer,
        target: &CodeUnit,
        contextual_arities: Option<&[usize]>,
    ) -> bool {
        let mut alternatives = Vec::new();
        if self.is_case_class(scala, target) {
            alternatives.extend(
                self.callable_alternatives_for(scala, target)
                    .iter()
                    .cloned(),
            );
        }
        let normalized_target = scala_normalized_fq_name(&target.fq_name());
        for companion in self.exact_companion_objects(scala, target) {
            for apply in self
                .members_for_exact_owner_name(&companion.fq_name(), "apply")
                .iter()
                .filter(|unit| unit.is_function())
            {
                alternatives.extend(
                    self.callable_alternatives_for(scala, apply)
                        .iter()
                        .filter(|alternative| {
                            alternative
                                .return_type
                                .as_deref()
                                .is_some_and(|return_type| {
                                    scala_normalized_fq_name(return_type) == normalized_target
                                })
                        })
                        .cloned(),
                );
            }
        }
        let matches = alternatives
            .iter()
            .filter(|alternative| {
                contextual_arities.is_none_or(|arities| {
                    callable_shape_matches(&alternative.shape, Some(arities), false)
                })
            })
            .count();
        matches == 1
    }

    fn unique_companion_apply_method_value_target(
        &self,
        scala: &ScalaAnalyzer,
        resolver: &NameResolver,
        name: &str,
        contextual_arities: Option<&[usize]>,
    ) -> Option<CodeUnit> {
        let fqn = resolver.resolve(name)?;
        let mut targets = self
            .index
            .by_fqn(&fqn)
            .iter()
            .filter(|unit| unit.is_class() && !unit.short_name().ends_with('$'));
        let target = targets.next()?.clone();
        if targets.next().is_some()
            || !self.class_companion_apply_method_value_matches(scala, &target, contextual_arities)
        {
            return None;
        }
        Some(target)
    }

    fn is_case_class(&self, scala: &ScalaAnalyzer, target: &CodeUnit) -> bool {
        let source_facts = self.source_facts_for_file(scala, target.source());
        self.declaration_ranges_for(scala, target)
            .iter()
            .any(|range| {
                source_facts
                    .case_class_ranges
                    .contains(&(range.start_byte, range.end_byte))
            })
    }

    fn declaration_ranges_for(&self, scala: &ScalaAnalyzer, target: &CodeUnit) -> Vec<Range> {
        match &self.bulk_file_states {
            Some(states) => states
                .get(target.source())
                .and_then(|state| state.ranges.get(target))
                .cloned()
                .unwrap_or_default(),
            None => scala.ranges(target),
        }
    }

    fn signature_metadata_for(
        &self,
        scala: &ScalaAnalyzer,
        target: &CodeUnit,
    ) -> Vec<crate::analyzer::SignatureMetadata> {
        match &self.bulk_file_states {
            Some(states) => states
                .get(target.source())
                .and_then(|state| state.signature_metadata.get(target))
                .cloned()
                .unwrap_or_default(),
            None => scala.signature_metadata(target),
        }
    }

    fn source_facts_for_file(
        &self,
        scala: &ScalaAnalyzer,
        file: &ProjectFile,
    ) -> CachedScalaSourceFacts {
        let cell = self
            .source_facts_by_file
            .lock()
            .expect("Scala source-facts cache poisoned")
            .entry(file.clone())
            .or_insert_with(|| Arc::new(OnceLock::new()))
            .clone();
        cell.get_or_init(|| {
            Arc::new(
                self.source_for_file(scala, file)
                    .and_then(|source| scala_source_facts(&source))
                    .unwrap_or_default(),
            )
        })
        .clone()
    }

    fn source_for_file(&self, scala: &ScalaAnalyzer, file: &ProjectFile) -> Option<String> {
        match &self.bulk_file_states {
            Some(states) => states
                .get(file)
                .map(|state| state.source.as_str())
                .filter(|source| !source.is_empty())
                .map(str::to_owned),
            None => scala.indexed_source(file),
        }
    }

    fn direct_extension_method(
        &self,
        scala: &ScalaAnalyzer,
        normalized_fqn: &str,
    ) -> Vec<ExtensionMethod> {
        self.index
            .by_normalized_fqn(normalized_fqn)
            .iter()
            .filter(|unit| unit.is_function() || unit.is_field())
            .filter_map(|unit| self.extension_method_for_unit(scala, unit))
            .collect()
    }

    fn extension_methods_for_owner_member(
        &self,
        scala: &ScalaAnalyzer,
        normalized_owner_fqn: &str,
        member: &str,
    ) -> ExtensionMethodEntries {
        let key = (normalized_owner_fqn.to_string(), member.to_string());
        if let Some(methods) = self
            .extension_methods_by_owner_member
            .lock()
            .expect("extension method cache poisoned")
            .get(&key)
            .cloned()
        {
            return methods;
        }

        let mut methods = self
            .index
            .members_for_owner_name(normalized_owner_fqn, normalized_owner_fqn, member)
            .into_iter()
            .filter(|unit| unit.is_function() || unit.is_field())
            .filter_map(|unit| self.extension_method_for_unit(scala, unit))
            .collect::<Vec<_>>();
        methods.sort_by(|left, right| left.fqn.cmp(&right.fqn));
        methods.dedup_by(|left, right| left.fqn == right.fqn);
        let methods = Arc::new(methods);
        self.extension_methods_by_owner_member
            .lock()
            .expect("extension method cache poisoned")
            .insert(key, methods.clone());
        methods
    }

    fn extension_method_for_unit(
        &self,
        scala: &ScalaAnalyzer,
        unit: &CodeUnit,
    ) -> Option<ExtensionMethod> {
        let alternatives = self.callable_alternatives_for(scala, unit);
        if !alternatives
            .iter()
            .any(|alternative| alternative.extension_receiver_type.is_some())
        {
            return None;
        }
        let _ = owner_fqn(unit)?;
        Some(ExtensionMethod {
            fqn: unit.fq_name(),
            alternatives,
        })
    }

    fn override_targets_for_method(
        &self,
        scala: &ScalaAnalyzer,
        owner_fqn: &str,
        method_fqn: &str,
        method_name: &str,
        method_arity: Option<usize>,
    ) -> OverrideTargetEntries {
        let key = method_key(method_fqn, method_arity);
        if let Some(targets) = self
            .override_targets_by_method
            .lock()
            .expect("override target cache poisoned")
            .get(&key)
            .cloned()
        {
            return targets;
        }

        let mut level = self.direct_ancestors_for_owner(scala, owner_fqn);
        let mut seen = HashSet::default();
        let mut targets = Vec::new();
        while !level.is_empty() {
            let mut next = Vec::new();
            for ancestor in level {
                if !seen.insert(ancestor.clone()) {
                    continue;
                }
                next.extend(self.direct_ancestors_for_declaration(scala, &ancestor));
                if !self.is_scala_trait_declaration(scala, &ancestor) {
                    continue;
                }
                let ancestor_owner = ancestor.fq_name();
                let normalized_ancestor_owner = scala_normalized_fq_name(&ancestor_owner);
                targets.extend(
                    self.index
                        .members_for_owner_name(
                            &ancestor_owner,
                            &normalized_ancestor_owner,
                            method_name,
                        )
                        .iter()
                        .filter(|ancestor_method| {
                            ancestor_method.is_function()
                                && method_arities_compatible(
                                    method_arity,
                                    self.facts
                                        .fact_for_declaration(ancestor_method)
                                        .and_then(|facts| facts.arity),
                                )
                        })
                        .map(|ancestor_method| ancestor_method.fq_name()),
                );
            }
            if !targets.is_empty() {
                break;
            }
            level = next;
        }
        targets.sort();
        targets.dedup();

        let targets = Arc::new(targets);
        self.override_targets_by_method
            .lock()
            .expect("override target cache poisoned")
            .insert(key, targets.clone());
        targets
    }
}

#[derive(Clone)]
pub(crate) struct CallableAlternative {
    pub(crate) shape: Vec<ScalaCallableParameterList>,
    pub(crate) parameter_function_arities: Vec<Vec<Option<usize>>>,
    pub(crate) extension_receiver_type: Option<String>,
    pub(crate) return_type: Option<String>,
}

#[derive(Clone)]
pub(crate) struct ExtensionMethod {
    pub(crate) fqn: String,
    alternatives: CachedCallableAlternatives,
}

/// Per-file map from a source-visible type/object name to the analyzer's fqn,
/// mirroring the forward scanner's [`Visibility`](super::resolver).
pub(crate) struct NameResolver {
    names: VisibleNameBindings,
    object_names: VisibleNameBindings,
    package_names: VisibleNameBindings,
    ambiguous_import_priorities: HashMap<String, u8>,
    package_prefixes: Vec<String>,
    member_names: VisibleNameBindings,
    direct_extension_methods: HashMap<String, Vec<ExtensionMethod>>,
    wildcard_extension_owners: Vec<String>,
}

#[derive(Default)]
struct VisibleNameBindings {
    entries: HashMap<String, VisibleNameBinding>,
}

struct VisibleNameBinding {
    priority: u8,
    candidates: HashSet<String>,
    declarations: HashSet<CodeUnit>,
}

impl VisibleNameBindings {
    fn add_declaration(&mut self, name: String, declaration: &CodeUnit, priority: u8) {
        self.add_candidate(
            name,
            declaration.fq_name(),
            Some(declaration.clone()),
            priority,
        );
    }

    fn add_candidate(
        &mut self,
        name: String,
        fqn: String,
        declaration: Option<CodeUnit>,
        priority: u8,
    ) {
        match self.entries.entry(name) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(VisibleNameBinding {
                    priority,
                    candidates: HashSet::from_iter([fqn]),
                    declarations: declaration.into_iter().collect(),
                });
            }
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                let binding = entry.get_mut();
                if priority > binding.priority {
                    binding.priority = priority;
                    binding.candidates.clear();
                    binding.candidates.insert(fqn);
                    binding.declarations.clear();
                    binding.declarations.extend(declaration);
                } else if priority == binding.priority {
                    binding.candidates.insert(fqn);
                    binding.declarations.extend(declaration);
                }
            }
        }
    }

    fn resolve(&self, name: &str) -> Option<String> {
        let binding = self.entries.get(name)?;
        (binding.candidates.len() == 1 && binding.declarations.len() <= 1)
            .then(|| binding.candidates.iter().next().cloned())?
    }

    fn contains(&self, name: &str) -> bool {
        self.entries.contains_key(name)
    }

    fn priority(&self, name: &str) -> Option<u8> {
        self.entries.get(name).map(|binding| binding.priority)
    }

    fn names_resolving_to(&self, target_fqn: &str) -> Vec<String> {
        let normalized_target = scala_normalized_fq_name(target_fqn);
        self.entries
            .iter()
            .filter(|(_, binding)| {
                binding.candidates.len() == 1
                    && binding.declarations.len() <= 1
                    && binding.candidates.iter().next().is_some_and(|candidate| {
                        candidate == target_fqn
                            || scala_normalized_fq_name(candidate) == normalized_target
                    })
            })
            .map(|(name, _)| name.clone())
            .collect()
    }
}

fn add_hierarchy_package_type_bindings<F>(
    names: &mut VisibleNameBindings,
    types: &ProjectTypes,
    package: &str,
    simple: &str,
    priority: F,
) where
    F: Fn(&CodeUnit) -> u8,
{
    let package_level = types
        .index
        .types_in_package(package, simple)
        .iter()
        .filter(|unit| unit.is_class() && is_package_level_type(unit))
        .collect::<Vec<_>>();
    let ordinary = package_level
        .iter()
        .copied()
        .filter(|unit| !unit.short_name().ends_with('$'))
        .collect::<Vec<_>>();
    let selected = if ordinary.is_empty() {
        package_level
    } else {
        ordinary
    };
    for decl in selected {
        names.add_declaration(simple.to_string(), decl, priority(decl));
    }
}

fn add_hierarchy_package_object_bindings<F>(
    object_names: &mut VisibleNameBindings,
    types: &ProjectTypes,
    package: &str,
    simple: &str,
    priority: F,
) where
    F: Fn(&CodeUnit) -> u8,
{
    for decl in types
        .index
        .types_in_package(package, simple)
        .iter()
        .filter(|unit| {
            unit.is_class() && is_package_level_type(unit) && unit.short_name().ends_with('$')
        })
    {
        object_names.add_declaration(simple.to_string(), decl, priority(decl));
    }
}

impl NameResolver {
    pub(crate) fn for_file_with_facts(
        scala: &ScalaAnalyzer,
        source_file: Option<&ProjectFile>,
        package: Option<&str>,
        imports: &[crate::analyzer::ImportInfo],
        types: &ProjectTypes,
    ) -> Self {
        let package_prefixes = package.into_iter().map(str::to_string).collect::<Vec<_>>();
        Self::for_file_with_package_context(scala, source_file, &package_prefixes, imports, types)
    }

    pub(crate) fn for_file_with_package_context(
        scala: &ScalaAnalyzer,
        source_file: Option<&ProjectFile>,
        package_prefixes: &[String],
        imports: &[crate::analyzer::ImportInfo],
        types: &ProjectTypes,
    ) -> Self {
        Self::for_file_with_facts_impl(scala, source_file, package_prefixes, imports, types, true)
    }

    fn for_type_hierarchy_file(
        source_file: Option<&ProjectFile>,
        package: Option<&str>,
        imports: &[crate::analyzer::ImportInfo],
        types: &ProjectTypes,
        required_names: &HashSet<String>,
    ) -> Self {
        let mut names = VisibleNameBindings::default();
        let mut object_names = VisibleNameBindings::default();
        let mut package_names = VisibleNameBindings::default();
        let mut ambiguous_import_priorities = HashMap::default();
        let file_package = package.unwrap_or_default();
        let package_prefixes = package.into_iter().map(str::to_string).collect::<Vec<_>>();
        for required in required_names {
            add_hierarchy_package_type_bindings(
                &mut names,
                types,
                file_package,
                required,
                |decl| u8::from(source_file == Some(decl.source())) * 3,
            );
            add_hierarchy_package_object_bindings(
                &mut object_names,
                types,
                file_package,
                required,
                |decl| u8::from(source_file == Some(decl.source())) * 3,
            );
        }

        let wildcard_environment =
            resolve_scala_wildcard_import_environment(imports, &package_prefixes, |candidate| {
                let normalized = scala_normalized_fq_name(candidate);
                let mut objects = types
                    .index
                    .by_normalized_fqn(&normalized)
                    .iter()
                    .filter(|unit| unit.is_class() && unit.short_name().ends_with('$'));
                let stable_singleton = objects.next().is_some() && objects.next().is_none();
                ScalaWildcardOwnerFacts {
                    package: types.index.package_exists(candidate),
                    stable_singleton,
                }
            });
        if !wildcard_environment.ambiguous {
            for owner in &wildcard_environment.owners {
                if owner.is_singleton() {
                    let children = types.index.fqn_direct_children(&owner.declaration_fqn());
                    for required in required_names {
                        let ordinary = children
                            .iter()
                            .filter(|unit| {
                                unit.is_class()
                                    && !unit.short_name().ends_with('$')
                                    && scala_simple_type_name(unit) == *required
                            })
                            .collect::<Vec<_>>();
                        for declaration in ordinary {
                            names.add_declaration(required.clone(), declaration, 1);
                        }
                        for declaration in children.iter().filter(|unit| {
                            unit.is_class()
                                && unit.short_name().ends_with('$')
                                && scala_simple_type_name(unit) == *required
                        }) {
                            object_names.add_declaration(required.clone(), declaration, 1);
                            if !names.contains(required) {
                                names.add_declaration(required.clone(), declaration, 1);
                            }
                        }
                    }
                } else {
                    for required in required_names {
                        add_hierarchy_package_type_bindings(
                            &mut names,
                            types,
                            &owner.fqn,
                            required,
                            |_| 1,
                        );
                        add_hierarchy_package_object_bindings(
                            &mut object_names,
                            types,
                            &owner.fqn,
                            required,
                            |_| 1,
                        );
                    }
                }
            }
        }

        for import in imports {
            let Some(path) = scala_import_path(import) else {
                continue;
            };
            if import.is_wildcard {
                continue;
            }
            let local_name = import
                .identifier
                .as_deref()
                .unwrap_or_else(|| path.rsplit('.').next().unwrap_or(&path));
            if !required_names.contains(local_name) {
                continue;
            }
            let Some(tier) = types.explicit_import_tier(&path, &package_prefixes) else {
                continue;
            };
            if tier.declaration && tier.package {
                ambiguous_import_priorities.insert(local_name.to_string(), 2);
            }
            if tier.declaration {
                let (type_declarations, object_declarations) =
                    types.explicit_import_class_declarations(&tier.candidate);
                for declaration in &type_declarations {
                    names.add_declaration(local_name.to_string(), declaration, 2);
                }
                for declaration in &object_declarations {
                    object_names.add_declaration(local_name.to_string(), declaration, 2);
                }
            }
            if tier.package {
                package_names.add_candidate(
                    local_name.to_string(),
                    scala_normalized_fq_name(&tier.candidate),
                    None,
                    2,
                );
            }
        }
        Self {
            names,
            object_names,
            package_names,
            ambiguous_import_priorities,
            package_prefixes,
            member_names: VisibleNameBindings::default(),
            direct_extension_methods: HashMap::default(),
            wildcard_extension_owners: Vec::new(),
        }
    }

    pub(crate) fn for_file_types(
        scala: &ScalaAnalyzer,
        target: &CodeUnit,
        types: &ProjectTypes,
    ) -> Self {
        let file = target.source();
        match &types.bulk_file_states {
            Some(states) => match states.get(file) {
                Some(state) => {
                    let reference_byte = state
                        .ranges
                        .get(target)
                        .into_iter()
                        .flatten()
                        .map(|range| range.start_byte)
                        .min();
                    let imports = visible_imports_at_byte(&state.imports, reference_byte);
                    Self::for_file_with_facts_impl(
                        scala,
                        Some(file),
                        &[target.package_name().to_string()],
                        &imports,
                        types,
                        false,
                    )
                }
                None => Self::for_file_with_facts_impl(
                    scala,
                    Some(file),
                    &[target.package_name().to_string()],
                    &[],
                    types,
                    false,
                ),
            },
            None => {
                let imports = scala.import_info_of(file);
                let reference_byte = scala
                    .ranges(target)
                    .into_iter()
                    .map(|range| range.start_byte)
                    .min();
                let imports = visible_imports_at_byte(&imports, reference_byte);
                Self::for_file_with_facts_impl(
                    scala,
                    Some(file),
                    &[target.package_name().to_string()],
                    &imports,
                    types,
                    false,
                )
            }
        }
    }

    fn for_file_with_facts_impl(
        scala: &ScalaAnalyzer,
        source_file: Option<&ProjectFile>,
        package_prefixes: &[String],
        imports: &[crate::analyzer::ImportInfo],
        types: &ProjectTypes,
        include_members: bool,
    ) -> Self {
        let mut names = VisibleNameBindings::default();
        let mut object_names = VisibleNameBindings::default();
        let mut package_names = VisibleNameBindings::default();
        let mut ambiguous_import_priorities = HashMap::default();
        let mut member_names = VisibleNameBindings::default();
        let mut direct_extension_methods: HashMap<String, Vec<ExtensionMethod>> =
            HashMap::default();
        let mut wildcard_extension_owners = Vec::new();

        let fallback_default_package = String::new();
        let active_package_prefixes = if package_prefixes.is_empty() {
            std::slice::from_ref(&fallback_default_package)
        } else {
            package_prefixes
        };
        // Parser-established package scopes are visible from innermost to
        // outermost. A dotted package clause contributes only its complete
        // package; it does not invent parent-package bindings.
        for (index, package) in active_package_prefixes.iter().enumerate() {
            // Preserve Scala's ordinary lookup precedence: a wildcard import
            // beats declarations in another compilation unit of the active
            // package, an explicit import beats a wildcard, and declarations
            // in this compilation unit beat imports. Within the package
            // scopes established by nested/sequential package clauses, the
            // innermost package wins over its enclosing package.
            let package_priority = index.min(63) as u8;
            for (simple, decl) in types.package_types_in(package).iter() {
                let priority = if source_file == Some(decl.source()) {
                    224u8.saturating_add(index.min(30) as u8)
                } else {
                    package_priority
                };
                names.add_declaration(simple.clone(), decl, priority);
            }
            for (simple, decl) in types.package_objects_in(scala, package).iter() {
                let priority = if source_file == Some(decl.source()) {
                    224u8.saturating_add(index.min(30) as u8)
                } else {
                    package_priority
                };
                object_names.add_declaration(simple.clone(), decl, priority);
            }
        }

        let wildcard_environment = resolve_scala_wildcard_import_environment(
            imports,
            active_package_prefixes,
            |candidate| ScalaWildcardOwnerFacts {
                package: !types.package_types_in(candidate).is_empty()
                    || !types.package_objects_in(scala, candidate).is_empty(),
                stable_singleton: types
                    .object_by_normalized_fqn(scala, &scala_normalized_fq_name(candidate))
                    .is_some(),
            },
        );
        for owner in &wildcard_environment.owners {
            if owner.is_singleton() {
                let normalized_owner = scala_normalized_fq_name(&owner.declaration_fqn());
                for (simple, decl) in types.nested_types_in(scala, &normalized_owner).iter() {
                    names.add_declaration(simple.clone(), decl, 128);
                }
                for (simple, decl) in types.nested_objects_in(scala, &normalized_owner).iter() {
                    object_names.add_declaration(simple.clone(), decl, 128);
                }
                if include_members && !wildcard_environment.ambiguous {
                    if let Some(declaration) =
                        types.object_by_normalized_fqn(scala, &normalized_owner)
                    {
                        for child in types.index.fqn_direct_children(&declaration.fq_name()) {
                            if child.is_function() || child.is_field() {
                                let visible_name = child
                                    .short_name()
                                    .rsplit('.')
                                    .next()
                                    .unwrap_or(child.short_name())
                                    .to_string();
                                member_names.add_candidate(
                                    visible_name,
                                    child.fq_name(),
                                    None,
                                    128,
                                );
                            }
                        }
                        for (visible_name, member_fqn) in
                            types.exported_member_bindings(scala, declaration)
                        {
                            member_names.add_candidate(visible_name, member_fqn, None, 128);
                        }
                    }
                    wildcard_extension_owners.push(normalized_owner);
                }
            } else {
                for (simple, decl) in types.package_types_in(&owner.fqn).iter() {
                    names.add_declaration(simple.clone(), decl, 128);
                }
                for (simple, decl) in types.package_objects_in(scala, &owner.fqn).iter() {
                    object_names.add_declaration(simple.clone(), decl, 128);
                }
                if include_members && !wildcard_environment.ambiguous {
                    wildcard_extension_owners.push(owner.fqn.clone());
                }
            }
        }

        for import in imports {
            let Some(path) = scala_import_path(import) else {
                continue;
            };
            if import.is_wildcard {
                continue;
            }
            let Some(tier) = types.explicit_import_tier(&path, active_package_prefixes) else {
                continue;
            };
            let local_name = import
                .identifier
                .clone()
                .unwrap_or_else(|| path.rsplit('.').next().unwrap_or(&path).to_string());
            if tier.declaration && tier.package {
                ambiguous_import_priorities.insert(local_name.clone(), 192);
            }
            if tier.declaration {
                let (type_declarations, mut object_declarations) =
                    types.explicit_import_class_declarations(&tier.candidate);
                if object_declarations.is_empty() {
                    object_declarations.extend(
                        type_declarations
                            .iter()
                            .filter(|declaration| {
                                types.type_accepts_object_roles(scala, declaration)
                            })
                            .cloned(),
                    );
                }
                for declaration in &type_declarations {
                    names.add_declaration(local_name.clone(), declaration, 192);
                }
                for declaration in &object_declarations {
                    object_names.add_declaration(local_name.clone(), declaration, 192);
                }
            }
            if tier.package {
                package_names.add_candidate(
                    local_name.clone(),
                    scala_normalized_fq_name(&tier.candidate),
                    None,
                    192,
                );
            }
            let normalized = scala_normalized_fq_name(&tier.candidate);
            if include_members && let Some(member) = types.member_by_normalized_fqn(&normalized) {
                let member_fqn = member.fq_name();
                member_names.add_candidate(local_name.clone(), member_fqn.clone(), None, 192);
                for method in types.direct_extension_method(scala, &normalized) {
                    direct_extension_methods
                        .entry(local_name.clone())
                        .or_default()
                        .push(method);
                }
            }
        }

        wildcard_extension_owners.sort();
        wildcard_extension_owners.dedup();
        for methods in direct_extension_methods.values_mut() {
            methods.sort_by(|left, right| left.fqn.cmp(&right.fqn));
            methods.dedup_by(|left, right| left.fqn == right.fqn);
        }

        Self {
            names,
            object_names,
            package_names,
            ambiguous_import_priorities,
            package_prefixes: active_package_prefixes.to_vec(),
            member_names,
            direct_extension_methods,
            wildcard_extension_owners,
        }
    }

    /// Resolve a type/object source name (stripping generics) to its fqn.
    pub(crate) fn resolve(&self, raw: &str) -> Option<String> {
        let simple = simple_type_name(raw)?;
        if self.import_collision_blocks(simple, self.names.priority(simple)) {
            return None;
        }
        self.names.resolve(simple)
    }

    pub(crate) fn resolve_object(&self, raw: &str) -> Option<String> {
        let simple = simple_type_name(raw)?;
        if self.import_collision_blocks(simple, self.object_names.priority(simple)) {
            return None;
        }
        self.object_names.resolve(simple)
    }

    fn resolve_stable_object_root(&self, raw: &str) -> Option<String> {
        let simple = simple_type_name(raw)?;
        let object_priority = self.object_names.priority(simple)?;
        let non_package_priority = self
            .names
            .priority(simple)
            .into_iter()
            .chain(Some(object_priority))
            .max()?;
        if self.import_collision_blocks(simple, Some(non_package_priority)) {
            return None;
        }
        if object_priority != non_package_priority
            || self
                .package_names
                .priority(simple)
                .is_some_and(|package_priority| package_priority >= non_package_priority)
        {
            return None;
        }
        self.object_names.resolve(simple)
    }

    fn has_type_or_object_binding(&self, raw: &str) -> bool {
        simple_type_name(raw)
            .is_some_and(|simple| self.names.contains(simple) || self.object_names.contains(simple))
    }

    fn has_type_or_object_or_package_binding(&self, raw: &str) -> bool {
        simple_type_name(raw).is_some_and(|simple| {
            self.names.contains(simple)
                || self.object_names.contains(simple)
                || self.package_names.contains(simple)
        })
    }

    fn resolve_package(&self, types: &ProjectTypes, raw: &str) -> Option<String> {
        let simple = simple_type_name(raw)?;
        if self.import_collision_blocks(simple, self.package_names.priority(simple)) {
            return None;
        }
        let type_priority = self
            .names
            .priority(simple)
            .into_iter()
            .chain(self.object_names.priority(simple))
            .max();
        if let Some(package_priority) = self.package_names.priority(simple)
            && type_priority.is_none_or(|priority| package_priority > priority)
        {
            return self.package_names.resolve(simple);
        }
        if type_priority.is_some() {
            return None;
        }
        for package in self.package_prefixes.iter().rev() {
            let candidate = if package.is_empty() {
                simple.to_string()
            } else {
                format!("{package}.{simple}")
            };
            if types.index.package_exists(&candidate) {
                return Some(candidate);
            }
        }
        types
            .index
            .package_exists(simple)
            .then(|| simple.to_string())
    }

    /// Resolve a source-visible member name imported directly from an owner.
    pub(crate) fn resolve_member(&self, raw: &str) -> Option<String> {
        let simple = simple_type_name(raw)?;
        if self.import_collision_blocks(simple, None) {
            return None;
        }
        self.member_names.resolve(simple)
    }

    pub(crate) fn visible_member_names_for(&self, target_fqn: &str) -> Vec<String> {
        let mut names = self.member_names.names_resolving_to(target_fqn);
        names.retain(|name| !self.import_collision_blocks(name, self.member_names.priority(name)));
        names.sort();
        names.dedup();
        names
    }

    pub(crate) fn visible_extension_methods(
        &self,
        scala: &ScalaAnalyzer,
        types: &ProjectTypes,
        member: &str,
    ) -> Vec<ExtensionMethod> {
        if self.import_collision_blocks(member, None) {
            return Vec::new();
        }
        let mut methods = Vec::new();
        methods.extend(self.direct_extension_methods(member).iter().cloned());
        for owner in self.wildcard_extension_owners() {
            methods.extend(
                types
                    .extension_methods_for_owner_member(scala, owner, member)
                    .iter()
                    .cloned(),
            );
        }
        methods.sort_by(|left, right| left.fqn.cmp(&right.fqn));
        methods.dedup_by(|left, right| left.fqn == right.fqn);
        methods
    }

    fn direct_extension_methods(&self, member: &str) -> &[ExtensionMethod] {
        self.direct_extension_methods
            .get(member)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    fn wildcard_extension_owners(&self) -> &[String] {
        &self.wildcard_extension_owners
    }

    fn import_collision_blocks(&self, name: &str, winner_priority: Option<u8>) -> bool {
        self.ambiguous_import_priorities
            .get(name)
            .is_some_and(|collision_priority| {
                winner_priority.is_none_or(|priority| *collision_priority >= priority)
            })
    }
}

fn visible_imports_at_byte(
    imports: &[crate::analyzer::ImportInfo],
    reference_byte: Option<usize>,
) -> Vec<crate::analyzer::ImportInfo> {
    let Some(reference_byte) = reference_byte else {
        return imports.to_vec();
    };
    imports
        .iter()
        .filter(|import| scala_import_is_visible_at_byte(import, reference_byte))
        .cloned()
        .collect()
}

fn owner_fqn(unit: &CodeUnit) -> Option<String> {
    let (owner_short, _) = unit.short_name().rsplit_once('.')?;
    Some(if unit.package_name().is_empty() {
        owner_short.to_string()
    } else {
        format!("{}.{}", unit.package_name(), owner_short)
    })
}

pub(super) fn is_package_level_type(unit: &CodeUnit) -> bool {
    !unit.short_name().contains('.')
}

fn method_arities_compatible(method: Option<usize>, ancestor: Option<usize>) -> bool {
    method.is_none() || ancestor.is_none() || method == ancestor
}

fn method_call_shape_matches(
    facts: &CallableFacts,
    alternatives: &[CallableAlternative],
    call_arities: Option<&[usize]>,
    unique_callable: bool,
) -> bool {
    let fallback_shape;
    let fallback_shapes;
    let shapes = if alternatives.is_empty() {
        fallback_shape = facts
            .callable_arity
            .or_else(|| facts.arity.map(crate::analyzer::CallableArity::exact))
            .map(|arity| vec![ScalaCallableParameterList::explicit(arity)])
            .unwrap_or_default();
        fallback_shapes = vec![fallback_shape];
        fallback_shapes.as_slice()
    } else {
        return alternatives.iter().any(|alternative| {
            callable_shape_matches(&alternative.shape, call_arities, unique_callable)
        });
    };
    shapes
        .iter()
        .any(|declared| callable_shape_matches(declared, call_arities, unique_callable))
}

fn callable_shape_matches(
    declared: &[ScalaCallableParameterList],
    call_arities: Option<&[usize]>,
    unique_callable: bool,
) -> bool {
    match call_arities {
        Some(call_arities) => {
            if call_arities.len() > declared.len() {
                return false;
            }
            let provided_lists_match = call_arities
                .iter()
                .zip(declared)
                .all(|(call_arity, declared)| declared.arity.accepts(*call_arity));
            provided_lists_match
                && (unique_callable
                    || declared[call_arities.len()..]
                        .iter()
                        .all(|list| list.kind == ScalaParameterListKind::Contextual))
        }
        None => declared.first().is_none_or(|list| list.arity.total() == 0) || unique_callable,
    }
}

fn method_key(fqn: &str, arity: Option<usize>) -> String {
    match arity {
        Some(arity) => format!("{fqn}#{arity}"),
        None => fqn.to_string(),
    }
}

/// The leading simple name of a (possibly generic/qualified) type text.
fn simple_type_name(type_text: &str) -> Option<&str> {
    type_text
        .split(['[', '(', '{', '.', ' ', '<'])
        .next()
        .map(str::trim)
        .filter(|name| !name.is_empty())
}

/// Build the whole Scala `caller -> callee` edge set in a single inverted pass
/// over the workspace.
/// `nodes`/`keep_file` mirror the Go builder.
pub(super) fn build_scala_edges<Output, F>(
    scala: &ScalaAnalyzer,
    graph: &ScalaEdgeGraph,
    nodes: &HashSet<String>,
    keep_file: F,
) -> Output
where
    Output: UsageEdgeBuildOutput<String>,
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let language = tree_sitter_scala::LANGUAGE.into();
    build_edge_output(&graph.files, keep_file, |file| {
        let state = graph.types.bulk_file_state(file)?;
        let declarations = build_file_declarations_from_state(state);
        let class_ranges = ClassRangeIndex::build_from_state(state);
        parse_source_and_collect_with_declarations(
            graph.types.source_for_file(scala, file)?,
            file,
            nodes,
            &language,
            declarations,
            |parsed, collector| {
                let resolver = Arc::new(NameResolver::for_file_with_facts(
                    scala,
                    Some(file),
                    Some(&state.package_name),
                    &[],
                    &graph.types,
                ));
                let mut ctx = ScalaScan {
                    scala,
                    source: parsed.source.as_str(),
                    source_file: file,
                    imports: &state.imports,
                    import_contexts: ScalaImportContextIndex::new(
                        &state.imports,
                        parsed.tree.root_node().end_byte(),
                    ),
                    import_context_cursor: 0,
                    package_contexts: ScalaPackageContextIndex::new(
                        parsed.tree.root_node(),
                        parsed.source.as_str(),
                    ),
                    package_context_cursor: 0,
                    resolver,
                    active_resolver_key: None,
                    resolver_contexts: HashMap::default(),
                    types: &graph.types,
                    class_ranges,
                    collector,
                };
                let mut bindings = LocalInferenceEngine::new(LocalInferenceConfig::default());
                walk(parsed.tree.root_node(), &mut ctx, &mut bindings);
            },
        )
    })
}

struct ScalaScan<'a, 'b> {
    scala: &'a ScalaAnalyzer,
    source: &'a str,
    source_file: &'a ProjectFile,
    imports: &'a [crate::analyzer::ImportInfo],
    import_contexts: ScalaImportContextIndex,
    import_context_cursor: usize,
    package_contexts: ScalaPackageContextIndex,
    package_context_cursor: usize,
    resolver: Arc<NameResolver>,
    active_resolver_key: Option<(Vec<String>, Vec<usize>)>,
    resolver_contexts: HashMap<(Vec<String>, Vec<usize>), Arc<NameResolver>>,
    types: &'a ProjectTypes,
    class_ranges: ClassRangeIndex,
    collector: &'a mut EdgeCollector<'b>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct ScalaBinding {
    receiver_type: Option<String>,
    declaration_owner: Option<String>,
}

impl ScalaScan<'_, '_> {
    fn activate_import_context(&mut self, node: Node<'_>) {
        let visible_imports = self
            .import_contexts
            .advance_to(node.start_byte(), &mut self.import_context_cursor);
        let visible_packages = self
            .package_contexts
            .advance_to(node.start_byte(), &mut self.package_context_cursor);
        if self
            .active_resolver_key
            .as_ref()
            .is_some_and(|(packages, imports)| {
                packages.as_slice() == visible_packages && imports.as_slice() == visible_imports
            })
        {
            return;
        }
        let key = (visible_packages.to_vec(), visible_imports.to_vec());
        if let Some(resolver) = self.resolver_contexts.get(&key) {
            self.resolver = resolver.clone();
            self.active_resolver_key = Some(key);
            return;
        }
        let imports = key
            .1
            .iter()
            .filter_map(|index| self.imports.get(*index).cloned())
            .collect::<Vec<_>>();
        let resolver = Arc::new(NameResolver::for_file_with_package_context(
            self.scala,
            Some(self.source_file),
            &key.0,
            &imports,
            self.types,
        ));
        self.resolver_contexts.insert(key.clone(), resolver.clone());
        self.resolver = resolver;
        self.active_resolver_key = Some(key);
    }

    /// The fqn of the smallest class/object declaration containing `byte`.
    fn enclosing_class(&self, byte: usize) -> Option<&str> {
        self.class_ranges.enclosing(byte)
    }

    fn enclosing_class_unit(&self, byte: usize) -> Option<&CodeUnit> {
        self.class_ranges.enclosing_unit(byte)
    }

    fn lexically_visible_type(&self, byte: usize, name: &str) -> Option<String> {
        self.class_ranges.find_in_enclosing_units(byte, |owner| {
            self.types.exact_nested_type(&owner.fq_name(), name)
        })
    }

    fn lexically_visible_object(&self, byte: usize, name: &str) -> Option<String> {
        self.class_ranges.find_in_enclosing_units(byte, |owner| {
            self.types
                .exact_nested_object(self.scala, &owner.fq_name(), name)
        })
    }

    fn lexically_visible_type_path(&self, byte: usize, path: &[String]) -> Option<String> {
        let [name] = path else {
            return None;
        };
        self.lexically_visible_type(byte, name)
    }

    fn record(&mut self, callee: String, node: Node<'_>) {
        self.collector.record_kind(
            callee,
            classify_reference_node(node),
            node.start_byte(),
            node.end_byte(),
        );
    }

    fn record_with_caller(&mut self, caller: String, callee: String, node: Node<'_>) {
        self.collector.record_with_caller_kind(
            caller,
            callee,
            classify_reference_node(node),
            node.start_byte(),
            node.end_byte(),
        );
    }
}

const SCOPE_NODES: &[&str] = &[
    "class_definition",
    "object_definition",
    "trait_definition",
    "enum_definition",
    "function_definition",
    "block",
    "indented_block",
    "case_clause",
    "lambda_expression",
];

fn walk(
    node: Node<'_>,
    ctx: &mut ScalaScan<'_, '_>,
    bindings: &mut LocalInferenceEngine<ScalaBinding>,
) {
    let mut state = (ctx, bindings);
    walk_tree_iterative(
        node,
        &mut state,
        |node, (ctx, bindings)| {
            if walk_enter(node, ctx, bindings) {
                TreeWalkAction::DescendWithExit
            } else {
                TreeWalkAction::Descend
            }
        },
        |(_, bindings)| bindings.exit_scope(),
    );
}

fn walk_enter(
    node: Node<'_>,
    ctx: &mut ScalaScan<'_, '_>,
    bindings: &mut LocalInferenceEngine<ScalaBinding>,
) -> bool {
    ctx.activate_import_context(node);
    let enters_scope = SCOPE_NODES.contains(&node.kind());
    if enters_scope {
        bindings.enter_scope();
    }
    seed_declaration(node, ctx, bindings);
    record_override_declaration(node, ctx);
    record_reference(node, ctx, bindings);
    enters_scope
}

fn record_reference(
    node: Node<'_>,
    ctx: &mut ScalaScan<'_, '_>,
    bindings: &LocalInferenceEngine<ScalaBinding>,
) {
    match node.kind() {
        // A type reference in any type position: param/return types, `extends`,
        // and the type child of `new Foo()`. Construction is covered here without
        // a separate `instance_expression` case (avoids double counting).
        "type_identifier" => {
            if record_qualified_stable_reference(node, ctx, bindings) {
                return;
            }
            let text = node_text(node, ctx.source);
            let object_reference = is_scala_object_reference(node);
            if (is_extractor_reference(node) || is_infix_pattern_operator(node))
                && bindings.resolve_symbol(text).is_unknown()
                && !bindings.is_shadowed(text)
            {
                let class_fqn = ctx
                    .lexically_visible_type(node.start_byte(), text)
                    .or_else(|| ctx.resolver.resolve(text));
                let resolution = ctx.types.resolve_type_application(
                    ctx.scala,
                    &ctx.resolver,
                    class_fqn.as_deref(),
                    ctx.lexically_visible_object(node.start_byte(), text)
                        .or_else(|| ctx.resolver.resolve_object(text))
                        .as_deref(),
                    text,
                    call_arities_for_reference(node).as_deref(),
                    TypeApplicationRole::Extractor,
                );
                if let Some(target) = resolution.type_target {
                    ctx.record(target.fq_name(), node);
                }
                for callable in resolution.callable_targets {
                    ctx.record(callable.fq_name(), node);
                }
            }
            let resolved = if object_reference {
                (bindings.resolve_symbol(text).is_unknown() && !bindings.is_shadowed(text))
                    .then(|| {
                        ctx.lexically_visible_object(node.start_byte(), text)
                            .or_else(|| ctx.resolver.resolve_object(text))
                    })
                    .flatten()
            } else if is_scala_class_reference(node, ctx.source) {
                ctx.lexically_visible_type(node.start_byte(), text)
                    .or_else(|| ctx.resolver.resolve(text))
            } else {
                None
            };
            if let Some(fqn) = resolved {
                let call_arities = call_arities_for_reference(node);
                if is_constructor_like_reference(node, ctx.source) {
                    let resolution = ctx.types.resolve_type_application(
                        ctx.scala,
                        &ctx.resolver,
                        Some(&fqn),
                        None,
                        text,
                        call_arities.as_deref(),
                        TypeApplicationRole::ExplicitConstructor,
                    );
                    if let Some(target) = resolution.type_target {
                        ctx.record(target.fq_name(), node);
                    }
                    for callable in resolution.callable_targets {
                        ctx.record(callable.fq_name(), node);
                    }
                    return;
                }
                ctx.record(fqn, node);
            }
        }
        "call_expression" => {
            let Some(function) = node.child_by_field_name("function") else {
                return;
            };
            match function.kind() {
                // `recv.method(..)` — type the receiver, then `Owner.method`.
                "field_expression" => {
                    let (Some(receiver), Some(field)) = (
                        function.child_by_field_name("value"),
                        function.child_by_field_name("field"),
                    ) else {
                        return;
                    };
                    let name = node_text(field, ctx.source);
                    if name.is_empty() {
                        return;
                    }
                    if let Some(owner) = receiver_type_fqn(receiver, ctx, bindings) {
                        let call_arities = call_arities_for_reference(field);
                        match ctx.types.effective_method_declarations_for_owner(
                            ctx.scala,
                            &owner,
                            name,
                            call_arities.as_deref(),
                        ) {
                            BareMemberResolution::Resolved(methods) => {
                                for method in methods {
                                    ctx.record(method.fq_name(), field);
                                }
                            }
                            BareMemberResolution::Unresolved => {}
                            BareMemberResolution::NoMatch => {
                                for extension in visible_extensions(
                                    ctx,
                                    name,
                                    Some(&owner),
                                    call_arities.as_deref(),
                                ) {
                                    ctx.record(extension.fqn, field);
                                }
                            }
                        }
                    } else {
                        let call_arities = call_arities_for_reference(field);
                        let extensions =
                            visible_extensions(ctx, name, None, call_arities.as_deref());
                        if extensions.is_empty() {
                            ctx.collector.record_unproven_name(
                                name,
                                field.start_byte(),
                                field.end_byte(),
                            );
                        } else {
                            for extension in extensions {
                                ctx.record(extension.fqn, field);
                            }
                        }
                    }
                }
                // `method(..)` — unqualified, attributes to the enclosing class.
                "identifier" => {
                    let name = node_text(function, ctx.source);
                    if name.is_empty() {
                        return;
                    }
                    let call_arities = call_arities_for_reference(function);
                    if record_lexically_visible_call(function, name, call_arities.as_deref(), ctx) {
                        return;
                    }
                    if let Some(imported) = ctx.resolver.resolve_member(name) {
                        for target in ctx.types.imported_member_targets(
                            ctx.scala,
                            &imported,
                            call_arities.as_deref(),
                        ) {
                            ctx.record(target, function);
                        }
                        // A unique imported binding owns this visible name.
                        // If no overload matches the call shape, fail closed
                        // instead of reinterpreting it as a type application.
                        return;
                    }
                    record_unqualified_type_application(function, name, ctx, bindings);
                }
                _ => {}
            }
        }
        "infix_expression" => {
            let (Some(receiver), Some(operator)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("operator"),
            ) else {
                return;
            };
            let member = node_text(operator, ctx.source).trim();
            if member.is_empty() {
                return;
            }
            let Some(owner) = receiver_type_fqn(receiver, ctx, bindings) else {
                return;
            };
            let call_arities = call_arities_for_reference(operator);
            if let BareMemberResolution::Resolved(methods) =
                ctx.types.effective_method_declarations_for_owner(
                    ctx.scala,
                    &owner,
                    member,
                    call_arities.as_deref(),
                )
            {
                for method in methods {
                    ctx.record(method.fq_name(), operator);
                }
            }
        }
        "identifier" | "operator_identifier" => {
            if record_qualified_stable_reference(node, ctx, bindings) {
                return;
            }
            let name = node_text(node, ctx.source);
            if name.is_empty()
                || has_ancestor_kind(node, "import_declaration")
                || is_declaration_name(node)
            {
                return;
            }
            let bare_companion_method_value = is_bare_companion_method_value_reference(node);
            if (is_extractor_reference(node) || is_infix_pattern_operator(node))
                && let Some(fqn) = (bindings.resolve_symbol(name).is_unknown()
                    && !bindings.is_shadowed(name))
                .then(|| {
                    ctx.lexically_visible_type(node.start_byte(), name)
                        .or_else(|| ctx.resolver.resolve(name))
                })
                .flatten()
                && let Some(target) = ctx
                    .types
                    .type_by_normalized_fqn(&scala_normalized_fq_name(&fqn))
                && ctx.types.class_accepts_extractor_role(ctx.scala, target)
            {
                ctx.record(target.fq_name(), node);
            }
            if is_scala_class_reference(node, ctx.source)
                && !bare_companion_method_value
                && let Some(fqn) = {
                    ctx.lexically_visible_type(node.start_byte(), name)
                        .or_else(|| ctx.resolver.resolve(name))
                }
            {
                ctx.record(fqn, node);
                return;
            }
            if let Some(owner) = exact_owner_field_binding(bindings, name) {
                match ctx.types.field_for_owner_member(ctx.scala, &owner, name) {
                    FieldResolution::Resolved(field) => {
                        ctx.record(field.declaration.fq_name(), node);
                        return;
                    }
                    FieldResolution::Unresolved => return,
                    FieldResolution::NoMatch => {}
                }
            }
            if bindings.is_shadowed(name) {
                return;
            }
            if bare_companion_method_value {
                let target = match companion_method_value_context(node, ctx, bindings) {
                    ScalaMethodValueContext::Unknown => {
                        ctx.types.unique_companion_apply_method_value_target(
                            ctx.scala,
                            &ctx.resolver,
                            name,
                            None,
                        )
                    }
                    ScalaMethodValueContext::Function(arity) => {
                        ctx.types.unique_companion_apply_method_value_target(
                            ctx.scala,
                            &ctx.resolver,
                            name,
                            Some(&[arity]),
                        )
                    }
                    ScalaMethodValueContext::Incompatible => {
                        if let Some(object) = ctx.resolver.resolve_object(name) {
                            ctx.record(object, node);
                        }
                        None
                    }
                };
                if let Some(target) = target {
                    ctx.record(target.fq_name(), node);
                }
                return;
            }
            if let Some(reference) = stable_identifier_reference(node, ctx.source) {
                if reference.segments.first().is_some_and(|root| {
                    !bindings.resolve_symbol(root).is_unknown() || bindings.is_shadowed(root)
                }) {
                    return;
                }
                let (member, owner_segments) =
                    reference.segments.split_last().expect("stable path");
                let owner_lexical_root = owner_segments
                    .first()
                    .and_then(|root| ctx.lexically_visible_object(node.start_byte(), root));
                if let Some(owner) = ctx.types.resolve_qualified_stable_type_at(
                    ctx.scala,
                    &ctx.resolver,
                    owner_segments,
                    true,
                    owner_lexical_root,
                ) && let Some(field) = ctx.types.exact_field(ctx.scala, &owner, member)
                {
                    ctx.record(field, node);
                    return;
                }
                let lexical_root = reference
                    .segments
                    .first()
                    .and_then(|root| ctx.lexically_visible_object(node.start_byte(), root));
                if let Some(object) = ctx.types.resolve_qualified_stable_type_at(
                    ctx.scala,
                    &ctx.resolver,
                    &reference.segments,
                    true,
                    lexical_root,
                ) {
                    ctx.record(object, node);
                }
                return;
            }
            if is_terminal_stable_field_reference(node) {
                let qualifier = node
                    .parent()
                    .and_then(|expression| expression.child_by_field_name("value"));
                if let Some(qualifier) = qualifier
                    && let Some(owner) = receiver_type_fqn(qualifier, ctx, bindings)
                {
                    match ctx.types.field_for_owner_member(ctx.scala, &owner, name) {
                        FieldResolution::Resolved(field) => {
                            ctx.record(field.declaration.fq_name(), node);
                        }
                        FieldResolution::Unresolved => return,
                        FieldResolution::NoMatch => {
                            if record_ordinary_class_methods(&owner, name, None, node, ctx) {
                                return;
                            }
                            if let Some(object) =
                                ctx.types.exact_nested_object(ctx.scala, &owner, name)
                            {
                                ctx.record(object, node);
                            }
                        }
                    }
                }
                return;
            }
            if let Some(owner) = ctx.enclosing_class(node.start_byte()) {
                match ctx.types.field_for_owner_member(ctx.scala, owner, name) {
                    FieldResolution::Resolved(field) => {
                        ctx.record(field.declaration.fq_name(), node);
                        return;
                    }
                    FieldResolution::Unresolved => return,
                    FieldResolution::NoMatch => {}
                }
            }
            if record_lexically_visible_parameterless_method(node, name, ctx) {
                return;
            }
            if is_scala_object_reference(node)
                && bindings.resolve_symbol(name).is_unknown()
                && let Some(fqn) = ctx
                    .lexically_visible_object(node.start_byte(), name)
                    .or_else(|| ctx.resolver.resolve_object(name))
            {
                ctx.record(fqn, node);
                return;
            }
            if let Some(fqn) = ctx.resolver.resolve_member(name) {
                ctx.record(fqn, node);
            }
        }
        _ => {}
    }
}

fn record_unqualified_type_application(
    function: Node<'_>,
    name: &str,
    ctx: &mut ScalaScan<'_, '_>,
    bindings: &LocalInferenceEngine<ScalaBinding>,
) -> bool {
    if !bindings.resolve_symbol(name).is_unknown() || bindings.is_shadowed(name) {
        return false;
    }
    let call_arities = call_arities_for_reference(function);
    let class_fqn = ctx
        .lexically_visible_type(function.start_byte(), name)
        .or_else(|| ctx.resolver.resolve(name));
    let object_fqn = ctx
        .lexically_visible_object(function.start_byte(), name)
        .or_else(|| ctx.resolver.resolve_object(name));
    if class_fqn.is_none() && object_fqn.is_none() {
        return false;
    }
    let resolution = ctx.types.resolve_type_application(
        ctx.scala,
        &ctx.resolver,
        class_fqn.as_deref(),
        object_fqn.as_deref(),
        name,
        call_arities.as_deref(),
        if is_extractor_reference(function) || is_infix_pattern_operator(function) {
            TypeApplicationRole::Extractor
        } else {
            TypeApplicationRole::BareApplication
        },
    );
    if let Some(target) = resolution.type_target {
        ctx.record(target.fq_name(), function);
    }
    for callable in resolution.callable_targets {
        ctx.record(callable.fq_name(), function);
    }
    true
}

fn record_qualified_stable_reference(
    node: Node<'_>,
    ctx: &mut ScalaScan<'_, '_>,
    bindings: &LocalInferenceEngine<ScalaBinding>,
) -> bool {
    let Some(reference) = qualified_stable_type_reference(node, ctx.source) else {
        return false;
    };
    if reference
        .segments
        .first()
        .is_none_or(|root| bindings.is_shadowed(root))
    {
        return true;
    }
    let lexical_root = reference
        .segments
        .first()
        .and_then(|root| ctx.lexically_visible_object(node.start_byte(), root));
    let class_fqn = ctx.types.resolve_qualified_stable_type_at(
        ctx.scala,
        &ctx.resolver,
        &reference.segments,
        false,
        lexical_root.clone(),
    );
    let object_fqn = ctx.types.resolve_qualified_stable_type_at(
        ctx.scala,
        &ctx.resolver,
        &reference.segments,
        true,
        lexical_root,
    );
    if class_fqn.is_none()
        && reference.role == ScalaQualifiedStableTypeRole::Type
        && let Some((member, owner_segments)) = reference.segments.split_last()
    {
        let owner_lexical_root = owner_segments
            .first()
            .and_then(|root| ctx.lexically_visible_object(node.start_byte(), root));
        if let Some(owner) = ctx.types.resolve_qualified_stable_type_at(
            ctx.scala,
            &ctx.resolver,
            owner_segments,
            true,
            owner_lexical_root,
        ) && let FieldResolution::Resolved(field) = ctx
            .types
            .stable_type_member_for_owner(ctx.scala, &owner, member)
        {
            ctx.record(field.declaration.fq_name(), node);
        }
        return true;
    }
    if reference.role == ScalaQualifiedStableTypeRole::Type {
        if let Some(fqn) = class_fqn.or(object_fqn) {
            ctx.record(fqn, node);
        }
        return true;
    }
    if class_fqn.is_none() && object_fqn.is_none() {
        return true;
    }
    let role = match reference.role {
        ScalaQualifiedStableTypeRole::Constructor => TypeApplicationRole::ExplicitConstructor,
        ScalaQualifiedStableTypeRole::Apply => TypeApplicationRole::BareApplication,
        ScalaQualifiedStableTypeRole::Extractor => TypeApplicationRole::Extractor,
        ScalaQualifiedStableTypeRole::Type => unreachable!(),
    };
    let name = reference
        .segments
        .last()
        .expect("qualified Scala reference has a terminal segment");
    let resolution = ctx.types.resolve_type_application(
        ctx.scala,
        &ctx.resolver,
        class_fqn.as_deref(),
        object_fqn.as_deref(),
        name,
        call_arities_for_reference(reference.expression).as_deref(),
        role,
    );
    if let Some(target) = resolution.type_target {
        ctx.record(target.fq_name(), node);
    } else if let Some(object) = object_fqn {
        ctx.record(object, node);
    }
    for callable in resolution.callable_targets {
        ctx.record(callable.fq_name(), node);
    }
    true
}

fn companion_method_value_context(
    node: Node<'_>,
    ctx: &ScalaScan<'_, '_>,
    bindings: &LocalInferenceEngine<ScalaBinding>,
) -> ScalaMethodValueContext {
    if let Some(definition) = node.parent()
        && matches!(definition.kind(), "val_definition" | "var_definition")
        && definition.child_by_field_name("value") == Some(node)
    {
        let Some(type_node) = definition.child_by_field_name("type") else {
            return ScalaMethodValueContext::Unknown;
        };
        if type_node.kind() != "function_type" {
            return ScalaMethodValueContext::Incompatible;
        }
        let Some(parameter_types) = type_node.child_by_field_name("parameter_types") else {
            return ScalaMethodValueContext::Incompatible;
        };
        let mut cursor = parameter_types.walk();
        return ScalaMethodValueContext::Function(
            parameter_types.named_children(&mut cursor).count(),
        );
    }
    call_parameter_method_value_context(node, ctx, bindings)
}

fn call_parameter_method_value_context(
    node: Node<'_>,
    ctx: &ScalaScan<'_, '_>,
    bindings: &LocalInferenceEngine<ScalaBinding>,
) -> ScalaMethodValueContext {
    let Some(arguments) = node.parent() else {
        return ScalaMethodValueContext::Unknown;
    };
    if arguments.kind() != "arguments" {
        return ScalaMethodValueContext::Unknown;
    }
    let mut arguments_cursor = arguments.walk();
    let Some(parameter_index) = arguments
        .named_children(&mut arguments_cursor)
        .position(|argument| argument == node)
    else {
        return ScalaMethodValueContext::Unknown;
    };
    let Some(call) = arguments.parent() else {
        return ScalaMethodValueContext::Unknown;
    };
    if call.kind() != "call_expression" || call.child_by_field_name("arguments") != Some(arguments)
    {
        return ScalaMethodValueContext::Unknown;
    }

    let mut parameter_list = 0usize;
    let Some(mut function) = call.child_by_field_name("function") else {
        return ScalaMethodValueContext::Unknown;
    };
    while function.kind() == "call_expression" {
        parameter_list += 1;
        let Some(inner) = function.child_by_field_name("function") else {
            return ScalaMethodValueContext::Unknown;
        };
        function = inner;
    }
    if function.kind() == "generic_function" {
        let Some(inner) = function.child_by_field_name("function") else {
            return ScalaMethodValueContext::Unknown;
        };
        function = inner;
    }
    if !matches!(function.kind(), "identifier" | "operator_identifier") {
        return ScalaMethodValueContext::Unknown;
    }
    let function_name = node_text(function, ctx.source).trim();
    if function_name.is_empty() {
        return ScalaMethodValueContext::Unknown;
    }
    if bindings.is_shadowed(function_name) {
        return ScalaMethodValueContext::Incompatible;
    }
    let Some(call_arities) = call_arities_for_reference(function) else {
        return ScalaMethodValueContext::Unknown;
    };
    let Some(owner) = ctx.enclosing_class_unit(function.start_byte()) else {
        return ScalaMethodValueContext::Unknown;
    };
    let methods = match ctx.types.bare_member_declarations_for_owner(
        ctx.scala,
        owner,
        function_name,
        Some(&call_arities),
    ) {
        BareMemberResolution::Resolved(methods) => methods,
        BareMemberResolution::NoMatch => {
            let Some(imported) = ctx.resolver.resolve_member(function_name) else {
                return ScalaMethodValueContext::Unknown;
            };
            ctx.scala
                .definitions(&imported)
                .filter(CodeUnit::is_function)
                .collect()
        }
        BareMemberResolution::Unresolved => return ScalaMethodValueContext::Incompatible,
    };
    if methods.is_empty() {
        return ScalaMethodValueContext::Incompatible;
    }

    let mut resolved = None;
    for method in methods {
        let Some(arity) = ctx.types.callable_parameter_function_arity(
            ctx.scala,
            &method,
            &call_arities,
            parameter_list,
            parameter_index,
        ) else {
            return ScalaMethodValueContext::Incompatible;
        };
        if resolved.is_some_and(|resolved| resolved != arity) {
            return ScalaMethodValueContext::Incompatible;
        }
        resolved = Some(arity);
    }
    resolved.map_or(
        ScalaMethodValueContext::Incompatible,
        ScalaMethodValueContext::Function,
    )
}

fn record_ordinary_class_methods(
    owner_fq_name: &str,
    member: &str,
    call_arities: Option<&[usize]>,
    node: Node<'_>,
    ctx: &mut ScalaScan<'_, '_>,
) -> bool {
    let mut owners = ctx
        .types
        .index
        .by_fqn(owner_fq_name)
        .iter()
        .filter(|owner| owner.is_class());
    let Some(owner) = owners.next() else {
        return false;
    };
    if owners.next().is_some() {
        return true;
    }
    match ctx.types.ordinary_class_member_declarations_for_owner(
        ctx.scala,
        owner,
        member,
        call_arities,
    ) {
        BareMemberResolution::Resolved(methods) => {
            for method in methods {
                ctx.record(method.fq_name(), node);
            }
            true
        }
        BareMemberResolution::Unresolved => true,
        BareMemberResolution::NoMatch => false,
    }
}

fn record_lexically_visible_call(
    node: Node<'_>,
    member: &str,
    call_arities: Option<&[usize]>,
    ctx: &mut ScalaScan<'_, '_>,
) -> bool {
    for declaration in enclosing_template_declarations(node) {
        if let Some(owner) = ctx
            .class_ranges
            .unit_for_exact_span(declaration.start_byte(), declaration.end_byte())
        {
            match ctx.types.effective_method_declarations_for_owner(
                ctx.scala,
                &owner.fq_name(),
                member,
                call_arities,
            ) {
                BareMemberResolution::Resolved(methods) => {
                    for method in methods {
                        ctx.record(method.fq_name(), node);
                    }
                    return true;
                }
                BareMemberResolution::Unresolved => return true,
                BareMemberResolution::NoMatch => {}
            }
        }
        match ordinary_class_member_declarations_for_template(
            declaration,
            member,
            call_arities,
            ctx,
        ) {
            BareMemberResolution::Resolved(methods) => {
                for method in methods {
                    ctx.record(method.fq_name(), node);
                }
                return true;
            }
            BareMemberResolution::Unresolved => return true,
            BareMemberResolution::NoMatch => {}
        }
        if let Some(self_owner) = template_self_type(declaration)
            .and_then(|type_node| resolve_receiver_type_node(type_node, ctx))
            && record_ordinary_class_methods(&self_owner, member, call_arities, node, ctx)
        {
            return true;
        }
    }
    false
}

fn record_lexically_visible_parameterless_method(
    node: Node<'_>,
    member: &str,
    ctx: &mut ScalaScan<'_, '_>,
) -> bool {
    if ctx
        .lexically_visible_object(node.start_byte(), member)
        .is_some()
    {
        return false;
    }
    for declaration in enclosing_template_declarations(node) {
        match ordinary_class_member_declarations_for_template(declaration, member, None, ctx) {
            BareMemberResolution::Resolved(methods) => {
                for method in methods {
                    ctx.record(method.fq_name(), node);
                }
                return true;
            }
            BareMemberResolution::Unresolved => return true,
            BareMemberResolution::NoMatch => {}
        }
        if let Some(self_owner) = template_self_type(declaration)
            .and_then(|type_node| resolve_receiver_type_node(type_node, ctx))
            && record_ordinary_class_methods(&self_owner, member, None, node, ctx)
        {
            return true;
        }
    }
    false
}

fn ordinary_class_member_declarations_for_template(
    declaration: Node<'_>,
    member: &str,
    call_arities: Option<&[usize]>,
    ctx: &ScalaScan<'_, '_>,
) -> BareMemberResolution {
    if let Some(owner) = ctx
        .class_ranges
        .unit_for_exact_span(declaration.start_byte(), declaration.end_byte())
    {
        return ctx.types.ordinary_class_member_declarations_for_owner(
            ctx.scala,
            owner,
            member,
            call_arities,
        );
    }
    if template_direct_term_member_named(declaration, member, ctx.source) {
        return BareMemberResolution::Unresolved;
    }
    let Some(owners) = template_supertype_owners(declaration, ctx) else {
        return BareMemberResolution::Unresolved;
    };
    if owners.is_empty() {
        BareMemberResolution::NoMatch
    } else {
        ctx.types.ordinary_class_member_declarations_for_owners(
            ctx.scala,
            &owners,
            member,
            call_arities,
        )
    }
}

fn template_supertype_owners(
    declaration: Node<'_>,
    ctx: &ScalaScan<'_, '_>,
) -> Option<Vec<CodeUnit>> {
    let mut owners = Vec::new();
    for (_, lookup_node) in scala_supertype_lookup_nodes(declaration) {
        let fqn = resolve_receiver_type_node(lookup_node, ctx)?;
        let mut declarations = ctx
            .types
            .index
            .by_fqn(&fqn)
            .iter()
            .filter(|unit| unit.is_class());
        let owner = declarations.next()?;
        if declarations.next().is_some() {
            return None;
        }
        owners.push(owner.clone());
    }
    Some(owners)
}

/// The fqn of a receiver expression's type, for the shapes that resolve without
/// return-type inference.
fn receiver_type_fqn(
    receiver: Node<'_>,
    ctx: &ScalaScan<'_, '_>,
    bindings: &LocalInferenceEngine<ScalaBinding>,
) -> Option<String> {
    match receiver.kind() {
        // `this` is a plain `identifier` in tree-sitter-scala (not its own node).
        "identifier" => {
            let name = node_text(receiver, ctx.source);
            if name == "this" {
                return ctx
                    .enclosing_class(receiver.start_byte())
                    .map(str::to_string);
            }
            // A typed local resolves to its type; otherwise the name may be an
            // object/type, unless it is a known (shadowed) untyped local.
            first_precise(bindings, name)
                .and_then(|binding| binding.receiver_type)
                .or_else(|| {
                    if bindings.is_shadowed(name) {
                        return None;
                    }
                    let owner = ctx.enclosing_class(receiver.start_byte())?;
                    match ctx.types.field_for_owner_member(ctx.scala, owner, name) {
                        FieldResolution::Resolved(field) => field.declared_type,
                        FieldResolution::NoMatch | FieldResolution::Unresolved => None,
                    }
                })
                .or_else(|| {
                    (!bindings.is_shadowed(name)).then(|| {
                        ctx.resolver.resolve_member(name).and_then(|method| {
                            ctx.types
                                .member_return_type(ctx.scala, &ctx.resolver, &method)
                        })
                    })?
                })
                .or_else(|| {
                    (!bindings.is_shadowed(name)).then(|| {
                        ctx.resolver
                            .resolve_object(name)
                            .or_else(|| ctx.resolver.resolve(name))
                    })?
                })
        }
        "field_expression" => stable_object_expression_fqn(receiver, ctx, bindings).or_else(|| {
            let value = receiver.child_by_field_name("value")?;
            let field = receiver.child_by_field_name("field")?;
            let owner = receiver_type_fqn(value, ctx, bindings)?;
            let member = node_text(field, ctx.source).trim();
            if member.is_empty() {
                return None;
            }
            match ctx.types.field_for_owner_member(ctx.scala, &owner, member) {
                FieldResolution::Resolved(field) => field.declared_type,
                FieldResolution::NoMatch | FieldResolution::Unresolved => None,
            }
        }),
        "instance_expression" => constructed_type(receiver, ctx),
        "call_expression" => call_result_type(receiver, ctx, bindings),
        kind => scala_literal_type_name(kind).map(str::to_string),
    }
}

fn stable_object_expression_fqn(
    node: Node<'_>,
    ctx: &ScalaScan<'_, '_>,
    bindings: &LocalInferenceEngine<ScalaBinding>,
) -> Option<String> {
    resolve_stable_object_expression(
        node,
        ctx.source,
        |root| {
            (bindings.resolve_symbol(root).is_unknown() && !bindings.is_shadowed(root))
                .then(|| ctx.resolver.resolve_object(root))
                .flatten()
        },
        |owner, member| ctx.types.exact_nested_object(ctx.scala, owner, member),
    )
}

fn seed_declaration(
    node: Node<'_>,
    ctx: &ScalaScan<'_, '_>,
    bindings: &mut LocalInferenceEngine<ScalaBinding>,
) {
    match node.kind() {
        "class_definition" | "object_definition" | "trait_definition" | "enum_definition" => {
            seed_class_parameters(node, ctx, bindings);
            preseed_direct_owner_fields(node, ctx, bindings);
        }
        "function_definition" => seed_parameters(node, ctx, bindings),
        "val_definition" | "var_definition" => seed_value_definition(node, ctx, bindings),
        _ => {}
    }
}

fn record_override_declaration(node: Node<'_>, ctx: &mut ScalaScan<'_, '_>) {
    if !matches!(node.kind(), "function_definition" | "function_declaration") {
        return;
    }
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let name = node_text(name_node, ctx.source).trim();
    if name.is_empty() {
        return;
    }
    let Some(owner) = ctx.enclosing_class(name_node.start_byte()) else {
        return;
    };
    let method_fqn = format!("{owner}.{name}");
    let targets = ctx.types.override_targets_for_method(
        ctx.scala,
        owner,
        &method_fqn,
        name,
        function_definition_arity(node, ctx.source),
    );
    for target in targets.iter().cloned() {
        ctx.record_with_caller(method_fqn.clone(), target, name_node);
    }
}

fn function_definition_arity(node: Node<'_>, source: &str) -> Option<usize> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| child.kind() == "parameters")
        .and_then(|parameters| parenthesized_arity(node_text(parameters, source)))
        .or(Some(0))
}

fn seed_parameters(
    node: Node<'_>,
    ctx: &ScalaScan<'_, '_>,
    bindings: &mut LocalInferenceEngine<ScalaBinding>,
) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() != "parameters" {
            continue;
        }
        let mut inner = child.walk();
        for parameter in child.named_children(&mut inner) {
            if parameter.kind() == "parameter" {
                seed_parameter(parameter, ctx, None, bindings);
            }
        }
    }
}

fn seed_class_parameters(
    node: Node<'_>,
    ctx: &ScalaScan<'_, '_>,
    bindings: &mut LocalInferenceEngine<ScalaBinding>,
) {
    let owner = ctx.enclosing_class(node.start_byte()).map(str::to_string);
    let mut cursor = node.walk();
    for parameters in node
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "class_parameters")
    {
        let mut parameter_cursor = parameters.walk();
        for parameter in parameters.named_children(&mut parameter_cursor) {
            if parameter.kind() == "class_parameter" {
                let declaration_owner = scala_class_parameter_field_keyword(parameter)
                    .is_some()
                    .then(|| owner.clone())
                    .flatten();
                seed_parameter(parameter, ctx, declaration_owner, bindings);
            }
        }
    }
}

fn seed_parameter(
    parameter: Node<'_>,
    ctx: &ScalaScan<'_, '_>,
    declaration_owner: Option<String>,
    bindings: &mut LocalInferenceEngine<ScalaBinding>,
) {
    let Some(name) = parameter.child_by_field_name("name") else {
        return;
    };
    let binding_name = node_text(name, ctx.source).trim();
    if binding_name.is_empty() {
        return;
    }
    let resolved = parameter
        .child_by_field_name("type")
        .and_then(|type_node| resolve_receiver_type_node(type_node, ctx));
    seed_binding(binding_name, resolved, declaration_owner, bindings);
}

fn preseed_direct_owner_fields(
    node: Node<'_>,
    ctx: &ScalaScan<'_, '_>,
    bindings: &mut LocalInferenceEngine<ScalaBinding>,
) {
    let Some(owner) = ctx.enclosing_class(node.start_byte()).map(str::to_string) else {
        return;
    };
    let mut cursor = node.walk();
    for body in node
        .named_children(&mut cursor)
        .filter(|child| matches!(child.kind(), "template_body" | "enum_body"))
    {
        preseed_owner_fields_in(body, ctx, &owner, bindings);
    }
}

fn preseed_owner_fields_in(
    node: Node<'_>,
    ctx: &ScalaScan<'_, '_>,
    owner: &str,
    bindings: &mut LocalInferenceEngine<ScalaBinding>,
) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "val_definition" | "var_definition" => {
                if direct_owner_field_owner(child, ctx).as_deref() == Some(owner) {
                    seed_value_definition_with_owner(child, ctx, Some(owner.to_string()), bindings);
                }
            }
            "function_definition"
            | "function_declaration"
            | "class_definition"
            | "object_definition"
            | "trait_definition"
            | "enum_definition"
            | "block"
            | "indented_block"
            | "case_clause"
            | "lambda_expression" => {}
            _ => preseed_owner_fields_in(child, ctx, owner, bindings),
        }
    }
}

fn seed_value_definition(
    node: Node<'_>,
    ctx: &ScalaScan<'_, '_>,
    bindings: &mut LocalInferenceEngine<ScalaBinding>,
) {
    let declaration_owner = direct_owner_field_owner(node, ctx);
    seed_value_definition_with_owner(node, ctx, declaration_owner, bindings);
}

fn seed_value_definition_with_owner(
    node: Node<'_>,
    ctx: &ScalaScan<'_, '_>,
    declaration_owner: Option<String>,
    bindings: &mut LocalInferenceEngine<ScalaBinding>,
) {
    // Prefer the declared type; otherwise infer from a `new Foo()` initializer
    // or a call with a declared factory return.
    let resolved = node
        .child_by_field_name("type")
        .and_then(|type_node| resolve_receiver_type_node(type_node, ctx))
        .or_else(|| {
            node.child_by_field_name("value")
                .and_then(|value| constructed_or_applied_type(value, ctx))
        })
        .or_else(|| {
            node.child_by_field_name("value")
                .and_then(|value| call_result_type(value, ctx, bindings))
        });
    let Some(pattern) = node.child_by_field_name("pattern") else {
        return;
    };
    for name in pattern_names(pattern, ctx.source) {
        seed_binding(name, resolved.clone(), declaration_owner.clone(), bindings);
    }
}

fn direct_owner_field_owner(node: Node<'_>, ctx: &ScalaScan<'_, '_>) -> Option<String> {
    let owner = ctx.enclosing_class(node.start_byte())?.to_string();
    let mut current = node.parent();
    while let Some(ancestor) = current {
        match ancestor.kind() {
            "template_body" | "enum_body" => return Some(owner),
            "function_definition"
            | "block"
            | "indented_block"
            | "case_clause"
            | "lambda_expression"
            | "class_definition"
            | "object_definition"
            | "trait_definition"
            | "enum_definition" => return None,
            _ => current = ancestor.parent(),
        }
    }
    None
}

/// The fqn of the type constructed by a `new Foo()` value expression.
fn constructed_type(node: Node<'_>, ctx: &ScalaScan<'_, '_>) -> Option<String> {
    if node.kind() != "instance_expression" {
        return None;
    }
    let mut cursor = node.walk();
    let type_node = node
        .named_children(&mut cursor)
        .find(|child| !matches!(child.kind(), "arguments" | "template_body"))?;
    let path = scala_type_lookup_segments(type_node, ctx.source);
    let name = path.last()?;
    let class_fqn = resolve_receiver_type_node(type_node, ctx)?;
    ctx.types
        .resolve_type_application(
            ctx.scala,
            &ctx.resolver,
            Some(&class_fqn),
            None,
            name,
            call_arities_for_reference(type_node).as_deref(),
            TypeApplicationRole::ExplicitConstructor,
        )
        .type_target
        .map(|target| target.fq_name())
}

fn constructed_or_applied_type(node: Node<'_>, ctx: &ScalaScan<'_, '_>) -> Option<String> {
    constructed_type(node, ctx).or_else(|| {
        if node.kind() != "call_expression" {
            return None;
        }
        let function = node.child_by_field_name("function")?;
        if !matches!(function.kind(), "identifier" | "type_identifier") {
            return None;
        }
        let name = node_text(function, ctx.source).trim();
        if name.is_empty() {
            return None;
        }
        let class_fqn = ctx
            .lexically_visible_type(function.start_byte(), name)
            .or_else(|| ctx.resolver.resolve(name));
        let object_fqn = ctx
            .lexically_visible_object(function.start_byte(), name)
            .or_else(|| ctx.resolver.resolve_object(name));
        ctx.types
            .resolve_type_application(
                ctx.scala,
                &ctx.resolver,
                class_fqn.as_deref(),
                object_fqn.as_deref(),
                name,
                call_arities_for_reference(function).as_deref(),
                TypeApplicationRole::BareApplication,
            )
            .type_target
            .map(|target| target.fq_name())
    })
}

fn call_result_type(
    node: Node<'_>,
    ctx: &ScalaScan<'_, '_>,
    bindings: &LocalInferenceEngine<ScalaBinding>,
) -> Option<String> {
    if node.kind() != "call_expression" {
        return None;
    }
    let function = node.child_by_field_name("function")?;
    match function.kind() {
        "field_expression" => {
            let receiver = function.child_by_field_name("value")?;
            let field = function.child_by_field_name("field")?;
            let owner = receiver_type_fqn(receiver, ctx, bindings)?;
            let method = node_text(field, ctx.source);
            let call_arities = call_arities_for_reference(field);
            ctx.types.member_return_type_for_owner_member(
                ctx.scala,
                &ctx.resolver,
                &owner,
                method,
                call_arities.as_deref(),
            )
        }
        "identifier" => {
            let method = node_text(function, ctx.source);
            let call_arities = call_arities_for_reference(function);
            match lexically_visible_unqualified_member_return_type(
                function,
                method,
                call_arities.as_deref(),
                ctx,
            ) {
                MemberReturnResolution::Resolved(return_type) => Some(return_type),
                MemberReturnResolution::NoMatch => {
                    ctx.resolver.resolve_member(method).and_then(|member| {
                        ctx.types
                            .member_return_type(ctx.scala, &ctx.resolver, &member)
                    })
                }
                MemberReturnResolution::Unresolved => None,
            }
        }
        _ => None,
    }
}

fn lexically_visible_unqualified_member_return_type(
    node: Node<'_>,
    member: &str,
    call_arities: Option<&[usize]>,
    ctx: &ScalaScan<'_, '_>,
) -> MemberReturnResolution {
    for declaration in enclosing_template_declarations(node) {
        let resolution = if let Some(owner) = ctx
            .class_ranges
            .unit_for_exact_span(declaration.start_byte(), declaration.end_byte())
        {
            ctx.types.unqualified_member_return_type(
                ctx.scala,
                &ctx.resolver,
                owner,
                member,
                call_arities,
            )
        } else if template_direct_term_member_named(declaration, member, ctx.source) {
            MemberReturnResolution::Unresolved
        } else {
            let Some(owners) = template_supertype_owners(declaration, ctx) else {
                return MemberReturnResolution::Unresolved;
            };
            ctx.types.unqualified_member_return_type_for_owners(
                ctx.scala,
                &ctx.resolver,
                &owners,
                member,
                call_arities,
            )
        };
        match resolution {
            MemberReturnResolution::NoMatch => {}
            resolution => return resolution,
        }
        let Some(self_owner) = template_self_type(declaration)
            .and_then(|type_node| resolve_receiver_type_node(type_node, ctx))
        else {
            continue;
        };
        let mut declarations = ctx
            .scala
            .definitions(&self_owner)
            .filter(CodeUnit::is_class);
        let Some(declaration) = declarations.next() else {
            continue;
        };
        if declarations.next().is_some() {
            return MemberReturnResolution::Unresolved;
        }
        match ctx.types.unqualified_member_return_type(
            ctx.scala,
            &ctx.resolver,
            &declaration,
            member,
            call_arities,
        ) {
            MemberReturnResolution::NoMatch => {}
            resolution => return resolution,
        }
    }
    MemberReturnResolution::NoMatch
}

fn pattern_names<'a>(node: Node<'_>, source: &'a str) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "identifier" | "operator_identifier" => {
                let name = node_text(node, source).trim();
                if !name.is_empty() {
                    out.push(name);
                }
            }
            "stable_identifier" => {}
            _ => {
                for index in (0..node.named_child_count()).rev() {
                    if let Some(child) = node.named_child(index) {
                        stack.push(child);
                    }
                }
            }
        }
    }
    out
}

fn seed_binding(
    name: &str,
    receiver_type: Option<String>,
    declaration_owner: Option<String>,
    bindings: &mut LocalInferenceEngine<ScalaBinding>,
) {
    if receiver_type.is_none() && declaration_owner.is_none() {
        bindings.declare_shadow(name.to_string());
        return;
    }
    bindings.seed_symbol(
        name.to_string(),
        ScalaBinding {
            receiver_type,
            declaration_owner,
        },
    );
}

fn exact_owner_field_binding(
    bindings: &LocalInferenceEngine<ScalaBinding>,
    name: &str,
) -> Option<String> {
    first_precise(bindings, name).and_then(|binding| binding.declaration_owner)
}

fn resolve_receiver_type_node(type_node: Node<'_>, ctx: &ScalaScan<'_, '_>) -> Option<String> {
    let path = scala_type_lookup_segments(type_node, ctx.source);
    if path.is_empty() {
        return None;
    }
    ctx.lexically_visible_type_path(type_node.start_byte(), &path)
        .or_else(|| {
            ctx.types
                .resolve_type_in_declaration_context(&ctx.resolver, &path)
        })
        .or_else(|| {
            (path.len() == 1)
                .then(|| scala_builtin_type_name(&path[0]).map(str::to_string))
                .flatten()
        })
}

fn visible_extensions(
    ctx: &ScalaScan<'_, '_>,
    member: &str,
    receiver_owner: Option<&str>,
    call_arities: Option<&[usize]>,
) -> Vec<ExtensionMethod> {
    let mut matches = Vec::new();
    for method in ctx
        .resolver
        .visible_extension_methods(ctx.scala, ctx.types, member)
    {
        if method.alternatives.iter().any(|alternative| {
            extension_alternative_receiver_matches(&ctx.resolver, alternative, receiver_owner)
        }) {
            matches.push(method);
        }
    }
    matches.sort_by(|left, right| left.fqn.cmp(&right.fqn));
    matches.dedup_by(|left, right| left.fqn == right.fqn);
    let callable_count = matches
        .iter()
        .flat_map(|method| method.alternatives.iter())
        .count();
    let unique_callable = callable_count == 1;
    matches.retain(|method| {
        method.alternatives.iter().any(|alternative| {
            extension_alternative_receiver_matches(&ctx.resolver, alternative, receiver_owner)
                && callable_shape_matches(&alternative.shape, call_arities, unique_callable)
        })
    });
    matches
}

fn extension_alternative_receiver_matches(
    resolver: &NameResolver,
    alternative: &CallableAlternative,
    receiver_owner: Option<&str>,
) -> bool {
    scala_extension_receiver_matches_resolved(
        alternative.extension_receiver_type.as_deref(),
        receiver_owner,
        |type_text| {
            resolver
                .resolve(type_text)
                .or_else(|| scala_builtin_type_name(type_text).map(str::to_string))
        },
    )
}

fn has_ancestor_kind(node: Node<'_>, kind: &str) -> bool {
    let mut parent = node.parent();
    while let Some(current) = parent {
        if current.kind() == kind {
            return true;
        }
        parent = current.parent();
    }
    false
}
