//! Whole-workspace inverted edge builder for Scala.
//!
//! Walks each file once and resolves every reference to the callee fqn it names,
//! via the shared [`build_edges`] driver. Scala has no single `resolve_type_name`
//! primitive, so name->fqn resolution is rebuilt here by mirroring the forward
//! scanner's visibility model: a per-file [`NameResolver`] maps a
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

use super::local::{
    ScalaLocalBinding, precise_scala_binding, seed_scala_binding,
    seed_scala_binding_with_receiver_declaration,
};
use super::namespace::{
    ScalaDirectAncestorResolution, ScalaQualifiedTypeRootBinding, ScalaQualifiedTypeRootResolution,
    ScalaTypeNamespaceResolution, ScalaUnindexedTypeBinding, resolve_exact_lexical_type_namespace,
    scala_anonymous_instance_for_template, scala_nearest_unindexed_type_binding,
    scala_qualified_type_root, scala_type_reference_is_singleton,
};
use super::resolver::{
    preferred_scala_type, scala_builtin_type_name, scala_extension_receiver_matches_resolved,
    scala_literal_type_name, scala_normalized_fq_name,
};
use super::shared::ScalaEdgeGraph;
use super::syntax::{
    ScalaCallSiteShape, ScalaCallableParameterList, ScalaCallableRole, ScalaCallableSiteRole,
    ScalaCallableUsePolicy, ScalaFunctionParameterShape, ScalaGenericOwnerSourceFacts,
    ScalaImportContextIndex, ScalaMethodValueContext, ScalaPackageContextIndex,
    ScalaParameterTypeIdentity, ScalaQualifiedStableTypeRole, ScalaSourceFacts,
    ScalaTypeExpressionPath, call_arities_for_reference, call_site_shape_for_reference,
    enclosing_template_declarations, intermediate_field_qualifier_reference,
    invocation_function_reference, is_bare_companion_method_value_reference,
    is_call_function_reference, is_constructor_like_reference, is_declaration_name,
    is_extractor_reference, is_field_expression_value, is_identifier_node,
    is_infix_pattern_operator, is_owner_qualified_this, is_scala_case_pattern_binder,
    is_scala_class_reference, is_scala_named_argument_assignment, is_scala_object_reference,
    is_semantic_call_argument, is_stable_type_qualifier, is_terminal_stable_field_reference,
    named_argument_invocation_owner, node_text, parenthesized_arity,
    qualified_stable_type_reference, resolve_stable_object_expression,
    scala_callable_alternative_is_candidate, scala_callable_alternative_matches,
    scala_callable_shape_matches, scala_import_is_visible_at_byte, scala_pattern_binder_names,
    scala_source_facts, scala_union_type_alternative_paths, stable_identifier_prefix_reference,
    stable_identifier_reference, template_direct_term_member_named, template_self_type,
    terminal_invocation_owner_name,
};
use crate::analyzer::scala::imports::scala_import_infos_from_node;
use crate::analyzer::scala::{
    ScalaAdapter, ScalaExplicitImportFacts, ScalaExplicitImportTier, ScalaExportSelector,
    ScalaSupertypeLookupPath, ScalaWildcardOwnerFacts, resolve_scala_explicit_import_tier,
    resolve_scala_wildcard_import_environment, scala_class_parameter_field_keyword,
    scala_enclosing_package_root_candidates, scala_import_path, scala_import_path_candidates,
    scala_normalize_full_name, scala_simple_type_name, scala_supertype_lookup_nodes,
    scala_type_lookup_segments,
};
use crate::analyzer::tree_sitter_analyzer::FileState;
use crate::analyzer::usage_facts::CallableFacts;
use crate::analyzer::usages::inverted_edges::{
    ClassRangeIndex, EdgeCollector, UsageEdgeBuildOutput, UsageReferenceKind, build_edge_output,
    build_file_declarations_from_state, classify_reference_node,
    parse_source_and_collect_with_declarations,
};
use crate::analyzer::usages::local_inference::{LocalInferenceConfig, LocalInferenceEngine};
use crate::analyzer::usages::model::UsageHitKind;
use crate::analyzer::{
    CallableArity, CodeUnit, GlobalUsageDefinitionIndex, Range, UsageFactsIndex,
};
use crate::analyzer::{
    IAnalyzer, ImportAnalysisProvider, ProjectFile, ScalaAnalyzer, TypeHierarchyProvider,
};
use crate::hash::{HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock};
use tree_sitter::{Node, Parser};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) enum ScalaReferenceRole {
    Type,
    Callable,
    CompanionApplication,
    CompanionExtractor,
    CompanionValue,
    Field,
    StableObject,
    Override,
}

#[derive(Clone, Debug)]
pub(super) enum ScalaResolvedReference {
    Exact(CodeUnit),
    Logical(String),
}

pub(super) trait ScalaReferenceSink {
    fn may_match_name(&self, _name: &str) -> bool {
        true
    }

    fn register_imports(&mut self, _imports: &[crate::analyzer::ImportInfo]) {}

    fn record(
        &mut self,
        target: ScalaResolvedReference,
        role: ScalaReferenceRole,
        reference_kind: UsageReferenceKind,
        hit_kind: UsageHitKind,
        start: usize,
        end: usize,
    );

    fn record_callable(
        &mut self,
        target: ScalaResolvedReference,
        call_shape: &ScalaCallSiteShape,
        reference_kind: UsageReferenceKind,
        hit_kind: UsageHitKind,
        start: usize,
        end: usize,
    ) {
        let _ = call_shape;
        self.record(
            target,
            ScalaReferenceRole::Callable,
            reference_kind,
            hit_kind,
            start,
            end,
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn record_with_caller(
        &mut self,
        _caller: String,
        target: ScalaResolvedReference,
        role: ScalaReferenceRole,
        reference_kind: UsageReferenceKind,
        hit_kind: UsageHitKind,
        start: usize,
        end: usize,
    ) {
        self.record(target, role, reference_kind, hit_kind, start, end);
    }

    fn record_unproven_name(&mut self, _name: &str, _start: usize, _end: usize) {}

    fn record_import_name(
        &mut self,
        _imports: &[crate::analyzer::ImportInfo],
        _active_package: &str,
        _name: &str,
        _start: usize,
        _end: usize,
    ) {
    }

    #[allow(clippy::too_many_arguments)]
    fn record_exact_owner_member(
        &mut self,
        _owner: CodeUnit,
        _member: &str,
        _role: ScalaReferenceRole,
        _reference_kind: UsageReferenceKind,
        _hit_kind: UsageHitKind,
        _start: usize,
        _end: usize,
    ) {
    }

    fn should_stop(&self) -> bool {
        false
    }
}

type PackageTypeEntries = Arc<Vec<(String, CodeUnit)>>;
type CachedScalaSourceFacts = Arc<ScalaSourceFacts>;
type ScalaSourceFactsCell = Arc<OnceLock<CachedScalaSourceFacts>>;
pub(crate) type CachedCallableAlternatives = Arc<Vec<CallableAlternative>>;
type CallableAlternativesCell = Arc<OnceLock<CachedCallableAlternatives>>;
type ExtensionOwnerMemberKey = (String, String);
type ExtensionMethodEntries = Arc<Vec<ExtensionMethod>>;
type OverrideTargetEntries = Arc<Vec<CodeUnit>>;

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
    pub(super) value_result: Option<ScalaValueOwner>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum ScalaValueOwner {
    Exact(CodeUnit),
    Logical(String),
}

struct ScalaCallableValueResolution {
    callable_targets: Vec<CodeUnit>,
    value_result: Option<ScalaValueOwner>,
}

enum ScalaCallableTierResolution {
    NoApplicableCallable,
    Applicable(Option<ScalaCallableValueResolution>),
}

enum ScalaApplyValueResolution {
    NoDeclaration,
    NoApplicableCallable,
    Authoritative(Option<ScalaCallableValueResolution>),
}

/// Every type-namespace declaration the project exposes, indexed for the
/// per-file name->fqn rebuild. Built once and shared across all files' scans.
pub(crate) struct ProjectTypes {
    index: Arc<GlobalUsageDefinitionIndex>,
    type_aliases: Arc<HashSet<CodeUnit>>,
    facts: Arc<UsageFactsIndex>,
    direct_ancestors_by_owner: Option<HashMap<String, Vec<CodeUnit>>>,
    direct_ancestors_by_unit: Option<HashMap<CodeUnit, Vec<CodeUnit>>>,
    ambiguous_direct_ancestor_owners: Option<HashSet<CodeUnit>>,
    structural_parent_by_unit: Option<HashMap<CodeUnit, CodeUnit>>,
    scala_trait_fqns: Option<HashSet<String>>,
    package_types_by_package: Mutex<HashMap<String, PackageTypeEntries>>,
    package_objects_by_package: Mutex<HashMap<String, PackageTypeEntries>>,
    nested_types_by_owner: Mutex<HashMap<String, PackageTypeEntries>>,
    nested_objects_by_owner: Mutex<HashMap<String, PackageTypeEntries>>,
    source_facts_by_file: Mutex<HashMap<ProjectFile, ScalaSourceFactsCell>>,
    bulk_file_states: Option<HashMap<ProjectFile, FileState>>,
    callable_alternatives_by_unit: Mutex<HashMap<CodeUnit, CallableAlternativesCell>>,
    effective_callable_alternatives_by_unit: Mutex<HashMap<CodeUnit, CallableAlternativesCell>>,
    extension_methods_by_owner_member:
        Mutex<HashMap<ExtensionOwnerMemberKey, ExtensionMethodEntries>>,
    override_targets_by_method: Mutex<HashMap<String, OverrideTargetEntries>>,
    exported_member_bindings_by_owner: Mutex<HashMap<String, Vec<(String, String)>>>,
}

#[derive(Clone, Copy)]
enum ScalaCallMatch<'a> {
    Arities(Option<&'a [usize]>),
    Shape(&'a ScalaCallSiteShape),
}

impl ScalaCallMatch<'_> {
    fn is_unapplied(self) -> bool {
        match self {
            Self::Arities(call_arities) => call_arities.is_none(),
            Self::Shape(shape) => shape.lists.is_empty(),
        }
    }
}

fn sorted_unique_units(mut units: Vec<CodeUnit>) -> Vec<CodeUnit> {
    units.sort();
    units.dedup();
    units
}

impl ProjectTypes {
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
        let type_aliases = Arc::new(
            file_states
                .values()
                .flat_map(|state| state.type_aliases.iter().cloned())
                .collect(),
        );
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
        let structural_parent_by_unit = file_states
            .values()
            .flat_map(|state| {
                state.children.iter().flat_map(|(parent, children)| {
                    children
                        .iter()
                        .cloned()
                        .map(|child| (child, parent.clone()))
                })
            })
            .collect();
        let mut types = Self {
            index,
            type_aliases,
            facts,
            direct_ancestors_by_owner: Some(HashMap::default()),
            direct_ancestors_by_unit: Some(HashMap::default()),
            ambiguous_direct_ancestor_owners: Some(HashSet::default()),
            structural_parent_by_unit: Some(structural_parent_by_unit),
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
            effective_callable_alternatives_by_unit: Mutex::new(HashMap::default()),
            extension_methods_by_owner_member: Mutex::new(HashMap::default()),
            override_targets_by_method: Mutex::new(HashMap::default()),
            exported_member_bindings_by_owner: Mutex::new(HashMap::default()),
        };
        let (direct_ancestors_by_unit, ambiguous_direct_ancestor_owners) = types
            .resolve_direct_ancestors_from_file_states(
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
        types.ambiguous_direct_ancestor_owners = Some(ambiguous_direct_ancestor_owners);
        types
    }

    pub(crate) fn exact_direct_ancestors_snapshot(
        &self,
    ) -> Option<&HashMap<CodeUnit, Vec<CodeUnit>>> {
        self.direct_ancestors_by_unit.as_ref()
    }

    fn bulk_file_state(&self, file: &ProjectFile) -> Option<&FileState> {
        self.bulk_file_states.as_ref()?.get(file)
    }

    fn is_type_alias(&self, _scala: &ScalaAnalyzer, unit: &CodeUnit) -> bool {
        self.type_aliases.contains(unit)
    }

    /// Whether this field-shaped declaration identity also has a term-level
    /// declaration. Scala permits a type alias and a `val` with the same name
    /// in one owner; the analyzer intentionally coalesces those declarations
    /// into one CodeUnit while retaining both parser-recorded signatures.
    pub(super) fn has_term_field_declaration(&self, unit: &CodeUnit) -> bool {
        unit.is_field()
            && (!self.type_aliases.contains(unit)
                || self
                    .bulk_file_state(unit.source())
                    .and_then(|state| state.signatures.get(unit))
                    .is_some_and(|signatures| signatures.len() > 1))
    }

    fn is_exclusive_type_alias(&self, unit: &CodeUnit) -> bool {
        self.type_aliases.contains(unit) && !self.has_term_field_declaration(unit)
    }

    fn term_field_declaration_is_globally_unique(&self, unit: &CodeUnit) -> bool {
        self.index
            .by_fqn(&unit.fq_name())
            .iter()
            .filter(|candidate| self.has_term_field_declaration(candidate))
            .count()
            == 1
    }

    fn is_type_namespace_declaration(&self, unit: &CodeUnit) -> bool {
        unit.is_class() || self.type_aliases.contains(unit)
    }

    fn is_exact_structural_child(
        &self,
        scala: &ScalaAnalyzer,
        owner: &CodeUnit,
        unit: &CodeUnit,
    ) -> bool {
        match &self.structural_parent_by_unit {
            Some(parents) => parents.get(unit) == Some(owner),
            None => scala.structural_parent_of(unit).as_ref() == Some(owner),
        }
    }

    fn exact_structural_parent(&self, scala: &ScalaAnalyzer, unit: &CodeUnit) -> Option<CodeUnit> {
        match &self.structural_parent_by_unit {
            Some(parents) => parents.get(unit).cloned(),
            None => scala.structural_parent_of(unit),
        }
    }

    fn declaration_parent(&self, scala: &ScalaAnalyzer, unit: &CodeUnit) -> Option<CodeUnit> {
        match &self.structural_parent_by_unit {
            Some(parents) => parents.get(unit).cloned(),
            None => scala
                .structural_parent_of(unit)
                .or_else(|| scala.parent_of(unit)),
        }
    }

    pub(crate) fn exact_type_declaration_for_owner_context(
        &self,
        fqn: &str,
        owner: &CodeUnit,
    ) -> ScalaTypeNamespaceResolution {
        let candidates = sorted_unique_units(
            self.index
                .by_fqn(fqn)
                .iter()
                .filter(|unit| unit.is_class() && unit.fq_name() == fqn)
                .cloned()
                .collect::<Vec<_>>(),
        );
        let same_source = candidates
            .iter()
            .filter(|unit| unit.source() == owner.source())
            .cloned()
            .collect::<Vec<_>>();
        match same_source.as_slice() {
            [definition] => {
                return ScalaTypeNamespaceResolution::Resolved((*definition).clone());
            }
            [_, _, ..] => return ScalaTypeNamespaceResolution::Ambiguous,
            [] => {}
        }
        match candidates.as_slice() {
            [] => ScalaTypeNamespaceResolution::NoMatch,
            [definition] => ScalaTypeNamespaceResolution::Resolved((*definition).clone()),
            _ => ScalaTypeNamespaceResolution::Ambiguous,
        }
    }

    fn exact_type_declarations_for_owner_context(
        &self,
        fqn: &str,
        owner: &CodeUnit,
    ) -> Vec<CodeUnit> {
        let candidates = sorted_unique_units(
            self.index
                .by_fqn(fqn)
                .iter()
                .filter(|unit| unit.is_class() && unit.fq_name() == fqn)
                .cloned()
                .collect::<Vec<_>>(),
        );
        let same_source = candidates
            .iter()
            .filter(|unit| unit.source() == owner.source())
            .cloned()
            .collect::<Vec<_>>();
        if same_source.is_empty() {
            candidates
        } else {
            sorted_unique_units(same_source)
        }
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

    fn physical_callable_targets(
        &self,
        scala: &ScalaAnalyzer,
        targets: Vec<CodeUnit>,
    ) -> PhysicalCallableTargets {
        if targets.is_empty() {
            return PhysicalCallableTargets::NoCandidates;
        }
        let owners = targets
            .iter()
            .filter_map(|target| self.exact_structural_parent(scala, target))
            .collect::<HashSet<_>>();
        if owners.len() > 1 {
            PhysicalCallableTargets::Ambiguous
        } else {
            PhysicalCallableTargets::Unique(targets)
        }
    }

    fn fallback_callable_role(&self, scala: &ScalaAnalyzer, unit: &CodeUnit) -> ScalaCallableRole {
        if unit.is_synthetic() {
            ScalaCallableRole::PrimaryConstructor
        } else if self
            .exact_structural_parent(scala, unit)
            .is_some_and(|owner| owner.identifier().trim_end_matches('$') == unit.identifier())
        {
            ScalaCallableRole::SecondaryConstructor
        } else {
            ScalaCallableRole::Ordinary
        }
    }

    fn direct_member_bindings(&self, owner_fqn: &str) -> ExportedMemberBindings {
        let mut bindings = ExportedMemberBindings::default();
        for child in self.index.fqn_direct_children(owner_fqn) {
            if child.is_function() || child.is_field() || self.type_aliases.contains(&child) {
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
                let lexical_root = export
                    .owner_path
                    .first()
                    .and_then(|root| self.exact_nested_object_for_owner(scala, &current, root));
                let Some(source_owner_fqn) = self.resolve_qualified_stable_type_at(
                    scala,
                    &resolver,
                    &export.owner_path,
                    true,
                    lexical_root,
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
    ) -> (HashMap<CodeUnit, Vec<CodeUnit>>, HashSet<CodeUnit>) {
        let mut ancestors_by_owner = HashMap::default();
        let mut ambiguous_owners = HashSet::default();
        let projected_parent_by_unit = file_states
            .values()
            .flat_map(|state| {
                state.children.iter().flat_map(|(parent, children)| {
                    children
                        .iter()
                        .cloned()
                        .map(|child| (child, parent.clone()))
                })
            })
            .collect::<HashMap<_, _>>();
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
                        &projected_parent_by_unit,
                    ) else {
                        if self.type_lookup_path_is_ambiguous(resolver, path.segments()) {
                            ambiguous_owners.insert(owner.clone());
                            ancestors.clear();
                            break;
                        }
                        continue;
                    };
                    if !seen.insert(fqn.clone()) {
                        continue;
                    }
                    ancestors.extend(self.exact_type_declarations_for_owner_context(&fqn, &owner));
                }
                if !ancestors.is_empty() {
                    ancestors_by_owner.insert(owner.clone(), ancestors);
                }
            }
        }
        (ancestors_by_owner, ambiguous_owners)
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

    pub(super) fn exact_owner_inherits(
        &self,
        scala: &ScalaAnalyzer,
        owner: &CodeUnit,
        target: &CodeUnit,
    ) -> bool {
        let mut pending = vec![owner.clone()];
        let mut seen = HashSet::default();
        while let Some(current) = pending.pop() {
            if !seen.insert(current.clone()) {
                continue;
            }
            if &current == target {
                return true;
            }
            let ancestors = match self.exact_direct_ancestor_resolution(scala, &current) {
                ScalaDirectAncestorResolution::Resolved(ancestors) if !ancestors.is_empty() => {
                    ancestors
                }
                ScalaDirectAncestorResolution::Resolved(_) => {
                    self.direct_ancestors_for_declaration(scala, &current)
                }
                ScalaDirectAncestorResolution::Ambiguous => return false,
            };
            pending.extend(ancestors);
        }
        false
    }

    pub(crate) fn exact_direct_ancestor_resolution(
        &self,
        scala: &ScalaAnalyzer,
        owner: &CodeUnit,
    ) -> ScalaDirectAncestorResolution {
        if self
            .ambiguous_direct_ancestor_owners
            .as_ref()
            .is_some_and(|owners| owners.contains(owner))
        {
            return ScalaDirectAncestorResolution::Ambiguous;
        }
        if let Some(ancestors_by_unit) = &self.direct_ancestors_by_unit {
            return ScalaDirectAncestorResolution::Resolved(
                ancestors_by_unit.get(owner).cloned().unwrap_or_default(),
            );
        }

        let Some(facts) = scala.forward_owner_facts(owner) else {
            return ScalaDirectAncestorResolution::Resolved(Vec::new());
        };
        let resolver = NameResolver::for_file_types(scala, owner, self);
        let mut ancestors = Vec::new();
        let mut seen = HashSet::default();
        for path in facts.supertype_lookup_paths {
            let Some(fqn) =
                self.resolve_type_in_hierarchy_context(scala, &resolver, path.segments())
            else {
                if self.type_lookup_path_is_ambiguous(&resolver, path.segments()) {
                    return ScalaDirectAncestorResolution::Ambiguous;
                }
                continue;
            };
            for declaration in self.exact_type_declarations_for_owner_context(&fqn, owner) {
                if seen.insert(declaration.clone()) {
                    ancestors.push(declaration);
                }
            }
        }
        ScalaDirectAncestorResolution::Resolved(ancestors)
    }

    pub(super) fn exact_lexical_type_namespace(
        &self,
        scala: &ScalaAnalyzer,
        owners_nearest_first: impl IntoIterator<Item = CodeUnit>,
        name: &str,
        authoritative_local_barrier: bool,
    ) -> ScalaTypeNamespaceResolution {
        resolve_exact_lexical_type_namespace(
            owners_nearest_first,
            name,
            authoritative_local_barrier,
            |owner, member| {
                self.members_for_exact_owner_unit(scala, owner, member)
                    .into_iter()
                    .filter(|unit| {
                        unit.is_class() && !unit.short_name().ends_with('$')
                            || self.is_type_alias(scala, unit)
                    })
                    .cloned()
                    .collect()
            },
            |owner| self.exact_direct_ancestor_resolution(scala, owner),
        )
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
                        .filter(|unit| self.has_term_field_declaration(unit))
                        .map(|ancestor_method| (*ancestor_method).clone()),
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

    pub(super) fn field_for_owner_unit(
        &self,
        scala: &ScalaAnalyzer,
        owner: &CodeUnit,
        member: &str,
    ) -> FieldResolution {
        let mut level = vec![owner.clone()];
        let mut seen = HashSet::default();
        while !level.is_empty() {
            let mut matches = Vec::new();
            let mut next = Vec::new();
            for owner in level {
                if !seen.insert(owner.clone()) {
                    continue;
                }
                matches.extend(
                    self.members_for_exact_owner_unit(scala, &owner, member)
                        .into_iter()
                        .filter(|unit| self.has_term_field_declaration(unit))
                        .cloned(),
                );
                let ancestors = match self.exact_direct_ancestor_resolution(scala, &owner) {
                    ScalaDirectAncestorResolution::Resolved(ancestors) if !ancestors.is_empty() => {
                        ancestors
                    }
                    ScalaDirectAncestorResolution::Resolved(_) => {
                        // The forward hierarchy resolver deliberately fails closed on
                        // ambiguity, but its bounded fallback cannot currently recover
                        // every nested lexical supertype. The analyzer hierarchy retains
                        // exact CodeUnits for that case, so use it only after the exact
                        // resolver has authoritatively ruled out ambiguity.
                        self.direct_ancestors_for_declaration(scala, &owner)
                    }
                    ScalaDirectAncestorResolution::Ambiguous => {
                        return FieldResolution::Unresolved;
                    }
                };
                next.extend(ancestors);
            }
            matches.sort();
            matches.dedup();
            match matches.as_slice() {
                [field] => {
                    return FieldResolution::Resolved(ResolvedField {
                        declaration: field.clone(),
                        declared_type: self.field_declared_type(scala, field),
                    });
                }
                [_, _, ..] => return FieldResolution::Unresolved,
                [] => level = next,
            }
        }
        FieldResolution::NoMatch
    }

    pub(super) fn stable_type_member_for_owner_unit(
        &self,
        scala: &ScalaAnalyzer,
        owner: &CodeUnit,
        member: &str,
    ) -> FieldResolution {
        let mut level = vec![owner.clone()];
        let mut seen = HashSet::default();
        while !level.is_empty() {
            let mut matches = Vec::new();
            let mut next = Vec::new();
            let mut next_is_ambiguous = false;
            let mut level_owners = Vec::new();
            for owner in level {
                if !seen.insert(owner.clone()) {
                    continue;
                }
                level_owners.push(owner.clone());
                matches.extend(
                    self.members_for_exact_owner_unit(scala, &owner, member)
                        .into_iter()
                        .filter(|unit| unit.is_field() || self.is_type_alias(scala, unit))
                        .cloned(),
                );
            }
            // A declaration directly owned at this hierarchy tier is
            // authoritative. Only consult exports and ancestors when the
            // complete direct tier has no matching declaration; otherwise an
            // unrelated ambiguous replica beyond that tier can incorrectly
            // hide the exact physical member.
            if matches.is_empty() {
                for owner in level_owners {
                    // Export aliases do not have a declaration under the exporter.
                    // Consult parser-recorded export bindings only for a physically
                    // unique exporter and require one physical target for every
                    // selected binding.
                    let exported_bindings = self
                        .exported_member_bindings(scala, &owner)
                        .into_iter()
                        .filter(|(visible_name, _)| visible_name == member)
                        .collect::<Vec<_>>();
                    if !exported_bindings.is_empty() {
                        let physical_owners = self
                            .index
                            .by_fqn(&owner.fq_name())
                            .iter()
                            .filter(|candidate| candidate.is_class())
                            .collect::<Vec<_>>();
                        if physical_owners.len() != 1 || physical_owners[0] != &owner {
                            return FieldResolution::Unresolved;
                        }
                    }
                    for (_, target_fqn) in exported_bindings {
                        let exported = self
                            .index
                            .by_fqn(&target_fqn)
                            .iter()
                            .filter(|candidate| {
                                candidate.is_field() || self.is_type_alias(scala, candidate)
                            })
                            .collect::<Vec<_>>();
                        let [exported] = exported.as_slice() else {
                            return FieldResolution::Unresolved;
                        };
                        matches.push((*exported).clone());
                    }
                    let ancestors = match self.exact_direct_ancestor_resolution(scala, &owner) {
                        ScalaDirectAncestorResolution::Resolved(ancestors) => ancestors,
                        ScalaDirectAncestorResolution::Ambiguous => {
                            next_is_ambiguous = true;
                            Vec::new()
                        }
                    };
                    next.extend(ancestors);
                }
            }
            if !matches.is_empty() {
                let type_members = matches
                    .iter()
                    .filter(|field| self.is_type_alias(scala, field))
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
            if next_is_ambiguous {
                return FieldResolution::Unresolved;
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
                && let Some(field_type) =
                    self.resolve_type_in_declaration_context(scala, &resolver, path)
                && let Some(field_type) = self.canonical_receiver_type(scala, &field_type)
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
            .and_then(|facts| facts.return_type_fqn.as_deref())
            .and_then(|field_type| self.canonical_receiver_type(scala, field_type))
    }

    fn canonical_receiver_type(
        &self,
        scala: &ScalaAnalyzer,
        receiver_type: &str,
    ) -> Option<String> {
        let mut current = receiver_type.to_string();
        let mut seen = HashSet::default();
        while seen.insert(current.clone()) {
            let declarations = self.index.by_fqn(&current);
            let aliases = declarations
                .iter()
                .filter(|unit| self.is_type_alias(scala, unit))
                .collect::<Vec<_>>();
            if aliases.is_empty() {
                return Some(current);
            }
            if declarations
                .iter()
                .any(|unit| unit.is_class() && !self.is_type_alias(scala, unit))
            {
                return None;
            }
            let underlying = aliases
                .into_iter()
                .filter_map(|alias| self.type_alias_underlying_type(scala, alias))
                .collect::<HashSet<_>>();
            if underlying.len() != 1 {
                return None;
            }
            current = underlying.into_iter().next().expect("one alias target");
        }
        None
    }

    fn type_alias_underlying_type(
        &self,
        scala: &ScalaAnalyzer,
        alias: &CodeUnit,
    ) -> Option<String> {
        let source_facts = self.source_facts_for_file(scala, alias.source());
        let resolver = NameResolver::for_file_types(scala, alias, self);
        let resolved = self
            .declaration_ranges_for(scala, alias)
            .into_iter()
            .filter_map(|range| {
                source_facts
                    .type_alias_paths_by_range
                    .get(&(range.start_byte, range.end_byte))
                    .and_then(|path| {
                        self.resolve_type_in_declaration_context(scala, &resolver, path)
                    })
            })
            .collect::<HashSet<_>>();
        (resolved.len() == 1)
            .then(|| resolved.into_iter().next())
            .flatten()
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

    fn method_declarations_for_members(
        &self,
        scala: &ScalaAnalyzer,
        members: &[&CodeUnit],
        call_arities: Option<&[usize]>,
    ) -> Vec<CodeUnit> {
        self.method_declarations_for_members_matching(
            scala,
            members,
            ScalaCallMatch::Arities(call_arities),
            ScalaCallableSiteRole::Ordinary,
        )
    }

    fn method_declarations_for_members_with_shape(
        &self,
        scala: &ScalaAnalyzer,
        members: &[&CodeUnit],
        call_shape: &ScalaCallSiteShape,
    ) -> Vec<CodeUnit> {
        self.method_declarations_for_members_matching(
            scala,
            members,
            ScalaCallMatch::Shape(call_shape),
            ScalaCallableSiteRole::Ordinary,
        )
    }

    fn callable_declarations_for_members_with_shape(
        &self,
        scala: &ScalaAnalyzer,
        members: &[&CodeUnit],
        call_shape: &ScalaCallSiteShape,
        site_role: ScalaCallableSiteRole,
    ) -> Vec<CodeUnit> {
        self.method_declarations_for_members_matching(
            scala,
            members,
            ScalaCallMatch::Shape(call_shape),
            site_role,
        )
    }

    fn callable_declarations_for_members(
        &self,
        scala: &ScalaAnalyzer,
        members: &[&CodeUnit],
        call_shape: Option<&ScalaCallSiteShape>,
        site_role: ScalaCallableSiteRole,
    ) -> Vec<CodeUnit> {
        match call_shape {
            Some(shape) => {
                self.callable_declarations_for_members_with_shape(scala, members, shape, site_role)
            }
            None => self.method_declarations_for_members_matching(
                scala,
                members,
                ScalaCallMatch::Arities(None),
                site_role,
            ),
        }
    }

    fn method_declarations_for_members_matching(
        &self,
        scala: &ScalaAnalyzer,
        members: &[&CodeUnit],
        call: ScalaCallMatch<'_>,
        site_role: ScalaCallableSiteRole,
    ) -> Vec<CodeUnit> {
        let candidates = members
            .iter()
            .filter(|method| method.is_function())
            .filter_map(|method| {
                self.facts.fact_for_declaration(method).map(|facts| {
                    (
                        *method,
                        facts,
                        self.effective_callable_alternatives_for(scala, method),
                    )
                })
            })
            .collect::<Vec<_>>();
        let callable_count = match call {
            ScalaCallMatch::Arities(_) => candidates
                .iter()
                .map(|(method, _, alternatives)| {
                    if alternatives.is_empty() {
                        usize::from(site_role.accepts(self.fallback_callable_role(scala, method)))
                    } else {
                        alternatives
                            .iter()
                            .filter(|alternative| site_role.accepts(alternative.role))
                            .count()
                    }
                })
                .sum::<usize>(),
            ScalaCallMatch::Shape(shape) => candidates
                .iter()
                .map(|(method, facts, alternatives)| {
                    if alternatives.is_empty() {
                        if shape.method_value_parameter_types_authoritative {
                            return 0;
                        }
                        let fallback = facts
                            .callable_arity
                            .or_else(|| facts.arity.map(CallableArity::exact))
                            .map(ScalaCallableParameterList::explicit)
                            .into_iter()
                            .collect::<Vec<_>>();
                        usize::from(scala_callable_alternative_is_candidate(
                            self.fallback_callable_role(scala, method),
                            &fallback,
                            shape,
                            site_role,
                        ))
                    } else {
                        alternatives
                            .iter()
                            .filter(|alternative| {
                                callable_alternative_is_candidate(alternative, shape, site_role)
                            })
                            .count()
                    }
                })
                .sum::<usize>(),
        };
        let unique_callable = callable_count == 1;
        candidates
            .iter()
            .filter(|(method, facts, alternatives)| match call {
                ScalaCallMatch::Arities(call_arities) => callable_call_shape_matches(
                    facts,
                    alternatives,
                    call_arities,
                    self.fallback_callable_role(scala, method),
                    site_role,
                    unique_callable,
                ),
                ScalaCallMatch::Shape(shape) => {
                    if alternatives.is_empty() {
                        if shape.method_value_parameter_types_authoritative {
                            return false;
                        }
                        let fallback = facts
                            .callable_arity
                            .or_else(|| facts.arity.map(CallableArity::exact))
                            .map(ScalaCallableParameterList::explicit)
                            .into_iter()
                            .collect::<Vec<_>>();
                        scala_callable_alternative_matches(
                            self.fallback_callable_role(scala, method),
                            &fallback,
                            Some(shape),
                            site_role,
                            unique_callable,
                        )
                    } else {
                        alternatives.iter().any(|alternative| {
                            callable_alternative_matches(
                                alternative,
                                Some(shape),
                                site_role,
                                unique_callable,
                            )
                        })
                    }
                }
            })
            .map(|(method, _, _)| (*method).clone())
            .collect()
    }

    fn imported_member_targets_with_shape(
        &self,
        scala: &ScalaAnalyzer,
        member_fqn: &str,
        call_shape: &ScalaCallSiteShape,
    ) -> Vec<CodeUnit> {
        let members = self
            .index
            .by_fqn(member_fqn)
            .iter()
            .filter(|unit| unit.is_function())
            .collect::<Vec<_>>();
        self.method_declarations_for_members_with_shape(scala, &members, call_shape)
    }

    pub(super) fn bare_member_declarations_for_owner(
        &self,
        scala: &ScalaAnalyzer,
        owner: &CodeUnit,
        member: &str,
        call_arities: Option<&[usize]>,
    ) -> BareMemberResolution {
        self.bare_member_declarations_for_owner_matching(
            scala,
            owner,
            member,
            ScalaCallMatch::Arities(call_arities),
        )
    }

    fn bare_member_declarations_for_owner_matching(
        &self,
        scala: &ScalaAnalyzer,
        owner: &CodeUnit,
        member: &str,
        call: ScalaCallMatch<'_>,
    ) -> BareMemberResolution {
        if !owner.is_class() {
            return BareMemberResolution::NoMatch;
        }
        let mut owners = vec![owner.clone()];
        let mut seen = HashSet::default();
        while !owners.is_empty() {
            let mut matched = Vec::new();
            let mut declaring_owners = HashSet::default();
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
                let methods = match call {
                    ScalaCallMatch::Arities(call_arities) => {
                        self.method_declarations_for_members(scala, &members, call_arities)
                    }
                    ScalaCallMatch::Shape(call_shape) => {
                        self.method_declarations_for_members_with_shape(scala, &members, call_shape)
                    }
                };
                if !methods.is_empty() {
                    declaring_owners.insert(owner.clone());
                    matched.extend(methods);
                }
                next.extend(self.direct_ancestors_for_declaration(scala, &owner));
            }
            if declaring_owners.len() > 1 {
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
        self.ordinary_class_member_declarations_for_owner_matching(
            scala,
            owner,
            member,
            ScalaCallMatch::Arities(call_arities),
        )
    }

    fn ordinary_class_member_declarations_for_owner_matching(
        &self,
        scala: &ScalaAnalyzer,
        owner: &CodeUnit,
        member: &str,
        call: ScalaCallMatch<'_>,
    ) -> BareMemberResolution {
        if !owner.is_class() {
            return BareMemberResolution::NoMatch;
        }
        self.ordinary_class_member_declarations_for_owners_matching(
            scala,
            std::slice::from_ref(owner),
            member,
            call,
        )
    }

    pub(super) fn ordinary_class_member_declarations_for_owners(
        &self,
        scala: &ScalaAnalyzer,
        direct_owners: &[CodeUnit],
        member: &str,
        call_arities: Option<&[usize]>,
    ) -> BareMemberResolution {
        self.ordinary_class_member_declarations_for_owners_matching(
            scala,
            direct_owners,
            member,
            ScalaCallMatch::Arities(call_arities),
        )
    }

    fn ordinary_class_member_declarations_for_owners_matching(
        &self,
        scala: &ScalaAnalyzer,
        direct_owners: &[CodeUnit],
        member: &str,
        call: ScalaCallMatch<'_>,
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
                if call.is_unapplied()
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
                let methods = match call {
                    ScalaCallMatch::Arities(call_arities) => {
                        self.method_declarations_for_members(scala, &members, call_arities)
                    }
                    ScalaCallMatch::Shape(call_shape) => {
                        self.method_declarations_for_members_with_shape(scala, &members, call_shape)
                    }
                };
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

    pub(super) fn is_abstract_scala_method(
        &self,
        scala: &ScalaAnalyzer,
        method: &CodeUnit,
    ) -> bool {
        let ranges = self.declaration_ranges_for(scala, method);
        !ranges.is_empty()
            && ranges.iter().all(|range| {
                self.source_facts_for_file(scala, method.source())
                    .abstract_callable_ranges
                    .contains(&(range.start_byte, range.end_byte))
            })
    }

    fn member_blocks_callable_lookup(&self, scala: &ScalaAnalyzer, member: &CodeUnit) -> bool {
        self.has_term_field_declaration(member)
            || member.is_class() && self.type_is_stable_owner(scala, member)
    }

    pub(crate) fn callable_parameter_function_shape(
        &self,
        scala: &ScalaAnalyzer,
        method: &CodeUnit,
        call_arities: &[usize],
        parameter_list: usize,
        parameter_index: usize,
    ) -> Option<ScalaFunctionParameterShape> {
        let alternatives = self.callable_alternatives_for(scala, method);
        let mut resolved = None;
        for alternative in alternatives.iter().filter(|alternative| {
            alternative.role == ScalaCallableRole::Ordinary
                && ordinary_callable_shape_matches(&alternative.shape, Some(call_arities), true)
        }) {
            let shape = alternative
                .parameter_function_shapes
                .get(parameter_list)
                .and_then(|parameters| parameters.get(parameter_index))
                .cloned()
                .flatten()?;
            if resolved.as_ref().is_some_and(|resolved| resolved != &shape) {
                return None;
            }
            resolved = Some(shape);
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
        self.effective_method_declarations_for_owner_matching(
            scala,
            owner_fqn,
            member,
            ScalaCallMatch::Arities(call_arities),
        )
    }

    fn effective_method_declarations_for_owner_with_shape(
        &self,
        scala: &ScalaAnalyzer,
        owner_fqn: &str,
        member: &str,
        call_shape: &ScalaCallSiteShape,
    ) -> BareMemberResolution {
        self.effective_method_declarations_for_owner_matching(
            scala,
            owner_fqn,
            member,
            ScalaCallMatch::Shape(call_shape),
        )
    }

    fn effective_method_declarations_for_owner_matching(
        &self,
        scala: &ScalaAnalyzer,
        owner_fqn: &str,
        member: &str,
        call: ScalaCallMatch<'_>,
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

        self.effective_method_declarations_for_exact_owner_matching(scala, owner, member, call)
    }

    fn effective_method_declarations_for_exact_owner_with_shape(
        &self,
        scala: &ScalaAnalyzer,
        owner: &CodeUnit,
        member: &str,
        call_shape: &ScalaCallSiteShape,
    ) -> BareMemberResolution {
        self.effective_method_declarations_for_exact_owner_matching(
            scala,
            owner,
            member,
            ScalaCallMatch::Shape(call_shape),
        )
    }

    fn effective_method_declarations_for_exact_owner(
        &self,
        scala: &ScalaAnalyzer,
        owner: &CodeUnit,
        member: &str,
        call_arities: Option<&[usize]>,
    ) -> BareMemberResolution {
        self.effective_method_declarations_for_exact_owner_matching(
            scala,
            owner,
            member,
            ScalaCallMatch::Arities(call_arities),
        )
    }

    fn effective_method_declarations_for_exact_owner_matching(
        &self,
        scala: &ScalaAnalyzer,
        owner: &CodeUnit,
        member: &str,
        call: ScalaCallMatch<'_>,
    ) -> BareMemberResolution {
        if !owner.is_class() {
            return BareMemberResolution::NoMatch;
        }

        let root_owner = owner.clone();
        let linearized = self.linearized_owners(scala, &root_owner);
        let mut abstract_trait_fallback = None;
        for owner in &linearized {
            if call.is_unapplied()
                && !self
                    .exact_nested_objects_for_owner(scala, owner, member)
                    .is_empty()
            {
                return BareMemberResolution::Unresolved;
            }
            let members = self.members_for_exact_owner_unit(scala, owner, member);
            if members
                .iter()
                .any(|member| self.member_blocks_callable_lookup(scala, member))
            {
                return BareMemberResolution::Unresolved;
            }
            let methods = match call {
                ScalaCallMatch::Arities(call_arities) => {
                    self.method_declarations_for_members(scala, &members, call_arities)
                }
                ScalaCallMatch::Shape(shape) => {
                    self.method_declarations_for_members_with_shape(scala, &members, shape)
                }
            };
            if !methods.is_empty() {
                let replica_conflict = linearized.iter().any(|replica| {
                    if replica == owner || replica.fq_name() != owner.fq_name() {
                        return false;
                    }
                    if call.is_unapplied()
                        && !self
                            .exact_nested_objects_for_owner(scala, replica, member)
                            .is_empty()
                    {
                        return true;
                    }
                    let replica_members = self.members_for_exact_owner_unit(scala, replica, member);
                    if replica_members
                        .iter()
                        .any(|member| self.member_blocks_callable_lookup(scala, member))
                    {
                        return true;
                    }
                    match call {
                        ScalaCallMatch::Arities(call_arities) => !self
                            .method_declarations_for_members(scala, &replica_members, call_arities)
                            .is_empty(),
                        ScalaCallMatch::Shape(shape) => !self
                            .method_declarations_for_members_with_shape(
                                scala,
                                &replica_members,
                                shape,
                            )
                            .is_empty(),
                    }
                });
                if replica_conflict {
                    return BareMemberResolution::Unresolved;
                }
                let inherited_abstract_trait = owner != &root_owner
                    && self.is_scala_trait_declaration(scala, owner)
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

    fn generic_owner_source_facts(
        &self,
        scala: &ScalaAnalyzer,
        owner: &CodeUnit,
    ) -> Option<ScalaGenericOwnerSourceFacts> {
        let source_facts = self.source_facts_for_file(scala, owner.source());
        let mut matches = self
            .declaration_ranges_for(scala, owner)
            .into_iter()
            .filter_map(|range| {
                source_facts
                    .generic_owner_facts_by_range
                    .get(&(range.start_byte, range.end_byte))
                    .cloned()
            });
        let first = matches.next()?;
        matches.all(|facts| facts == first).then_some(first)
    }

    fn concrete_type_expression_owner(
        &self,
        scala: &ScalaAnalyzer,
        declaration: &CodeUnit,
        expression: &ScalaTypeExpressionPath,
    ) -> Option<CodeUnit> {
        let resolver = NameResolver::for_file_types(scala, declaration, self);
        let fqn = self.resolve_type_in_callable_declaration_context(
            scala,
            &resolver,
            declaration,
            &expression.segments,
        )?;
        match self.exact_type_declaration_for_owner_context(&fqn, declaration) {
            ScalaTypeNamespaceResolution::Resolved(owner) => Some(owner),
            ScalaTypeNamespaceResolution::AuthoritativeMiss
            | ScalaTypeNamespaceResolution::Ambiguous
            | ScalaTypeNamespaceResolution::NoMatch => None,
        }
    }

    fn generic_environments_for_linearization(
        &self,
        scala: &ScalaAnalyzer,
        root: &CodeUnit,
    ) -> Option<HashMap<CodeUnit, HashMap<String, CodeUnit>>> {
        let mut environments = HashMap::<CodeUnit, HashMap<String, CodeUnit>>::default();
        environments.insert(root.clone(), HashMap::default());
        let mut pending = vec![root.clone()];
        let mut expanded = HashSet::default();
        while let Some(owner) = pending.pop() {
            if !expanded.insert(owner.clone()) {
                continue;
            }
            let environment = environments.get(&owner)?.clone();
            let owner_facts = self.generic_owner_source_facts(scala, &owner)?;
            let direct_ancestors = match self.exact_direct_ancestor_resolution(scala, &owner) {
                ScalaDirectAncestorResolution::Resolved(ancestors) => ancestors,
                ScalaDirectAncestorResolution::Ambiguous => return None,
            };
            for ancestor in direct_ancestors {
                let mut matching_expressions = owner_facts.supertypes.iter().filter(|expression| {
                    self.concrete_type_expression_owner(scala, &owner, expression)
                        .as_ref()
                        == Some(&ancestor)
                });
                let expression = matching_expressions.next()?;
                if matching_expressions.next().is_some() {
                    return None;
                }
                let ancestor_facts = self.generic_owner_source_facts(scala, &ancestor)?;
                if ancestor_facts.type_parameters.len() != expression.arguments.len() {
                    return None;
                }
                let mut ancestor_environment = HashMap::default();
                for (parameter, argument) in ancestor_facts
                    .type_parameters
                    .iter()
                    .zip(&expression.arguments)
                {
                    let value = if argument.arguments.is_empty()
                        && argument.segments.len() == 1
                        && owner_facts
                            .type_parameters
                            .iter()
                            .any(|candidate| candidate == &argument.segments[0])
                    {
                        environment.get(&argument.segments[0]).cloned()
                    } else {
                        self.concrete_type_expression_owner(scala, &owner, argument)
                    }?;
                    ancestor_environment.insert(parameter.clone(), value);
                }
                if environments
                    .get(&ancestor)
                    .is_some_and(|existing| existing != &ancestor_environment)
                {
                    return None;
                }
                if environments
                    .insert(ancestor.clone(), ancestor_environment)
                    .is_none()
                {
                    pending.push(ancestor);
                }
            }
        }
        Some(environments)
    }

    fn callable_return_value_from_path(
        &self,
        scala: &ScalaAnalyzer,
        method: &CodeUnit,
        declaring_owner: &CodeUnit,
        environment: &HashMap<String, CodeUnit>,
        return_path: &[String],
    ) -> Option<ScalaValueOwner> {
        if return_path.len() == 1
            && let Some(owner) = environment.get(&return_path[0])
        {
            return Some(ScalaValueOwner::Exact(owner.clone()));
        }
        let owner_facts = self.generic_owner_source_facts(scala, declaring_owner)?;
        if return_path.len() == 1
            && owner_facts
                .type_parameters
                .iter()
                .any(|parameter| parameter == &return_path[0])
        {
            return None;
        }
        let resolver = NameResolver::for_file_types(scala, method, self);
        let fqn = self.resolve_type_in_callable_declaration_context(
            scala,
            &resolver,
            method,
            return_path,
        )?;
        match self.exact_type_declaration_for_owner_context(&fqn, method) {
            ScalaTypeNamespaceResolution::Resolved(owner) => Some(ScalaValueOwner::Exact(owner)),
            ScalaTypeNamespaceResolution::NoMatch => Some(ScalaValueOwner::Logical(fqn)),
            ScalaTypeNamespaceResolution::AuthoritativeMiss
            | ScalaTypeNamespaceResolution::Ambiguous => None,
        }
    }

    fn callable_value_resolution_for_members(
        &self,
        scala: &ScalaAnalyzer,
        declaring_owner: &CodeUnit,
        members: &[&CodeUnit],
        call_shape: Option<&ScalaCallSiteShape>,
        environment: &HashMap<String, CodeUnit>,
    ) -> ScalaCallableTierResolution {
        if members
            .iter()
            .any(|member| self.member_blocks_callable_lookup(scala, member))
        {
            return ScalaCallableTierResolution::NoApplicableCallable;
        }
        let mut source_candidates = Vec::new();
        for method in members
            .iter()
            .copied()
            .filter(|member| member.is_function())
        {
            let source_facts = self.source_facts_for_file(scala, method.source());
            for range in self.declaration_ranges_for(scala, method) {
                if let Some(alternative) = source_facts
                    .callable_alternatives_by_range
                    .get(&(range.start_byte, range.end_byte))
                    .filter(|alternative| alternative.role == ScalaCallableRole::Ordinary)
                {
                    source_candidates.push((method, alternative.clone()));
                }
            }
        }
        let candidate_count = source_candidates
            .iter()
            .filter(|(_, alternative)| {
                call_shape.is_none_or(|shape| {
                    scala_callable_alternative_is_candidate(
                        alternative.role,
                        &alternative.shape,
                        shape,
                        ScalaCallableSiteRole::Ordinary,
                    )
                })
            })
            .count();
        let unique_callable = candidate_count == 1;
        let mut callable_targets = Vec::new();
        let mut value_result = None;
        let mut saw_unknown_return = false;
        for (method, alternative) in source_candidates {
            if !scala_callable_alternative_matches(
                alternative.role,
                &alternative.shape,
                call_shape,
                ScalaCallableSiteRole::Ordinary,
                unique_callable,
            ) {
                continue;
            }
            let value = alternative
                .return_type_path
                .as_deref()
                .and_then(|return_path| {
                    self.callable_return_value_from_path(
                        scala,
                        method,
                        declaring_owner,
                        environment,
                        return_path,
                    )
                });
            let Some(value) = value else {
                callable_targets.push(method.clone());
                saw_unknown_return = true;
                continue;
            };
            if value_result
                .as_ref()
                .is_some_and(|resolved| resolved != &value)
            {
                return ScalaCallableTierResolution::Applicable(None);
            }
            value_result = Some(value);
            callable_targets.push(method.clone());
        }
        callable_targets.sort();
        callable_targets.dedup();
        if callable_targets.is_empty() {
            return ScalaCallableTierResolution::NoApplicableCallable;
        }
        ScalaCallableTierResolution::Applicable(Some(ScalaCallableValueResolution {
            callable_targets,
            value_result: (!saw_unknown_return).then_some(value_result).flatten(),
        }))
    }

    fn inherited_apply_value_resolution(
        &self,
        scala: &ScalaAnalyzer,
        root: &CodeUnit,
        call_shape: Option<&ScalaCallSiteShape>,
    ) -> ScalaApplyValueResolution {
        let root_members = self.members_for_exact_owner_unit(scala, root, "apply");
        if !root_members.is_empty() {
            // A direct declaration is authoritative without consulting an
            // unrelated or ambiguous ancestor hierarchy. Objects cannot
            // introduce type parameters of their own, so this tier starts
            // with an empty substitution environment.
            return match self.callable_value_resolution_for_members(
                scala,
                root,
                &root_members,
                call_shape,
                &HashMap::default(),
            ) {
                ScalaCallableTierResolution::NoApplicableCallable => {
                    ScalaApplyValueResolution::NoApplicableCallable
                }
                ScalaCallableTierResolution::Applicable(resolution) => {
                    ScalaApplyValueResolution::Authoritative(resolution)
                }
            };
        }
        let mut declaring_tier = None;
        for owner in self.linearized_owners(scala, root).into_iter().skip(1) {
            let members = self.members_for_exact_owner_unit(scala, &owner, "apply");
            if !members.is_empty() {
                declaring_tier = Some((owner, members));
                break;
            }
        }
        let Some((owner, members)) = declaring_tier else {
            return ScalaApplyValueResolution::NoDeclaration;
        };
        // The first declaring tier is authoritative even if its overloads,
        // return type, or generic substitution cannot be proven.
        let resolution = self
            .generic_environments_for_linearization(scala, root)
            .and_then(|environments| {
                let environment = environments.get(&owner)?;
                Some(self.callable_value_resolution_for_members(
                    scala,
                    &owner,
                    &members,
                    call_shape,
                    environment,
                ))
            });
        match resolution {
            Some(ScalaCallableTierResolution::NoApplicableCallable) => {
                ScalaApplyValueResolution::NoApplicableCallable
            }
            Some(ScalaCallableTierResolution::Applicable(resolution)) => {
                ScalaApplyValueResolution::Authoritative(resolution)
            }
            None => ScalaApplyValueResolution::Authoritative(None),
        }
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
            for alternative in alternatives
                .iter()
                .filter(|alternative| alternative.role == ScalaCallableRole::Ordinary)
            {
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

    pub(super) fn member_return_type_for_fqn_call(
        &self,
        scala: &ScalaAnalyzer,
        resolver: &NameResolver,
        member_fqn: &str,
        call_arities: Option<&[usize]>,
    ) -> Option<String> {
        let members = self.index.by_fqn(member_fqn).iter().collect::<Vec<_>>();
        self.member_return_type_for_members(scala, resolver, &members, call_arities)
    }

    fn member_return_type_for_members(
        &self,
        scala: &ScalaAnalyzer,
        resolver: &NameResolver,
        members: &[&CodeUnit],
        call_arities: Option<&[usize]>,
    ) -> Option<String> {
        let call_shape = call_arities.map(ScalaCallSiteShape::ordinary);
        self.member_return_type_for_members_with_shape(
            scala,
            resolver,
            members,
            call_shape.as_ref(),
        )
    }

    fn member_return_type_for_members_with_shape(
        &self,
        scala: &ScalaAnalyzer,
        resolver: &NameResolver,
        members: &[&CodeUnit],
        call_shape: Option<&ScalaCallSiteShape>,
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
            .map(|(method, _, alternatives)| {
                if alternatives.is_empty() {
                    usize::from(
                        self.fallback_callable_role(scala, method) == ScalaCallableRole::Ordinary,
                    )
                } else {
                    alternatives
                        .iter()
                        .filter(|alternative| {
                            alternative.role == ScalaCallableRole::Ordinary
                                && call_shape.is_none_or(|actual| {
                                    scala_callable_alternative_is_candidate(
                                        alternative.role,
                                        &alternative.shape,
                                        actual,
                                        ScalaCallableSiteRole::Ordinary,
                                    )
                                })
                        })
                        .count()
                }
            })
            .sum::<usize>();
        let unique_callable = callable_count == 1;
        let mut resolved_return = None;
        let mut matched = false;
        for (method, facts, alternatives) in candidates {
            if alternatives.is_empty() {
                let fallback_shape = facts
                    .callable_arity
                    .or_else(|| facts.arity.map(CallableArity::exact))
                    .map(ScalaCallableParameterList::explicit)
                    .into_iter()
                    .collect::<Vec<_>>();
                if !scala_callable_alternative_matches(
                    self.fallback_callable_role(scala, method),
                    &fallback_shape,
                    call_shape,
                    ScalaCallableSiteRole::Ordinary,
                    unique_callable,
                ) {
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
                scala_callable_alternative_matches(
                    alternative.role,
                    &alternative.shape,
                    call_shape,
                    ScalaCallableSiteRole::Ordinary,
                    unique_callable,
                )
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

    fn members_for_exact_owner_unit<'a>(
        &'a self,
        scala: &ScalaAnalyzer,
        owner: &CodeUnit,
        member: &str,
    ) -> Vec<&'a CodeUnit> {
        self.members_for_exact_owner_name(&owner.fq_name(), member)
            .into_iter()
            .filter(|unit| unit.source() == owner.source())
            .filter(|unit| self.is_exact_structural_child(scala, owner, unit))
            .collect()
    }

    pub(crate) fn exact_member_declarations(
        &self,
        scala: &ScalaAnalyzer,
        owner: &CodeUnit,
        member: &str,
    ) -> Vec<CodeUnit> {
        self.members_for_exact_owner_unit(scala, owner, member)
            .into_iter()
            .cloned()
            .collect()
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
        let mut grouped: HashMap<String, Vec<CodeUnit>> = HashMap::default();
        for ((candidate_package, simple), units) in self.index.package_types() {
            if candidate_package != package {
                continue;
            }
            grouped.entry(simple.clone()).or_default().extend(
                units
                    .iter()
                    .filter(|unit| is_package_level_type(unit))
                    .cloned(),
            );
        }
        for alias in self
            .type_aliases
            .iter()
            .filter(|unit| unit.package_name() == package && is_package_level_type(unit))
        {
            grouped
                .entry(scala_simple_type_name(alias))
                .or_default()
                .push(alias.clone());
        }

        let mut values = Vec::new();
        for (simple, mut package_level) in grouped {
            package_level.sort();
            package_level.dedup();
            let ordinary = package_level
                .iter()
                .filter(|unit| {
                    self.type_aliases.contains(*unit) || !unit.short_name().ends_with('$')
                })
                .collect::<Vec<_>>();
            let selected = if ordinary.is_empty() {
                package_level.iter().collect::<Vec<_>>()
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
                .filter(|unit| self.is_type_namespace_declaration(unit)),
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
            .filter(|unit| self.is_type_namespace_declaration(unit))
            .collect::<Vec<_>>();
        let ordinary = classes
            .iter()
            .copied()
            .filter(|unit| self.type_aliases.contains(*unit) || !unit.short_name().ends_with('$'))
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

    fn logical_type_by_normalized_fqn(&self, normalized_fqn: &str) -> Option<String> {
        let classes = self
            .index
            .by_normalized_fqn(normalized_fqn)
            .iter()
            .filter(|unit| self.is_type_namespace_declaration(unit))
            .collect::<Vec<_>>();
        let ordinary = classes
            .iter()
            .copied()
            .filter(|unit| self.type_aliases.contains(*unit) || !unit.short_name().ends_with('$'))
            .collect::<Vec<_>>();
        let selected = if ordinary.is_empty() {
            classes
        } else {
            ordinary
        };
        let logical = selected
            .iter()
            .map(|unit| unit.fq_name())
            .collect::<HashSet<_>>();
        (logical.len() == 1)
            .then(|| logical.into_iter().next())
            .flatten()
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

    fn explicit_import_type_declarations(&self, candidate: &str) -> (Vec<CodeUnit>, Vec<CodeUnit>) {
        let normalized = scala_normalized_fq_name(candidate);
        let classes = self
            .index
            .by_normalized_fqn(&normalized)
            .iter()
            .filter(|unit| self.is_type_namespace_declaration(unit))
            .collect::<Vec<_>>();
        let ordinary = classes
            .iter()
            .copied()
            .filter(|unit| self.type_aliases.contains(*unit) || !unit.short_name().ends_with('$'))
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
            .filter(|unit| unit.is_class() && unit.short_name().ends_with('$'))
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
        self.exact_nested_object_unit(scala, owner_fqn, member)
            .map(|unit| unit.fq_name())
    }

    fn exact_nested_object_unit(
        &self,
        scala: &ScalaAnalyzer,
        owner_fqn: &str,
        member: &str,
    ) -> Option<CodeUnit> {
        let candidate = format!("{owner_fqn}.{member}$");
        let mut matches = self
            .index
            .by_fqn(&candidate)
            .iter()
            .filter(|unit| unit.is_class() && self.type_accepts_object_roles(scala, unit));
        let resolved = matches.next()?.clone();
        matches.next().is_none().then_some(resolved)
    }

    pub(super) fn exact_nested_object_for_owner(
        &self,
        scala: &ScalaAnalyzer,
        owner: &CodeUnit,
        member: &str,
    ) -> Option<CodeUnit> {
        let matches = self.exact_nested_objects_for_owner(scala, owner, member);
        let [resolved] = matches.as_slice() else {
            return None;
        };
        Some(resolved.clone())
    }

    fn exact_nested_objects_for_owner(
        &self,
        scala: &ScalaAnalyzer,
        owner: &CodeUnit,
        member: &str,
    ) -> Vec<CodeUnit> {
        let candidate = format!("{}.{member}$", owner.fq_name());
        sorted_unique_units(
            self.index
                .by_fqn(&candidate)
                .iter()
                .filter(|unit| unit.is_class() && unit.source() == owner.source())
                .filter(|unit| self.is_exact_structural_child(scala, owner, unit))
                .cloned()
                .collect(),
        )
    }

    pub(super) fn exact_nested_type(&self, owner_fqn: &str, member: &str) -> Option<String> {
        let candidate = format!("{owner_fqn}.{member}");
        let mut matches = self
            .index
            .by_fqn(&candidate)
            .iter()
            .filter(|unit| self.is_type_namespace_declaration(unit));
        let resolved = matches.next()?.fq_name();
        matches.next().is_none().then_some(resolved)
    }

    fn exact_nested_types_for_owner(
        &self,
        scala: &ScalaAnalyzer,
        owner: &CodeUnit,
        member: &str,
    ) -> Vec<CodeUnit> {
        let candidate = format!("{}.{member}", owner.fq_name());
        sorted_unique_units(
            self.index
                .by_fqn(&candidate)
                .iter()
                .filter(|unit| {
                    self.is_type_namespace_declaration(unit) && unit.source() == owner.source()
                })
                .filter(|unit| self.is_exact_structural_child(scala, owner, unit))
                .cloned()
                .collect(),
        )
    }

    fn projected_nested_objects_for_owner(
        &self,
        parents: &HashMap<CodeUnit, CodeUnit>,
        owner: &CodeUnit,
        member: &str,
    ) -> Vec<CodeUnit> {
        let candidate = format!("{}.{member}$", owner.fq_name());
        sorted_unique_units(
            self.index
                .by_fqn(&candidate)
                .iter()
                .filter(|unit| unit.is_class() && unit.source() == owner.source())
                .filter(|unit| parents.get(*unit) == Some(owner))
                .cloned()
                .collect(),
        )
    }

    fn projected_nested_types_for_owner(
        &self,
        parents: &HashMap<CodeUnit, CodeUnit>,
        owner: &CodeUnit,
        member: &str,
    ) -> Vec<CodeUnit> {
        let candidate = format!("{}.{member}", owner.fq_name());
        sorted_unique_units(
            self.index
                .by_fqn(&candidate)
                .iter()
                .filter(|unit| {
                    self.is_type_namespace_declaration(unit) && unit.source() == owner.source()
                })
                .filter(|unit| parents.get(*unit) == Some(owner))
                .cloned()
                .collect(),
        )
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

    fn type_lookup_path_is_ambiguous(&self, resolver: &NameResolver, segments: &[String]) -> bool {
        let Some(first) = segments.first() else {
            return false;
        };
        if resolver.type_binding_is_ambiguous(first) {
            return true;
        }
        let suffix = segments.join(".");
        resolver
            .package_prefixes
            .iter()
            .map(|package| {
                if package.is_empty() {
                    suffix.clone()
                } else {
                    format!("{package}.{suffix}")
                }
            })
            .chain(std::iter::once(suffix.clone()))
            .any(|candidate| {
                let normalized = scala_normalized_fq_name(&candidate);
                let candidates = self
                    .index
                    .by_normalized_fqn(&normalized)
                    .iter()
                    .filter(|unit| unit.is_class())
                    .collect::<Vec<_>>();
                let ordinary = candidates
                    .iter()
                    .filter(|unit| !unit.short_name().ends_with('$'))
                    .map(|unit| unit.fq_name())
                    .collect::<HashSet<_>>();
                if !ordinary.is_empty() {
                    ordinary.len() > 1
                } else {
                    candidates
                        .iter()
                        .map(|unit| unit.fq_name())
                        .collect::<HashSet<_>>()
                        .len()
                        > 1
                }
            })
    }

    pub(crate) fn resolve_type_in_declaration_context(
        &self,
        scala: &ScalaAnalyzer,
        resolver: &NameResolver,
        segments: &[String],
    ) -> Option<String> {
        self.resolve_qualified_type_from_roots(
            resolver,
            segments,
            true,
            |owner, member| self.exact_nested_objects_for_owner(scala, owner, member),
            |owner, member| self.exact_nested_types_for_owner(scala, owner, member),
        )
    }

    pub(crate) fn resolve_type_in_hierarchy_context(
        &self,
        scala: &ScalaAnalyzer,
        resolver: &NameResolver,
        segments: &[String],
    ) -> Option<String> {
        self.resolve_qualified_type_from_roots(
            resolver,
            segments,
            false,
            |owner, member| self.exact_nested_objects_for_owner(scala, owner, member),
            |owner, member| self.exact_nested_types_for_owner(scala, owner, member),
        )
    }

    fn resolve_type_in_projected_declaration_context(
        &self,
        resolver: &NameResolver,
        segments: &[String],
        parents: &HashMap<CodeUnit, CodeUnit>,
    ) -> Option<String> {
        self.resolve_qualified_type_from_roots(
            resolver,
            segments,
            false,
            |owner, member| self.projected_nested_objects_for_owner(parents, owner, member),
            |owner, member| self.projected_nested_types_for_owner(parents, owner, member),
        )
    }

    fn resolve_qualified_type_from_roots<ObjectChildren, TypeChildren>(
        &self,
        resolver: &NameResolver,
        segments: &[String],
        require_physical_terminal: bool,
        mut object_children: ObjectChildren,
        mut type_children: TypeChildren,
    ) -> Option<String>
    where
        ObjectChildren: FnMut(&CodeUnit, &str) -> Vec<CodeUnit>,
        TypeChildren: FnMut(&CodeUnit, &str) -> Vec<CodeUnit>,
    {
        let (first, rest) = segments.split_first()?;
        if first == "_root_" {
            if rest.is_empty() {
                return None;
            }
            let normalized = scala_normalized_fq_name(&rest.join("."));
            return if require_physical_terminal {
                self.unique_type_by_normalized_fqn(&normalized)
                    .map(CodeUnit::fq_name)
            } else {
                self.logical_type_by_normalized_fqn(&normalized)
            };
        }
        if rest.is_empty() {
            return (if require_physical_terminal {
                resolver.resolve(first)
            } else {
                resolver.resolve_logical(first)
            })
            .or_else(|| scala_builtin_type_name(first).map(str::to_string));
        }

        match resolver.resolve_qualified_type_root(self, first, Vec::new()) {
            ScalaQualifiedTypeRootResolution::Resolved(
                ScalaQualifiedTypeRootBinding::StableObjects(mut owners),
            ) => {
                for segment in &rest[..rest.len() - 1] {
                    owners = owners
                        .iter()
                        .flat_map(|owner| object_children(owner, segment))
                        .collect();
                    let mut seen = HashSet::default();
                    owners.retain(|owner| seen.insert(owner.clone()));
                }
                let terminal = rest.last()?;
                let mut matches = owners
                    .iter()
                    .flat_map(|owner| type_children(owner, terminal))
                    .collect::<Vec<_>>();
                if matches.is_empty() {
                    matches = owners
                        .iter()
                        .flat_map(|owner| object_children(owner, terminal))
                        .collect();
                }
                let mut seen = HashSet::default();
                matches.retain(|unit| seen.insert(unit.clone()));
                if require_physical_terminal {
                    let [resolved] = matches.as_slice() else {
                        return None;
                    };
                    return Some(resolved.fq_name());
                }
                let logical = matches
                    .iter()
                    .map(CodeUnit::fq_name)
                    .collect::<HashSet<_>>();
                return (logical.len() == 1)
                    .then(|| logical.into_iter().next())
                    .flatten();
            }
            ScalaQualifiedTypeRootResolution::Resolved(ScalaQualifiedTypeRootBinding::Package(
                package,
            )) => {
                let qualified = std::iter::once(package.as_str())
                    .chain(rest.iter().map(String::as_str))
                    .collect::<Vec<_>>()
                    .join(".");
                let normalized = scala_normalized_fq_name(&qualified);
                if require_physical_terminal {
                    return self
                        .unique_type_by_normalized_fqn(&normalized)
                        .map(CodeUnit::fq_name);
                }
                return self.logical_type_by_normalized_fqn(&normalized);
            }
            ScalaQualifiedTypeRootResolution::Ambiguous
            | ScalaQualifiedTypeRootResolution::AuthoritativeMiss => return None,
            ScalaQualifiedTypeRootResolution::NoMatch => {}
        }

        if resolver.has_type_or_object_or_package_binding(first)
            || !self.has_package_prefix(segments)
        {
            return None;
        }
        let qualified = segments.join(".");
        let normalized = scala_normalized_fq_name(&qualified);
        if require_physical_terminal {
            self.unique_type_by_normalized_fqn(&normalized)
                .map(CodeUnit::fq_name)
        } else {
            self.logical_type_by_normalized_fqn(&normalized)
        }
    }

    pub(super) fn resolve_qualified_stable_type_at(
        &self,
        scala: &ScalaAnalyzer,
        resolver: &NameResolver,
        segments: &[String],
        terminal_object: bool,
        lexical_root: Option<CodeUnit>,
    ) -> Option<String> {
        self.resolve_qualified_stable_type_unit_at(
            scala,
            resolver,
            segments,
            terminal_object,
            lexical_root,
        )
        .map(|unit| unit.fq_name())
    }

    pub(super) fn resolve_qualified_stable_type_unit_at(
        &self,
        scala: &ScalaAnalyzer,
        resolver: &NameResolver,
        segments: &[String],
        terminal_object: bool,
        lexical_root: Option<CodeUnit>,
    ) -> Option<CodeUnit> {
        self.resolve_qualified_stable_type_unit_at_with_lexical_roots(
            scala,
            resolver,
            segments,
            terminal_object,
            lexical_root.into_iter().collect(),
        )
    }

    pub(super) fn resolve_qualified_stable_type_unit_at_with_lexical_roots(
        &self,
        scala: &ScalaAnalyzer,
        resolver: &NameResolver,
        segments: &[String],
        terminal_object: bool,
        lexical_roots: Vec<CodeUnit>,
    ) -> Option<CodeUnit> {
        let (first, rest) = segments.split_first()?;
        if first == "_root_" {
            if rest.is_empty() {
                return None;
            }
            let normalized = scala_normalized_fq_name(&rest.join("."));
            return if terminal_object {
                self.unique_object_by_normalized_fqn(scala, &normalized)
                    .cloned()
            } else {
                self.unique_type_by_normalized_fqn(&normalized).cloned()
            };
        }
        if rest.is_empty() {
            let mut lexical_matches = lexical_roots
                .into_iter()
                .filter(|candidate| scala_simple_type_name(candidate) == *first)
                .filter(|candidate| {
                    if terminal_object {
                        self.type_accepts_object_roles(scala, candidate)
                    } else {
                        candidate.is_class() || self.is_type_alias(scala, candidate)
                    }
                })
                .collect::<Vec<_>>();
            lexical_matches.sort();
            lexical_matches.dedup();
            if let [resolved] = lexical_matches.as_slice() {
                return Some(resolved.clone());
            }
            if !lexical_matches.is_empty() {
                return None;
            }
            let fqn = if terminal_object {
                resolver.resolve_object(first)
            } else {
                resolver.resolve(first)
            }?;
            let normalized = scala_normalized_fq_name(&fqn);
            return if terminal_object {
                self.unique_object_by_normalized_fqn(scala, &normalized)
                    .cloned()
            } else {
                self.unique_type_by_normalized_fqn(&normalized).cloned()
            };
        }

        match resolver.resolve_qualified_type_root(self, first, lexical_roots) {
            ScalaQualifiedTypeRootResolution::Resolved(
                ScalaQualifiedTypeRootBinding::StableObjects(mut owners),
            ) => {
                for segment in &rest[..rest.len() - 1] {
                    owners = owners
                        .iter()
                        .flat_map(|owner| {
                            self.exact_nested_objects_for_owner(scala, owner, segment)
                        })
                        .collect();
                    let mut seen = HashSet::default();
                    owners.retain(|owner| seen.insert(owner.clone()));
                }
                let terminal = rest.last()?;
                let matches = owners
                    .iter()
                    .flat_map(|owner| {
                        if terminal_object {
                            self.exact_nested_objects_for_owner(scala, owner, terminal)
                        } else {
                            self.exact_nested_types_for_owner(scala, owner, terminal)
                        }
                    })
                    .collect::<Vec<_>>();
                let mut seen = HashSet::default();
                let matches = matches
                    .into_iter()
                    .filter(|unit| seen.insert(unit.clone()))
                    .collect::<Vec<_>>();
                let [resolved] = matches.as_slice() else {
                    return None;
                };
                return Some(resolved.clone());
            }
            ScalaQualifiedTypeRootResolution::Resolved(ScalaQualifiedTypeRootBinding::Package(
                package,
            )) => {
                let qualified = std::iter::once(package.as_str())
                    .chain(rest.iter().map(String::as_str))
                    .collect::<Vec<_>>()
                    .join(".");
                let normalized = scala_normalized_fq_name(&qualified);
                return if terminal_object {
                    self.unique_object_by_normalized_fqn(scala, &normalized)
                        .cloned()
                } else {
                    self.unique_type_by_normalized_fqn(&normalized).cloned()
                };
            }
            ScalaQualifiedTypeRootResolution::Ambiguous
            | ScalaQualifiedTypeRootResolution::AuthoritativeMiss => return None,
            ScalaQualifiedTypeRootResolution::NoMatch => {}
        }

        if resolver.has_type_or_object_or_package_binding(first)
            || !self.has_package_prefix(segments)
        {
            return None;
        }
        let normalized = scala_normalized_fq_name(&segments.join("."));
        if terminal_object {
            return self
                .unique_object_by_normalized_fqn(scala, &normalized)
                .cloned();
        }
        self.unique_type_by_normalized_fqn(&normalized).cloned()
    }

    fn resolve_type_in_callable_declaration_context(
        &self,
        scala: &ScalaAnalyzer,
        resolver: &NameResolver,
        declaration: &CodeUnit,
        segments: &[String],
    ) -> Option<String> {
        let (first, rest) = segments.split_first()?;
        let mut scope = self.declaration_parent(scala, declaration);
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
            scope = self.declaration_parent(scala, &owner);
        }
        self.resolve_type_in_declaration_context(scala, resolver, segments)
    }

    fn resolve_type_in_owner_context(
        &self,
        resolver: &NameResolver,
        segments: &[String],
        owner: &CodeUnit,
        state: &FileState,
        parent_by_child: &HashMap<&CodeUnit, &CodeUnit>,
        projected_parent_by_unit: &HashMap<CodeUnit, CodeUnit>,
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
            return self.resolve_type_in_projected_declaration_context(
                resolver,
                segments,
                projected_parent_by_unit,
            );
        }
        if let Some(relative) = self.resolve_package_relative_type(&state.package_name, segments) {
            return Some(relative);
        }
        self.resolve_type_in_projected_declaration_context(
            resolver,
            segments,
            projected_parent_by_unit,
        )
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
                .filter(|unit| self.is_type_namespace_declaration(unit))
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
                .filter(|unit| {
                    self.type_aliases.contains(*unit) || !unit.short_name().ends_with('$')
                })
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

    fn importable_member_by_normalized_fqn(
        &self,
        scala: &ScalaAnalyzer,
        normalized_fqn: &str,
        source_file: Option<&ProjectFile>,
    ) -> Option<&CodeUnit> {
        let candidates = self
            .index
            .by_normalized_fqn(normalized_fqn)
            .iter()
            .filter(|unit| unit.is_function() || self.has_term_field_declaration(unit))
            .collect::<Vec<_>>();
        if let [candidate] = candidates.as_slice() {
            return Some(*candidate);
        }
        if candidates.iter().any(|unit| unit.is_function()) {
            return None;
        }
        let source_file = source_file?;
        let stable_members = candidates
            .into_iter()
            .filter(|unit| self.has_term_field_declaration(unit))
            .filter(|unit| unit.source() == source_file)
            .filter(|unit| {
                self.exact_structural_parent(scala, unit)
                    .is_some_and(|owner| {
                        owner.source() == source_file
                            && owner.is_class()
                            && owner.short_name().ends_with('$')
                            && self.type_is_stable_owner(scala, &owner)
                    })
            })
            .collect::<Vec<_>>();
        let [candidate] = stable_members.as_slice() else {
            return None;
        };
        Some(*candidate)
    }

    fn exact_field(
        &self,
        _scala: &ScalaAnalyzer,
        owner_fqn: &str,
        member: &str,
    ) -> Option<CodeUnit> {
        let field_fqn = format!("{owner_fqn}.{member}");
        let fields = self
            .index
            .by_fqn(&field_fqn)
            .iter()
            .filter(|unit| self.has_term_field_declaration(unit))
            .collect::<Vec<_>>();
        (fields.len() == 1).then(|| fields[0].clone())
    }

    pub(crate) fn constructor_target_matches(
        &self,
        scala: &ScalaAnalyzer,
        target: &CodeUnit,
        call_shape: Option<&ScalaCallSiteShape>,
        site_role: ScalaCallableSiteRole,
    ) -> bool {
        let alternatives = self.callable_alternatives_for(scala, target);
        if alternatives.is_empty() {
            return scala_callable_alternative_matches(
                ScalaCallableRole::PrimaryConstructor,
                &[ScalaCallableParameterList::explicit(CallableArity::exact(
                    0,
                ))],
                call_shape,
                site_role,
                false,
            );
        }
        alternatives.iter().any(|alternative| {
            scala_callable_alternative_matches(
                alternative.role,
                &alternative.shape,
                call_shape,
                site_role,
                false,
            )
        })
    }

    pub(crate) fn callable_alternatives_for(
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
                            role: facts.role,
                            shape: facts.shape.clone(),
                            parameter_defaults: facts.parameter_defaults.clone(),
                            parameter_types: facts
                                .parameter_type_paths
                                .iter()
                                .map(|parameters| {
                                    parameters
                                        .iter()
                                        .map(|path| {
                                            path.as_deref().and_then(|path| {
                                                self.resolve_callable_parameter_type_identity(
                                                    scala,
                                                    &declaration_resolver,
                                                    target,
                                                    path,
                                                )
                                            })
                                        })
                                        .collect()
                                })
                                .collect(),
                            parameter_function_shapes: facts
                                .parameter_function_arities
                                .iter()
                                .zip(&facts.parameter_function_type_paths)
                                .map(|(arities, parameter_paths)| {
                                    arities
                                        .iter()
                                        .zip(parameter_paths)
                                        .map(|(arity, paths)| {
                                            let arity = (*arity)?;
                                            let parameter_types = paths.as_ref().and_then(|paths| {
                                                paths
                                                    .iter()
                                                    .map(|path| {
                                                        path.as_deref().and_then(|path| {
                                                            self.resolve_callable_parameter_type_identity(
                                                                scala,
                                                                &declaration_resolver,
                                                                target,
                                                                path,
                                                            )
                                                        })
                                                    })
                                                    .collect::<Option<Vec<_>>>()
                                            });
                                            Some(ScalaFunctionParameterShape {
                                                arity,
                                                parameter_types,
                                                parameter_types_authoritative: true,
                                            })
                                        })
                                        .collect()
                                })
                                .collect(),
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
                    synthetic.role = ScalaCallableRole::Ordinary;
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
                        role: if target.is_synthetic() {
                            ScalaCallableRole::PrimaryConstructor
                        } else {
                            ScalaCallableRole::Ordinary
                        },
                        shape: vec![ScalaCallableParameterList::explicit(arity)],
                        parameter_defaults: Vec::new(),
                        parameter_types: Vec::new(),
                        parameter_function_shapes: Vec::new(),
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
                    role: if target.is_synthetic() {
                        ScalaCallableRole::PrimaryConstructor
                    } else {
                        ScalaCallableRole::Ordinary
                    },
                    shape: vec![ScalaCallableParameterList::explicit(arity)],
                    parameter_defaults: Vec::new(),
                    parameter_types: Vec::new(),
                    parameter_function_shapes: Vec::new(),
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

    /// Return the source-declared callable alternatives with default parameters
    /// inherited by exact override families applied to the concrete declaration.
    ///
    /// Scala dispatches a call to an override even when the omitted argument's
    /// default is declared only by an ancestor.  We preserve that concrete
    /// target, but merge defaults only when every parameter position has an
    /// exact, source-backed type identity and the hierarchy itself is
    /// unambiguous.
    pub(crate) fn effective_callable_alternatives_for(
        &self,
        scala: &ScalaAnalyzer,
        target: &CodeUnit,
    ) -> CachedCallableAlternatives {
        let cell = self
            .effective_callable_alternatives_by_unit
            .lock()
            .expect("Scala effective callable-alternative cache poisoned")
            .entry(target.clone())
            .or_insert_with(|| Arc::new(OnceLock::new()))
            .clone();
        cell.get_or_init(|| {
            let declared = self.callable_alternatives_for(scala, target);
            let Some(owner) = self.exact_structural_parent(scala, target) else {
                return declared;
            };
            if !target.is_function()
                || declared.is_empty()
                || !self.hierarchy_is_unambiguous(scala, &owner)
            {
                return declared;
            }

            let linearized = self.linearized_owners(scala, &owner);
            if linearized.first() != Some(&owner) {
                return declared;
            }
            let mut effective = declared.as_ref().clone();
            for alternative in &mut effective {
                if alternative.role != ScalaCallableRole::Ordinary
                    || alternative.parameter_defaults.len() != alternative.shape.len()
                    || alternative.parameter_types.len() != alternative.shape.len()
                {
                    continue;
                }
                let declared_alternative = alternative.clone();
                let Some(defaults) = self.inherited_default_mask_for_alternative(
                    scala,
                    &linearized[1..],
                    target.identifier(),
                    &declared_alternative,
                ) else {
                    continue;
                };
                alternative.parameter_defaults = defaults;
                apply_parameter_defaults_to_shape(alternative);
            }
            Arc::new(effective)
        })
        .clone()
    }

    fn hierarchy_is_unambiguous(&self, scala: &ScalaAnalyzer, root: &CodeUnit) -> bool {
        let mut pending = vec![root.clone()];
        let mut seen = HashSet::default();
        while let Some(owner) = pending.pop() {
            if !seen.insert(owner.clone()) {
                continue;
            }
            match self.exact_direct_ancestor_resolution(scala, &owner) {
                ScalaDirectAncestorResolution::Resolved(ancestors) => pending.extend(ancestors),
                ScalaDirectAncestorResolution::Ambiguous => return false,
            }
        }
        true
    }

    fn inherited_default_mask_for_alternative(
        &self,
        scala: &ScalaAnalyzer,
        ancestors: &[CodeUnit],
        member: &str,
        declared: &CallableAlternative,
    ) -> Option<Vec<Vec<bool>>> {
        let mut defaults = declared.parameter_defaults.clone();
        let mut inherited = Vec::new();
        for owner in ancestors {
            let mut exact = Vec::new();
            let mut unknown = false;
            for method in self
                .members_for_exact_owner_unit(scala, owner, member)
                .into_iter()
                .filter(|unit| unit.is_function())
            {
                for alternative in self.callable_alternatives_for(scala, method).iter() {
                    match override_family_relation(declared, alternative) {
                        OverrideFamilyRelation::Exact => exact.push(alternative.clone()),
                        OverrideFamilyRelation::Unknown => unknown = true,
                        OverrideFamilyRelation::Different => {}
                    }
                }
            }
            if unknown || exact.len() > 1 {
                return None;
            }
            let Some(ancestor) = exact.pop() else {
                continue;
            };
            inherited.push((owner.clone(), ancestor));
        }
        for (index, (left, _)) in inherited.iter().enumerate() {
            for (right, _) in &inherited[index + 1..] {
                if !self.exact_owner_inherits(scala, left, right)
                    && !self.exact_owner_inherits(scala, right, left)
                {
                    return None;
                }
            }
        }
        for (_, ancestor) in inherited {
            if ancestor.parameter_defaults.len() != defaults.len() {
                return None;
            }
            for (effective_list, inherited_list) in
                defaults.iter_mut().zip(&ancestor.parameter_defaults)
            {
                if effective_list.len() != inherited_list.len() {
                    return None;
                }
                for (effective, inherited) in effective_list.iter_mut().zip(inherited_list) {
                    *effective |= *inherited;
                }
            }
        }
        Some(defaults)
    }

    fn resolve_callable_parameter_type_identity(
        &self,
        scala: &ScalaAnalyzer,
        resolver: &NameResolver,
        declaration: &CodeUnit,
        path: &[String],
    ) -> Option<ScalaParameterTypeIdentity> {
        if let Some(declaration) =
            self.resolve_callable_parameter_type_unit(scala, resolver, declaration, path)
        {
            return Some(ScalaParameterTypeIdentity::Declaration(declaration));
        }
        let [simple] = path else {
            return None;
        };
        if resolver.has_type_or_object_or_package_binding(simple) {
            return None;
        }
        scala_builtin_type_name(simple).map(ScalaParameterTypeIdentity::Builtin)
    }

    fn resolve_callable_parameter_type_unit(
        &self,
        scala: &ScalaAnalyzer,
        resolver: &NameResolver,
        declaration: &CodeUnit,
        path: &[String],
    ) -> Option<CodeUnit> {
        let (first, rest) = path.split_first()?;
        if rest.is_empty() {
            let fqn = resolver.resolve(first)?;
            let candidates = self
                .index
                .by_fqn(&fqn)
                .iter()
                .filter(|unit| unit.is_class() && !unit.short_name().ends_with('$'))
                .cloned()
                .collect::<Vec<_>>();
            let same_source = candidates
                .iter()
                .filter(|unit| unit.source() == declaration.source())
                .cloned()
                .collect::<Vec<_>>();
            return match same_source.as_slice() {
                [exact] => Some(exact.clone()),
                [] => match candidates.as_slice() {
                    [exact] => Some(exact.clone()),
                    _ => None,
                },
                _ => None,
            };
        }

        let mut scope = self.declaration_parent(scala, declaration);
        let mut seen = HashSet::default();
        while let Some(owner) = scope {
            if !seen.insert(owner.clone()) {
                break;
            }
            let mut roots = self.exact_nested_objects_for_owner(scala, &owner, first);
            roots.extend(self.exact_nested_types_for_owner(scala, &owner, first));
            roots.sort();
            roots.dedup();
            if let [root] = roots.as_slice() {
                let mut owners = vec![root.clone()];
                for segment in &rest[..rest.len() - 1] {
                    owners = owners
                        .iter()
                        .flat_map(|owner| {
                            self.exact_nested_objects_for_owner(scala, owner, segment)
                        })
                        .collect();
                    owners.sort();
                    owners.dedup();
                    if owners.len() != 1 {
                        break;
                    }
                }
                if owners.len() == 1 {
                    let terminal = rest.last()?;
                    let mut matches =
                        self.exact_nested_types_for_owner(scala, &owners[0], terminal);
                    matches.sort();
                    matches.dedup();
                    if let [exact] = matches.as_slice() {
                        return Some(exact.clone());
                    }
                }
            } else if !roots.is_empty() {
                return None;
            }
            scope = self.declaration_parent(scala, &owner);
        }

        self.resolve_qualified_stable_type_unit_at(scala, resolver, path, false, None)
    }

    pub(crate) fn exact_case_class_for_companion_apply(
        &self,
        scala: &ScalaAnalyzer,
        target: &CodeUnit,
    ) -> Option<CodeUnit> {
        if !target.is_function() || target.short_name().rsplit('.').next() != Some("apply") {
            return None;
        }
        let companion = self.exact_structural_parent(scala, target)?;
        if !companion.is_class() || !companion.short_name().ends_with('$') {
            return None;
        }
        let structural_parent = self.exact_structural_parent(scala, &companion);
        let mut candidates = self
            .index
            .by_normalized_fqn(&scala_normalized_fq_name(&companion.fq_name()))
            .iter()
            .filter(|candidate| {
                candidate.is_class()
                    && !candidate.short_name().ends_with('$')
                    && candidate.source() == companion.source()
                    && self.exact_structural_parent(scala, candidate) == structural_parent
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

    pub(super) fn stable_roots_for_resolved_type_name(
        &self,
        scala: &ScalaAnalyzer,
        resolver: &NameResolver,
        name: &str,
    ) -> Vec<CodeUnit> {
        let Some(fqn) = resolver.resolve(name) else {
            return Vec::new();
        };
        let Some(declaration) = self
            .unique_type_by_normalized_fqn(&scala_normalized_fq_name(&fqn))
            .cloned()
        else {
            return Vec::new();
        };
        // This bridge exists only for stable *type* roots such as enums. A
        // standalone object must stay in the term namespace so the resolver
        // can detect same-priority package/object alias collisions.
        if declaration.short_name().ends_with('$') {
            return Vec::new();
        }
        let mut roots = self.exact_companion_objects(scala, &declaration);
        if self.type_is_stable_owner(scala, &declaration) {
            roots.push(declaration);
        }
        roots.sort();
        roots.dedup();
        roots
    }

    pub(super) fn exact_companion_objects(
        &self,
        scala: &ScalaAnalyzer,
        target: &CodeUnit,
    ) -> Vec<CodeUnit> {
        let target_parent = self.exact_structural_parent(scala, target);
        self.index
            .by_normalized_fqn(&scala_normalized_fq_name(&target.fq_name()))
            .iter()
            .filter(|candidate| {
                candidate.is_class()
                    && *candidate != target
                    && candidate.source() == target.source()
                    && candidate.short_name().ends_with('$')
                    && self.exact_structural_parent(scala, candidate) == target_parent
            })
            .cloned()
            .collect()
    }

    pub(super) fn exact_companion_classes(
        &self,
        scala: &ScalaAnalyzer,
        target: &CodeUnit,
    ) -> Vec<CodeUnit> {
        let target_parent = self.exact_structural_parent(scala, target);
        self.index
            .by_normalized_fqn(&scala_normalized_fq_name(&target.fq_name()))
            .iter()
            .filter(|candidate| {
                candidate.is_class()
                    && *candidate != target
                    && candidate.source() == target.source()
                    && !candidate.short_name().ends_with('$')
                    && self.exact_structural_parent(scala, candidate) == target_parent
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
                        self.members_for_exact_owner_unit(scala, companion, member)
                            .iter()
                            .any(|unit| unit.is_function())
                    })
                })
    }

    fn class_application_matches_with_shape(
        &self,
        scala: &ScalaAnalyzer,
        resolver: &NameResolver,
        target: &CodeUnit,
        call_shape: Option<&ScalaCallSiteShape>,
    ) -> bool {
        if self.class_companion_apply_call_matches_with_shape(scala, resolver, target, call_shape) {
            return true;
        }
        if self
            .exact_companion_objects(scala, target)
            .iter()
            .any(|companion| {
                self.members_for_exact_owner_unit(scala, companion, "apply")
                    .iter()
                    .any(|unit| {
                        unit.is_function()
                            && call_shape.is_some_and(|shape| {
                                !self
                                    .callable_declarations_for_members_with_shape(
                                        scala,
                                        &[*unit],
                                        shape,
                                        ScalaCallableSiteRole::Ordinary,
                                    )
                                    .is_empty()
                            })
                    })
            })
        {
            return false;
        }
        self.constructor_target_matches(
            scala,
            target,
            call_shape,
            ScalaCallableSiteRole::PrimaryConstruction,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn resolve_type_application(
        &self,
        scala: &ScalaAnalyzer,
        resolver: &NameResolver,
        class_fqn: Option<&str>,
        object_fqn: Option<&str>,
        name: &str,
        call_shape: Option<&ScalaCallSiteShape>,
        role: TypeApplicationRole,
        reference_file: Option<&ProjectFile>,
    ) -> TypeApplicationResolution {
        let mut type_candidates = class_fqn
            .map(|fqn| {
                self.index
                    .by_fqn(fqn)
                    .iter()
                    .filter(|unit| unit.is_class() && !unit.short_name().ends_with('$'))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if let Some(reference_file) = reference_file {
            let same_file = type_candidates
                .iter()
                .copied()
                .filter(|unit| unit.source() == reference_file)
                .collect::<Vec<_>>();
            if !same_file.is_empty() {
                type_candidates = same_file;
            }
        }
        let type_target = (type_candidates.len() == 1).then(|| type_candidates[0].clone());
        if role == TypeApplicationRole::Extractor {
            let extractor_owners = if !type_candidates.is_empty() {
                type_candidates
                    .iter()
                    .flat_map(|target| self.exact_companion_objects(scala, target))
                    .collect::<Vec<_>>()
            } else {
                let owners = object_fqn
                    .into_iter()
                    .flat_map(|fqn| self.index.by_fqn(fqn).iter())
                    .filter(|unit| unit.is_class())
                    .cloned()
                    .collect::<Vec<_>>();
                let same_file = reference_file
                    .map(|file| {
                        owners
                            .iter()
                            .filter(|unit| unit.source() == file)
                            .cloned()
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                if same_file.is_empty() {
                    owners
                } else {
                    same_file
                }
            };
            let unapply_targets = extractor_owners
                .iter()
                .flat_map(|companion| {
                    ["unapply", "unapplySeq"]
                        .into_iter()
                        .flat_map(move |member| {
                            let members =
                                self.members_for_exact_owner_unit(scala, companion, member);
                            self.method_declarations_for_members(scala, &members, None)
                        })
                })
                .collect::<Vec<_>>();
            let mut callable_targets = match self.physical_callable_targets(scala, unapply_targets)
            {
                PhysicalCallableTargets::Unique(targets) => targets,
                PhysicalCallableTargets::Ambiguous => Vec::new(),
                PhysicalCallableTargets::NoCandidates => {
                    let primary_targets = type_candidates
                        .iter()
                        .flat_map(|target| {
                            let members = self
                                .members_for_exact_owner_name(&target.fq_name(), name)
                                .into_iter()
                                .filter(|unit| unit.source() == target.source())
                                .collect::<Vec<_>>();
                            self.callable_declarations_for_members(
                                scala,
                                &members,
                                call_shape,
                                ScalaCallableSiteRole::PrimaryConstruction,
                            )
                        })
                        .collect::<Vec<_>>();
                    match self.physical_callable_targets(scala, primary_targets) {
                        PhysicalCallableTargets::Unique(targets) => targets,
                        PhysicalCallableTargets::NoCandidates
                        | PhysicalCallableTargets::Ambiguous => Vec::new(),
                    }
                }
            };
            let mut seen = HashSet::default();
            callable_targets.retain(|target| seen.insert(target.clone()));
            return TypeApplicationResolution {
                type_target: type_target
                    .filter(|target| self.class_accepts_extractor_role(scala, target)),
                callable_targets,
                value_result: None,
            };
        }

        if role == TypeApplicationRole::ExplicitConstructor {
            let callable_targets = type_candidates
                .iter()
                .flat_map(|target| {
                    let members = self
                        .members_for_exact_owner_name(&target.fq_name(), name)
                        .into_iter()
                        .filter(|unit| unit.source() == target.source())
                        .collect::<Vec<_>>();
                    self.callable_declarations_for_members(
                        scala,
                        &members,
                        call_shape,
                        ScalaCallableSiteRole::ExplicitConstruction,
                    )
                })
                .collect::<Vec<_>>();
            let callable_targets = self
                .physical_callable_targets(scala, callable_targets)
                .into_unique();
            let type_target = type_target.filter(|target| {
                self.is_scala_trait_declaration(scala, target) || {
                    let members = self
                        .members_for_exact_owner_name(&target.fq_name(), name)
                        .into_iter()
                        .filter(|unit| unit.source() == target.source())
                        .collect::<Vec<_>>();
                    !self
                        .callable_declarations_for_members(
                            scala,
                            &members,
                            call_shape,
                            ScalaCallableSiteRole::ExplicitConstruction,
                        )
                        .is_empty()
                        || self.constructor_target_matches(
                            scala,
                            target,
                            call_shape,
                            ScalaCallableSiteRole::ExplicitConstruction,
                        )
                }
            });
            return TypeApplicationResolution {
                value_result: type_target.clone().map(ScalaValueOwner::Exact),
                type_target,
                callable_targets,
            };
        }

        let apply_owners = if !type_candidates.is_empty() {
            type_candidates
                .iter()
                .flat_map(|target| self.exact_companion_objects(scala, target))
                .collect::<Vec<_>>()
        } else {
            let owners = object_fqn
                .into_iter()
                .flat_map(|fqn| self.index.by_fqn(fqn).iter())
                .filter(|unit| unit.is_class())
                .cloned()
                .collect::<Vec<_>>();
            let same_file = reference_file
                .map(|file| {
                    owners
                        .iter()
                        .filter(|unit| unit.source() == file)
                        .cloned()
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            if same_file.is_empty() {
                owners
            } else {
                same_file
            }
        };
        if apply_owners.len() > 1 {
            return TypeApplicationResolution {
                type_target: None,
                callable_targets: Vec::new(),
                value_result: None,
            };
        }
        let apply_resolution = apply_owners
            .first()
            .map(|owner| self.inherited_apply_value_resolution(scala, owner, call_shape))
            .unwrap_or(ScalaApplyValueResolution::NoDeclaration);
        let apply_resolution = match apply_resolution {
            ScalaApplyValueResolution::NoDeclaration => {
                if let (Some(type_target), Some(companion)) =
                    (type_target.as_ref(), apply_owners.first())
                    && let Some(callable) = self.unresolved_inherited_companion_apply_fallback(
                        scala,
                        type_target,
                        companion,
                        call_shape,
                    )
                {
                    return TypeApplicationResolution {
                        type_target: None,
                        callable_targets: vec![callable],
                        value_result: None,
                    };
                }
                None
            }
            ScalaApplyValueResolution::NoApplicableCallable => None,
            ScalaApplyValueResolution::Authoritative(None) => {
                return TypeApplicationResolution {
                    type_target: None,
                    callable_targets: Vec::new(),
                    value_result: None,
                };
            }
            ScalaApplyValueResolution::Authoritative(resolution) => resolution,
        };
        let apply_targets = apply_resolution
            .as_ref()
            .map(|resolution| resolution.callable_targets.clone())
            .unwrap_or_default();
        match self.physical_callable_targets(scala, apply_targets) {
            PhysicalCallableTargets::Unique(mut apply_targets) => {
                if !type_candidates.is_empty() {
                    let mut seen = HashSet::default();
                    apply_targets.retain(|target| seen.insert(target.clone()));
                }
                let value_result = apply_resolution.and_then(|resolution| resolution.value_result);
                return TypeApplicationResolution {
                    type_target: type_target.filter(|target| {
                        value_result.as_ref().is_some_and(|value| match value {
                            ScalaValueOwner::Exact(owner) => owner == target,
                            ScalaValueOwner::Logical(fqn) => {
                                scala_normalized_fq_name(fqn)
                                    == scala_normalized_fq_name(&target.fq_name())
                            }
                        })
                    }),
                    callable_targets: apply_targets,
                    value_result,
                };
            }
            PhysicalCallableTargets::Ambiguous => {
                return TypeApplicationResolution {
                    type_target: None,
                    callable_targets: Vec::new(),
                    value_result: None,
                };
            }
            PhysicalCallableTargets::NoCandidates => {}
        }

        let callable_targets = type_candidates
            .iter()
            .flat_map(|target| {
                let members = self
                    .members_for_exact_owner_name(&target.fq_name(), name)
                    .into_iter()
                    .filter(|unit| unit.source() == target.source())
                    .collect::<Vec<_>>();
                self.callable_declarations_for_members(
                    scala,
                    &members,
                    call_shape,
                    ScalaCallableSiteRole::PrimaryConstruction,
                )
            })
            .collect::<Vec<_>>();
        let callable_targets = self
            .physical_callable_targets(scala, callable_targets)
            .into_unique();
        TypeApplicationResolution {
            value_result: type_target
                .as_ref()
                .filter(|target| {
                    self.class_application_matches_with_shape(scala, resolver, target, call_shape)
                })
                .cloned()
                .map(ScalaValueOwner::Exact),
            type_target: type_target.filter(|target| {
                self.class_application_matches_with_shape(scala, resolver, target, call_shape)
            }),
            callable_targets,
        }
    }

    fn unresolved_inherited_companion_apply_fallback(
        &self,
        scala: &ScalaAnalyzer,
        type_target: &CodeUnit,
        companion: &CodeUnit,
        call_shape: Option<&ScalaCallSiteShape>,
    ) -> Option<CodeUnit> {
        let normalized_owner = scala_normalized_fq_name(&type_target.fq_name());
        let mut physical_companions = scala
            .global_usage_definition_index()
            .by_normalized_fqn(&normalized_owner)
            .iter()
            .filter(|candidate| {
                candidate.is_class()
                    && *candidate != type_target
                    && self.type_accepts_object_roles(scala, candidate)
            });
        let physical_companion = physical_companions.next()?;
        if physical_companion != companion || physical_companions.next().is_some() {
            return None;
        }

        let facts = scala.forward_owner_facts(companion)?;
        if facts.supertype_lookup_paths.is_empty() {
            return None;
        }

        let members = self.members_for_exact_owner_unit(scala, type_target, "apply");
        let mut callables = self.callable_declarations_for_members(
            scala,
            &members,
            call_shape,
            ScalaCallableSiteRole::Ordinary,
        );
        callables.sort();
        callables.dedup();
        match callables.as_slice() {
            [callable] => Some(callable.clone()),
            _ => None,
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
                    self.members_for_exact_owner_unit(scala, companion, "apply")
                        .iter()
                        .any(|unit| unit.is_function())
                })
    }

    fn class_companion_apply_call_matches_with_shape(
        &self,
        scala: &ScalaAnalyzer,
        resolver: &NameResolver,
        target: &CodeUnit,
        call_shape: Option<&ScalaCallSiteShape>,
    ) -> bool {
        if self.is_case_class(scala, target)
            && self.constructor_target_matches(
                scala,
                target,
                call_shape,
                ScalaCallableSiteRole::PrimaryConstruction,
            )
        {
            return true;
        }
        self.exact_companion_objects(scala, target)
            .iter()
            .any(|companion| {
                call_shape
                    .and_then(|shape| {
                        let members = self.members_for_exact_owner_unit(scala, companion, "apply");
                        self.member_return_type_for_members_with_shape(
                            scala,
                            resolver,
                            &members,
                            Some(shape),
                        )
                    })
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
                    .filter(|alternative| alternative.role == ScalaCallableRole::PrimaryConstructor)
                    .cloned()
                    .map(|mut alternative| {
                        alternative.role = ScalaCallableRole::Ordinary;
                        alternative
                    }),
            );
        }
        let normalized_target = scala_normalized_fq_name(&target.fq_name());
        for companion in self.exact_companion_objects(scala, target) {
            for apply in self
                .members_for_exact_owner_unit(scala, &companion, "apply")
                .iter()
                .filter(|unit| unit.is_function())
            {
                alternatives.extend(
                    self.callable_alternatives_for(scala, apply)
                        .iter()
                        .filter(|alternative| {
                            alternative.role == ScalaCallableRole::Ordinary
                                && alternative
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
                alternative.role == ScalaCallableRole::Ordinary
                    && contextual_arities.is_none_or(|arities| {
                        ordinary_callable_shape_matches(&alternative.shape, Some(arities), false)
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

    pub(super) fn is_case_class(&self, scala: &ScalaAnalyzer, target: &CodeUnit) -> bool {
        let source_facts = self.source_facts_for_file(scala, target.source());
        self.declaration_ranges_for(scala, target)
            .iter()
            .any(|range| {
                source_facts
                    .case_class_ranges
                    .contains(&(range.start_byte, range.end_byte))
            })
    }

    pub(crate) fn is_enum(&self, scala: &ScalaAnalyzer, target: &CodeUnit) -> bool {
        let source_facts = self.source_facts_for_file(scala, target.source());
        self.declaration_ranges_for(scala, target)
            .iter()
            .any(|range| {
                source_facts
                    .enum_ranges
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
                .map(str::to_owned)
                .or_else(|| scala.indexed_source(file)),
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
        methods.sort_by(|left, right| left.declaration.cmp(&right.declaration));
        methods.dedup_by(|left, right| left.declaration == right.declaration);
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
            declaration: unit.clone(),
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
                        .map(|ancestor_method| (*ancestor_method).clone()),
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
    pub(crate) role: ScalaCallableRole,
    pub(crate) shape: Vec<ScalaCallableParameterList>,
    pub(crate) parameter_defaults: Vec<Vec<bool>>,
    pub(crate) parameter_types: Vec<Vec<Option<ScalaParameterTypeIdentity>>>,
    pub(crate) parameter_function_shapes: Vec<Vec<Option<ScalaFunctionParameterShape>>>,
    pub(crate) extension_receiver_type: Option<String>,
    pub(crate) return_type: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OverrideFamilyRelation {
    Exact,
    Different,
    Unknown,
}

fn override_family_relation(
    declared: &CallableAlternative,
    ancestor: &CallableAlternative,
) -> OverrideFamilyRelation {
    if declared.role != ScalaCallableRole::Ordinary
        || ancestor.role != ScalaCallableRole::Ordinary
        || declared.shape.len() != ancestor.shape.len()
    {
        return OverrideFamilyRelation::Different;
    }
    for (declared_list, ancestor_list) in declared.shape.iter().zip(&ancestor.shape) {
        if declared_list.kind != ancestor_list.kind
            || declared_list.arity.total() != ancestor_list.arity.total()
            || callable_arity_is_repeated(declared_list.arity)
                != callable_arity_is_repeated(ancestor_list.arity)
        {
            return OverrideFamilyRelation::Different;
        }
    }
    if declared.parameter_types.len() != declared.shape.len()
        || ancestor.parameter_types.len() != ancestor.shape.len()
    {
        return OverrideFamilyRelation::Unknown;
    }
    for ((declared_types, ancestor_types), declared_shape) in declared
        .parameter_types
        .iter()
        .zip(&ancestor.parameter_types)
        .zip(&declared.shape)
    {
        if declared_types.len() != declared_shape.arity.total()
            || ancestor_types.len() != declared_shape.arity.total()
        {
            return OverrideFamilyRelation::Unknown;
        }
        for (declared_type, ancestor_type) in declared_types.iter().zip(ancestor_types) {
            match (declared_type, ancestor_type) {
                (Some(declared_type), Some(ancestor_type)) if declared_type == ancestor_type => {}
                (Some(_), Some(_)) => return OverrideFamilyRelation::Different,
                _ => return OverrideFamilyRelation::Unknown,
            }
        }
    }
    OverrideFamilyRelation::Exact
}

fn callable_arity_is_repeated(arity: CallableArity) -> bool {
    arity.accepts(arity.total().saturating_add(1))
}

fn apply_parameter_defaults_to_shape(alternative: &mut CallableAlternative) {
    for (list, defaults) in alternative
        .shape
        .iter_mut()
        .zip(&alternative.parameter_defaults)
    {
        let total = list.arity.total();
        if defaults.len() != total {
            continue;
        }
        let repeated = callable_arity_is_repeated(list.arity);
        let required = total
            .saturating_sub(defaults.iter().filter(|is_default| **is_default).count())
            .saturating_sub(usize::from(repeated));
        list.arity = CallableArity::new(required, total, repeated);
    }
}

pub(crate) fn callable_alternative_is_candidate(
    alternative: &CallableAlternative,
    actual: &ScalaCallSiteShape,
    site_role: ScalaCallableSiteRole,
) -> bool {
    scala_callable_alternative_is_candidate(alternative.role, &alternative.shape, actual, site_role)
        && method_value_parameter_types_match(alternative, actual)
}

pub(crate) fn callable_alternative_matches(
    alternative: &CallableAlternative,
    actual: Option<&ScalaCallSiteShape>,
    site_role: ScalaCallableSiteRole,
    unique_callable: bool,
) -> bool {
    scala_callable_alternative_matches(
        alternative.role,
        &alternative.shape,
        actual,
        site_role,
        unique_callable,
    ) && actual.is_none_or(|actual| method_value_parameter_types_match(alternative, actual))
}

fn method_value_parameter_types_match(
    alternative: &CallableAlternative,
    actual: &ScalaCallSiteShape,
) -> bool {
    let Some(list_index) = next_explicit_parameter_list_index(&alternative.shape, actual) else {
        // Once all explicit lists have been consumed, the surrounding
        // function expectation describes the callable's return value rather
        // than another curried parameter list. It therefore cannot reject the
        // completed call even when that return-function parameter is generic
        // or otherwise lacks an exact physical identity.
        return true;
    };
    if !actual.method_value_parameter_types_authoritative {
        return true;
    }
    let Some(expected) = actual.method_value_parameter_types.as_ref() else {
        return false;
    };
    let Some(declared) = alternative.parameter_types.get(list_index) else {
        return false;
    };
    declared.len() == expected.len()
        && declared
            .iter()
            .zip(expected)
            .all(|(declared, expected)| declared.as_ref() == Some(expected))
}

fn next_explicit_parameter_list_index(
    declared: &[ScalaCallableParameterList],
    actual: &ScalaCallSiteShape,
) -> Option<usize> {
    let mut declared_index = 0usize;
    for actual_list in &actual.lists {
        if matches!(
            actual_list.kind,
            super::syntax::ScalaCallArgumentListKind::Ordinary
                | super::syntax::ScalaCallArgumentListKind::Block
        ) {
            while declared
                .get(declared_index)
                .is_some_and(|list| list.kind == super::syntax::ScalaParameterListKind::Contextual)
            {
                declared_index += 1;
            }
        }
        declared.get(declared_index)?;
        declared_index += 1;
    }
    let mut remaining = declared
        .iter()
        .enumerate()
        .skip(declared_index)
        .filter(|(_, list)| list.kind == super::syntax::ScalaParameterListKind::Explicit);
    let (index, _) = remaining.next()?;
    remaining.next().is_none().then_some(index)
}

#[derive(Clone)]
pub(crate) struct ExtensionMethod {
    pub(crate) declaration: CodeUnit,
    pub(crate) fqn: String,
    alternatives: CachedCallableAlternatives,
}

/// Per-file map from a source-visible type/object name to the analyzer's fqn,
/// mirroring the forward scanner's visibility rules.
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

    fn resolve_logical(&self, name: &str) -> Option<String> {
        let binding = self.entries.get(name)?;
        (binding.candidates.len() == 1).then(|| binding.candidates.iter().next().cloned())?
    }

    fn resolve_exact(&self, name: &str) -> Option<CodeUnit> {
        let binding = self.entries.get(name)?;
        let declarations = binding.declarations.iter().collect::<Vec<_>>();
        let [declaration] = declarations.as_slice() else {
            return None;
        };
        (binding.candidates.len() == 1).then(|| (*declaration).clone())
    }

    fn resolve_exact_candidates(&self, name: &str) -> Vec<CodeUnit> {
        let Some(binding) = self.entries.get(name) else {
            return Vec::new();
        };
        if binding.candidates.len() != 1 || binding.declarations.is_empty() {
            return Vec::new();
        }
        sorted_unique_units(binding.declarations.iter().cloned().collect())
    }

    fn resolve_declaration(&self, name: &str) -> ScalaQualifiedTypeRootResolution {
        let Some(binding) = self.entries.get(name) else {
            return ScalaQualifiedTypeRootResolution::NoMatch;
        };
        if binding.candidates.len() == 1 && !binding.declarations.is_empty() {
            ScalaQualifiedTypeRootResolution::Resolved(
                ScalaQualifiedTypeRootBinding::StableObjects(sorted_unique_units(
                    binding.declarations.iter().cloned().collect(),
                )),
            )
        } else {
            ScalaQualifiedTypeRootResolution::Ambiguous
        }
    }

    fn contains(&self, name: &str) -> bool {
        self.entries.contains_key(name)
    }

    fn is_ambiguous(&self, name: &str) -> bool {
        self.entries
            .get(name)
            .is_some_and(|binding| binding.candidates.len() != 1 || binding.declarations.len() > 1)
    }

    fn priority(&self, name: &str) -> Option<u8> {
        self.entries.get(name).map(|binding| binding.priority)
    }
}

fn add_wildcard_member_bindings(
    member_names: &mut VisibleNameBindings,
    declarations: impl IntoIterator<Item = CodeUnit>,
) {
    for declaration in declarations {
        if declaration.is_function() || declaration.is_field() {
            let visible_name = declaration
                .short_name()
                .rsplit('.')
                .next()
                .unwrap_or(declaration.short_name())
                .to_string();
            member_names.add_declaration(visible_name, &declaration, 128);
        }
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

fn scala_default_namespace_is_source_backed(name: &str) -> bool {
    !matches!(
        name,
        // These are compiler-provided lattice types. A source declaration with
        // the same spelling (notably in negative compiler tests) must not turn
        // an intrinsic reference into a physical inverse edge.
        "Any" | "AnyRef" | "Nothing" | "Null" | "Singleton" | "Matchable"
    )
}

impl NameResolver {
    pub(super) fn resolve_unit(&self, name: &str) -> Option<CodeUnit> {
        self.names.resolve_exact(name)
    }

    pub(super) fn resolve_object_unit(&self, name: &str) -> Option<CodeUnit> {
        self.object_names.resolve_exact(name)
    }

    pub(super) fn resolve_member_unit(&self, name: &str) -> Option<CodeUnit> {
        self.member_names.resolve_exact(name)
    }

    fn resolve_explicit_member_unit(&self, name: &str) -> Option<CodeUnit> {
        (self.member_names.priority(name) == Some(192))
            .then(|| self.member_names.resolve_exact(name))
            .flatten()
    }

    fn resolve_member_units(&self, name: &str) -> Vec<CodeUnit> {
        if self.import_collision_blocks(name, None) {
            return Vec::new();
        }
        self.member_names.resolve_exact_candidates(name)
    }

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
            if scala_default_namespace_is_source_backed(required) {
                add_hierarchy_package_type_bindings(&mut names, types, "scala", required, |_| 0);
                add_hierarchy_package_object_bindings(
                    &mut object_names,
                    types,
                    "scala",
                    required,
                    |_| 0,
                );
            }
            add_hierarchy_package_type_bindings(
                &mut names,
                types,
                file_package,
                required,
                |decl| {
                    if source_file == Some(decl.source()) {
                        4
                    } else {
                        1
                    }
                },
            );
            add_hierarchy_package_object_bindings(
                &mut object_names,
                types,
                file_package,
                required,
                |decl| {
                    if source_file == Some(decl.source()) {
                        4
                    } else {
                        1
                    }
                },
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
                            names.add_declaration(required.clone(), declaration, 2);
                        }
                        for declaration in children.iter().filter(|unit| {
                            unit.is_class()
                                && unit.short_name().ends_with('$')
                                && scala_simple_type_name(unit) == *required
                        }) {
                            object_names.add_declaration(required.clone(), declaration, 2);
                            if !names.contains(required) {
                                names.add_declaration(required.clone(), declaration, 2);
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
                            |_| 2,
                        );
                        add_hierarchy_package_object_bindings(
                            &mut object_names,
                            types,
                            &owner.fqn,
                            required,
                            |_| 2,
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
                ambiguous_import_priorities.insert(local_name.to_string(), 3);
            }
            if tier.declaration {
                let (type_declarations, object_declarations) =
                    types.explicit_import_type_declarations(&tier.candidate);
                for declaration in &type_declarations {
                    names.add_declaration(local_name.to_string(), declaration, 3);
                }
                for declaration in &object_declarations {
                    object_names.add_declaration(local_name.to_string(), declaration, 3);
                }
            }
            if tier.package {
                package_names.add_candidate(
                    local_name.to_string(),
                    scala_normalized_fq_name(&tier.candidate),
                    None,
                    3,
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
        // Every Scala compilation unit implicitly imports `scala.*`. Keep it
        // below the active package and every explicit/wildcard import, and bind
        // only physical source declarations so duplicate library replicas fail
        // closed in the same way as ordinary imports.
        for (simple, declaration) in types.package_types_in("scala").iter() {
            if scala_default_namespace_is_source_backed(simple) {
                names.add_declaration(simple.clone(), declaration, 1);
            }
        }
        for (simple, declaration) in types.package_objects_in(scala, "scala").iter() {
            if scala_default_namespace_is_source_backed(simple) {
                object_names.add_declaration(simple.clone(), declaration, 1);
            }
        }
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
            let package_priority = if package.is_empty() {
                0
            } else {
                64u8.saturating_add(index.min(63) as u8)
            };
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
            if include_members {
                for declaration in types.index.fqn_direct_children(package) {
                    if !declaration.is_function() && !declaration.is_field() {
                        continue;
                    }
                    let priority = if source_file == Some(declaration.source()) {
                        224u8.saturating_add(index.min(30) as u8)
                    } else {
                        package_priority
                    };
                    member_names.add_declaration(
                        declaration.identifier().to_string(),
                        &declaration,
                        priority,
                    );
                }
            }
        }

        let wildcard_environment = resolve_scala_wildcard_import_environment(
            imports,
            active_package_prefixes,
            |candidate| ScalaWildcardOwnerFacts {
                package: types.index.package_exists(candidate),
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
                                member_names.add_declaration(visible_name, &child, 128);
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
                    for declaration in types.index.fqn_direct_children(&owner.fqn) {
                        if declaration.is_function() || declaration.is_field() {
                            member_names.add_declaration(
                                declaration.identifier().to_string(),
                                &declaration,
                                128,
                            );
                        }
                    }
                    wildcard_extension_owners.push(owner.fqn.clone());
                }
            }
        }

        if include_members {
            // Resolve term and extension bindings one import at a time. An
            // ambiguous earlier wildcard must not erase a later, independent
            // wildcard import; it only contributes no bindings of its own.
            for import in imports.iter().filter(|import| import.is_wildcard) {
                let environment = resolve_scala_wildcard_import_environment(
                    std::slice::from_ref(import),
                    active_package_prefixes,
                    |candidate| ScalaWildcardOwnerFacts {
                        package: types.index.package_exists(candidate),
                        stable_singleton: types
                            .object_by_normalized_fqn(scala, &scala_normalized_fq_name(candidate))
                            .is_some(),
                    },
                );
                if environment.ambiguous {
                    continue;
                }
                for owner in &environment.owners {
                    if owner.is_singleton() {
                        let normalized_owner = scala_normalized_fq_name(&owner.declaration_fqn());
                        if let Some(declaration) =
                            types.object_by_normalized_fqn(scala, &normalized_owner)
                        {
                            add_wildcard_member_bindings(
                                &mut member_names,
                                types.index.fqn_direct_children(&declaration.fq_name()),
                            );
                            for (visible_name, member_fqn) in
                                types.exported_member_bindings(scala, declaration)
                            {
                                member_names.add_candidate(visible_name, member_fqn, None, 128);
                            }
                        }
                        wildcard_extension_owners.push(normalized_owner);
                    } else {
                        add_wildcard_member_bindings(
                            &mut member_names,
                            types.index.fqn_direct_children(&owner.fqn),
                        );
                        wildcard_extension_owners.push(owner.fqn.clone());
                    }
                }

                // Parser-recorded import paths omit Scala's physical `$`
                // separators. Bridge that logical path to one exact stable
                // type owner as well as its term companion: enum cases are
                // children of the enum type, not of an explicit companion
                // object such as Duration.Units.
                if let Some(path) = scala_import_path(import) {
                    let import_prefixes = import
                        .path
                        .as_ref()
                        .map(|path| path.lexical_prefixes.as_slice())
                        .filter(|prefixes| !prefixes.is_empty())
                        .unwrap_or(active_package_prefixes);
                    for candidate in scala_import_path_candidates(&path, import_prefixes) {
                        let normalized = scala_normalized_fq_name(&candidate);
                        let mut stable_owners = types
                            .index
                            .by_normalized_fqn(&normalized)
                            .iter()
                            .filter(|unit| unit.is_class() && !unit.short_name().ends_with('$'))
                            .filter(|unit| types.type_is_stable_owner(scala, unit));
                        let Some(owner) = stable_owners.next() else {
                            continue;
                        };
                        if stable_owners.next().is_some() {
                            break;
                        }
                        add_wildcard_member_bindings(
                            &mut member_names,
                            types.index.fqn_direct_children(&owner.fq_name()),
                        );
                        wildcard_extension_owners.push(normalized);
                        break;
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
                    types.explicit_import_type_declarations(&tier.candidate);
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
            if include_members
                && let Some(member) =
                    types.importable_member_by_normalized_fqn(scala, &normalized, source_file)
            {
                member_names.add_declaration(local_name.clone(), member, 192);
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

    fn resolve_logical(&self, raw: &str) -> Option<String> {
        let simple = simple_type_name(raw)?;
        if self.import_collision_blocks(simple, self.names.priority(simple)) {
            return None;
        }
        self.names.resolve_logical(simple)
    }

    pub(crate) fn type_binding_is_ambiguous(&self, raw: &str) -> bool {
        let Some(simple) = simple_type_name(raw) else {
            return false;
        };
        self.import_collision_blocks(simple, self.names.priority(simple))
            || self.names.is_ambiguous(simple)
    }

    pub(crate) fn object_binding_is_ambiguous(&self, raw: &str) -> bool {
        let Some(simple) = simple_type_name(raw) else {
            return false;
        };
        self.import_collision_blocks(simple, self.object_names.priority(simple))
            || self.object_names.is_ambiguous(simple)
    }

    pub(crate) fn resolve_object(&self, raw: &str) -> Option<String> {
        let simple = simple_type_name(raw)?;
        if self.import_collision_blocks(simple, self.object_names.priority(simple)) {
            return None;
        }
        self.object_names.resolve(simple)
    }

    fn resolve_qualified_type_root(
        &self,
        types: &ProjectTypes,
        raw: &str,
        mut lexical_objects: Vec<CodeUnit>,
    ) -> ScalaQualifiedTypeRootResolution {
        lexical_objects.sort();
        lexical_objects.dedup();
        if !lexical_objects.is_empty() {
            return ScalaQualifiedTypeRootResolution::Resolved(
                ScalaQualifiedTypeRootBinding::StableObjects(lexical_objects),
            );
        }
        let Some(simple) = simple_type_name(raw) else {
            return ScalaQualifiedTypeRootResolution::NoMatch;
        };
        let type_priority = self.names.priority(simple);
        let object_priority = self.object_names.priority(simple);
        let package_priority = self.package_names.priority(simple);
        let winner_priority = type_priority
            .into_iter()
            .chain(object_priority)
            .chain(package_priority)
            .max();
        if self.import_collision_blocks(simple, winner_priority) {
            return ScalaQualifiedTypeRootResolution::Ambiguous;
        }
        if let Some(winner) = winner_priority {
            if package_priority == Some(winner) && object_priority == Some(winner) {
                return ScalaQualifiedTypeRootResolution::Ambiguous;
            }
            if object_priority == Some(winner) {
                return self.object_names.resolve_declaration(simple);
            }
            if package_priority == Some(winner) {
                return self.package_names.resolve(simple).map_or(
                    ScalaQualifiedTypeRootResolution::Ambiguous,
                    |package| {
                        ScalaQualifiedTypeRootResolution::Resolved(
                            ScalaQualifiedTypeRootBinding::Package(package),
                        )
                    },
                );
            }
            return ScalaQualifiedTypeRootResolution::AuthoritativeMiss;
        }
        for candidate in scala_enclosing_package_root_candidates(&self.package_prefixes, simple) {
            if types.index.package_exists(&candidate) {
                return ScalaQualifiedTypeRootResolution::Resolved(
                    ScalaQualifiedTypeRootBinding::Package(candidate),
                );
            }
        }
        ScalaQualifiedTypeRootResolution::NoMatch
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

    /// Resolve a source-visible member name imported directly from an owner.
    pub(crate) fn resolve_member(&self, raw: &str) -> Option<String> {
        let simple = simple_type_name(raw)?;
        if self.import_collision_blocks(simple, None) {
            return None;
        }
        self.member_names.resolve(simple)
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

enum PhysicalCallableTargets {
    NoCandidates,
    Unique(Vec<CodeUnit>),
    Ambiguous,
}

impl PhysicalCallableTargets {
    fn into_unique(self) -> Vec<CodeUnit> {
        match self {
            Self::Unique(targets) => targets,
            Self::NoCandidates | Self::Ambiguous => Vec::new(),
        }
    }
}

pub(super) fn is_package_level_type(unit: &CodeUnit) -> bool {
    !unit.short_name().contains('.')
}

fn method_arities_compatible(method: Option<usize>, ancestor: Option<usize>) -> bool {
    method.is_none() || ancestor.is_none() || method == ancestor
}

fn callable_call_shape_matches(
    facts: &CallableFacts,
    alternatives: &[CallableAlternative],
    call_arities: Option<&[usize]>,
    fallback_role: ScalaCallableRole,
    site_role: ScalaCallableSiteRole,
    unique_callable: bool,
) -> bool {
    let actual = call_arities.map(ScalaCallSiteShape::ordinary);
    let fallback_shape;
    if alternatives.is_empty() {
        fallback_shape = facts
            .callable_arity
            .or_else(|| facts.arity.map(crate::analyzer::CallableArity::exact))
            .map(|arity| vec![ScalaCallableParameterList::explicit(arity)])
            .unwrap_or_default();
        return scala_callable_alternative_matches(
            fallback_role,
            &fallback_shape,
            actual.as_ref(),
            site_role,
            unique_callable,
        );
    }
    alternatives.iter().any(|alternative| {
        scala_callable_alternative_matches(
            alternative.role,
            &alternative.shape,
            actual.as_ref(),
            site_role,
            unique_callable,
        )
    })
}

fn ordinary_callable_shape_matches(
    declared: &[ScalaCallableParameterList],
    call_arities: Option<&[usize]>,
    unique_callable: bool,
) -> bool {
    let actual = call_arities.map(ScalaCallSiteShape::ordinary);
    scala_callable_shape_matches(
        declared,
        actual.as_ref(),
        ScalaCallableUsePolicy::OrdinaryMethod,
        unique_callable,
    )
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
        .split(['[', '(', '{', '.', ' '])
        .next()
        .map(str::trim)
        .filter(|name| !name.is_empty())
}

/// Build the whole Scala `caller -> callee` edge set in a single inverted pass
/// over the workspace.
/// `nodes`/`keep_file` mirror the Go builder.
struct ScalaEdgeSink<'a, 'b> {
    collector: &'a mut EdgeCollector<'b>,
    scala: &'a ScalaAnalyzer,
    types: &'a ProjectTypes,
}

impl ScalaReferenceSink for ScalaEdgeSink<'_, '_> {
    fn record(
        &mut self,
        target: ScalaResolvedReference,
        role: ScalaReferenceRole,
        reference_kind: UsageReferenceKind,
        _hit_kind: UsageHitKind,
        start: usize,
        end: usize,
    ) {
        if matches!(
            role,
            ScalaReferenceRole::CompanionApplication
                | ScalaReferenceRole::CompanionExtractor
                | ScalaReferenceRole::CompanionValue
        ) && let ScalaResolvedReference::Exact(callable) = &target
            && let Some(owner) = self.types.exact_structural_parent(self.scala, callable)
        {
            let companions = if owner.short_name().ends_with('$') {
                vec![owner]
            } else {
                self.types.exact_companion_objects(self.scala, &owner)
            };
            if let [companion] = companions.as_slice() {
                self.collector
                    .record_kind(companion.fq_name(), reference_kind, start, end);
            }
        }
        let target = match target {
            ScalaResolvedReference::Exact(unit) => unit.fq_name(),
            ScalaResolvedReference::Logical(fqn) => fqn,
        };
        self.collector
            .record_kind(target, reference_kind, start, end);
    }

    fn record_with_caller(
        &mut self,
        caller: String,
        target: ScalaResolvedReference,
        role: ScalaReferenceRole,
        reference_kind: UsageReferenceKind,
        _hit_kind: UsageHitKind,
        start: usize,
        end: usize,
    ) {
        if role == ScalaReferenceRole::Override
            && let ScalaResolvedReference::Exact(target) = &target
            && self
                .scala
                .structural_parent_of(target)
                .is_some_and(|owner| !self.types.is_scala_trait_declaration(self.scala, &owner))
        {
            return;
        }
        let target = match target {
            ScalaResolvedReference::Exact(unit) => unit.fq_name(),
            ScalaResolvedReference::Logical(fqn) => fqn,
        };
        self.collector
            .record_with_caller_kind(caller, target, reference_kind, start, end);
    }

    fn record_unproven_name(&mut self, name: &str, start: usize, end: usize) {
        self.collector.record_unproven_name(name, start, end);
    }
}

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
                let mut sink = ScalaEdgeSink {
                    collector,
                    scala,
                    types: &graph.types,
                };
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
                    active_package: state.package_name.clone(),
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
                    sink: &mut sink,
                    cancellation: None,
                };
                let mut bindings = LocalInferenceEngine::new(LocalInferenceConfig::default());
                walk(parsed.tree.root_node(), &mut ctx, &mut bindings);
            },
        )
    })
}

/// Scan one caller-supplied Scala file through the same structured resolver used
/// by the whole-workspace graph, without constructing or hydrating that graph.
/// The caller supplies the exact-target sink and owns file eligibility.
pub(super) fn scan_scala_query_file(
    scala: &ScalaAnalyzer,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    sink: &mut dyn ScalaReferenceSink,
    cancellation: Option<&crate::cancellation::CancellationToken>,
) -> bool {
    if cancellation.is_some_and(crate::cancellation::CancellationToken::is_cancelled) {
        return false;
    }
    if source.is_empty() {
        return false;
    }
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_scala::LANGUAGE.into())
        .is_err()
    {
        return false;
    }
    let Some(tree) = parser.parse(source, None) else {
        return false;
    };
    scala.record_query_parse();
    let types = scala.project_types();
    let package = super::resolver::package_name_of(scala, file).unwrap_or_default();
    let imports = scala.import_info_of(file);
    sink.register_imports(&imports);
    let resolver = Arc::new(NameResolver::for_file_with_facts(
        scala,
        Some(file),
        Some(&package),
        &[],
        &types,
    ));
    let mut ctx = ScalaScan {
        scala,
        source,
        source_file: file,
        imports: &imports,
        active_package: package,
        import_contexts: ScalaImportContextIndex::new(&imports, tree.root_node().end_byte()),
        import_context_cursor: 0,
        package_contexts: ScalaPackageContextIndex::new(tree.root_node(), source),
        package_context_cursor: 0,
        resolver,
        active_resolver_key: None,
        resolver_contexts: HashMap::default(),
        types: &types,
        class_ranges: ClassRangeIndex::build(analyzer, file),
        sink,
        cancellation,
    };
    let mut bindings = LocalInferenceEngine::new(LocalInferenceConfig::default());
    scala.record_query_walk();
    walk(tree.root_node(), &mut ctx, &mut bindings);
    true
}

struct ScalaScan<'a, 'b> {
    scala: &'a ScalaAnalyzer,
    source: &'a str,
    source_file: &'a ProjectFile,
    imports: &'a [crate::analyzer::ImportInfo],
    active_package: String,
    import_contexts: ScalaImportContextIndex,
    import_context_cursor: usize,
    package_contexts: ScalaPackageContextIndex,
    package_context_cursor: usize,
    resolver: Arc<NameResolver>,
    active_resolver_key: Option<(Vec<String>, Vec<usize>)>,
    resolver_contexts: HashMap<(Vec<String>, Vec<usize>), Arc<NameResolver>>,
    types: &'a ProjectTypes,
    class_ranges: ClassRangeIndex,
    sink: &'a mut dyn ScalaReferenceSink,
    cancellation: Option<&'b crate::cancellation::CancellationToken>,
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
            self.active_package = key.0.last().cloned().unwrap_or_default();
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
        self.active_package = key.0.last().cloned().unwrap_or_default();
        self.active_resolver_key = Some(key);
    }

    /// The fqn of the smallest class/object declaration containing `byte`.
    fn enclosing_class(&self, byte: usize) -> Option<&str> {
        self.class_ranges.enclosing(byte)
    }

    fn enclosing_class_unit(&self, byte: usize) -> Option<&CodeUnit> {
        self.class_ranges.enclosing_unit(byte)
    }

    fn exact_lexically_visible_type(&self, node: Node<'_>) -> ScalaTypeNamespaceResolution {
        let lookup_node = scala_qualified_type_root(node);
        let segments = scala_type_lookup_segments(lookup_node, self.source);
        let resolution = self.exact_lexically_visible_type_root(node);
        if segments.len() == 1 {
            return resolution;
        }
        match resolution {
            ScalaTypeNamespaceResolution::AuthoritativeMiss
            | ScalaTypeNamespaceResolution::Ambiguous => resolution,
            ScalaTypeNamespaceResolution::NoMatch | ScalaTypeNamespaceResolution::Resolved(_) => {
                ScalaTypeNamespaceResolution::NoMatch
            }
        }
    }

    fn exact_lexically_visible_type_root(&self, node: Node<'_>) -> ScalaTypeNamespaceResolution {
        let lookup_node = scala_qualified_type_root(node);
        if scala_type_reference_is_singleton(lookup_node) {
            return ScalaTypeNamespaceResolution::NoMatch;
        }
        let segments = scala_type_lookup_segments(lookup_node, self.source);
        let Some(root_name) = segments.first() else {
            return ScalaTypeNamespaceResolution::NoMatch;
        };
        if let Some(binding) =
            scala_nearest_unindexed_type_binding(self.source, lookup_node, root_name)
        {
            return match binding {
                ScalaUnindexedTypeBinding::Authoritative => {
                    ScalaTypeNamespaceResolution::AuthoritativeMiss
                }
                ScalaUnindexedTypeBinding::AnonymousRefinement(instance) => self
                    .exact_type_member_before_anonymous_binding(lookup_node, instance, root_name),
            };
        }
        let mut owners = Vec::new();
        let mut current = self.class_ranges.enclosing_unit(node.start_byte()).cloned();
        while let Some(owner) = current {
            current = self.types.exact_structural_parent(self.scala, &owner);
            if owner.is_class() {
                owners.push(owner);
            }
        }
        self.types
            .exact_lexical_type_namespace(self.scala, owners, root_name, false)
    }

    /// Resolve exact indexed type-member tiers encountered before an outer
    /// anonymous refinement binding. Intervening anonymous constructed bases
    /// and named templates both have higher precedence than the outer alias.
    fn exact_type_member_before_anonymous_binding(
        &self,
        lookup_node: Node<'_>,
        binding_instance: Node<'_>,
        name: &str,
    ) -> ScalaTypeNamespaceResolution {
        let mut current = Some(lookup_node);
        while let Some(node) = current {
            if node.kind() == "template_body" {
                if let Some(instance) = scala_anonymous_instance_for_template(node) {
                    let Some(owner) = self.constructed_type_declaration_for_boundary(instance)
                    else {
                        return ScalaTypeNamespaceResolution::AuthoritativeMiss;
                    };
                    if instance != binding_instance {
                        match self.types.exact_lexical_type_namespace(
                            self.scala,
                            std::iter::once(owner),
                            name,
                            false,
                        ) {
                            ScalaTypeNamespaceResolution::Resolved(member) => {
                                return ScalaTypeNamespaceResolution::Resolved(member);
                            }
                            ScalaTypeNamespaceResolution::NoMatch => {
                                current = node.parent();
                                continue;
                            }
                            ScalaTypeNamespaceResolution::AuthoritativeMiss
                            | ScalaTypeNamespaceResolution::Ambiguous => {
                                return ScalaTypeNamespaceResolution::AuthoritativeMiss;
                            }
                        }
                    }
                    match self
                        .types
                        .stable_type_member_for_owner_unit(self.scala, &owner, name)
                    {
                        FieldResolution::Resolved(member)
                            if self.types.is_type_alias(self.scala, &member.declaration) =>
                        {
                            return ScalaTypeNamespaceResolution::Resolved(member.declaration);
                        }
                        FieldResolution::Resolved(_) | FieldResolution::NoMatch => {
                            return ScalaTypeNamespaceResolution::AuthoritativeMiss;
                        }
                        FieldResolution::Unresolved => {
                            return ScalaTypeNamespaceResolution::AuthoritativeMiss;
                        }
                    }
                } else if let Some(named_owner) = scala_named_template_owner(node) {
                    let Some(owner) = self
                        .class_ranges
                        .unit_for_exact_span(named_owner.start_byte(), named_owner.end_byte())
                        .cloned()
                    else {
                        return ScalaTypeNamespaceResolution::AuthoritativeMiss;
                    };
                    match self.types.exact_lexical_type_namespace(
                        self.scala,
                        std::iter::once(owner),
                        name,
                        false,
                    ) {
                        ScalaTypeNamespaceResolution::Resolved(member) => {
                            return ScalaTypeNamespaceResolution::Resolved(member);
                        }
                        ScalaTypeNamespaceResolution::NoMatch => {}
                        ScalaTypeNamespaceResolution::AuthoritativeMiss
                        | ScalaTypeNamespaceResolution::Ambiguous => {
                            return ScalaTypeNamespaceResolution::AuthoritativeMiss;
                        }
                    }
                }
            }
            current = node.parent();
        }
        ScalaTypeNamespaceResolution::AuthoritativeMiss
    }

    /// Resolve an anonymous base which may itself be a nested type inherited
    /// from a surrounding anonymous base (for example `Metric.UnsafeAPI`).
    fn constructed_type_declaration_for_boundary(&self, instance: Node<'_>) -> Option<CodeUnit> {
        let mut templates = Vec::new();
        let mut current = instance.parent();
        while let Some(node) = current {
            if node.kind() == "template_body" {
                templates.push(node);
            }
            current = node.parent();
        }
        templates.reverse();

        let mut exact_owners = Vec::new();
        for template in templates {
            if let Some(outer_instance) = scala_anonymous_instance_for_template(template) {
                let owner = self
                    .constructed_type_declaration_against_owners(outer_instance, &exact_owners)?;
                exact_owners.push(owner);
            } else if let Some(named_owner) = scala_named_template_owner(template) {
                let owner = self
                    .class_ranges
                    .unit_for_exact_span(named_owner.start_byte(), named_owner.end_byte())
                    .cloned()?;
                exact_owners.push(owner);
            }
        }
        self.constructed_type_declaration_against_owners(instance, &exact_owners)
    }

    fn constructed_type_declaration_against_owners(
        &self,
        instance: Node<'_>,
        exact_owners_outer_first: &[CodeUnit],
    ) -> Option<CodeUnit> {
        let type_node = constructed_type_node(instance)?;
        let path = scala_type_lookup_segments(type_node, self.source);
        let [name] = path.as_slice() else {
            return constructed_type_declaration(instance, self);
        };
        let local_binding = scala_nearest_unindexed_type_binding(self.source, type_node, name);
        if local_binding.is_some() {
            return None;
        }

        for owner in exact_owners_outer_first.iter().rev() {
            match self.types.exact_lexical_type_namespace(
                self.scala,
                std::iter::once(owner.clone()),
                name,
                false,
            ) {
                ScalaTypeNamespaceResolution::Resolved(target) => {
                    return exact_constructed_type_target(type_node, target, name, self);
                }
                ScalaTypeNamespaceResolution::NoMatch => {}
                ScalaTypeNamespaceResolution::AuthoritativeMiss
                | ScalaTypeNamespaceResolution::Ambiguous => return None,
            }
        }
        constructed_type_declaration(instance, self)
    }

    fn visible_type(&self, node: Node<'_>, name: &str) -> Option<String> {
        match self.exact_lexically_visible_type(node) {
            ScalaTypeNamespaceResolution::Resolved(declaration) => Some(declaration.fq_name()),
            ScalaTypeNamespaceResolution::NoMatch => self.resolver.resolve(name),
            ScalaTypeNamespaceResolution::AuthoritativeMiss
            | ScalaTypeNamespaceResolution::Ambiguous => None,
        }
    }

    fn visible_type_reference(&self, node: Node<'_>, name: &str) -> Option<ScalaResolvedReference> {
        match self.exact_lexically_visible_type(node) {
            ScalaTypeNamespaceResolution::Resolved(declaration) => {
                Some(ScalaResolvedReference::Exact(declaration))
            }
            ScalaTypeNamespaceResolution::NoMatch => self
                .resolver
                .resolve_unit(name)
                .map(ScalaResolvedReference::Exact)
                .or_else(|| {
                    self.resolver
                        .resolve(name)
                        .map(ScalaResolvedReference::Logical)
                }),
            ScalaTypeNamespaceResolution::AuthoritativeMiss
            | ScalaTypeNamespaceResolution::Ambiguous => None,
        }
    }

    fn lexically_visible_object(&self, byte: usize, name: &str) -> Option<String> {
        self.lexically_visible_object_unit(byte, name)
            .map(|unit| unit.fq_name())
    }

    fn visible_object_reference(&self, byte: usize, name: &str) -> Option<ScalaResolvedReference> {
        self.lexically_visible_object_unit(byte, name)
            .map(ScalaResolvedReference::Exact)
            .or_else(|| {
                self.resolver
                    .resolve_object_unit(name)
                    .map(ScalaResolvedReference::Exact)
            })
            .or_else(|| {
                self.resolver
                    .resolve_object(name)
                    .map(ScalaResolvedReference::Logical)
            })
    }

    fn lexically_visible_object_unit(&self, byte: usize, name: &str) -> Option<CodeUnit> {
        self.class_ranges.find_in_enclosing_units(byte, |owner| {
            self.types
                .exact_nested_object_for_owner(self.scala, owner, name)
        })
    }

    fn record_with_caller(&mut self, caller: String, callee: CodeUnit, node: Node<'_>) {
        self.sink.record_with_caller(
            caller,
            ScalaResolvedReference::Exact(callee),
            ScalaReferenceRole::Override,
            classify_reference_node(node),
            UsageHitKind::OverrideDeclaration,
            node.start_byte(),
            node.end_byte(),
        );
    }

    fn record_exact(&mut self, callee: CodeUnit, role: ScalaReferenceRole, node: Node<'_>) {
        self.sink.record(
            ScalaResolvedReference::Exact(callee),
            role,
            classify_reference_node(node),
            UsageHitKind::Reference,
            node.start_byte(),
            node.end_byte(),
        );
    }

    fn record_exact_owner_member(
        &mut self,
        owner: CodeUnit,
        member: &str,
        role: ScalaReferenceRole,
        node: Node<'_>,
    ) {
        self.sink.record_exact_owner_member(
            owner,
            member,
            role,
            classify_reference_node(node),
            UsageHitKind::Reference,
            node.start_byte(),
            node.end_byte(),
        );
    }

    fn record_exact_callable(&mut self, callee: CodeUnit, node: Node<'_>) {
        let Some(call_shape) = call_site_shape_for_reference(node) else {
            self.record_exact(callee, ScalaReferenceRole::Callable, node);
            return;
        };
        self.record_exact_callable_with_shape(callee, node, &call_shape);
    }

    fn record_exact_companion_callable(
        &mut self,
        callee: CodeUnit,
        role: ScalaReferenceRole,
        node: Node<'_>,
    ) {
        debug_assert!(matches!(
            role,
            ScalaReferenceRole::CompanionApplication
                | ScalaReferenceRole::CompanionExtractor
                | ScalaReferenceRole::CompanionValue
        ));
        self.record_exact(callee, role, node);
    }

    fn record_exact_callable_with_shape(
        &mut self,
        callee: CodeUnit,
        node: Node<'_>,
        call_shape: &ScalaCallSiteShape,
    ) {
        self.sink.record_callable(
            ScalaResolvedReference::Exact(callee),
            call_shape,
            classify_reference_node(node),
            UsageHitKind::Reference,
            node.start_byte(),
            node.end_byte(),
        );
    }

    fn record_resolved(
        &mut self,
        callee: ScalaResolvedReference,
        role: ScalaReferenceRole,
        node: Node<'_>,
    ) {
        self.sink.record(
            callee,
            role,
            classify_reference_node(node),
            UsageHitKind::Reference,
            node.start_byte(),
            node.end_byte(),
        );
    }

    fn record_logical(&mut self, callee: String, role: ScalaReferenceRole, node: Node<'_>) {
        self.sink.record(
            ScalaResolvedReference::Logical(callee),
            role,
            classify_reference_node(node),
            UsageHitKind::Reference,
            node.start_byte(),
            node.end_byte(),
        );
    }

    fn record_unproven_name(&mut self, name: &str, node: Node<'_>) {
        self.sink
            .record_unproven_name(name, node.start_byte(), node.end_byte());
    }
}

const SCOPE_NODES: &[&str] = &[
    "class_definition",
    "object_definition",
    "trait_definition",
    "enum_definition",
    "function_definition",
    "block",
    "block_expression",
    "indented_block",
    "case_clause",
    "lambda_expression",
    "anonymous_function",
];

fn walk(
    node: Node<'_>,
    ctx: &mut ScalaScan<'_, '_>,
    bindings: &mut LocalInferenceEngine<ScalaLocalBinding>,
) {
    enum WalkEvent<'tree> {
        Enter(Node<'tree>),
        ActivateCaseBinders(Node<'tree>),
        RefreshAssignment(Node<'tree>),
        ExitScope,
    }

    let mut stack = vec![WalkEvent::Enter(node)];
    while let Some(event) = stack.pop() {
        if ctx.sink.should_stop()
            || ctx
                .cancellation
                .is_some_and(crate::cancellation::CancellationToken::is_cancelled)
        {
            break;
        }
        match event {
            WalkEvent::Enter(node) => {
                let enters_scope = walk_enter(node, ctx, bindings);
                if enters_scope {
                    stack.push(WalkEvent::ExitScope);
                }
                if node.kind() == "assignment_expression"
                    && !is_scala_named_argument_assignment(node)
                {
                    stack.push(WalkEvent::RefreshAssignment(node));
                }
                let case_pattern = (node.kind() == "case_clause")
                    .then(|| node.child_by_field_name("pattern"))
                    .flatten();
                let mut cursor = node.walk();
                let children = node.named_children(&mut cursor).collect::<Vec<_>>();
                for child in children.into_iter().rev() {
                    if case_pattern == Some(child) {
                        stack.push(WalkEvent::ActivateCaseBinders(child));
                    }
                    stack.push(WalkEvent::Enter(child));
                }
            }
            WalkEvent::ActivateCaseBinders(pattern) => {
                for name in scala_pattern_binder_names(pattern, ctx.source) {
                    bindings.declare_shadow(name.to_string());
                }
            }
            WalkEvent::RefreshAssignment(assignment) => {
                refresh_assignment_binding(assignment, ctx, bindings);
            }
            WalkEvent::ExitScope => bindings.exit_scope(),
        }
    }
}

fn walk_enter(
    node: Node<'_>,
    ctx: &mut ScalaScan<'_, '_>,
    bindings: &mut LocalInferenceEngine<ScalaLocalBinding>,
) -> bool {
    ctx.activate_import_context(node);
    seed_parent_scope_declaration(node, ctx, bindings);
    let enters_scope = SCOPE_NODES.contains(&node.kind());
    if enters_scope {
        bindings.enter_scope();
    }
    seed_declaration(node, ctx, bindings);
    if node.kind() == "import_declaration" {
        record_import_declaration(node, ctx);
    }
    record_override_declaration(node, ctx);
    record_reference(node, ctx, bindings);
    enters_scope
}

fn seed_parent_scope_declaration(
    node: Node<'_>,
    ctx: &ScalaScan<'_, '_>,
    bindings: &mut LocalInferenceEngine<ScalaLocalBinding>,
) {
    if node.kind() != "function_definition"
        || !node.parent().is_some_and(|mut parent| {
            loop {
                if parent.kind() == "function_definition" {
                    break true;
                }
                let Some(next) = parent.parent() else {
                    break false;
                };
                parent = next;
            }
        })
    {
        return;
    }
    if let Some(name) = node.child_by_field_name("name") {
        let name = node_text(name, ctx.source).trim();
        if !name.is_empty() {
            bindings.declare_shadow(name.to_string());
        }
    }
}

fn record_import_declaration(node: Node<'_>, ctx: &mut ScalaScan<'_, '_>) {
    let imports = scala_import_infos_from_node(node, ctx.source);
    if imports.is_empty() {
        return;
    }
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if is_identifier_node(current) {
            let name = node_text(current, ctx.source).trim();
            if !name.is_empty() {
                ctx.sink.record_import_name(
                    &imports,
                    &ctx.active_package,
                    name,
                    current.start_byte(),
                    current.end_byte(),
                );
            }
        }
        for index in (0..current.named_child_count()).rev() {
            if let Some(child) = current.named_child(index) {
                stack.push(child);
            }
        }
    }
}

fn record_reference(
    node: Node<'_>,
    ctx: &mut ScalaScan<'_, '_>,
    bindings: &LocalInferenceEngine<ScalaLocalBinding>,
) {
    if node.kind() == "type_identifier"
        && !is_extractor_reference(node)
        && !is_infix_pattern_operator(node)
    {
        let lookup = scala_qualified_type_root(node);
        let segments = scala_type_lookup_segments(lookup, ctx.source);
        if !segments
            .iter()
            .any(|segment| ctx.sink.may_match_name(segment))
        {
            return;
        }
    }
    if let Some(name) = reference_lookup_name(node, ctx.source)
        && !ctx.sink.may_match_name(name)
    {
        return;
    }
    match node.kind() {
        // A type reference in any type position: param/return types, `extends`,
        // and the type child of `new Foo()`. Construction is covered here without
        // a separate `instance_expression` case (avoids double counting).
        "type_identifier" => {
            if record_qualified_stable_reference(node, ctx, bindings) {
                return;
            }
            let text = node_text(node, ctx.source);
            if is_stable_type_qualifier(node)
                && bindings.resolve_symbol(text).is_unknown()
                && !bindings.is_shadowed(text)
                && let Some(ScalaResolvedReference::Exact(target)) =
                    ctx.visible_type_reference(node, text)
                && target.is_class()
                && !target.short_name().ends_with('$')
                && ctx.types.type_is_stable_owner(ctx.scala, &target)
            {
                ctx.record_exact(target, ScalaReferenceRole::Type, node);
                return;
            }
            let object_reference = is_scala_object_reference(node);
            if (is_extractor_reference(node) || is_infix_pattern_operator(node))
                && bindings.resolve_symbol(text).is_unknown()
                && !bindings.is_shadowed(text)
            {
                // Extractors live in Scala's term namespace. An inherited
                // stable field therefore wins even when a same-named type
                // alias is visible (for example `FSM.Event`, where the trait
                // exposes both `type Event` and `val Event`). Resolve that
                // exact field before consulting type/application candidates.
                if let Some(owner) = ctx.enclosing_class_unit(node.start_byte())
                    && let FieldResolution::Resolved(field) =
                        ctx.types.field_for_owner_unit(ctx.scala, owner, text)
                {
                    ctx.record_exact(field.declaration, ScalaReferenceRole::Field, node);
                    return;
                }
                let class_fqn = ctx.visible_type(node, text);
                let resolution = ctx.types.resolve_type_application(
                    ctx.scala,
                    &ctx.resolver,
                    class_fqn.as_deref(),
                    ctx.lexically_visible_object(node.start_byte(), text)
                        .or_else(|| ctx.resolver.resolve_object(text))
                        .as_deref(),
                    text,
                    call_site_shape_for_reference(node).as_ref(),
                    TypeApplicationRole::Extractor,
                    Some(ctx.source_file),
                );
                let resolved =
                    resolution.type_target.is_some() || !resolution.callable_targets.is_empty();
                if let Some(target) = resolution.type_target {
                    ctx.record_exact(target, ScalaReferenceRole::Type, node);
                }
                for callable in resolution.callable_targets {
                    ctx.record_exact_companion_callable(
                        callable,
                        ScalaReferenceRole::CompanionExtractor,
                        node,
                    );
                }
                if resolved {
                    return;
                }
            }
            let resolved = if object_reference {
                (bindings.resolve_symbol(text).is_unknown() && !bindings.is_shadowed(text))
                    .then(|| ctx.visible_object_reference(node.start_byte(), text))
                    .flatten()
            } else if is_scala_class_reference(node, ctx.source) {
                ctx.visible_type_reference(node, text)
            } else {
                None
            };
            if let Some(resolved) = resolved {
                if is_constructor_like_reference(node, ctx.source) {
                    if let ScalaResolvedReference::Exact(alias) = &resolved
                        && ctx.types.is_type_alias(ctx.scala, alias)
                    {
                        ctx.record_exact(alias.clone(), ScalaReferenceRole::Type, node);
                        return;
                    }
                    let fqn = match &resolved {
                        ScalaResolvedReference::Exact(unit) => unit.fq_name(),
                        ScalaResolvedReference::Logical(fqn) => fqn.clone(),
                    };
                    let resolution = ctx.types.resolve_type_application(
                        ctx.scala,
                        &ctx.resolver,
                        Some(&fqn),
                        None,
                        text,
                        call_site_shape_for_reference(node).as_ref(),
                        TypeApplicationRole::ExplicitConstructor,
                        Some(ctx.source_file),
                    );
                    if let Some(target) = resolution.type_target {
                        ctx.record_exact(target, ScalaReferenceRole::Type, node);
                    }
                    for callable in resolution.callable_targets {
                        ctx.record_exact_callable(callable, node);
                    }
                    return;
                }
                ctx.record_resolved(
                    resolved,
                    if object_reference {
                        ScalaReferenceRole::StableObject
                    } else {
                        ScalaReferenceRole::Type
                    },
                    node,
                );
            }
        }
        "call_expression" => {
            let Some(function) = node.child_by_field_name("function") else {
                return;
            };
            let function = invocation_function_reference(function);
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
                    if receiver.kind() == "identifier"
                        && let Some(receiver_bindings) = bindings
                            .resolve_symbol_ref(node_text(receiver, ctx.source))
                            .and_then(|resolution| resolution.as_precise())
                        && receiver_bindings.len() > 1
                    {
                        let Some(call_shape) = call_site_shape_for_reference(field) else {
                            return;
                        };
                        let mut methods = Vec::new();
                        for binding in receiver_bindings {
                            let Some(owner) = binding.receiver_type.as_deref() else {
                                return;
                            };
                            let BareMemberResolution::Resolved(resolved) = ctx
                                .types
                                .effective_method_declarations_for_owner_with_shape(
                                    ctx.scala,
                                    owner,
                                    name,
                                    &call_shape,
                                )
                            else {
                                return;
                            };
                            if resolved.is_empty() {
                                return;
                            }
                            methods.extend(resolved);
                        }
                        methods.sort();
                        methods.dedup();
                        for method in methods {
                            ctx.record_exact_callable_with_shape(method, field, &call_shape);
                        }
                        return;
                    }
                    if let Some(owner) = receiver_type_fqn(receiver, ctx, bindings) {
                        let Some(call_shape) = call_site_shape_for_reference(field) else {
                            return;
                        };
                        let exact_owner = receiver_type_declaration(receiver, ctx, bindings);
                        let field_resolution = exact_owner.as_ref().map_or_else(
                            || ctx.types.field_for_owner_member(ctx.scala, &owner, name),
                            |owner| ctx.types.field_for_owner_unit(ctx.scala, owner, name),
                        );
                        match field_resolution {
                            FieldResolution::Resolved(resolved) => {
                                // A selected value remains a reference to that exact field even
                                // when Scala immediately applies/indexes the returned value. The
                                // terminal `call_expression` owns this event because its child is
                                // deliberately suppressed below to preserve shaped-call safety.
                                ctx.record_exact(
                                    resolved.declaration,
                                    ScalaReferenceRole::Field,
                                    field,
                                );
                                return;
                            }
                            FieldResolution::Unresolved => return,
                            FieldResolution::NoMatch => {}
                        }
                        let method_value_shape =
                            match companion_method_value_context(node, ctx, bindings) {
                                ScalaMethodValueContext::Function(shape) => Some(shape),
                                ScalaMethodValueContext::Unknown
                                | ScalaMethodValueContext::Incompatible => None,
                            };
                        let call_shape = call_shape.with_method_value_shape(method_value_shape);
                        let call_arities = call_shape
                            .lists
                            .iter()
                            .map(|list| list.arity)
                            .collect::<Vec<_>>();
                        let resolution = exact_owner.as_ref().map_or_else(
                            || {
                                ctx.types
                                    .effective_method_declarations_for_owner_with_shape(
                                        ctx.scala,
                                        &owner,
                                        name,
                                        &call_shape,
                                    )
                            },
                            |exact_owner| {
                                ctx.types
                                    .effective_method_declarations_for_exact_owner_with_shape(
                                        ctx.scala,
                                        exact_owner,
                                        name,
                                        &call_shape,
                                    )
                            },
                        );
                        match resolution {
                            BareMemberResolution::Resolved(methods) => {
                                for method in methods {
                                    ctx.record_exact_callable_with_shape(
                                        method,
                                        field,
                                        &call_shape,
                                    );
                                }
                            }
                            BareMemberResolution::Unresolved => {}
                            BareMemberResolution::NoMatch => {
                                if record_qualified_stable_reference(field, ctx, bindings) {
                                    return;
                                }
                                for extension in visible_extensions(
                                    ctx,
                                    name,
                                    Some(&owner),
                                    Some(call_arities.as_slice()),
                                ) {
                                    ctx.record_exact(
                                        extension.declaration,
                                        ScalaReferenceRole::Callable,
                                        field,
                                    );
                                }
                            }
                        }
                    } else if !record_qualified_stable_reference(field, ctx, bindings)
                        && !record_qualified_package_call(field, ctx)
                    {
                        let call_arities = call_arities_for_reference(field);
                        let extensions =
                            visible_extensions(ctx, name, None, call_arities.as_deref());
                        if extensions.is_empty() {
                            ctx.record_unproven_name(name, field);
                        } else {
                            for extension in extensions {
                                ctx.record_exact(
                                    extension.declaration,
                                    ScalaReferenceRole::Callable,
                                    field,
                                );
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
                    let Some(call_shape) = call_site_shape_for_reference(function) else {
                        return;
                    };
                    let method_value_shape =
                        match companion_method_value_context(node, ctx, bindings) {
                            ScalaMethodValueContext::Function(shape) => Some(shape),
                            ScalaMethodValueContext::Unknown
                            | ScalaMethodValueContext::Incompatible => None,
                        };
                    let call_shape = call_shape.with_method_value_shape(method_value_shape);
                    let lexical_callable_bound =
                        match record_unqualified_applied_field(function, name, ctx, bindings) {
                            LexicalFieldReferenceResolution::Consumed => return,
                            LexicalFieldReferenceResolution::CallableBound => true,
                            LexicalFieldReferenceResolution::NoMatch => false,
                        };
                    if !lexical_callable_bound
                        && (!bindings.resolve_symbol(name).is_unknown()
                            || bindings.is_shadowed(name))
                    {
                        return;
                    }
                    if record_lexically_visible_call(function, name, &call_shape, ctx) {
                        return;
                    }
                    if lexical_callable_bound {
                        return;
                    }
                    let resolved_member_units = ctx.resolver.resolve_member_units(name);
                    let imported_type_alias_only = !resolved_member_units.is_empty()
                        && resolved_member_units
                            .iter()
                            .all(|unit| ctx.types.is_exclusive_type_alias(unit));
                    let imported_units = resolved_member_units
                        .into_iter()
                        .filter(|unit| {
                            unit.is_function() || ctx.types.has_term_field_declaration(unit)
                        })
                        .collect::<Vec<_>>();
                    if !imported_units.is_empty()
                        && imported_units.iter().all(|unit| unit.is_synthetic())
                        && (ctx.visible_type(function, name).is_some()
                            || ctx
                                .visible_object_reference(function.start_byte(), name)
                                .is_some())
                    {
                        record_unqualified_type_application(function, name, ctx, bindings);
                        return;
                    }
                    if !imported_units.is_empty() {
                        let imported_fields = imported_units
                            .iter()
                            .filter(|unit| ctx.types.has_term_field_declaration(unit))
                            .cloned()
                            .collect::<Vec<_>>();
                        if !imported_fields.is_empty() {
                            if let [field] = imported_fields.as_slice()
                                && (field.source() == ctx.source_file
                                    || ctx.types.term_field_declaration_is_globally_unique(field))
                            {
                                ctx.record_exact(
                                    field.clone(),
                                    ScalaReferenceRole::Field,
                                    function,
                                );
                            }
                            return;
                        }
                        let imported_refs = imported_units.iter().collect::<Vec<_>>();
                        for target in ctx.types.method_declarations_for_members_with_shape(
                            ctx.scala,
                            &imported_refs,
                            &call_shape,
                        ) {
                            ctx.record_exact_callable_with_shape(target, function, &call_shape);
                        }
                        return;
                    }
                    if ctx.visible_type(function, name).is_some()
                        || ctx
                            .visible_object_reference(function.start_byte(), name)
                            .is_some()
                    {
                        record_unqualified_type_application(function, name, ctx, bindings);
                        return;
                    }
                    if !imported_type_alias_only
                        && let Some(imported) = ctx.resolver.resolve_member(name)
                    {
                        for target in ctx.types.imported_member_targets_with_shape(
                            ctx.scala,
                            &imported,
                            &call_shape,
                        ) {
                            ctx.record_exact_callable_with_shape(target, function, &call_shape);
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
            let resolution = receiver_type_declaration(receiver, ctx, bindings).map_or_else(
                || {
                    ctx.types.effective_method_declarations_for_owner(
                        ctx.scala,
                        &owner,
                        member,
                        call_arities.as_deref(),
                    )
                },
                |exact_owner| {
                    ctx.types.effective_method_declarations_for_exact_owner(
                        ctx.scala,
                        &exact_owner,
                        member,
                        call_arities.as_deref(),
                    )
                },
            );
            if let BareMemberResolution::Resolved(methods) = resolution {
                for method in methods {
                    ctx.record_exact_callable(method, operator);
                }
            }
        }
        "postfix_expression" => {
            let Some(operator) = scala_postfix_operator_node(node) else {
                return;
            };
            let Some(receiver) = scala_postfix_receiver_node(node, operator) else {
                return;
            };
            let member = node_text(operator, ctx.source).trim();
            if member.is_empty() {
                return;
            }
            let Some(owner) = receiver_type_fqn(receiver, ctx, bindings) else {
                return;
            };
            let resolution = receiver_type_declaration(receiver, ctx, bindings).map_or_else(
                || {
                    ctx.types
                        .effective_method_declarations_for_owner(ctx.scala, &owner, member, None)
                },
                |exact_owner| {
                    ctx.types.effective_method_declarations_for_exact_owner(
                        ctx.scala,
                        &exact_owner,
                        member,
                        None,
                    )
                },
            );
            if let BareMemberResolution::Resolved(methods) = resolution {
                for method in methods {
                    ctx.record_exact_callable(method, operator);
                }
            }
        }
        "identifier" | "operator_identifier" => {
            let name = node_text(node, ctx.source);
            if name.is_empty() {
                return;
            }
            if has_ancestor_kind(node, "import_declaration") {
                record_local_stable_imported_member(node, name, ctx, bindings);
                return;
            }
            if is_declaration_name(node) || is_scala_case_pattern_binder(node) {
                return;
            }
            if let Some(owner_node) =
                named_argument_invocation_owner(node).and_then(terminal_invocation_owner_name)
            {
                let owner_name = node_text(owner_node, ctx.source).trim();
                if let Some(ScalaResolvedReference::Exact(owner)) =
                    ctx.visible_type_reference(owner_node, owner_name)
                {
                    ctx.record_exact_owner_member(owner, name, ScalaReferenceRole::Field, node);
                }
                return;
            }
            // The enclosing `call_expression` owns callable-shape resolution.
            // Visiting its bare function identifier again must not add an
            // unshaped imported-member edge after an arity mismatch.
            if is_call_function_reference(node) || reference_is_owned_by_invocation(node) {
                return;
            }
            if record_local_stable_imported_member(node, name, ctx, bindings)
                || record_local_stable_field_reference(node, ctx, bindings)
                || record_enclosing_field_qualifier(node, name, ctx, bindings)
            {
                return;
            }
            if !is_terminal_stable_field_reference(node) && !is_field_expression_value(node) {
                if record_lexically_visible_field_reference(node, name, ctx, bindings)
                    == LexicalFieldReferenceResolution::Consumed
                {
                    return;
                }
                if !matches!(
                    companion_method_value_context(node, ctx, bindings),
                    ScalaMethodValueContext::Function(_)
                ) && record_lexically_visible_parameterless_method(node, name, ctx)
                {
                    return;
                }
            }
            if record_intermediate_stable_object_reference(node, ctx, bindings)
                || (!is_terminal_stable_field_reference(node)
                    && record_qualified_stable_reference(node, ctx, bindings))
            {
                return;
            }
            // A stable selection's root is an independently meaningful term
            // reference. Resolve it before class/type handling consumes the same
            // spelling, so `Flag` in `Flag.values` is attributed to the exact
            // companion object while `Flag` in a type position still resolves to
            // the class/enum namespace below.
            if is_field_expression_value(node)
                && bindings.resolve_symbol(name).is_unknown()
                && !bindings.is_shadowed(name)
            {
                if let Some(ScalaResolvedReference::Exact(target)) =
                    ctx.visible_type_reference(node, name)
                    && ctx.types.type_is_stable_owner(ctx.scala, &target)
                {
                    ctx.record_exact(target, ScalaReferenceRole::Type, node);
                    return;
                }
                if let Some(target) = ctx.visible_object_reference(node.start_byte(), name) {
                    ctx.record_resolved(target, ScalaReferenceRole::StableObject, node);
                    return;
                }
            }
            let bare_companion_method_value = is_bare_companion_method_value_reference(node);
            if (is_extractor_reference(node) || is_infix_pattern_operator(node))
                && let Some(fqn) = (bindings.resolve_symbol(name).is_unknown()
                    && !bindings.is_shadowed(name))
                .then(|| ctx.visible_type(node, name))
                .flatten()
                && let Some(target) = ctx
                    .types
                    .type_by_normalized_fqn(&scala_normalized_fq_name(&fqn))
                && ctx.types.class_accepts_extractor_role(ctx.scala, target)
            {
                record_unqualified_type_application(node, name, ctx, bindings);
                return;
            }
            if is_scala_class_reference(node, ctx.source)
                && !bare_companion_method_value
                && let Some(target) = ctx.visible_type_reference(node, name)
            {
                ctx.record_resolved(target, ScalaReferenceRole::Type, node);
                return;
            }
            if let ScalaMethodValueContext::Function(shape) =
                companion_method_value_context(node, ctx, bindings)
            {
                let call_shape = ScalaCallSiteShape {
                    lists: Vec::new(),
                    method_value_arity: Some(shape.arity),
                    method_value_parameter_types: shape.parameter_types,
                    method_value_parameter_types_authoritative: shape.parameter_types_authoritative,
                    type_arguments_only: false,
                };
                if record_lexically_visible_call(node, name, &call_shape, ctx) {
                    return;
                }
                if let Some(imported) = ctx.resolver.resolve_member(name) {
                    let targets = ctx.types.imported_member_targets_with_shape(
                        ctx.scala,
                        &imported,
                        &call_shape,
                    );
                    for target in targets {
                        ctx.record_exact_callable(target, node);
                    }
                    return;
                }
                if !bare_companion_method_value {
                    return;
                }
            }
            if !is_terminal_stable_field_reference(node)
                && ctx
                    .lexically_visible_object(node.start_byte(), name)
                    .is_none()
            {
                for declaration in enclosing_template_declarations(node) {
                    if let Some(owner) = ctx
                        .class_ranges
                        .unit_for_exact_span(declaration.start_byte(), declaration.end_byte())
                        .cloned()
                    {
                        for role in [ScalaReferenceRole::Field, ScalaReferenceRole::Callable] {
                            ctx.record_exact_owner_member(owner.clone(), name, role, node);
                        }
                    }
                }
            }
            if !is_terminal_stable_field_reference(node)
                && let Some(call_shape) = call_site_shape_for_reference(node)
                && call_shape.type_arguments_only
            {
                if record_lexically_visible_call(node, name, &call_shape, ctx) {
                    return;
                }
                if let Some(imported) = ctx.resolver.resolve_member(name) {
                    for target in ctx.types.imported_member_targets_with_shape(
                        ctx.scala,
                        &imported,
                        &call_shape,
                    ) {
                        ctx.record_exact_callable(target, node);
                    }
                    return;
                }
                record_unqualified_type_application(node, name, ctx, bindings);
                return;
            }
            if bare_companion_method_value {
                if let Some(imported) = ctx.resolver.resolve_explicit_member_unit(name) {
                    ctx.record_exact(
                        imported.clone(),
                        if imported.is_field() {
                            ScalaReferenceRole::Field
                        } else {
                            ScalaReferenceRole::Callable
                        },
                        node,
                    );
                    return;
                }
                let target = match companion_method_value_context(node, ctx, bindings) {
                    ScalaMethodValueContext::Unknown => {
                        ctx.types.unique_companion_apply_method_value_target(
                            ctx.scala,
                            &ctx.resolver,
                            name,
                            None,
                        )
                    }
                    ScalaMethodValueContext::Function(shape) => {
                        ctx.types.unique_companion_apply_method_value_target(
                            ctx.scala,
                            &ctx.resolver,
                            name,
                            Some(&[shape.arity]),
                        )
                    }
                    ScalaMethodValueContext::Incompatible => {
                        if let Some(object) = ctx.resolver.resolve_object_unit(name) {
                            ctx.record_exact(object, ScalaReferenceRole::StableObject, node);
                        } else if let Some(object) = ctx.resolver.resolve_object(name) {
                            ctx.record_logical(object, ScalaReferenceRole::StableObject, node);
                        }
                        None
                    }
                };
                if let Some(target) = target {
                    ctx.record_exact_companion_callable(
                        target,
                        ScalaReferenceRole::CompanionValue,
                        node,
                    );
                    return;
                }
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
                    .and_then(|root| ctx.lexically_visible_object_unit(node.start_byte(), root));
                if let Some(owner) = ctx.types.resolve_qualified_stable_type_unit_at(
                    ctx.scala,
                    &ctx.resolver,
                    owner_segments,
                    true,
                    owner_lexical_root,
                ) && let Some(field) = ctx.types.exact_field(ctx.scala, &owner.fq_name(), member)
                {
                    ctx.record_exact(field, ScalaReferenceRole::Field, node);
                    return;
                }
                let lexical_root = reference
                    .segments
                    .first()
                    .and_then(|root| ctx.lexically_visible_object_unit(node.start_byte(), root));
                if let Some(object) = ctx.types.resolve_qualified_stable_type_unit_at(
                    ctx.scala,
                    &ctx.resolver,
                    &reference.segments,
                    true,
                    lexical_root,
                ) {
                    ctx.record_exact(object, ScalaReferenceRole::StableObject, node);
                    return;
                }
                // A terminal selection still has exact receiver dispatch below;
                // a stable-path miss must not consume parameterless methods.
                if reference.segments.len() > 1 && !is_terminal_stable_field_reference(node) {
                    return;
                }
            }
            if is_terminal_stable_field_reference(node)
                && let Some(qualifier) = node
                    .parent()
                    .and_then(|expression| expression.child_by_field_name("value"))
            {
                if record_union_receiver_parameterless_methods(qualifier, name, node, ctx, bindings)
                {
                    return;
                }
                if let Some(owner) = receiver_type_fqn(qualifier, ctx, bindings) {
                    let exact_owner = receiver_type_declaration(qualifier, ctx, bindings);
                    let field_resolution = exact_owner.as_ref().map_or_else(
                        || ctx.types.field_for_owner_member(ctx.scala, &owner, name),
                        |owner| ctx.types.field_for_owner_unit(ctx.scala, owner, name),
                    );
                    match field_resolution {
                        FieldResolution::Resolved(field) => {
                            ctx.record_exact(field.declaration, ScalaReferenceRole::Field, node);
                        }
                        FieldResolution::Unresolved => return,
                        FieldResolution::NoMatch => {
                            let object = exact_owner
                                .as_ref()
                                .and_then(|owner| {
                                    ctx.types
                                        .exact_nested_object_for_owner(ctx.scala, owner, name)
                                })
                                .or_else(|| {
                                    ctx.types.exact_nested_object_unit(ctx.scala, &owner, name)
                                });
                            if let Some(object) = object {
                                ctx.record_exact(object, ScalaReferenceRole::StableObject, node);
                                return;
                            }
                            if let Some(exact_owner) = exact_owner.as_ref() {
                                match ctx.types.bare_member_declarations_for_owner(
                                    ctx.scala,
                                    exact_owner,
                                    name,
                                    None,
                                ) {
                                    BareMemberResolution::Resolved(methods) => {
                                        for method in methods {
                                            ctx.record_exact_callable(method, node);
                                        }
                                        return;
                                    }
                                    BareMemberResolution::Unresolved => return,
                                    BareMemberResolution::NoMatch => {}
                                }
                            } else if record_ordinary_class_methods(&owner, name, None, node, ctx) {
                                return;
                            }
                            let extensions = visible_extensions(ctx, name, Some(&owner), None);
                            if !extensions.is_empty() {
                                for extension in extensions {
                                    ctx.record_exact(
                                        extension.declaration,
                                        ScalaReferenceRole::Callable,
                                        node,
                                    );
                                }
                                return;
                            }
                        }
                    }
                }
                return;
            }
            if record_lexically_visible_parameterless_method(node, name, ctx) {
                return;
            }
            if is_scala_object_reference(node)
                && bindings.resolve_symbol(name).is_unknown()
                && let Some(target) = ctx.visible_object_reference(node.start_byte(), name)
            {
                ctx.record_resolved(target, ScalaReferenceRole::StableObject, node);
                return;
            }
            if let Some(target) = ctx.resolver.resolve_member_unit(name) {
                ctx.record_exact(
                    target.clone(),
                    if target.is_field() {
                        ScalaReferenceRole::Field
                    } else {
                        ScalaReferenceRole::Callable
                    },
                    node,
                );
            } else if let Some(fqn) = ctx.resolver.resolve_member(name) {
                ctx.record_logical(fqn, ScalaReferenceRole::Callable, node);
            }
        }
        _ => {}
    }
}

fn reference_lookup_name<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    let node = match node.kind() {
        "call_expression" => {
            let function = node.child_by_field_name("function")?;
            let function = invocation_function_reference(function);
            if function.kind() == "field_expression" {
                function.child_by_field_name("field")?
            } else {
                function
            }
        }
        "infix_expression" | "postfix_expression" => node.child_by_field_name("operator")?,
        "identifier" | "operator_identifier" => node,
        _ => return None,
    };
    let name = node_text(node, source).trim();
    (!name.is_empty()).then_some(name)
}

/// Resolve an explicit member import whose owner is a parser-proven local
/// stable value, for example:
///
/// ```scala
/// val cluster = Cluster(system)
/// import cluster.{ selfAddress as localAddress }
/// use(localAddress)
/// ```
///
/// The ordinary name resolver deliberately interprets import paths as global
/// namespaces, so it cannot resolve `cluster.selfAddress`. The local inference
/// environment already carries the exact physical declaration returned by the
/// `Cluster(...)` application; bridge the parser-recorded import path to that
/// declaration without reconstructing or scanning source text. A matching
/// local-root import is authoritative: imprecise owners, missing members, or
/// conflicting visible imports consume the name and fail closed rather than
/// falling through to an unrelated global member with the same spelling.
fn record_local_stable_imported_member(
    node: Node<'_>,
    visible_name: &str,
    ctx: &mut ScalaScan<'_, '_>,
    bindings: &LocalInferenceEngine<ScalaLocalBinding>,
) -> bool {
    if bindings.is_shadowed(visible_name) {
        return false;
    }

    let mut matched_local_import = false;
    let mut selected_targets: Option<Vec<CodeUnit>> = None;
    for import in ctx.imports.iter().filter(|import| {
        !import.is_wildcard && scala_import_is_visible_at_byte(import, node.start_byte())
    }) {
        if import.identifier.as_deref() != Some(visible_name) {
            continue;
        }
        let Some(path) = import.path.as_ref() else {
            continue;
        };
        let Some((member, owner_path)) = path.segments.split_last() else {
            continue;
        };
        let Some(root_name) = owner_path.first() else {
            continue;
        };
        if !bindings.is_shadowed(root_name) {
            continue;
        }
        matched_local_import = true;

        let Some(binding) = precise_scala_binding(bindings, root_name) else {
            return true;
        };
        let Some(mut owner) = binding.receiver_declaration.or_else(|| {
            let receiver_type = binding.receiver_type.as_deref()?;
            let mut candidates = ctx
                .types
                .index
                .by_fqn(receiver_type)
                .iter()
                .filter(|unit| unit.is_class());
            let declaration = candidates.next()?.clone();
            candidates.next().is_none().then_some(declaration)
        }) else {
            return true;
        };
        for segment in &owner_path[1..] {
            let Some(nested) = ctx
                .types
                .exact_nested_object_for_owner(ctx.scala, &owner, segment)
            else {
                return true;
            };
            owner = nested;
        }

        let mut targets = match ctx.types.field_for_owner_unit(ctx.scala, &owner, member) {
            FieldResolution::Resolved(field) => vec![field.declaration],
            FieldResolution::Unresolved => return true,
            FieldResolution::NoMatch => {
                if let Some(object) = ctx
                    .types
                    .exact_nested_object_for_owner(ctx.scala, &owner, member)
                {
                    vec![object]
                } else {
                    match ctx
                        .types
                        .bare_member_declarations_for_owner(ctx.scala, &owner, member, None)
                    {
                        BareMemberResolution::Resolved(methods) if !methods.is_empty() => methods,
                        BareMemberResolution::Resolved(_)
                        | BareMemberResolution::NoMatch
                        | BareMemberResolution::Unresolved => return true,
                    }
                }
            }
        };
        targets.sort();
        targets.dedup();
        if selected_targets
            .as_ref()
            .is_some_and(|selected| selected != &targets)
        {
            return true;
        }
        selected_targets = Some(targets);
    }

    if !matched_local_import {
        return false;
    }
    for target in selected_targets.into_iter().flatten() {
        let role = if target.is_field() {
            ScalaReferenceRole::Field
        } else if target.is_function() {
            ScalaReferenceRole::Callable
        } else {
            ScalaReferenceRole::StableObject
        };
        ctx.record_exact(target, role, node);
    }
    true
}

fn record_union_receiver_parameterless_methods(
    receiver: Node<'_>,
    member: &str,
    node: Node<'_>,
    ctx: &mut ScalaScan<'_, '_>,
    bindings: &LocalInferenceEngine<ScalaLocalBinding>,
) -> bool {
    if receiver.kind() != "identifier" {
        return false;
    }
    let Some(receiver_bindings) = bindings
        .resolve_symbol_ref(node_text(receiver, ctx.source))
        .and_then(|resolution| resolution.as_precise())
        .filter(|bindings| bindings.len() > 1)
    else {
        return false;
    };
    let mut methods = Vec::new();
    for binding in receiver_bindings {
        let Some(owner) = binding.receiver_type.as_deref() else {
            return true;
        };
        let resolution = ctx
            .types
            .effective_method_declarations_for_owner(ctx.scala, owner, member, None);
        let mut resolved = match resolution {
            BareMemberResolution::Resolved(resolved) => resolved,
            BareMemberResolution::NoMatch | BareMemberResolution::Unresolved => {
                match ctx.types.field_for_owner_member(ctx.scala, owner, member) {
                    FieldResolution::Resolved(field) => vec![field.declaration],
                    FieldResolution::NoMatch | FieldResolution::Unresolved => return true,
                }
            }
        };
        if resolved.is_empty() {
            return true;
        }
        let field_owners = resolved
            .iter()
            .filter(|declaration| declaration.is_field())
            .filter_map(|field| ctx.types.exact_structural_parent(ctx.scala, field))
            .collect::<Vec<_>>();
        for field_owner in field_owners {
            for ancestor in ctx.scala.get_ancestors(&field_owner) {
                resolved.extend(
                    ctx.scala
                        .definitions(&format!("{}.{}", ancestor.fq_name(), member))
                        .filter(|declaration| {
                            declaration.is_function()
                                && ctx
                                    .types
                                    .exact_structural_parent(ctx.scala, declaration)
                                    .as_ref()
                                    == Some(&ancestor)
                        }),
                );
            }
        }
        let receiver_owners = ctx
            .types
            .index
            .by_fqn(owner)
            .iter()
            .filter(|declaration| declaration.is_class())
            .cloned()
            .collect::<Vec<_>>();
        if let [receiver_owner] = receiver_owners.as_slice() {
            for ancestor in ctx.scala.get_ancestors(receiver_owner) {
                resolved.extend(
                    ctx.scala
                        .definitions(&format!("{}.{}", ancestor.fq_name(), member))
                        .filter(|declaration| {
                            declaration.is_function()
                                && ctx
                                    .types
                                    .exact_structural_parent(ctx.scala, declaration)
                                    .as_ref()
                                    == Some(&ancestor)
                        }),
                );
            }
        }
        methods.extend(resolved);
    }
    methods.sort();
    methods.dedup();
    for method in methods {
        ctx.record_exact_callable(method, node);
    }
    true
}

/// Resolve a parser-recorded stable path such as `pkg.helper(...)` directly to
/// exact workspace callables. Receiver inference intentionally treats package
/// roots as namespaces rather than value types, so this path is handled only
/// after ordinary receiver/member resolution has failed.
fn record_qualified_package_call(field: Node<'_>, ctx: &mut ScalaScan<'_, '_>) -> bool {
    let Some(reference) = qualified_stable_type_reference(field, ctx.source) else {
        return false;
    };
    if reference.segments.len() < 2 {
        return false;
    }
    let Some(call_shape) = call_site_shape_for_reference(field) else {
        return false;
    };
    let fqn = reference.segments.join(".");
    let methods = ctx
        .types
        .imported_member_targets_with_shape(ctx.scala, &fqn, &call_shape);
    if methods.is_empty() {
        return false;
    }
    for method in methods {
        ctx.record_exact_callable(method, field);
    }
    true
}

/// Record an unqualified owner field used as an application/indexing function.
///
/// Tree-sitter gives `values(index)` to the enclosing `call_expression`; the
/// identifier child is intentionally not revisited because doing so would lose
/// callable shape. Preserve that ownership while still emitting the exact field
/// selection before ordinary method/type-application dispatch. Local parameters
/// and local values remain authoritative shadows.
fn record_unqualified_applied_field(
    function: Node<'_>,
    name: &str,
    ctx: &mut ScalaScan<'_, '_>,
    bindings: &LocalInferenceEngine<ScalaLocalBinding>,
) -> LexicalFieldReferenceResolution {
    match record_lexically_visible_field_reference(function, name, ctx, bindings) {
        LexicalFieldReferenceResolution::Consumed => {
            return LexicalFieldReferenceResolution::Consumed;
        }
        LexicalFieldReferenceResolution::CallableBound => {
            return LexicalFieldReferenceResolution::CallableBound;
        }
        LexicalFieldReferenceResolution::NoMatch => {}
    }
    if let Some(target) = ctx.resolver.resolve_member_unit(name)
        && ctx.types.has_term_field_declaration(&target)
        && !ctx.types.is_type_alias(ctx.scala, &target)
    {
        ctx.record_exact(target, ScalaReferenceRole::Field, function);
        return LexicalFieldReferenceResolution::Consumed;
    }
    LexicalFieldReferenceResolution::NoMatch
}

/// Calls and infix expressions resolve callable shape at their owning AST
/// node. Their member/operator child must not be revisited as an unshaped
/// stable reference, which could otherwise resurrect an inapplicable overload.
fn reference_is_owned_by_invocation(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    if parent.kind() == "infix_expression" && parent.child_by_field_name("operator") == Some(node) {
        return true;
    }
    if parent.kind() == "postfix_expression" && scala_postfix_operator_node(parent) == Some(node) {
        return true;
    }
    parent.kind() == "field_expression"
        && parent.child_by_field_name("field") == Some(node)
        && is_call_function_reference(parent)
}

fn scala_postfix_operator_node(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    let mut operator = None;
    for child in node.named_children(&mut cursor) {
        if matches!(child.kind(), "identifier" | "operator_identifier") {
            operator = Some(child);
        }
    }
    operator
}

fn scala_postfix_receiver_node<'tree>(
    node: Node<'tree>,
    operator: Node<'tree>,
) -> Option<Node<'tree>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| child.end_byte() <= operator.start_byte())
}

fn record_unqualified_type_application(
    function: Node<'_>,
    name: &str,
    ctx: &mut ScalaScan<'_, '_>,
    bindings: &LocalInferenceEngine<ScalaLocalBinding>,
) -> bool {
    if !bindings.resolve_symbol(name).is_unknown() || bindings.is_shadowed(name) {
        return false;
    }
    let class_fqn = ctx.visible_type(function, name);
    let object_fqn = ctx
        .lexically_visible_object(function.start_byte(), name)
        .or_else(|| ctx.resolver.resolve_object(name));
    if class_fqn.is_none() && object_fqn.is_none() {
        return false;
    }
    let application_role =
        if is_extractor_reference(function) || is_infix_pattern_operator(function) {
            TypeApplicationRole::Extractor
        } else {
            TypeApplicationRole::BareApplication
        };
    let call_shape = call_site_shape_for_reference(function);
    let resolution = ctx.types.resolve_type_application(
        ctx.scala,
        &ctx.resolver,
        class_fqn.as_deref(),
        object_fqn.as_deref(),
        name,
        call_shape.as_ref(),
        application_role,
        Some(ctx.source_file),
    );
    if let Some(target) = resolution.type_target {
        ctx.record_exact(target.clone(), ScalaReferenceRole::Type, function);
        let exact_companions = ctx.types.exact_companion_objects(ctx.scala, &target);
        let has_exact_companion_callable = resolution.callable_targets.iter().any(|callable| {
            ctx.scala
                .structural_parent_of(callable)
                .is_some_and(|owner| exact_companions.contains(&owner))
        });
        if application_role == TypeApplicationRole::BareApplication && !has_exact_companion_callable
        {
            for constructor in ctx
                .types
                .exact_member_declarations(ctx.scala, &target, target.identifier())
                .into_iter()
                .filter(CodeUnit::is_synthetic)
                .filter(|constructor| {
                    ctx.types.constructor_target_matches(
                        ctx.scala,
                        constructor,
                        call_shape.as_ref(),
                        ScalaCallableSiteRole::PrimaryConstruction,
                    )
                })
            {
                ctx.record_exact_companion_callable(
                    constructor,
                    ScalaReferenceRole::CompanionApplication,
                    function,
                );
            }
        }
    }
    for callable in resolution.callable_targets {
        ctx.record_exact_companion_callable(
            callable,
            if application_role == TypeApplicationRole::Extractor {
                ScalaReferenceRole::CompanionExtractor
            } else {
                ScalaReferenceRole::CompanionApplication
            },
            function,
        );
    }
    true
}

fn record_qualified_stable_reference(
    node: Node<'_>,
    ctx: &mut ScalaScan<'_, '_>,
    bindings: &LocalInferenceEngine<ScalaLocalBinding>,
) -> bool {
    let Some(reference) = qualified_stable_type_reference(node, ctx.source) else {
        return false;
    };
    if reference.segments.is_empty() {
        return true;
    }
    if reference.role == ScalaQualifiedStableTypeRole::Type
        && let [owner_name, this_segment, member] = reference.segments.as_slice()
        && this_segment == "this"
    {
        let mut matches = Vec::new();
        let mut enclosing = ctx.enclosing_class_unit(node.start_byte()).cloned();
        while let Some(owner) = enclosing {
            enclosing = ctx.types.exact_structural_parent(ctx.scala, &owner);
            if owner.is_class() && scala_simple_type_name(&owner) == *owner_name {
                matches.push(owner);
            }
        }
        if let [owner] = matches.as_slice()
            && let FieldResolution::Resolved(field) = ctx
                .types
                .stable_type_member_for_owner_unit(ctx.scala, owner, member)
        {
            let role = if ctx.types.is_type_alias(ctx.scala, &field.declaration) {
                ScalaReferenceRole::Type
            } else {
                ScalaReferenceRole::Field
            };
            ctx.record_exact(field.declaration, role, node);
        }
        return true;
    }
    if reference
        .segments
        .first()
        .is_some_and(|root| bindings.is_shadowed(root))
    {
        return reference.role == ScalaQualifiedStableTypeRole::Type
            && !is_terminal_stable_field_reference(node);
    }
    // In a qualified extractor such as `Domain.Continuous(value)`, the stable
    // enum/type root is an independently meaningful reference in addition to
    // the terminal extractor. Preserve the complete parser expression as the
    // hit range so exact forward sites covering the qualified extractor round
    // trip, while the resolver's exact-unit requirement keeps physical
    // replicas ambiguous.
    if reference.role == ScalaQualifiedStableTypeRole::Extractor
        && reference.segments.len() > 1
        && let Some(root) = reference.segments.first()
        && let Some(target) = ctx.resolver.resolve_unit(root)
        && ctx.types.type_is_stable_owner(ctx.scala, &target)
    {
        ctx.record_exact(target, ScalaReferenceRole::Type, reference.expression);
    }
    let lexical_object_root = reference
        .segments
        .first()
        .and_then(|root| ctx.lexically_visible_object_unit(node.start_byte(), root));
    let lexical_type_root = ctx.exact_lexically_visible_type_root(node);
    let class_lookup_blocked = matches!(
        lexical_type_root,
        ScalaTypeNamespaceResolution::AuthoritativeMiss | ScalaTypeNamespaceResolution::Ambiguous
    );
    let lexical_roots = match &lexical_type_root {
        ScalaTypeNamespaceResolution::Resolved(declaration) => {
            let mut roots = ctx.types.exact_companion_objects(ctx.scala, declaration);
            if ctx.types.type_is_stable_owner(ctx.scala, declaration) {
                roots.push(declaration.clone());
            }
            roots.sort();
            roots.dedup();
            roots
        }
        ScalaTypeNamespaceResolution::NoMatch => {
            let root = reference.segments.first().expect("qualified stable root");
            let mut roots =
                ctx.types
                    .stable_roots_for_resolved_type_name(ctx.scala, &ctx.resolver, root);
            if roots.is_empty()
                && let Some(object) = lexical_object_root
            {
                roots.push(object);
            }
            roots
        }
        ScalaTypeNamespaceResolution::AuthoritativeMiss
        | ScalaTypeNamespaceResolution::Ambiguous => Vec::new(),
    };
    let class_unit = (!class_lookup_blocked)
        .then(|| {
            ctx.types
                .resolve_qualified_stable_type_unit_at_with_lexical_roots(
                    ctx.scala,
                    &ctx.resolver,
                    &reference.segments,
                    false,
                    lexical_roots.clone(),
                )
        })
        .flatten();
    let object_unit = ctx
        .types
        .resolve_qualified_stable_type_unit_at_with_lexical_roots(
            ctx.scala,
            &ctx.resolver,
            &reference.segments,
            true,
            lexical_roots,
        );
    if class_unit.is_none()
        && !class_lookup_blocked
        && reference.role == ScalaQualifiedStableTypeRole::Type
        && let Some((member, owner_segments)) = reference.segments.split_last()
    {
        if owner_segments.is_empty() {
            return false;
        }
        let owner_lexical_root = owner_segments
            .first()
            .and_then(|root| ctx.lexically_visible_object_unit(node.start_byte(), root));
        if let Some(owner) = ctx.types.resolve_qualified_stable_type_unit_at(
            ctx.scala,
            &ctx.resolver,
            owner_segments,
            true,
            owner_lexical_root,
        ) && let FieldResolution::Resolved(field) = ctx
            .types
            .stable_type_member_for_owner_unit(ctx.scala, &owner, member)
        {
            let role = if ctx.types.is_type_alias(ctx.scala, &field.declaration) {
                ScalaReferenceRole::Type
            } else {
                ScalaReferenceRole::Field
            };
            ctx.record_exact(field.declaration, role, node);
        }
        return true;
    }
    if reference.role == ScalaQualifiedStableTypeRole::Type {
        if class_lookup_blocked {
            return true;
        }
        if let Some(target) = class_unit.or(object_unit) {
            ctx.record_exact(target, ScalaReferenceRole::Type, node);
        }
        return true;
    }
    if class_unit.is_none() && object_unit.is_none() {
        if reference.role != ScalaQualifiedStableTypeRole::Type {
            // A bare extractor can be an inherited stable `val` (for example
            // Akka FSM's `Event`). Type/object lookup owns qualified misses,
            // but application-shaped misses must continue into exact receiver,
            // lexical-field, or extension resolution below.
            return false;
        }
        return true;
    }
    let role = match reference.role {
        ScalaQualifiedStableTypeRole::Constructor => TypeApplicationRole::ExplicitConstructor,
        ScalaQualifiedStableTypeRole::Apply => TypeApplicationRole::BareApplication,
        ScalaQualifiedStableTypeRole::Extractor => TypeApplicationRole::Extractor,
        ScalaQualifiedStableTypeRole::Type => unreachable!(),
    };
    if role == TypeApplicationRole::ExplicitConstructor
        && let Some(alias) = class_unit
            .as_ref()
            .filter(|unit| ctx.types.is_type_alias(ctx.scala, unit))
    {
        ctx.record_exact(alias.clone(), ScalaReferenceRole::Type, node);
        return true;
    }
    let name = reference
        .segments
        .last()
        .expect("qualified Scala reference has a terminal segment");
    let class_fqn = class_unit.as_ref().map(CodeUnit::fq_name);
    let object_fqn = object_unit.as_ref().map(CodeUnit::fq_name);
    let resolution = ctx.types.resolve_type_application(
        ctx.scala,
        &ctx.resolver,
        class_fqn.as_deref(),
        object_fqn.as_deref(),
        name,
        call_site_shape_for_reference(reference.expression).as_ref(),
        role,
        Some(ctx.source_file),
    );
    if let Some(target) = resolution.type_target {
        ctx.record_exact(target, ScalaReferenceRole::Type, node);
    }
    for callable in resolution.callable_targets {
        if role == TypeApplicationRole::ExplicitConstructor {
            ctx.record_exact_callable(callable, node);
        } else {
            ctx.record_exact_companion_callable(
                callable,
                if role == TypeApplicationRole::Extractor {
                    ScalaReferenceRole::CompanionExtractor
                } else {
                    ScalaReferenceRole::CompanionApplication
                },
                node,
            );
        }
    }
    true
}

fn record_intermediate_stable_object_reference(
    node: Node<'_>,
    ctx: &mut ScalaScan<'_, '_>,
    bindings: &LocalInferenceEngine<ScalaLocalBinding>,
) -> bool {
    let Some(reference) = intermediate_field_qualifier_reference(node, ctx.source) else {
        return false;
    };
    let Some(root) = reference.segments.first() else {
        return false;
    };
    if !bindings.resolve_symbol(root).is_unknown() || bindings.is_shadowed(root) {
        // Local and parameter roots belong to the established structured
        // receiver-chain paths below, not to namespace-rooted stable objects.
        return false;
    }
    let lexical_root = ctx.lexically_visible_object_unit(node.start_byte(), root);
    if let Some(target) = ctx.types.resolve_qualified_stable_type_unit_at(
        ctx.scala,
        &ctx.resolver,
        &reference.segments,
        true,
        lexical_root,
    ) {
        ctx.record_exact(target, ScalaReferenceRole::StableObject, node);
        return true;
    }
    // This parser shape also covers ordinary field chains such as
    // `Owner.this.service.run` and `state.payload.value`. An unresolved object
    // prefix is therefore not authoritative; let the exact receiver/field
    // paths below retain ownership.
    false
}

/// Record a stable field path rooted in a parser-proven local binding. Namespace
/// lookup deliberately rejects shadowed roots, so a path such as
/// `repr.qctx.type` must instead start from `repr`'s inferred receiver type and
/// traverse the fields carried by the stable identifier AST. Field lookup stays
/// fail-closed when that logical receiver has multiple physical declarations.
fn record_local_stable_field_reference(
    node: Node<'_>,
    ctx: &mut ScalaScan<'_, '_>,
    bindings: &LocalInferenceEngine<ScalaLocalBinding>,
) -> bool {
    let segments = stable_identifier_prefix_reference(node, ctx.source)
        .map(|reference| reference.segments)
        .or_else(|| {
            qualified_stable_type_reference(node, ctx.source)
                .filter(|reference| reference.role == ScalaQualifiedStableTypeRole::Type)
                .map(|reference| reference.segments)
        });
    let Some(segments) = segments else {
        return false;
    };
    let Some((member, owner_segments)) = segments.split_last() else {
        return false;
    };
    let Some(root) = owner_segments.first() else {
        return false;
    };
    if !bindings.is_shadowed(root) {
        return false;
    }
    let Some(binding) = precise_scala_binding(bindings, root) else {
        return true;
    };
    let Some(mut owner) = binding.receiver_type else {
        return true;
    };
    let mut exact_owner = binding.receiver_declaration.or_else(|| {
        let mut candidates = ctx
            .types
            .index
            .by_fqn(&owner)
            .iter()
            .filter(|unit| unit.is_class());
        let declaration = candidates.next()?.clone();
        candidates.next().is_none().then_some(declaration)
    });
    for segment in &owner_segments[1..] {
        let resolution = exact_owner.as_ref().map_or_else(
            || ctx.types.field_for_owner_member(ctx.scala, &owner, segment),
            |owner| ctx.types.field_for_owner_unit(ctx.scala, owner, segment),
        );
        owner = match resolution {
            FieldResolution::Resolved(field) => match field.declared_type {
                Some(declared_type) => {
                    exact_owner = ctx
                        .types
                        .exact_structural_parent(ctx.scala, &field.declaration)
                        .and_then(|context| {
                            match ctx
                                .types
                                .exact_type_declaration_for_owner_context(&declared_type, &context)
                            {
                                ScalaTypeNamespaceResolution::Resolved(declaration) => {
                                    Some(declaration)
                                }
                                ScalaTypeNamespaceResolution::NoMatch
                                | ScalaTypeNamespaceResolution::AuthoritativeMiss
                                | ScalaTypeNamespaceResolution::Ambiguous => None,
                            }
                        });
                    declared_type
                }
                None => return true,
            },
            FieldResolution::NoMatch | FieldResolution::Unresolved => return true,
        };
    }
    let resolution = exact_owner.as_ref().map_or_else(
        || ctx.types.field_for_owner_member(ctx.scala, &owner, member),
        |owner| ctx.types.field_for_owner_unit(ctx.scala, owner, member),
    );
    match resolution {
        FieldResolution::Resolved(field) => {
            ctx.record_exact(field.declaration, ScalaReferenceRole::Field, node);
        }
        FieldResolution::Unresolved => {}
        FieldResolution::NoMatch => {
            if let Some(exact_owner) = exact_owner.as_ref() {
                if let BareMemberResolution::Resolved(methods) = ctx
                    .types
                    .bare_member_declarations_for_owner(ctx.scala, exact_owner, member, None)
                {
                    for method in methods {
                        ctx.record_exact_callable(method, node);
                    }
                }
            } else {
                record_ordinary_class_methods(&owner, member, None, node, ctx);
            }
        }
    }
    true
}

/// A receiver root is itself a field reference even when the terminal member
/// is a method call. Record that root before terminal dispatch, preserving a
/// direct field binding across assignment refreshes while failing closed for a
/// local or parameter shadow of the same spelling.
fn record_enclosing_field_qualifier(
    node: Node<'_>,
    name: &str,
    ctx: &mut ScalaScan<'_, '_>,
    bindings: &LocalInferenceEngine<ScalaLocalBinding>,
) -> bool {
    if !node.parent().is_some_and(|parent| {
        parent.kind() == "field_expression" && parent.child_by_field_name("value") == Some(node)
    }) {
        return false;
    }
    record_lexically_visible_field_reference(node, name, ctx, bindings)
        == LexicalFieldReferenceResolution::Consumed
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LexicalFieldReferenceResolution {
    Consumed,
    CallableBound,
    NoMatch,
}

/// Resolve an unqualified field through Scala's exact lexical owner chain.
///
/// Local and parameter bindings are authoritative. Otherwise each physical
/// enclosing template is examined nearest-first, including that template's
/// inherited field tier. A field declaration, field ambiguity, or callable at
/// the nearest matching tier stops the walk, so neither a same-named outer
/// field nor a package-level member can leak through it. Callable recording is
/// left to the existing shape-aware path after this helper reports
/// [`LexicalFieldReferenceResolution::CallableBound`].
fn record_lexically_visible_field_reference(
    node: Node<'_>,
    name: &str,
    ctx: &mut ScalaScan<'_, '_>,
    bindings: &LocalInferenceEngine<ScalaLocalBinding>,
) -> LexicalFieldReferenceResolution {
    let bound_field_owner = exact_owner_field_binding(bindings, name);
    if bindings.is_shadowed(name) && bound_field_owner.is_none() {
        return LexicalFieldReferenceResolution::Consumed;
    }
    let mut owner = ctx.enclosing_class_unit(node.start_byte()).cloned();
    let mut seen = HashSet::default();
    while let Some(current) = owner {
        if !seen.insert(current.clone()) {
            return LexicalFieldReferenceResolution::Consumed;
        }
        owner = ctx.types.exact_structural_parent(ctx.scala, &current);
        if !current.is_class() {
            continue;
        }
        match ctx.types.field_for_owner_unit(ctx.scala, &current, name) {
            FieldResolution::Resolved(field) => {
                ctx.record_exact(field.declaration, ScalaReferenceRole::Field, node);
                return LexicalFieldReferenceResolution::Consumed;
            }
            FieldResolution::Unresolved => return LexicalFieldReferenceResolution::Consumed,
            FieldResolution::NoMatch if bound_field_owner.as_ref() == Some(&current) => {
                ctx.record_exact_owner_member(current, name, ScalaReferenceRole::Field, node);
                return LexicalFieldReferenceResolution::Consumed;
            }
            FieldResolution::NoMatch => {}
        }
        if callable_name_is_bound_for_exact_owner(&current, name, ctx) {
            return LexicalFieldReferenceResolution::CallableBound;
        }
    }
    if bound_field_owner.is_some() {
        LexicalFieldReferenceResolution::Consumed
    } else {
        LexicalFieldReferenceResolution::NoMatch
    }
}

fn companion_method_value_context(
    node: Node<'_>,
    ctx: &ScalaScan<'_, '_>,
    bindings: &LocalInferenceEngine<ScalaLocalBinding>,
) -> ScalaMethodValueContext {
    if let Some(expected_type) = node
        .parent()
        .and_then(|definition| match definition.kind() {
            "val_definition" | "var_definition"
                if definition.child_by_field_name("value") == Some(node) =>
            {
                definition.child_by_field_name("type")
            }
            "function_definition" if definition.child_by_field_name("body") == Some(node) => {
                definition.child_by_field_name("return_type")
            }
            _ => None,
        })
    {
        if expected_type.kind() != "function_type" {
            return ScalaMethodValueContext::Incompatible;
        }
        let Some(parameter_types) = expected_type.child_by_field_name("parameter_types") else {
            return ScalaMethodValueContext::Incompatible;
        };
        let mut cursor = parameter_types.walk();
        return ScalaMethodValueContext::Function(ScalaFunctionParameterShape::arity_only(
            parameter_types.named_children(&mut cursor).count(),
        ));
    }
    call_parameter_method_value_context(node, ctx, bindings)
}

fn call_parameter_method_value_context(
    node: Node<'_>,
    ctx: &ScalaScan<'_, '_>,
    bindings: &LocalInferenceEngine<ScalaLocalBinding>,
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
        .filter(|argument| is_semantic_call_argument(*argument))
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
        let Some(shape) = ctx.types.callable_parameter_function_shape(
            ctx.scala,
            &method,
            &call_arities,
            parameter_list,
            parameter_index,
        ) else {
            return ScalaMethodValueContext::Incompatible;
        };
        if resolved.as_ref().is_some_and(|resolved| resolved != &shape) {
            return ScalaMethodValueContext::Incompatible;
        }
        resolved = Some(shape);
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
                ctx.record_exact_callable(method, node);
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
    call_shape: &ScalaCallSiteShape,
    ctx: &mut ScalaScan<'_, '_>,
) -> bool {
    let call_arities = call_shape
        .lists
        .iter()
        .map(|list| list.arity)
        .collect::<Vec<_>>();
    let fallback_arities =
        (call_shape.method_value_arity.is_none()).then_some(call_arities.as_slice());
    for declaration in enclosing_template_declarations(node) {
        if let Some(owner) = ctx
            .class_ranges
            .unit_for_exact_span(declaration.start_byte(), declaration.end_byte())
        {
            let resolution = ctx
                .types
                .effective_method_declarations_for_exact_owner_with_shape(
                    ctx.scala, owner, member, call_shape,
                );
            match resolution {
                BareMemberResolution::Resolved(methods) => {
                    for method in methods {
                        ctx.record_exact_callable_with_shape(method, node, call_shape);
                    }
                    return true;
                }
                BareMemberResolution::Unresolved => return true,
                BareMemberResolution::NoMatch => {
                    if call_shape.method_value_parameter_types_authoritative
                        && callable_name_is_bound_for_exact_owner(owner, member, ctx)
                    {
                        return true;
                    }
                }
            }
        }
        match ordinary_class_member_declarations_for_template(
            declaration,
            member,
            fallback_arities,
            ctx,
        ) {
            BareMemberResolution::Resolved(methods) => {
                for method in methods {
                    ctx.record_exact_callable_with_shape(method, node, call_shape);
                }
                return true;
            }
            BareMemberResolution::Unresolved => return true,
            BareMemberResolution::NoMatch => {}
        }
        if let Some(self_owner) = template_self_type(declaration)
            .and_then(|type_node| resolve_receiver_type_node(type_node, ctx))
            && record_ordinary_class_methods(&self_owner, member, fallback_arities, node, ctx)
        {
            return true;
        }
    }
    false
}

fn callable_name_is_bound_for_exact_owner(
    owner: &CodeUnit,
    member: &str,
    ctx: &ScalaScan<'_, '_>,
) -> bool {
    ctx.types
        .linearized_owners(ctx.scala, owner)
        .iter()
        .any(|owner| {
            ctx.types
                .members_for_exact_owner_unit(ctx.scala, owner, member)
                .iter()
                .any(|unit| {
                    unit.is_function()
                        && ctx.types.fallback_callable_role(ctx.scala, unit)
                            == ScalaCallableRole::Ordinary
                })
        })
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
                    ctx.record_exact_callable(method, node);
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
fn receiver_type_declaration(
    receiver: Node<'_>,
    ctx: &ScalaScan<'_, '_>,
    bindings: &LocalInferenceEngine<ScalaLocalBinding>,
) -> Option<CodeUnit> {
    match receiver.kind() {
        "identifier" => {
            let name = node_text(receiver, ctx.source);
            if name == "this" {
                return ctx.enclosing_class_unit(receiver.start_byte()).cloned();
            }
            if let Some(binding) = precise_scala_binding(bindings, name) {
                if let Some(declaration) = binding.receiver_declaration {
                    return Some(declaration);
                }
                let receiver_type = binding.receiver_type?;
                return exact_receiver_type_declaration(
                    &receiver_type,
                    ctx.enclosing_class_unit(receiver.start_byte())?,
                    ctx,
                );
            }
            if bindings.is_shadowed(name) || !is_field_expression_value(receiver) {
                return None;
            }
            match ctx.visible_object_reference(receiver.start_byte(), name) {
                Some(ScalaResolvedReference::Exact(object)) => Some(object),
                Some(ScalaResolvedReference::Logical(_)) | None => None,
            }
        }
        "field_expression" => {
            let value = receiver.child_by_field_name("value")?;
            let member = receiver.child_by_field_name("field")?;
            let owner = receiver_type_declaration(value, ctx, bindings)?;
            let member = node_text(member, ctx.source).trim();
            let FieldResolution::Resolved(field) =
                ctx.types.field_for_owner_unit(ctx.scala, &owner, member)
            else {
                return None;
            };
            let declared_type = field.declared_type?;
            let owner_context = ctx
                .scala
                .structural_parent_of(&field.declaration)
                .unwrap_or(owner);
            exact_receiver_type_declaration(&declared_type, &owner_context, ctx)
        }
        _ => None,
    }
}

fn exact_receiver_type_declaration(
    receiver_type: &str,
    owner_context: &CodeUnit,
    ctx: &ScalaScan<'_, '_>,
) -> Option<CodeUnit> {
    match ctx
        .types
        .exact_type_declaration_for_owner_context(receiver_type, owner_context)
    {
        ScalaTypeNamespaceResolution::Resolved(declaration) => return Some(declaration),
        ScalaTypeNamespaceResolution::NoMatch
        | ScalaTypeNamespaceResolution::AuthoritativeMiss
        | ScalaTypeNamespaceResolution::Ambiguous => {}
    }
    let mut candidates = ctx
        .types
        .index
        .by_fqn(receiver_type)
        .iter()
        .filter(|unit| unit.is_class());
    let declaration = candidates.next()?.clone();
    candidates.next().is_none().then_some(declaration)
}

fn receiver_type_fqn(
    receiver: Node<'_>,
    ctx: &ScalaScan<'_, '_>,
    bindings: &LocalInferenceEngine<ScalaLocalBinding>,
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
            precise_scala_binding(bindings, name)
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
                    (!bindings.is_shadowed(name) && is_field_expression_value(receiver)).then(
                        || {
                            ctx.visible_object_reference(receiver.start_byte(), name)
                                .map(|reference| match reference {
                                    ScalaResolvedReference::Exact(object) => object.fq_name(),
                                    ScalaResolvedReference::Logical(fqn) => fqn,
                                })
                        },
                    )?
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
        "field_expression" if is_owner_qualified_this(receiver, ctx.source) => {
            let owner = receiver.child_by_field_name("value")?;
            let name = node_text(owner, ctx.source).trim();
            ctx.visible_type(owner, name)
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
        kind => scala_literal_type_name(kind).map(|name| {
            let scala_fqn = format!("scala.{name}");
            let declarations = ctx.types.index.by_fqn(&scala_fqn);
            if declarations.len() == 1 && declarations[0].is_class() {
                scala_fqn
            } else {
                name.to_string()
            }
        }),
    }
}

fn stable_object_expression_fqn(
    node: Node<'_>,
    ctx: &ScalaScan<'_, '_>,
    bindings: &LocalInferenceEngine<ScalaLocalBinding>,
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
    bindings: &mut LocalInferenceEngine<ScalaLocalBinding>,
) {
    match node.kind() {
        "class_definition" | "object_definition" | "trait_definition" | "enum_definition" => {
            seed_class_parameters(node, ctx, bindings);
            preseed_direct_owner_fields(node, ctx, bindings);
        }
        "function_definition" => {
            if let Some(name) = node.child_by_field_name("name") {
                let name = node_text(name, ctx.source).trim();
                if !name.is_empty() {
                    bindings.declare_shadow(name.to_string());
                }
            }
            preseed_enclosing_owner_fields(node, ctx, bindings);
            seed_parameters(node, ctx, bindings);
        }
        "val_definition" | "var_definition" => seed_value_definition(node, ctx, bindings),
        _ => {}
    }
}

fn preseed_enclosing_owner_fields(
    node: Node<'_>,
    ctx: &ScalaScan<'_, '_>,
    bindings: &mut LocalInferenceEngine<ScalaLocalBinding>,
) {
    let mut current = node.parent();
    while let Some(ancestor) = current {
        match ancestor.kind() {
            "class_definition" | "object_definition" | "trait_definition" | "enum_definition" => {
                preseed_direct_owner_fields(ancestor, ctx, bindings);
                return;
            }
            "function_definition"
            | "block"
            | "block_expression"
            | "case_clause"
            | "lambda_expression"
            | "anonymous_function" => return,
            _ => current = ancestor.parent(),
        }
    }
}

fn refresh_assignment_binding(
    node: Node<'_>,
    ctx: &ScalaScan<'_, '_>,
    bindings: &mut LocalInferenceEngine<ScalaLocalBinding>,
) {
    let (Some(left), Some(right)) = (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
    ) else {
        return;
    };
    if !matches!(left.kind(), "identifier" | "operator_identifier") {
        return;
    }
    let name = node_text(left, ctx.source).trim();
    if name.is_empty() || !bindings.is_shadowed(name) {
        return;
    }
    let declaration_owner =
        precise_scala_binding(bindings, name).and_then(|binding| binding.declaration_owner);
    let source_binding = matches!(right.kind(), "identifier" | "operator_identifier")
        .then(|| precise_scala_binding(bindings, node_text(right, ctx.source).trim()))
        .flatten();
    if let Some(receiver_declaration) = source_binding
        .as_ref()
        .and_then(|binding| binding.receiver_declaration.clone())
    {
        seed_scala_binding_with_receiver_declaration(
            name,
            receiver_declaration,
            declaration_owner,
            bindings,
        );
        return;
    }
    let receiver = constructed_or_applied_type(right, ctx)
        .or_else(|| call_result_type(right, ctx, bindings).map(ScalaValueOwner::Logical))
        .or_else(|| {
            source_binding
                .and_then(|binding| binding.receiver_type)
                .map(ScalaValueOwner::Logical)
        });
    seed_value_owner(name, receiver, declaration_owner, bindings);
}

fn record_override_declaration(node: Node<'_>, ctx: &mut ScalaScan<'_, '_>) {
    if !matches!(node.kind(), "function_definition" | "function_declaration") {
        return;
    }
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    if !node
        .parent()
        .is_some_and(|parent| matches!(parent.kind(), "template_body" | "enum_body"))
    {
        return;
    }
    let name = node_text(name_node, ctx.source).trim();
    if name.is_empty() || !ctx.sink.may_match_name(name) {
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
    bindings: &mut LocalInferenceEngine<ScalaLocalBinding>,
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
    bindings: &mut LocalInferenceEngine<ScalaLocalBinding>,
) {
    let owner = ctx.enclosing_class_unit(node.start_byte()).cloned();
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
    declaration_owner: Option<CodeUnit>,
    bindings: &mut LocalInferenceEngine<ScalaLocalBinding>,
) {
    let Some(name) = parameter.child_by_field_name("name") else {
        return;
    };
    let binding_name = node_text(name, ctx.source).trim();
    if binding_name.is_empty() {
        return;
    }
    if let Some(type_node) = parameter.child_by_field_name("type")
        && let Some(paths) = scala_union_type_alternative_paths(type_node, ctx.source)
    {
        let owners = paths
            .iter()
            .map(|path| {
                ctx.types
                    .resolve_type_in_declaration_context(ctx.scala, &ctx.resolver, path)
            })
            .collect::<Option<Vec<_>>>();
        if let Some(owners) = owners {
            bindings.seed_symbol_many(
                binding_name.to_string(),
                owners.into_iter().map(|receiver_type| ScalaLocalBinding {
                    receiver_type: Some(receiver_type),
                    receiver_declaration: None,
                    declaration_owner: declaration_owner.clone(),
                }),
            );
        } else {
            bindings.declare_shadow(binding_name.to_string());
        }
        return;
    }
    if let Some(receiver_declaration) = parameter
        .child_by_field_name("type")
        .and_then(|type_node| resolve_receiver_type_declaration_node(type_node, ctx))
    {
        seed_scala_binding_with_receiver_declaration(
            binding_name,
            receiver_declaration,
            declaration_owner,
            bindings,
        );
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
    bindings: &mut LocalInferenceEngine<ScalaLocalBinding>,
) {
    let Some(owner) = ctx.enclosing_class_unit(node.start_byte()).cloned() else {
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
    owner: &CodeUnit,
    bindings: &mut LocalInferenceEngine<ScalaLocalBinding>,
) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "val_definition" | "var_definition" => {
                if direct_owner_field_owner(child, ctx).as_ref() == Some(owner) {
                    seed_value_definition_with_owner(child, ctx, Some(owner.clone()), bindings);
                }
            }
            "function_definition"
            | "function_declaration"
            | "class_definition"
            | "object_definition"
            | "trait_definition"
            | "enum_definition"
            | "block"
            | "block_expression"
            | "indented_block"
            | "case_clause"
            | "lambda_expression"
            | "anonymous_function" => {}
            _ => preseed_owner_fields_in(child, ctx, owner, bindings),
        }
    }
}

fn seed_value_definition(
    node: Node<'_>,
    ctx: &ScalaScan<'_, '_>,
    bindings: &mut LocalInferenceEngine<ScalaLocalBinding>,
) {
    let declaration_owner = direct_owner_field_owner(node, ctx);
    seed_value_definition_with_owner(node, ctx, declaration_owner, bindings);
}

fn seed_value_definition_with_owner(
    node: Node<'_>,
    ctx: &ScalaScan<'_, '_>,
    declaration_owner: Option<CodeUnit>,
    bindings: &mut LocalInferenceEngine<ScalaLocalBinding>,
) {
    // Prefer the declared type; otherwise infer from a `new Foo()` initializer
    // or a call with a declared factory return.
    let receiver_declaration = node
        .child_by_field_name("type")
        .and_then(|type_node| resolve_receiver_type_declaration_node(type_node, ctx));
    let resolved = node
        .child_by_field_name("type")
        .filter(|_| receiver_declaration.is_none())
        .and_then(|type_node| resolve_receiver_type_node(type_node, ctx))
        .map(ScalaValueOwner::Logical)
        .or_else(|| {
            node.child_by_field_name("value")
                .and_then(|value| constructed_or_applied_type(value, ctx))
        })
        .or_else(|| {
            node.child_by_field_name("value")
                .and_then(|value| call_result_type(value, ctx, bindings))
                .map(ScalaValueOwner::Logical)
        });
    let Some(pattern) = node.child_by_field_name("pattern") else {
        return;
    };
    for name in scala_pattern_binder_names(pattern, ctx.source) {
        if let Some(receiver_declaration) = receiver_declaration.clone() {
            seed_scala_binding_with_receiver_declaration(
                name,
                receiver_declaration,
                declaration_owner.clone(),
                bindings,
            );
        } else {
            seed_value_owner(name, resolved.clone(), declaration_owner.clone(), bindings);
        }
    }
}

fn direct_owner_field_owner(node: Node<'_>, ctx: &ScalaScan<'_, '_>) -> Option<CodeUnit> {
    let owner = ctx.enclosing_class_unit(node.start_byte())?.clone();
    let mut current = node.parent();
    while let Some(ancestor) = current {
        match ancestor.kind() {
            "template_body" | "enum_body" => return Some(owner),
            "function_definition"
            | "block"
            | "block_expression"
            | "indented_block"
            | "case_clause"
            | "lambda_expression"
            | "anonymous_function"
            | "class_definition"
            | "object_definition"
            | "trait_definition"
            | "enum_definition" => return None,
            _ => current = ancestor.parent(),
        }
    }
    None
}

fn scala_named_template_owner(mut template: Node<'_>) -> Option<Node<'_>> {
    while let Some(parent) = template.parent() {
        match parent.kind() {
            "class_definition" | "object_definition" | "trait_definition" | "enum_definition" => {
                return Some(parent);
            }
            "instance_expression" | "template_body" => return None,
            _ => template = parent,
        }
    }
    None
}

/// The fqn of the type constructed by a `new Foo()` value expression.
fn constructed_type(node: Node<'_>, ctx: &ScalaScan<'_, '_>) -> Option<String> {
    constructed_type_declaration(node, ctx).map(|target| target.fq_name())
}

/// The exact declaration constructed by a `new Foo()` value expression.
fn constructed_type_declaration(node: Node<'_>, ctx: &ScalaScan<'_, '_>) -> Option<CodeUnit> {
    let type_node = constructed_type_node(node)?;
    let path = scala_type_lookup_segments(type_node, ctx.source);
    let name = path.last()?;
    if let Some(target) = resolve_receiver_type_declaration_node(type_node, ctx) {
        return exact_constructed_type_target(type_node, target, name, ctx);
    }
    let class_fqn = resolve_receiver_type_node(type_node, ctx)?;
    ctx.types
        .resolve_type_application(
            ctx.scala,
            &ctx.resolver,
            Some(&class_fqn),
            None,
            name,
            call_site_shape_for_reference(type_node).as_ref(),
            TypeApplicationRole::ExplicitConstructor,
            Some(ctx.source_file),
        )
        .type_target
}

fn constructed_type_node(mut node: Node<'_>) -> Option<Node<'_>> {
    while node.kind() == "call_expression" {
        node = node.child_by_field_name("function")?;
    }
    if node.kind() != "instance_expression" {
        return None;
    }
    let mut cursor = node.walk();
    let type_nodes = node
        .named_children(&mut cursor)
        .filter(|child| !matches!(child.kind(), "arguments" | "template_body"))
        .collect::<Vec<_>>();
    let [type_node] = type_nodes.as_slice() else {
        return None;
    };
    if matches!(
        type_node.kind(),
        "compound_type" | "infix_type" | "intersection_type" | "with_type"
    ) {
        return None;
    }
    Some(*type_node)
}

fn exact_constructed_type_target(
    type_node: Node<'_>,
    target: CodeUnit,
    name: &str,
    ctx: &ScalaScan<'_, '_>,
) -> Option<CodeUnit> {
    let resolved = ctx
        .types
        .resolve_type_application(
            ctx.scala,
            &ctx.resolver,
            Some(&target.fq_name()),
            None,
            name,
            call_site_shape_for_reference(type_node).as_ref(),
            TypeApplicationRole::ExplicitConstructor,
            Some(ctx.source_file),
        )
        .type_target?;
    (resolved == target).then_some(target)
}

fn unwrap_single_scala_expression(mut node: Node<'_>) -> Node<'_> {
    while matches!(node.kind(), "block" | "block_expression" | "indented_block")
        && node.named_child_count() == 1
    {
        node = node
            .named_child(0)
            .expect("a block with one named child has that child");
    }
    node
}

fn constructed_or_applied_type(node: Node<'_>, ctx: &ScalaScan<'_, '_>) -> Option<ScalaValueOwner> {
    let node = unwrap_single_scala_expression(node);
    constructed_type(node, ctx)
        .map(ScalaValueOwner::Logical)
        .or_else(|| {
            if node.kind() != "call_expression" {
                return None;
            }
            let mut function = node.child_by_field_name("function")?;
            while function.kind() == "call_expression" {
                function = function.child_by_field_name("function")?;
            }
            function = invocation_function_reference(function);
            if !matches!(function.kind(), "identifier" | "type_identifier") {
                return None;
            }
            let name = node_text(function, ctx.source).trim();
            if name.is_empty() {
                return None;
            }
            let class_fqn = ctx.visible_type(function, name);
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
                    call_site_shape_for_reference(function).as_ref(),
                    TypeApplicationRole::BareApplication,
                    Some(ctx.source_file),
                )
                .value_result
        })
}

fn call_result_type(
    node: Node<'_>,
    ctx: &ScalaScan<'_, '_>,
    bindings: &LocalInferenceEngine<ScalaLocalBinding>,
) -> Option<String> {
    let node = unwrap_single_scala_expression(node);
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
            if !bindings.resolve_symbol(method).is_unknown() || bindings.is_shadowed(method) {
                return None;
            }
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
                        ctx.types.member_return_type_for_fqn_call(
                            ctx.scala,
                            &ctx.resolver,
                            &member,
                            call_arities.as_deref(),
                        )
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

fn seed_binding(
    name: &str,
    receiver_type: Option<String>,
    declaration_owner: Option<CodeUnit>,
    bindings: &mut LocalInferenceEngine<ScalaLocalBinding>,
) {
    seed_scala_binding(name, receiver_type, declaration_owner, bindings);
}

fn seed_value_owner(
    name: &str,
    receiver: Option<ScalaValueOwner>,
    declaration_owner: Option<CodeUnit>,
    bindings: &mut LocalInferenceEngine<ScalaLocalBinding>,
) {
    match receiver {
        Some(ScalaValueOwner::Exact(receiver)) => seed_scala_binding_with_receiver_declaration(
            name,
            receiver,
            declaration_owner,
            bindings,
        ),
        Some(ScalaValueOwner::Logical(receiver)) => {
            seed_binding(name, Some(receiver), declaration_owner, bindings)
        }
        None => seed_binding(name, None, declaration_owner, bindings),
    }
}

fn exact_owner_field_binding(
    bindings: &LocalInferenceEngine<ScalaLocalBinding>,
    name: &str,
) -> Option<CodeUnit> {
    precise_scala_binding(bindings, name).and_then(|binding| binding.declaration_owner)
}

fn resolve_receiver_type_node(type_node: Node<'_>, ctx: &ScalaScan<'_, '_>) -> Option<String> {
    let type_node = scala_capture_underlying_type(type_node, ctx.source);
    let path = scala_type_lookup_segments(type_node, ctx.source);
    if path.is_empty() {
        return None;
    }
    let resolved = if path.len() > 1
        && let Some(root) = path
            .first()
            .and_then(|root| ctx.lexically_visible_object_unit(type_node.start_byte(), root))
        && let Some(declaration) = ctx.types.resolve_qualified_stable_type_unit_at(
            ctx.scala,
            &ctx.resolver,
            &path,
            false,
            Some(root),
        ) {
        Some(declaration.fq_name())
    } else {
        match ctx.exact_lexically_visible_type(type_node) {
            ScalaTypeNamespaceResolution::Resolved(declaration) => Some(declaration.fq_name()),
            ScalaTypeNamespaceResolution::AuthoritativeMiss
            | ScalaTypeNamespaceResolution::Ambiguous => return None,
            ScalaTypeNamespaceResolution::NoMatch => ctx
                .types
                .resolve_type_in_declaration_context(ctx.scala, &ctx.resolver, &path)
                .or_else(|| {
                    (path.len() == 1)
                        .then(|| scala_builtin_type_name(&path[0]).map(str::to_string))
                        .flatten()
                }),
        }
    }?;
    ctx.types.canonical_receiver_type(ctx.scala, &resolved)
}

fn resolve_receiver_type_declaration_node(
    type_node: Node<'_>,
    ctx: &ScalaScan<'_, '_>,
) -> Option<CodeUnit> {
    let type_node = scala_capture_underlying_type(type_node, ctx.source);
    let path = scala_type_lookup_segments(type_node, ctx.source);
    let declaration = if path.len() > 1
        && let Some(root) = path
            .first()
            .and_then(|root| ctx.lexically_visible_object_unit(type_node.start_byte(), root))
        && let Some(declaration) = ctx.types.resolve_qualified_stable_type_unit_at(
            ctx.scala,
            &ctx.resolver,
            &path,
            false,
            Some(root),
        ) {
        declaration
    } else {
        match ctx.exact_lexically_visible_type(type_node) {
            ScalaTypeNamespaceResolution::Resolved(declaration) => declaration,
            ScalaTypeNamespaceResolution::AuthoritativeMiss
            | ScalaTypeNamespaceResolution::Ambiguous => return None,
            ScalaTypeNamespaceResolution::NoMatch if path.len() == 1 => {
                ctx.resolver.resolve_unit(&path[0])?
            }
            ScalaTypeNamespaceResolution::NoMatch => return None,
        }
    };
    if !ctx.types.is_type_alias(ctx.scala, &declaration) {
        return Some(declaration);
    }
    let receiver_type = ctx
        .types
        .canonical_receiver_type(ctx.scala, &declaration.fq_name())?;
    let owner_context = ctx
        .types
        .exact_structural_parent(ctx.scala, &declaration)
        .unwrap_or_else(|| declaration.clone());
    match ctx
        .types
        .exact_type_declaration_for_owner_context(&receiver_type, &owner_context)
    {
        ScalaTypeNamespaceResolution::Resolved(declaration) => Some(declaration),
        ScalaTypeNamespaceResolution::AuthoritativeMiss
        | ScalaTypeNamespaceResolution::Ambiguous
        | ScalaTypeNamespaceResolution::NoMatch => None,
    }
}

/// Tree-sitter represents Scala 3's postfix capture marker (`T^`) as an
/// `infix_type` whose right operand is the zero-width missing node. Preserve
/// the parser's structure while resolving the actual receiver type on the
/// left; ordinary infix/intersection types remain untouched.
fn scala_capture_underlying_type<'tree>(type_node: Node<'tree>, source: &str) -> Node<'tree> {
    if type_node.kind() == "infix_type"
        && type_node
            .child_by_field_name("operator")
            .is_some_and(|operator| node_text(operator, source).trim() == "^")
        && type_node
            .child_by_field_name("right")
            .is_some_and(|right| right.start_byte() == right.end_byte())
        && let Some(left) = type_node.child_by_field_name("left")
    {
        return left;
    }
    type_node
}

fn visible_extensions(
    ctx: &ScalaScan<'_, '_>,
    member: &str,
    receiver_owner: Option<&str>,
    call_arities: Option<&[usize]>,
) -> Vec<ExtensionMethod> {
    let mut matches = Vec::new();
    let visible = ctx
        .resolver
        .visible_extension_methods(ctx.scala, ctx.types, member);
    for method in visible {
        if method.alternatives.iter().any(|alternative| {
            alternative.role == ScalaCallableRole::Ordinary
                && extension_alternative_receiver_matches(
                    &ctx.resolver,
                    alternative,
                    receiver_owner,
                )
        }) {
            matches.push(method);
        }
    }
    matches.sort_by(|left, right| left.fqn.cmp(&right.fqn));
    matches.dedup_by(|left, right| left.fqn == right.fqn);
    let callable_count = matches
        .iter()
        .flat_map(|method| method.alternatives.iter())
        .filter(|alternative| alternative.role == ScalaCallableRole::Ordinary)
        .count();
    let unique_callable = callable_count == 1;
    matches.retain(|method| {
        method.alternatives.iter().any(|alternative| {
            alternative.role == ScalaCallableRole::Ordinary
                && extension_alternative_receiver_matches(
                    &ctx.resolver,
                    alternative,
                    receiver_owner,
                )
                && ordinary_callable_shape_matches(
                    &alternative.shape,
                    call_arities,
                    unique_callable,
                )
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
