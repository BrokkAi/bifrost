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
    package_name_of, preferred_scala_type, resolved_extension_receiver_type,
    scala_builtin_type_name, scala_extension_receiver_matches_resolved, scala_literal_type_name,
    scala_normalized_fq_name,
};
use super::shared::ScalaEdgeGraph;
use super::syntax::{call_arity_for_reference, node_text, parenthesized_arity, scala_import_path};
use crate::analyzer::scala::{ScalaAdapter, scala_normalize_full_name, scala_simple_type_name};
use crate::analyzer::tree_sitter_analyzer::FileState;
use crate::analyzer::usages::common::{TreeWalkAction, walk_tree_iterative};
use crate::analyzer::usages::inverted_edges::{
    ClassRangeIndex, EdgeCollector, UsageEdgeBuildOutput, build_edge_output,
    build_file_declarations, build_file_declarations_from_state, classify_reference_node,
    first_precise, parse_and_collect_with_declarations,
};
use crate::analyzer::usages::local_inference::{LocalInferenceConfig, LocalInferenceEngine};
use crate::analyzer::{CodeUnit, GlobalUsageDefinitionIndex, UsageFactsIndex};
use crate::analyzer::{
    IAnalyzer, ImportAnalysisProvider, ProjectFile, ScalaAnalyzer, TypeHierarchyProvider,
};
use crate::hash::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use tree_sitter::Node;

type PackageTypeEntries = Arc<Vec<(String, CodeUnit)>>;
type ExtensionOwnerMemberKey = (String, String);
type ExtensionMethodEntries = Arc<Vec<ExtensionMethod>>;
type OverrideTargetEntries = Arc<Vec<String>>;

/// Every class/object/trait/enum the project declares, indexed for the per-file
/// name->fqn rebuild. Built once and shared across all files' scans.
pub(crate) struct ProjectTypes {
    index: Arc<GlobalUsageDefinitionIndex>,
    facts: Arc<UsageFactsIndex>,
    direct_ancestors_by_owner: Option<HashMap<String, Vec<CodeUnit>>>,
    scala_trait_fqns: Option<HashSet<String>>,
    package_types_by_package: Mutex<HashMap<String, PackageTypeEntries>>,
    extension_methods_by_owner_member:
        Mutex<HashMap<ExtensionOwnerMemberKey, ExtensionMethodEntries>>,
    override_targets_by_method: Mutex<HashMap<String, OverrideTargetEntries>>,
}

impl ProjectTypes {
    pub(crate) fn build(scala: &ScalaAnalyzer) -> Self {
        let index = scala.global_usage_definition_index_shared();
        Self {
            index,
            facts: scala.usage_facts_index_shared(),
            direct_ancestors_by_owner: None,
            scala_trait_fqns: None,
            package_types_by_package: Mutex::new(HashMap::default()),
            extension_methods_by_owner_member: Mutex::new(HashMap::default()),
            override_targets_by_method: Mutex::new(HashMap::default()),
        }
    }

    pub(crate) fn build_from_file_states(
        scala: &ScalaAnalyzer,
        file_states: &HashMap<ProjectFile, FileState>,
    ) -> Self {
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
            scala_trait_fqns: Some(
                file_states
                    .values()
                    .flat_map(|state| state.scala_traits.iter().map(CodeUnit::fq_name))
                    .collect(),
            ),
            package_types_by_package: Mutex::new(HashMap::default()),
            extension_methods_by_owner_member: Mutex::new(HashMap::default()),
            override_targets_by_method: Mutex::new(HashMap::default()),
        };
        types.direct_ancestors_by_owner =
            Some(types.build_direct_ancestors_from_file_states(scala, file_states));
        types
    }

    fn build_direct_ancestors_from_file_states(
        &self,
        scala: &ScalaAnalyzer,
        file_states: &HashMap<ProjectFile, FileState>,
    ) -> HashMap<String, Vec<CodeUnit>> {
        let mut ancestors_by_owner = HashMap::default();
        for state in file_states.values() {
            if state.raw_supertypes.is_empty() {
                continue;
            }
            let resolver = NameResolver::for_file_with_facts(
                scala,
                Some(&state.package_name),
                &state.imports,
                self,
            );
            for (owner, raw_supertypes) in &state.raw_supertypes {
                if !owner.is_class() {
                    continue;
                }
                let mut ancestors = Vec::new();
                let mut seen = HashSet::default();
                for raw in raw_supertypes {
                    let Some(fqn) = resolver.resolve(raw) else {
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
                    ancestors_by_owner.insert(owner.fq_name(), ancestors);
                }
            }
        }
        ancestors_by_owner
    }

    fn direct_ancestors_for_owner(&self, scala: &ScalaAnalyzer, owner_fqn: &str) -> Vec<CodeUnit> {
        if let Some(ancestors_by_owner) = &self.direct_ancestors_by_owner {
            return ancestors_by_owner
                .get(owner_fqn)
                .cloned()
                .unwrap_or_default();
        }
        scala
            .definitions(owner_fqn)
            .find(|unit| unit.is_class())
            .map(|owner| scala.get_ancestors(&owner))
            .unwrap_or_default()
    }

    fn is_scala_trait_declaration(&self, scala: &ScalaAnalyzer, code_unit: &CodeUnit) -> bool {
        if let Some(traits) = &self.scala_trait_fqns {
            return traits.contains(&code_unit.fq_name());
        }
        scala.is_scala_trait_declaration(code_unit)
    }

    fn method_targets_for_owner_member(
        &self,
        owner_fqn: &str,
        member: &str,
        call_arity: Option<usize>,
    ) -> Vec<String> {
        let normalized_owner = scala_normalized_fq_name(owner_fqn);
        self.index
            .members_for_owner_name(owner_fqn, &normalized_owner, member)
            .iter()
            .filter(|method| {
                method.is_function()
                    && method_call_arity_matches(
                        self.facts
                            .fact_for_declaration(method)
                            .and_then(|facts| facts.arity),
                        self.facts
                            .fact_for_declaration(method)
                            .and_then(|facts| facts.callable_arity),
                        call_arity,
                    )
            })
            .map(|method| method.fq_name())
            .collect()
    }

    fn inherited_method_targets_for_owner_member(
        &self,
        scala: &ScalaAnalyzer,
        owner_fqn: &str,
        member: &str,
        call_arity: Option<usize>,
    ) -> Vec<String> {
        for ancestor in self.direct_ancestors_for_owner(scala, owner_fqn) {
            let targets =
                self.method_targets_for_owner_member(&ancestor.fq_name(), member, call_arity);
            if !targets.is_empty() {
                return targets;
            }
        }
        Vec::new()
    }

    pub(crate) fn member_return_type(&self, member_fqn: &str) -> Option<String> {
        self.facts
            .callable_return_type(member_fqn)
            .map(str::to_string)
    }

    fn member_return_type_for_owner_member(
        &self,
        owner_fqn: &str,
        member: &str,
        call_arity: Option<usize>,
    ) -> Option<String> {
        let normalized_owner = scala_normalized_fq_name(owner_fqn);
        let members = self
            .index
            .members_for_owner_name(owner_fqn, &normalized_owner, member);
        let mut returns = members
            .iter()
            .filter(|method| {
                method.is_function()
                    && method_call_arity_matches(
                        self.facts
                            .fact_for_declaration(method)
                            .and_then(|facts| facts.arity),
                        self.facts
                            .fact_for_declaration(method)
                            .and_then(|facts| facts.callable_arity),
                        call_arity,
                    )
            })
            .filter_map(|method| {
                self.facts
                    .fact_for_declaration(method)
                    .and_then(|facts| facts.return_type_fqn.clone())
            });
        let first = returns.next()?;
        returns
            .all(|return_type| return_type == first)
            .then_some(first)
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
            if candidate_package == package
                && let Some(unit) = preferred_scala_type(units)
            {
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

    fn member_by_normalized_fqn(&self, normalized_fqn: &str) -> Option<&CodeUnit> {
        self.index
            .by_normalized_fqn(normalized_fqn)
            .iter()
            .find(|unit| unit.is_function() || unit.is_field())
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
        let signature = unit
            .signature()
            .map(str::to_string)
            .or_else(|| scala.signatures(unit).into_iter().next())?;
        if !signature.starts_with("extension ") {
            return None;
        }
        let _ = owner_fqn(unit)?;
        Some(ExtensionMethod {
            fqn: unit.fq_name(),
            receiver_type: resolved_extension_receiver_type(scala, unit, &signature),
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

        let mut targets = Vec::new();
        for ancestor in self.direct_ancestors_for_owner(scala, owner_fqn) {
            if !self.is_scala_trait_declaration(scala, &ancestor) {
                continue;
            }
            if !targets.is_empty() {
                break;
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
pub(crate) struct ExtensionMethod {
    pub(crate) fqn: String,
    pub(crate) receiver_type: Option<String>,
}

/// Per-file map from a source-visible type/object name to the analyzer's fqn,
/// mirroring the forward scanner's [`Visibility`](super::resolver).
pub(crate) struct NameResolver {
    names: HashMap<String, String>,
    member_names: HashMap<String, String>,
    direct_extension_methods: HashMap<String, Vec<ExtensionMethod>>,
    wildcard_extension_owners: Vec<String>,
}

impl NameResolver {
    pub(crate) fn for_file(
        scala: &ScalaAnalyzer,
        file: &ProjectFile,
        types: &ProjectTypes,
    ) -> Self {
        Self::for_file_with_facts(
            scala,
            package_name_of(scala, file).as_deref(),
            &scala.import_info_of(file),
            types,
        )
    }

    pub(crate) fn for_file_with_facts(
        scala: &ScalaAnalyzer,
        package: Option<&str>,
        imports: &[crate::analyzer::ImportInfo],
        types: &ProjectTypes,
    ) -> Self {
        let mut names = HashMap::default();
        let mut member_names = HashMap::default();
        let mut direct_extension_methods: HashMap<String, Vec<ExtensionMethod>> =
            HashMap::default();
        let mut wildcard_extension_owners = Vec::new();

        let file_package = package.unwrap_or_default();
        // Types in the file's own package are reachable by simple name. The
        // default package is a real Scala scope, so it must be seeded too.
        for (simple, decl) in types.package_types_in(file_package).iter() {
            names.insert(simple.clone(), decl.fq_name());
        }

        for import in imports {
            let Some(path) = scala_import_path(import) else {
                continue;
            };
            if import.is_wildcard {
                let package_candidates = import_candidate_paths(&path, file_package);
                // `import pkg._` exposes every type in `pkg` by simple name.
                for decl_package in &package_candidates {
                    for (simple, decl) in types.package_types_in(decl_package).iter() {
                        names.insert(simple.clone(), decl.fq_name());
                    }
                }
                wildcard_extension_owners
                    .extend(import_candidate_normalized_paths(&path, file_package));
                continue;
            }
            // `import pkg.Type [as Alias]` binds the (possibly renamed) local name.
            let normalized_paths = import_candidate_normalized_paths(&path, file_package);
            if let Some(decl) = normalized_paths
                .iter()
                .find_map(|normalized| types.type_by_normalized_fqn(normalized))
            {
                let local_name = import
                    .identifier
                    .clone()
                    .unwrap_or_else(|| path.rsplit('.').next().unwrap_or(&path).to_string());
                names.insert(local_name, decl.fq_name());
                continue;
            }
            if let Some(member) = normalized_paths
                .iter()
                .find_map(|normalized| types.member_by_normalized_fqn(normalized))
            {
                let local_name = import
                    .identifier
                    .clone()
                    .unwrap_or_else(|| path.rsplit('.').next().unwrap_or(&path).to_string());
                let member_fqn = member.fq_name();
                member_names.insert(local_name.clone(), member_fqn.clone());
                for method in normalized_paths
                    .iter()
                    .flat_map(|normalized| types.direct_extension_method(scala, normalized))
                {
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
            member_names,
            direct_extension_methods,
            wildcard_extension_owners,
        }
    }

    /// Resolve a type/object source name (stripping generics) to its fqn.
    pub(crate) fn resolve(&self, raw: &str) -> Option<String> {
        let simple = simple_type_name(raw)?;
        self.names.get(simple).cloned()
    }

    /// Resolve a source-visible member name imported directly from an owner.
    pub(crate) fn resolve_member(&self, raw: &str) -> Option<String> {
        let simple = simple_type_name(raw)?;
        self.member_names.get(simple).cloned()
    }

    pub(crate) fn visible_extension_methods(
        &self,
        scala: &ScalaAnalyzer,
        types: &ProjectTypes,
        member: &str,
    ) -> Vec<ExtensionMethod> {
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
}

fn import_candidate_normalized_paths(path: &str, package_name: &str) -> HashSet<String> {
    import_candidate_paths(path, package_name)
        .into_iter()
        .map(|candidate| scala_normalized_fq_name(&candidate))
        .collect()
}

fn import_candidate_paths(path: &str, package_name: &str) -> HashSet<String> {
    let mut candidates = HashSet::from_iter([path.to_string()]);
    if !package_name.is_empty() && !path.starts_with(&format!("{package_name}.")) {
        candidates.insert(format!("{package_name}.{path}"));
    }
    candidates
}

fn owner_fqn(unit: &CodeUnit) -> Option<String> {
    let (owner_short, _) = unit.short_name().rsplit_once('.')?;
    Some(if unit.package_name().is_empty() {
        owner_short.to_string()
    } else {
        format!("{}.{}", unit.package_name(), owner_short)
    })
}

fn method_arities_compatible(method: Option<usize>, ancestor: Option<usize>) -> bool {
    method.is_none() || ancestor.is_none() || method == ancestor
}

fn method_call_arity_matches(
    method_arity: Option<usize>,
    callable_arity: Option<crate::analyzer::CallableArity>,
    call_arity: Option<usize>,
) -> bool {
    match call_arity {
        Some(call_arity) => callable_arity
            .map(|arity| arity.accepts(call_arity))
            .unwrap_or_else(|| method_arity.is_some_and(|arity| arity == call_arity)),
        None => method_arity.is_none_or(|arity| arity == 0),
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
    analyzer: &dyn IAnalyzer,
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
        let state = graph.file_states.get(file);
        let declarations = state
            .map(build_file_declarations_from_state)
            .unwrap_or_else(|| build_file_declarations(analyzer, file));
        let class_ranges = state
            .map(ClassRangeIndex::build_from_state)
            .unwrap_or_else(|| ClassRangeIndex::build(analyzer, file));
        parse_and_collect_with_declarations(
            file,
            nodes,
            &language,
            declarations,
            |parsed, collector| {
                let resolver = NameResolver::for_file_with_facts(
                    scala,
                    graph.package_by_file.get(file).map(String::as_str),
                    graph
                        .imports_by_file
                        .get(file)
                        .map(Vec::as_slice)
                        .unwrap_or(&[]),
                    &graph.types,
                );
                let factory_returns = collect_factory_return_types(
                    parsed.tree.root_node(),
                    parsed.source.as_str(),
                    &resolver,
                );
                let mut ctx = ScalaScan {
                    scala,
                    source: parsed.source.as_str(),
                    resolver: &resolver,
                    types: &graph.types,
                    factory_returns,
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
    resolver: &'a NameResolver,
    types: &'a ProjectTypes,
    factory_returns: HashMap<String, HashSet<String>>,
    class_ranges: ClassRangeIndex,
    collector: &'a mut EdgeCollector<'b>,
}

impl ScalaScan<'_, '_> {
    /// The fqn of the smallest class/object declaration containing `byte`.
    fn enclosing_class(&self, byte: usize) -> Option<&str> {
        self.class_ranges.enclosing(byte)
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

fn walk(node: Node<'_>, ctx: &mut ScalaScan<'_, '_>, bindings: &mut LocalInferenceEngine<String>) {
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
    bindings: &mut LocalInferenceEngine<String>,
) -> bool {
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
    bindings: &LocalInferenceEngine<String>,
) {
    match node.kind() {
        // A type reference in any type position: param/return types, `extends`,
        // and the type child of `new Foo()`. Construction is covered here without
        // a separate `instance_expression` case (avoids double counting).
        "type_identifier" => {
            // The qualifier of a `stable_type_identifier` (`pkg.Type`) is resolved
            // via the leaf type, so skip non-leaf qualifier positions.
            if node
                .parent()
                .is_some_and(|parent| parent.kind() == "stable_type_identifier")
                && node
                    .parent()
                    .and_then(|parent| parent.child_by_field_name("name"))
                    != Some(node)
            {
                return;
            }
            if let Some(fqn) = ctx.resolver.resolve(node_text(node, ctx.source)) {
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
                        let call_arity = call_arity_for_reference(field);
                        let targets = ctx
                            .types
                            .method_targets_for_owner_member(&owner, name, call_arity);
                        if targets.is_empty() {
                            let inherited = ctx.types.inherited_method_targets_for_owner_member(
                                ctx.scala, &owner, name, call_arity,
                            );
                            if inherited.is_empty() {
                                for extension in visible_extensions(ctx, name, Some(&owner)) {
                                    ctx.record(extension.fqn, field);
                                }
                            } else {
                                for target in inherited {
                                    ctx.record(target, field);
                                }
                            }
                        } else {
                            for target in targets {
                                ctx.record(target, field);
                            }
                        }
                    } else {
                        let extensions = visible_extensions(ctx, name, None);
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
                    if let Some(owner) = ctx.enclosing_class(function.start_byte()) {
                        let call_arity = call_arity_for_reference(function);
                        let targets = ctx
                            .types
                            .method_targets_for_owner_member(owner, name, call_arity);
                        if targets.is_empty() {
                            for target in ctx.types.inherited_method_targets_for_owner_member(
                                ctx.scala, owner, name, call_arity,
                            ) {
                                ctx.record(target, function);
                            }
                        } else {
                            for target in targets {
                                ctx.record(target, function);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        "identifier" => {
            let name = node_text(node, ctx.source);
            if name.is_empty()
                || bindings.is_shadowed(name)
                || has_ancestor_kind(node, "import_declaration")
                || is_declaration_name(node)
            {
                return;
            }
            if let Some(fqn) = ctx.resolver.resolve_member(name) {
                ctx.record(fqn, node);
            }
        }
        _ => {}
    }
}

/// The fqn of a receiver expression's type, for the shapes that resolve without
/// return-type inference.
fn receiver_type_fqn(
    receiver: Node<'_>,
    ctx: &ScalaScan<'_, '_>,
    bindings: &LocalInferenceEngine<String>,
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
                .or_else(|| {
                    (!bindings.is_shadowed(name)).then(|| {
                        ctx.resolver.resolve_member(name).and_then(|method| {
                            ctx.factory_returns
                                .get(&method)
                                .and_then(single_factory_return)
                                .or_else(|| ctx.types.member_return_type(&method))
                        })
                    })?
                })
                .or_else(|| {
                    (!bindings.is_shadowed(name))
                        .then(|| ctx.resolver.resolve(name))
                        .flatten()
                })
        }
        kind => scala_literal_type_name(kind).map(str::to_string),
    }
}

fn seed_declaration(
    node: Node<'_>,
    ctx: &ScalaScan<'_, '_>,
    bindings: &mut LocalInferenceEngine<String>,
) {
    match node.kind() {
        "class_definition" | "object_definition" | "trait_definition" | "enum_definition" => {
            seed_class_parameters(node, ctx, bindings)
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
    bindings: &mut LocalInferenceEngine<String>,
) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() != "parameters" {
            continue;
        }
        let mut inner = child.walk();
        for parameter in child.named_children(&mut inner) {
            if parameter.kind() == "parameter" {
                seed_parameter(parameter, ctx, bindings);
            }
        }
    }
}

fn seed_class_parameters(
    node: Node<'_>,
    ctx: &ScalaScan<'_, '_>,
    bindings: &mut LocalInferenceEngine<String>,
) {
    let Some(parameters) = node.child_by_field_name("class_parameters") else {
        return;
    };
    let mut cursor = parameters.walk();
    for parameter in parameters.named_children(&mut cursor) {
        if parameter.kind() == "class_parameter" {
            seed_parameter(parameter, ctx, bindings);
        }
    }
}

fn seed_parameter(
    parameter: Node<'_>,
    ctx: &ScalaScan<'_, '_>,
    bindings: &mut LocalInferenceEngine<String>,
) {
    let Some(name) = parameter.child_by_field_name("name") else {
        return;
    };
    let binding_name = node_text(name, ctx.source).trim();
    if binding_name.is_empty() {
        return;
    }
    let resolved = parameter.child_by_field_name("type").and_then(|type_node| {
        resolve_receiver_type(ctx.resolver, node_text(type_node, ctx.source))
    });
    seed_typed(binding_name, resolved, bindings);
}

fn seed_value_definition(
    node: Node<'_>,
    ctx: &ScalaScan<'_, '_>,
    bindings: &mut LocalInferenceEngine<String>,
) {
    // Prefer the declared type; otherwise infer from a `new Foo()` initializer
    // or a call with a declared factory return.
    let resolved = node
        .child_by_field_name("type")
        .and_then(|type_node| resolve_receiver_type(ctx.resolver, node_text(type_node, ctx.source)))
        .or_else(|| {
            node.child_by_field_name("value")
                .and_then(|value| constructed_type(value, ctx))
        })
        .or_else(|| {
            node.child_by_field_name("value")
                .and_then(|value| call_result_type(value, ctx, bindings))
        });
    let Some(pattern) = node.child_by_field_name("pattern") else {
        return;
    };
    for name in pattern_names(pattern, ctx.source) {
        seed_typed(name, resolved.clone(), bindings);
    }
}

/// The fqn of the type constructed by a `new Foo()` value expression.
fn constructed_type(node: Node<'_>, ctx: &ScalaScan<'_, '_>) -> Option<String> {
    if node.kind() == "instance_expression" {
        let mut cursor = node.walk();
        return node
            .named_children(&mut cursor)
            .find(|child| child.kind() == "type_identifier" || child.kind() == "generic_type")
            .and_then(|type_node| ctx.resolver.resolve(node_text(type_node, ctx.source)));
    }
    None
}

fn call_result_type(
    node: Node<'_>,
    ctx: &ScalaScan<'_, '_>,
    bindings: &LocalInferenceEngine<String>,
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
            let call_arity = call_arity_for_reference(field);
            let method_fqn = format!("{owner}.{method}");
            if let Some(returns) = ctx.factory_returns.get(&method_fqn) {
                return single_factory_return(returns);
            }
            ctx.types
                .member_return_type_for_owner_member(&owner, method, call_arity)
        }
        "identifier" => {
            let method = node_text(function, ctx.source);
            let owner = ctx.enclosing_class(function.start_byte())?;
            let call_arity = call_arity_for_reference(function);
            let method_fqn = format!("{owner}.{method}");
            if let Some(returns) = ctx.factory_returns.get(&method_fqn) {
                return single_factory_return(returns);
            }
            ctx.types
                .member_return_type_for_owner_member(owner, method, call_arity)
        }
        _ => None,
    }
}

fn single_factory_return(returns: &HashSet<String>) -> Option<String> {
    let mut iter = returns.iter();
    let first = iter.next()?;
    iter.next().is_none().then(|| first.clone())
}

fn collect_factory_return_types(
    root: Node<'_>,
    source: &str,
    resolver: &NameResolver,
) -> HashMap<String, HashSet<String>> {
    let mut returns: HashMap<String, HashSet<String>> = HashMap::default();
    let mut stack = vec![(root, None::<String>)];
    while let Some((node, owner)) = stack.pop() {
        match node.kind() {
            "class_definition" | "object_definition" | "trait_definition" | "enum_definition" => {
                let next_owner = node
                    .child_by_field_name("name")
                    .and_then(|name| resolver.resolve(node_text(name, source)));
                push_children_with_owner(node, next_owner, &mut stack);
            }
            "function_definition" => {
                if let Some(owner) = owner.as_ref()
                    && let Some(name) = node.child_by_field_name("name")
                    && let Some(return_type) = node.child_by_field_name("return_type")
                    && let Some(return_fqn) =
                        resolve_receiver_type(resolver, node_text(return_type, source))
                {
                    returns
                        .entry(format!("{owner}.{}", node_text(name, source)))
                        .or_default()
                        .insert(return_fqn);
                }
            }
            _ => push_children_with_owner(node, owner, &mut stack),
        }
    }
    returns
}

fn push_children_with_owner<'tree>(
    node: Node<'tree>,
    owner: Option<String>,
    stack: &mut Vec<(Node<'tree>, Option<String>)>,
) {
    for index in (0..node.named_child_count()).rev() {
        if let Some(child) = node.named_child(index) {
            stack.push((child, owner.clone()));
        }
    }
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

fn seed_typed(name: &str, resolved: Option<String>, bindings: &mut LocalInferenceEngine<String>) {
    match resolved {
        Some(fqn) => bindings.seed_symbol(name.to_string(), fqn),
        None => bindings.declare_shadow(name.to_string()),
    }
}

fn resolve_receiver_type(resolver: &NameResolver, type_text: &str) -> Option<String> {
    resolver
        .resolve(type_text)
        .or_else(|| scala_builtin_type_name(type_text).map(str::to_string))
}

fn visible_extensions(
    ctx: &ScalaScan<'_, '_>,
    member: &str,
    receiver_owner: Option<&str>,
) -> Vec<ExtensionMethod> {
    let mut matches = Vec::new();
    for method in ctx
        .resolver
        .visible_extension_methods(ctx.scala, ctx.types, member)
    {
        if extension_receiver_matches(ctx.resolver, &method, receiver_owner) {
            matches.push(method);
        }
    }
    matches.sort_by(|left, right| left.fqn.cmp(&right.fqn));
    matches.dedup_by(|left, right| left.fqn == right.fqn);
    matches
}

fn extension_receiver_matches(
    resolver: &NameResolver,
    method: &ExtensionMethod,
    receiver_owner: Option<&str>,
) -> bool {
    scala_extension_receiver_matches_resolved(
        method.receiver_type.as_deref(),
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

fn is_declaration_name(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        matches!(
            parent.kind(),
            "class_definition"
                | "object_definition"
                | "trait_definition"
                | "enum_definition"
                | "function_definition"
                | "function_declaration"
                | "parameter"
                | "class_parameter"
        ) && parent.child_by_field_name("name") == Some(node)
    })
}
