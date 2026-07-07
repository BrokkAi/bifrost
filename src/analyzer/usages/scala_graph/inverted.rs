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
    package_name_of, resolved_extension_receiver_type, scala_builtin_type_name, scala_display_name,
    scala_extension_receiver_matches_resolved, scala_literal_type_name, scala_normalized_fq_name,
};
use super::shared::ScalaEdgeGraph;
use super::syntax::{call_arity_for_reference, node_text, parenthesized_arity, scala_import_path};
use crate::analyzer::CodeUnit;
use crate::analyzer::usages::common::{TreeWalkAction, walk_tree_iterative};
use crate::analyzer::usages::inverted_edges::{
    ClassRangeIndex, EdgeCollector, UsageEdges, build_edges, first_precise, parse_and_collect,
};
use crate::analyzer::usages::local_inference::{LocalInferenceConfig, LocalInferenceEngine};
use crate::analyzer::{
    IAnalyzer, ImportAnalysisProvider, ProjectFile, ScalaAnalyzer, TypeHierarchyProvider,
};
use crate::hash::{HashMap, HashSet};
use tree_sitter::Node;

/// Every class/object/trait/enum the project declares, indexed for the per-file
/// name->fqn rebuild. Built once and shared across all files' scans.
pub(crate) struct ProjectTypes {
    /// `(package, source_name) -> fqn` — a type reachable by simple name from a
    /// file in the same package (or via a wildcard import of that package).
    by_package: HashMap<(String, String), String>,
    /// `normalized_fqn -> fqn` — resolve a non-wildcard import path (whose text is
    /// `$`-free) to the analyzer's own `$`-encoded fqn.
    by_normalized_fqn: HashMap<String, String>,
    /// `normalized_member_fqn -> member_fqn` for `import Owner.member` paths.
    by_normalized_member_fqn: HashMap<String, String>,
    methods_by_owner_member: HashMap<(String, String), Vec<MemberMethod>>,
    member_return_types: HashMap<String, String>,
    extension_methods_by_name: HashMap<String, Vec<ExtensionMethod>>,
}

impl ProjectTypes {
    pub(crate) fn build(scala: &ScalaAnalyzer) -> Self {
        let mut by_package = HashMap::default();
        let mut by_normalized_fqn = HashMap::default();
        let mut by_normalized_member_fqn = HashMap::default();
        let mut methods_by_owner_member: HashMap<(String, String), Vec<MemberMethod>> =
            HashMap::default();
        let mut member_return_types = HashMap::default();
        let mut extension_methods_by_name: HashMap<String, Vec<ExtensionMethod>> =
            HashMap::default();
        for unit in scala.all_declarations().filter(|unit| unit.is_class()) {
            let fqn = unit.fq_name();
            insert_package_type(
                &mut by_package,
                unit.package_name().to_string(),
                scala_display_name(unit),
                fqn.clone(),
            );
            by_normalized_fqn.insert(scala_normalized_fq_name(&fqn), fqn);
        }
        for unit in scala
            .all_declarations()
            .filter(|unit| unit.is_function() || unit.is_field())
        {
            let fqn = unit.fq_name();
            by_normalized_member_fqn.insert(scala_normalized_fq_name(&fqn), fqn.clone());
            let signature = unit
                .signature()
                .or_else(|| scala.signatures(unit).first().map(String::as_str));
            if let Some(return_type) = signature.and_then(signature_return_type)
                && let Some(return_fqn) =
                    return_type_fqn(return_type, unit.package_name(), &by_package)
            {
                member_return_types.insert(fqn.clone(), return_fqn);
            }
            if unit.is_function()
                && let Some(owner_fqn) = owner_fqn(unit)
            {
                methods_by_owner_member
                    .entry((owner_fqn.clone(), unit.identifier().to_string()))
                    .or_default()
                    .push(MemberMethod {
                        fqn: fqn.clone(),
                        owner_fqn,
                        name: unit.identifier().to_string(),
                        arity: signature.and_then(member_signature_arity),
                    });
            }
            if signature.is_some_and(|signature| signature.starts_with("extension "))
                && let Some(owner_fqn) = owner_fqn(unit)
            {
                extension_methods_by_name
                    .entry(unit.identifier().to_string())
                    .or_default()
                    .push(ExtensionMethod {
                        fqn,
                        owner_fqn,
                        receiver_type: signature.and_then(|signature| {
                            resolved_extension_receiver_type(scala, unit, signature)
                        }),
                    });
            }
        }
        Self {
            by_package,
            by_normalized_fqn,
            by_normalized_member_fqn,
            methods_by_owner_member,
            member_return_types,
            extension_methods_by_name,
        }
    }

    fn method_targets_for_owner_member(
        &self,
        owner_fqn: &str,
        member: &str,
        call_arity: Option<usize>,
    ) -> Vec<String> {
        let normalized_owner = scala_normalized_fq_name(owner_fqn);
        if let Some(methods) = self
            .methods_by_owner_member
            .get(&(owner_fqn.to_string(), member.to_string()))
        {
            return methods
                .iter()
                .filter(|method| method_call_arity_matches(method.arity, call_arity))
                .map(|method| method.fqn.clone())
                .collect();
        }
        if let Some(methods) = self
            .methods_by_owner_member
            .iter()
            .find(|((candidate_owner, candidate_member), _)| {
                scala_normalized_fq_name(candidate_owner) == normalized_owner
                    && candidate_member == member
            })
            .map(|(_, methods)| methods)
        {
            return methods
                .iter()
                .filter(|method| method_call_arity_matches(method.arity, call_arity))
                .map(|method| method.fqn.clone())
                .collect();
        }
        Vec::new()
    }

    fn inherited_method_targets_for_owner_member(
        &self,
        scala: &ScalaAnalyzer,
        owner_fqn: &str,
        member: &str,
        call_arity: Option<usize>,
    ) -> Vec<String> {
        if let Some(owner) = scala.definitions(owner_fqn).find(|unit| unit.is_class()) {
            for ancestor in scala.get_ancestors(owner) {
                let targets =
                    self.method_targets_for_owner_member(&ancestor.fq_name(), member, call_arity);
                if !targets.is_empty() {
                    return targets;
                }
            }
        }
        Vec::new()
    }

    fn member_return_type(&self, member_fqn: &str) -> Option<String> {
        self.member_return_types.get(member_fqn).cloned()
    }
}

fn insert_package_type(
    by_package: &mut HashMap<(String, String), String>,
    package: String,
    simple: String,
    fqn: String,
) {
    let key = (package, simple);
    if fqn.ends_with('$')
        && by_package
            .get(&key)
            .is_some_and(|existing| !existing.ends_with('$'))
    {
        return;
    }
    by_package.insert(key, fqn);
}

#[derive(Clone)]
pub(crate) struct ExtensionMethod {
    pub(crate) fqn: String,
    pub(crate) owner_fqn: String,
    pub(crate) receiver_type: Option<String>,
}

#[derive(Clone)]
struct MemberMethod {
    fqn: String,
    owner_fqn: String,
    name: String,
    arity: Option<usize>,
}

/// Per-file map from a source-visible type/object name to the analyzer's fqn,
/// mirroring the forward scanner's [`Visibility`](super::resolver).
pub(crate) struct NameResolver {
    names: HashMap<String, String>,
    member_names: HashMap<String, String>,
    visible_extensions: HashMap<String, Vec<ExtensionMethod>>,
}

impl NameResolver {
    pub(crate) fn for_file(
        scala: &ScalaAnalyzer,
        file: &ProjectFile,
        types: &ProjectTypes,
    ) -> Self {
        let mut names = HashMap::default();
        let mut member_names = HashMap::default();
        let mut visible_extensions: HashMap<String, Vec<ExtensionMethod>> = HashMap::default();

        // Types in the file's own package are reachable by simple name.
        if let Some(package) = package_name_of(scala, file) {
            for ((decl_package, simple), fqn) in &types.by_package {
                if *decl_package == package {
                    names.insert(simple.clone(), fqn.clone());
                }
            }
        }
        let file_package = package_name_of(scala, file).unwrap_or_default();

        for import in scala.import_info_of(file) {
            let Some(path) = scala_import_path(import) else {
                continue;
            };
            if import.is_wildcard {
                let package_candidates = import_candidate_paths(&path, &file_package);
                // `import pkg._` exposes every type in `pkg` by simple name.
                for ((decl_package, simple), fqn) in &types.by_package {
                    if package_candidates.contains(decl_package) {
                        names.insert(simple.clone(), fqn.clone());
                    }
                }
                let normalized_paths = import_candidate_normalized_paths(&path, &file_package);
                for methods in types.extension_methods_by_name.values() {
                    for method in methods {
                        if normalized_paths.contains(&scala_normalized_fq_name(&method.owner_fqn)) {
                            visible_extensions
                                .entry(scala_member_name(&method.fqn).to_string())
                                .or_default()
                                .push(method.clone());
                        }
                    }
                }
                continue;
            }
            // `import pkg.Type [as Alias]` binds the (possibly renamed) local name.
            let normalized_paths = import_candidate_normalized_paths(&path, &file_package);
            if let Some(fqn) = normalized_paths
                .iter()
                .find_map(|normalized| types.by_normalized_fqn.get(normalized))
            {
                let local_name = import
                    .identifier
                    .clone()
                    .unwrap_or_else(|| path.rsplit('.').next().unwrap_or(&path).to_string());
                names.insert(local_name, fqn.clone());
                continue;
            }
            if let Some(fqn) = normalized_paths
                .iter()
                .find_map(|normalized| types.by_normalized_member_fqn.get(normalized))
            {
                let local_name = import
                    .identifier
                    .clone()
                    .unwrap_or_else(|| path.rsplit('.').next().unwrap_or(&path).to_string());
                member_names.insert(local_name.clone(), fqn.clone());
                if let Some(methods) = types.extension_methods_by_name.get(scala_member_name(fqn)) {
                    visible_extensions
                        .entry(local_name)
                        .or_default()
                        .extend(methods.iter().filter(|method| method.fqn == *fqn).cloned());
                }
            }
        }

        Self {
            names,
            member_names,
            visible_extensions,
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

    pub(crate) fn visible_extension_methods(&self, member: &str) -> &[ExtensionMethod] {
        self.visible_extensions
            .get(member)
            .map(Vec::as_slice)
            .unwrap_or(&[])
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

pub(super) fn build_method_override_targets(
    scala: &ScalaAnalyzer,
    types: &ProjectTypes,
) -> HashMap<String, Vec<String>> {
    let mut override_targets: HashMap<String, Vec<String>> = HashMap::default();
    for methods in types.methods_by_owner_member.values() {
        for method in methods {
            let Some(owner) = scala
                .definitions(&method.owner_fqn)
                .find(|unit| unit.is_class())
            else {
                continue;
            };
            let mut targets = Vec::new();
            for ancestor in scala.get_ancestors(owner) {
                if !scala.is_scala_trait_declaration(&ancestor) {
                    continue;
                }
                if let Some(ancestor_methods) = types
                    .methods_by_owner_member
                    .get(&(ancestor.fq_name(), method.name.clone()))
                {
                    targets.extend(
                        ancestor_methods
                            .iter()
                            .filter(|ancestor_method| {
                                method_arities_compatible(method, ancestor_method)
                            })
                            .map(|ancestor_method| ancestor_method.fqn.clone()),
                    );
                }
                if !targets.is_empty() {
                    break;
                }
            }
            targets.sort();
            targets.dedup();
            if !targets.is_empty() {
                override_targets.insert(method_key(&method.fqn, method.arity), targets);
            }
        }
    }
    override_targets
}

fn method_arities_compatible(method: &MemberMethod, ancestor: &MemberMethod) -> bool {
    method.arity.is_none() || ancestor.arity.is_none() || method.arity == ancestor.arity
}

fn method_call_arity_matches(method_arity: Option<usize>, call_arity: Option<usize>) -> bool {
    let Some(method_arity) = method_arity else {
        return call_arity.is_none();
    };
    match call_arity {
        Some(call_arity) => call_arity == method_arity,
        None => method_arity == 0,
    }
}

fn method_key(fqn: &str, arity: Option<usize>) -> String {
    match arity {
        Some(arity) => format!("{fqn}#{arity}"),
        None => fqn.to_string(),
    }
}

fn member_signature_arity(signature: &str) -> Option<usize> {
    if let Some(extension_signature) = signature.strip_prefix("extension ") {
        let after_receiver = extension_signature.split_once(')')?.1.trim_start();
        return after_receiver
            .find('(')
            .and_then(|open| parenthesized_arity(&after_receiver[open..]))
            .or(Some(0));
    }
    let open = signature.find('(')?;
    parenthesized_arity(&signature[open..])
}

fn signature_return_type(signature: &str) -> Option<&str> {
    let (_, after_colon) = signature.rsplit_once(':')?;
    let end = after_colon.find(['=', '{']).unwrap_or(after_colon.len());
    let return_type = after_colon[..end].trim();
    (!return_type.is_empty()).then_some(return_type)
}

fn return_type_fqn(
    return_type: &str,
    package_name: &str,
    by_package: &HashMap<(String, String), String>,
) -> Option<String> {
    let base = return_type
        .split(['[', '(', '{', ' '])
        .next()
        .map(str::trim)
        .filter(|name| !name.is_empty())?;
    by_package
        .get(&(package_name.to_string(), base.to_string()))
        .cloned()
        .or_else(|| by_package.values().find(|fqn| *fqn == base).cloned())
}

fn scala_member_name(fqn: &str) -> &str {
    fqn.rsplit('.').next().unwrap_or(fqn)
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
pub(super) fn build_scala_edges<F>(
    analyzer: &dyn IAnalyzer,
    graph: &ScalaEdgeGraph<'_>,
    nodes: &HashSet<String>,
    keep_file: F,
) -> UsageEdges
where
    F: Fn(&ProjectFile) -> bool + Sync,
{
    let language = tree_sitter_scala::LANGUAGE.into();
    build_edges(&graph.files, keep_file, |file| {
        parse_and_collect(analyzer, file, nodes, &language, |parsed, collector| {
            let resolver = NameResolver::for_file(graph.scala, file, &graph.types);
            let factory_returns = collect_factory_return_types(
                parsed.tree.root_node(),
                parsed.source.as_str(),
                &resolver,
            );
            let mut ctx = ScalaScan {
                scala: graph.scala,
                source: parsed.source.as_str(),
                resolver: &resolver,
                types: &graph.types,
                override_targets_by_method_fqn: &graph.override_targets_by_method_fqn,
                factory_returns,
                class_ranges: ClassRangeIndex::build(analyzer, file),
                collector,
            };
            let mut bindings = LocalInferenceEngine::new(LocalInferenceConfig::default());
            walk(parsed.tree.root_node(), &mut ctx, &mut bindings);
        })
    })
}

struct ScalaScan<'a, 'b> {
    scala: &'a ScalaAnalyzer,
    source: &'a str,
    resolver: &'a NameResolver,
    types: &'a ProjectTypes,
    override_targets_by_method_fqn: &'a HashMap<String, Vec<String>>,
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
        self.collector
            .record(callee, node.start_byte(), node.end_byte());
    }

    fn record_with_caller(&mut self, caller: String, callee: String, node: Node<'_>) {
        self.collector
            .record_with_caller(caller, callee, node.start_byte(), node.end_byte());
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
                                for extension in
                                    visible_extensions(ctx.resolver, name, Some(&owner))
                                {
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
                        for extension in visible_extensions(ctx.resolver, name, None) {
                            ctx.record(extension.fqn, field);
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
    let Some(targets) = ctx.override_targets_by_method_fqn.get(&method_key(
        &method_fqn,
        function_definition_arity(node, ctx.source),
    )) else {
        return;
    };
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
            ctx.factory_returns
                .get(&format!("{owner}.{method}"))
                .and_then(single_factory_return)
        }
        "identifier" => {
            let method = node_text(function, ctx.source);
            let owner = ctx.enclosing_class(function.start_byte())?;
            ctx.factory_returns
                .get(&format!("{owner}.{method}"))
                .and_then(single_factory_return)
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
    resolver: &NameResolver,
    member: &str,
    receiver_owner: Option<&str>,
) -> Vec<ExtensionMethod> {
    let mut matches = Vec::new();
    for method in resolver.visible_extension_methods(member) {
        if extension_receiver_matches(resolver, method, receiver_owner) {
            matches.push(method.clone());
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
