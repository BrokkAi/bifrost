//! Python's forward, per-target usage scan: the scoped import closure, the
//! per-file walk that proves a reference, and the receiver-type facts both this
//! and the inverted walk resolve through.

use crate::graph::PythonGraphSource;
use crate::graph::hits::{
    record_hit, record_import_hit, record_self_receiver_hit, record_unproven_hit,
};
use crate::graph::resolver::{
    annotation_reference_candidates, member_name, normalized_receiver_type,
    receiver_annotation_matches_target, resolve_constructor_types, resolve_receiver_type,
    target_owner_code_unit, top_level_identifier,
};
use crate::graph_support::{PythonSource, PythonUsageSource};
use crate::imports::resolve_fqn_candidates;
use crate::usage_index::{
    ModuleBindingEvent, ModuleBindingEventKind, ModuleBindingTimeline, PythonScopeFacts,
    usage_matching_edges, usage_module_binding_timeline, usage_resolve_module_files,
    usage_scope_facts,
};
use brokk_bifrost_core::analyzer::usages::local_inference::{
    LocalBindingsSnapshot, LocalInferenceConfig, LocalInferenceEngine, SymbolResolution,
};
use brokk_bifrost_core::analyzer::usages::model::{ImportKind, UsageHit};
use brokk_bifrost_core::analyzer::usages::{ImportEdge, ImportEdgeKind};
use brokk_bifrost_core::analyzer::{CodeUnit, CodeUnitIndex, ProjectFile, Range};
use brokk_bifrost_core::cancellation::CancellationToken;
use brokk_bifrost_core::hash::{HashMap, HashSet};
use brokk_bifrost_core::text_utils::compute_line_starts;
use rayon::prelude::*;
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use tree_sitter::{Node, Parser, Tree};

pub struct ParsedFile {
    pub source: Arc<String>,
    pub tree: Tree,
}

pub struct PythonProjectGraph {
    parsed: HashMap<ProjectFile, ParsedFile>,
}

impl PythonProjectGraph {
    pub fn scan_files(
        &self,
        candidate_files: &HashSet<ProjectFile>,
        target_file: &ProjectFile,
    ) -> HashSet<ProjectFile> {
        candidate_files
            .iter()
            .cloned()
            .chain(std::iter::once(target_file.clone()))
            .collect()
    }
}

pub fn build_python_graph(
    candidate_files: &HashSet<ProjectFile>,
    target_file: &ProjectFile,
    cancellation: Option<&CancellationToken>,
) -> PythonProjectGraph {
    let parser_language = tree_sitter_python::LANGUAGE.into();
    let files: HashSet<ProjectFile> = candidate_files
        .iter()
        .cloned()
        .chain(std::iter::once(target_file.clone()))
        .collect();
    let mut parsed = HashMap::default();

    for file in files {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            break;
        }
        let Ok(source) = file.read_to_string() else {
            continue;
        };
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            break;
        }
        if source.is_empty() {
            continue;
        }
        let mut parser = Parser::new();
        if parser.set_language(&parser_language).is_err() {
            continue;
        }
        let Some(tree) = parser.parse(source.as_str(), None) else {
            continue;
        };
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            break;
        }
        parsed.insert(
            file,
            ParsedFile {
                source: Arc::new(source),
                tree,
            },
        );
    }

    PythonProjectGraph { parsed }
}

pub fn scan_files_for_seeds(
    graph: &PythonGraphSource<'_>,
    python: &dyn PythonUsageSource,
    project_graph: &PythonProjectGraph,
    files: &HashSet<ProjectFile>,
    target: &CodeUnit,
    seeds: &BTreeSet<(ProjectFile, String)>,
    cancellation: Option<&CancellationToken>,
) -> ScanResult {
    let collected: Mutex<BTreeSet<UsageHit>> = Mutex::new(BTreeSet::new());
    let unproven_collected: Mutex<BTreeSet<UsageHit>> = Mutex::new(BTreeSet::new());
    let target_short = top_level_identifier(graph.index, target);
    let target_member = member_name(graph.index, target);
    let target_owner = target_owner_code_unit(graph.index, target);
    // A same-file best-effort for unresolvable receivers is only safe when the
    // member name is unambiguous in the target's file (exactly one class there
    // declares it), so `recv.member` can only mean the target.
    let member_unique_in_target_file = target_member.as_deref().is_some_and(|member| {
        let owners: HashSet<CodeUnit> = graph
            .index
            .declarations(target.source())
            .into_iter()
            .filter(|decl| {
                decl.identifier() == member && target_owner_code_unit(graph.index, decl).is_some()
            })
            .filter_map(|decl| target_owner_code_unit(graph.index, &decl))
            .collect();
        owners.len() == 1
    });
    let files_vec: Vec<&ProjectFile> = files.iter().collect();
    let parser_language = tree_sitter_python::LANGUAGE.into();

    files_vec.par_iter().for_each(|file| {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return;
        }
        let owned_source: Option<Arc<String>>;
        let owned_tree: Option<Tree>;
        let (source_str, tree_ref) = if let Some(parsed) = project_graph.parsed.get(*file) {
            (parsed.source.as_str(), &parsed.tree)
        } else {
            let Ok(source) = file.read_to_string() else {
                return;
            };
            if source.is_empty() {
                return;
            }
            let mut parser = Parser::new();
            if parser.set_language(&parser_language).is_err() {
                return;
            }
            let Some(tree) = parser.parse(source.as_str(), None) else {
                return;
            };
            owned_source = Some(Arc::new(source));
            owned_tree = Some(tree);
            (
                owned_source.as_deref().unwrap().as_str(),
                owned_tree.as_ref().unwrap(),
            )
        };
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return;
        }

        let edges = {
            let _scope = brokk_bifrost_core::profiling::scope("python_graph::matching_edges");
            usage_matching_edges(python, file, seeds)
        };
        // This is an AST-name gate, not a source-text resolver. Every usage
        // accepted by the later structural walk has a matching identifier or
        // can occur inside an annotation string. Skip files that lack both
        // before building their scope facts and performing that expensive walk.
        if !file_may_reference_target(
            tree_ref.root_node(),
            source_str,
            target,
            target_short.as_str(),
            target_member.as_deref(),
            &edges,
        ) {
            return;
        }
        let module_bindings = {
            let _scope =
                brokk_bifrost_core::profiling::scope("python_graph::module_binding_timeline");
            let raw_module_bindings = usage_module_binding_timeline(python, file, || {
                collect_module_binding_timeline(tree_ref.root_node(), source_str)
            });
            classify_module_binding_timeline(
                python,
                file,
                raw_module_bindings.as_ref(),
                seeds,
                &edges,
            )
        };
        let target_self_file = *file == target.source();
        let scope_facts = {
            let _scope = brokk_bifrost_core::profiling::scope("python_graph::scope_facts");
            usage_scope_facts(python, file, || {
                collect_scope_facts_from_parsed_source(
                    graph,
                    python,
                    file,
                    source_str,
                    tree_ref.root_node(),
                )
            })
        };
        let scope_range_index = build_scope_range_index(graph, scope_facts.as_ref());

        let mut local_hits = BTreeSet::new();
        let mut local_unproven_hits = BTreeSet::new();
        let line_starts = compute_line_starts(source_str);

        let mut scan_ctx = ScanCtx {
            python,
            file,
            source: source_str,
            line_starts: &line_starts,
            graph,
            target,
            target_short: &target_short,
            target_member: target_member.as_deref(),
            target_owner: target_owner.clone(),
            target_is_module: target.is_module(),
            target_source: target.source(),
            seeds,
            edges: &edges,
            target_self_file,
            member_best_effort_unique: target_self_file && member_unique_in_target_file,
            module_bindings: &module_bindings,
            scope_facts: scope_facts.as_ref(),
            scope_range_index: &scope_range_index,
            hits: &mut local_hits,
            unproven_hits: &mut local_unproven_hits,
        };

        {
            let _scope = brokk_bifrost_core::profiling::scope("python_graph::scan_tree");
            scan_node(tree_ref.root_node(), &mut scan_ctx);
        }

        if !local_hits.is_empty() {
            let mut sink = collected
                .lock()
                .expect("usage hit collector mutex poisoned");
            sink.extend(local_hits);
        }
        if !local_unproven_hits.is_empty() {
            let mut sink = unproven_collected
                .lock()
                .expect("usage unproven hit collector mutex poisoned");
            sink.extend(local_unproven_hits);
        }
    });

    ScanResult {
        hits: collected
            .into_inner()
            .expect("usage hit collector mutex poisoned"),
        unproven_hits: unproven_collected
            .into_inner()
            .expect("usage unproven hit collector mutex poisoned"),
    }
}

fn file_may_reference_target(
    root: Node<'_>,
    source: &str,
    target: &CodeUnit,
    target_short: &str,
    target_member: Option<&str>,
    edges: &[ImportEdge],
) -> bool {
    if target.is_module() {
        return true;
    }

    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "string" {
            // Annotation strings can use an FQN or a re-export alias that is
            // not an exact identifier node. Keep them for the structured
            // annotation resolver below.
            return true;
        }
        if node.kind() == "identifier" {
            let name = slice(node, source);
            if name == target_short
                || target_member.is_some_and(|member| name == member)
                || edges.iter().any(|edge| edge.local_name == name)
            {
                return true;
            }
        }

        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    false
}

pub struct ScanResult {
    pub hits: BTreeSet<UsageHit>,
    pub unproven_hits: BTreeSet<UsageHit>,
}

pub struct ScanCtx<'a> {
    python: &'a dyn PythonUsageSource,
    pub file: &'a ProjectFile,
    pub source: &'a str,
    pub line_starts: &'a [usize],
    pub graph: &'a PythonGraphSource<'a>,
    target: &'a CodeUnit,
    target_short: &'a str,
    target_member: Option<&'a str>,
    target_owner: Option<CodeUnit>,
    target_is_module: bool,
    target_source: &'a ProjectFile,
    seeds: &'a BTreeSet<(ProjectFile, String)>,
    edges: &'a [ImportEdge],
    target_self_file: bool,
    /// True when a same-file best-effort is justified for an unresolvable
    /// receiver: the target is a member, its owner is in this file, and exactly
    /// one class in this file declares that member name (so `recv.member` with
    /// an un-inferrable `recv` unambiguously means the target). Cross-file
    /// untyped receivers stay conservative.
    member_best_effort_unique: bool,
    module_bindings: &'a HashMap<String, Vec<ClassifiedModuleBindingEvent>>,
    scope_facts: &'a HashMap<CodeUnit, LocalBindingsSnapshot<String>>,
    scope_range_index: &'a [ScopeRangeEntry],
    pub hits: &'a mut BTreeSet<UsageHit>,
    pub unproven_hits: &'a mut BTreeSet<UsageHit>,
}

struct ScopeRangeEntry {
    range: Range,
    scope: CodeUnit,
    prefix_max_end: usize,
}

fn build_scope_range_index(
    graph: &PythonGraphSource<'_>,
    scope_facts: &HashMap<CodeUnit, LocalBindingsSnapshot<String>>,
) -> Vec<ScopeRangeEntry> {
    let mut entries = scope_facts
        .keys()
        .flat_map(|scope| {
            graph
                .index
                .ranges(scope)
                .into_iter()
                .map(|range| ScopeRangeEntry {
                    range,
                    scope: scope.clone(),
                    prefix_max_end: 0,
                })
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| {
        left.range
            .start_byte
            .cmp(&right.range.start_byte)
            .then_with(|| right.range.end_byte.cmp(&left.range.end_byte))
            .then_with(|| left.scope.cmp(&right.scope))
    });
    let mut max_end = 0;
    for entry in &mut entries {
        max_end = max_end.max(entry.range.end_byte);
        entry.prefix_max_end = max_end;
    }
    entries
}

fn indexed_scope_entry<'entry, 'facts>(
    scope_range_index: &'entry [ScopeRangeEntry],
    scope_facts: &'facts HashMap<CodeUnit, LocalBindingsSnapshot<String>>,
    node: Node<'_>,
) -> Option<(&'entry CodeUnit, &'facts LocalBindingsSnapshot<String>)> {
    let mut cursor =
        scope_range_index.partition_point(|entry| entry.range.start_byte <= node.start_byte());
    while cursor > 0 {
        cursor -= 1;
        let entry = &scope_range_index[cursor];
        if entry.prefix_max_end < node.end_byte() {
            return None;
        }
        if entry.range.end_byte >= node.end_byte() {
            return scope_facts
                .get(&entry.scope)
                .map(|facts| (&entry.scope, facts));
        }
    }
    None
}

/// The per-function receiver-type facts enclosing `node`, if any. Shared by the
/// forward scan ([`ScanCtx`]) and the inverted builder (`PyScan`) so the two
/// paths resolve a receiver's scope through one place.
pub fn enclosing_scope_facts<'a>(
    index: &dyn CodeUnitIndex,
    file: &ProjectFile,
    scope_facts: &'a HashMap<CodeUnit, LocalBindingsSnapshot<String>>,
    node: Node<'_>,
) -> Option<&'a LocalBindingsSnapshot<String>> {
    let range = Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: 0,
        end_line: 0,
    };
    let enclosing = index.enclosing_code_unit(file, &range)?;
    scope_facts.get(&enclosing)
}

impl ScanCtx<'_> {
    fn scope_entry_for_node(
        &self,
        node: Node<'_>,
    ) -> Option<(&CodeUnit, &LocalBindingsSnapshot<String>)> {
        indexed_scope_entry(self.scope_range_index, self.scope_facts, node)
    }

    fn scope_facts_for_node(&self, node: Node<'_>) -> Option<&LocalBindingsSnapshot<String>> {
        self.scope_entry_for_node(node).map(|(_, facts)| facts)
    }

    fn binds_target(&self, ident: &str, node: Node<'_>) -> bool {
        let scope_entry = self.scope_entry_for_node(node);
        if self.target_self_file
            && ident == self.target_short
            && scope_entry
                .is_none_or(|(scope, facts)| scope.is_module() || !facts.is_shadowed(ident))
        {
            return true;
        }
        if scope_entry.is_some_and(|(scope, facts)| !scope.is_module() && facts.is_shadowed(ident))
        {
            return false;
        }
        self.module_binding_targets_query(ident, node)
    }

    fn receiver_binds_target(&self, expr: &str, node: Node<'_>) -> bool {
        if self.binds_target(expr, node) {
            return true;
        }

        if self.target_member.is_some() && self.import_edge_visible_for(expr, node) {
            return true;
        }

        // `self`/`cls` is implicitly typed as the enclosing class, so a same-file
        // `self.member` access is a usage of that class's member even though the
        // receiver is never assigned a type the way a local or parameter is.
        if matches!(expr, "self" | "cls") && self.self_receiver_matches_target(node) {
            return true;
        }

        match enclosing_runtime_parameter_type(expr, node, self.source) {
            EnclosingParameterType::Typed(raw_type) => {
                return self.receiver_type_matches_target(&raw_type);
            }
            EnclosingParameterType::Untyped => return false,
            EnclosingParameterType::NotDeclared => {}
        }

        let Some(scope_facts) = self.scope_facts_for_node(node) else {
            return false;
        };
        let resolution = scope_facts.resolution_for(expr);
        let Some(raw_type) = resolution
            .as_precise()
            .and_then(|targets| targets.iter().next())
        else {
            return false;
        };
        self.receiver_type_matches_target(raw_type)
    }

    /// Whether `node` is evaluated in the target member owner's class namespace.
    /// This includes class-level field initializers and the decorators,
    /// annotations, and defaults of a method declaration. The method body itself
    /// executes later with ordinary function scoping, where a bare member name
    /// does not reach the class namespace.
    fn node_directly_in_owner_class_body(&self, node: Node<'_>) -> bool {
        let Some(target_owner) = self.target_owner.as_ref() else {
            return false;
        };
        let range = Range {
            start_byte: node.start_byte(),
            end_byte: node.end_byte(),
            start_line: 0,
            end_line: 0,
        };
        let Some(enclosing) = self.graph.index.enclosing_code_unit(self.file, &range) else {
            return false;
        };
        if &enclosing == target_owner {
            return true;
        }
        if enclosing.is_function() {
            return target_owner_code_unit(self.graph.index, &enclosing).as_ref()
                == Some(target_owner)
                && function_declaration_expression_is_class_scoped(node);
        }
        target_owner_code_unit(self.graph.index, &enclosing).as_ref() == Some(target_owner)
    }

    /// Whether `expr`'s type is genuinely un-inferrable in `node`'s scope (an
    /// unseeded receiver such as an unannotated parameter), as opposed to a
    /// receiver we resolved to some specific — possibly different — type.
    fn receiver_type_is_unknown(&self, expr: &str, node: Node<'_>) -> bool {
        match enclosing_runtime_parameter_type(expr, node, self.source) {
            EnclosingParameterType::Typed(_) => return false,
            EnclosingParameterType::Untyped => return true,
            EnclosingParameterType::NotDeclared => {}
        }
        match self.scope_facts_for_node(node) {
            Some(facts) => facts.resolution_for(expr).is_unknown(),
            None => true,
        }
    }

    fn import_edge_visible_for(&self, ident: &str, node: Node<'_>) -> bool {
        if let Some(scope_facts) = self.scope_facts_for_node(node)
            && scope_facts.is_shadowed(ident)
        {
            return false;
        }
        self.module_binding_targets_query(ident, node)
    }

    fn module_binding_targets_query(&self, ident: &str, node: Node<'_>) -> bool {
        self.module_binding_matches_query(ident, node, true, |kind| {
            kind != ModuleBindingKind::Other
        })
    }

    fn module_binding_targets_symbol(&self, ident: &str, node: Node<'_>) -> bool {
        let unclassified_named_import = self.edges.iter().any(|edge| {
            edge.local_name == ident && !matches!(edge.kind, ImportEdgeKind::Namespace)
        });
        self.module_binding_matches_query(ident, node, unclassified_named_import, |kind| {
            kind == ModuleBindingKind::TargetSymbolImport
        })
    }

    fn module_binding_matches_query(
        &self,
        ident: &str,
        node: Node<'_>,
        unclassified: bool,
        matches: impl Fn(ModuleBindingKind) -> bool,
    ) -> bool {
        if !self.edges.iter().any(|edge| edge.local_name == ident) {
            return false;
        }
        let Some(events) = self.module_bindings.get(ident) else {
            return unclassified;
        };
        let cutoff = if reference_is_deferred_function_body(node) {
            usize::MAX
        } else {
            node.start_byte()
        };
        let visible: Vec<_> = events
            .iter()
            .filter(|event| event.visible_from <= cutoff)
            .collect();
        let start = visible
            .iter()
            .rposition(|event| !event.conditional)
            .unwrap_or(0);
        visible[start..].iter().any(|event| matches(event.kind))
    }

    /// Whether the class enclosing `node` is the target member's owner (or a
    /// subclass of it, for inherited members). Used to resolve `self`/`cls`
    /// receivers, whose type is the lexically enclosing class.
    fn self_receiver_matches_target(&self, node: Node<'_>) -> bool {
        let Some(target_owner) = self.target_owner.as_ref() else {
            return false;
        };
        let range = Range {
            start_byte: node.start_byte(),
            end_byte: node.end_byte(),
            start_line: 0,
            end_line: 0,
        };
        let Some(enclosing) = self.graph.index.enclosing_code_unit(self.file, &range) else {
            return false;
        };
        let enclosing_class = if enclosing.is_class() {
            enclosing
        } else {
            match target_owner_code_unit(self.graph.index, &enclosing) {
                Some(class) => class,
                None => return false,
            }
        };
        if &enclosing_class == target_owner {
            return true;
        }
        self.graph
            .hierarchy
            .map(|provider| provider.get_ancestors(&enclosing_class))
            .unwrap_or_default()
            .into_iter()
            .any(|ancestor| ancestor == *target_owner)
    }

    fn receiver_type_matches_target(&self, raw_type: &str) -> bool {
        if receiver_annotation_matches_target(
            raw_type,
            self.edges,
            self.target_short,
            self.target_self_file,
        ) {
            return true;
        }

        let Some(target_owner) = self.target_owner.as_ref() else {
            return false;
        };
        let Some(receiver_type) = resolve_receiver_type(
            self.graph,
            self.python,
            self.file,
            raw_type,
            self.target_self_file,
        ) else {
            return false;
        };
        if &receiver_type == target_owner {
            return true;
        }
        self.graph
            .hierarchy
            .map(|provider| provider.get_ancestors(&receiver_type))
            .unwrap_or_default()
            .into_iter()
            .any(|ancestor| ancestor == *target_owner)
    }
}

fn function_declaration_expression_is_class_scoped(node: Node<'_>) -> bool {
    let site_start = node.start_byte();
    let site_end = node.end_byte();
    let mut current = node;
    while let Some(parent) = current.parent() {
        if parent.kind() == "function_definition" {
            return parent.child_by_field_name("body").is_none_or(|body| {
                !(body.start_byte() <= site_start && site_end <= body.end_byte())
            });
        }
        if parent.kind() == "decorated_definition" {
            return current.kind() == "decorator";
        }
        if parent.kind() == "class_definition" {
            break;
        }
        current = parent;
    }
    false
}

fn scan_node(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "import_statement" | "import_from_statement" => {
                handle_import_candidate(node, ctx);
                continue;
            }
            "identifier" => {
                if handle_annotation_reference_candidate(node, ctx) {
                    continue;
                }
                handle_identifier_candidate(node, ctx);
            }
            "attribute" => {
                if handle_annotation_reference_candidate(node, ctx) {
                    continue;
                }
                handle_attribute_candidate(node, ctx);
            }
            "string_content" => {
                handle_annotation_reference_candidate(node, ctx);
            }
            "keyword_argument" => {
                handle_keyword_argument_candidate(node, ctx);
                if let Some(value) = node.child_by_field_name("value") {
                    stack.push(value);
                }
                continue;
            }
            _ => {}
        }

        let mut cursor = node.walk();
        let mut children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
        children.reverse();
        stack.extend(children);
    }
}

fn handle_annotation_reference_candidate(node: Node<'_>, ctx: &mut ScanCtx<'_>) -> bool {
    let Some(candidates) = annotation_reference_candidates(
        ctx.graph,
        ctx.python,
        ctx.file,
        ctx.source,
        node,
        ctx.target_self_file,
    ) else {
        return false;
    };

    if (ctx.target.is_class() || ctx.target.is_field() || ctx.target_member.is_none())
        && candidates.iter().all(|candidate| *candidate == *ctx.target)
        && candidates.iter().any(|candidate| *candidate == *ctx.target)
    {
        let site = if node.kind() == "attribute" {
            node.child_by_field_name("attribute").unwrap_or(node)
        } else {
            node
        };
        record_hit(site, ctx);
    }

    // An attribute annotation the resolver could not turn into a candidate is
    // not consumed here: the namespace-attribute path still has to see it, and
    // so do the node's children. `inverted.rs` always fell through this way.
    if node.kind() == "attribute" && candidates.is_empty() {
        return false;
    }

    true
}

fn handle_keyword_argument_candidate(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let (Some(target_member), Some(name), Some(arguments)) = (
        ctx.target_member,
        node.child_by_field_name("name"),
        node.parent(),
    ) else {
        return;
    };
    if name.kind() != "identifier"
        || slice(name, ctx.source) != target_member
        || arguments.kind() != "argument_list"
    {
        return;
    }
    let Some(call) = arguments.parent().filter(|parent| parent.kind() == "call") else {
        return;
    };
    let Some(function) = call.child_by_field_name("function") else {
        return;
    };
    if function.kind() == "identifier" && slice(function, ctx.source) == "cls" {
        if ctx.self_receiver_matches_target(function) {
            record_hit(name, ctx);
        }
        return;
    }
    let Some(target_owner) = ctx.target_owner.as_ref() else {
        return;
    };
    if let Some(root) = leftmost_identifier(function)
        && ctx
            .scope_facts_for_node(function)
            .is_some_and(|facts| facts.is_shadowed(slice(root, ctx.source)))
    {
        return;
    }
    let matches = resolve_constructor_types(ctx.graph, ctx.python, ctx.file, ctx.source, function)
        .into_iter()
        .any(|class| {
            &class == target_owner
                || ctx
                    .graph
                    .hierarchy
                    .map(|provider| provider.get_ancestors(&class))
                    .unwrap_or_default()
                    .into_iter()
                    .any(|ancestor| &ancestor == target_owner)
        });
    if matches {
        record_hit(name, ctx);
    }
}

fn leftmost_identifier(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        match node.kind() {
            "identifier" => return Some(node),
            "attribute" => node = node.child_by_field_name("object")?,
            _ => return None,
        }
    }
}

/// Emit an `Import`-binding hit for `from <mod> import <target>` (the token that
/// brings the target into this file). Gated on there being an import edge whose
/// local name is the target — so a same-named symbol imported from a different
/// module is not falsely counted. Only top-level symbols (not members) are
/// imported by their own name.
fn handle_import_candidate(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if ctx.target_member.is_some() {
        return;
    }
    if !ctx
        .edges
        .iter()
        .any(|edge| edge.local_name == ctx.target_short)
    {
        return;
    }
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        if node.kind() == "identifier" && slice(node, ctx.source) == ctx.target_short {
            record_import_hit(node, ctx);
            return;
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            stack.push(child);
        }
    }
}

fn handle_identifier_candidate(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if node
        .parent()
        .is_some_and(|parent| parent.kind() == "attribute")
    {
        return;
    }
    let text = slice(node, ctx.source);
    if text.is_empty() || is_declaration_identifier(node) || decorates_the_target(node, ctx) {
        return;
    }
    if let Some(member) = ctx.target_member {
        // A constructor call `Owner(...)` invokes the class's `__init__`, so it
        // is a usage of `__init__` even though `__init__` never appears.
        if member == "__init__" && is_call_callee(node) && ctx.binds_target(text, node) {
            record_hit(node, ctx);
            return;
        }
        // For a member target, a bare identifier is a usage only when it names
        // the member directly in the owner class body (the class namespace).
        if text == member && ctx.node_directly_in_owner_class_body(node) {
            record_hit(node, ctx);
        }
        return;
    }
    if !ctx.binds_target(text, node) {
        return;
    }
    if !ctx.target_is_module
        && ctx.edges.iter().any(|edge| edge.local_name == text)
        && !ctx.module_binding_targets_symbol(text, node)
    {
        return;
    }
    record_hit(node, ctx);
}

/// Whether `node` sits in a decorator of the very definition the scan is
/// looking for.
///
/// Python evaluates a decorator expression before the decorated name is bound,
/// so `@foo` above `def foo()` names an *outer* `foo` and never the definition
/// it decorates. Without this the decorated definition reads as a user of
/// itself, which the enclosing-equals-target drop used to hide.
fn decorates_the_target(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    if ctx.file != ctx.target_source {
        return false;
    }
    let mut current = node;
    while let Some(parent) = current.parent() {
        if parent.kind() == "decorated_definition" && current.kind() == "decorator" {
            let Some(definition) = parent.child_by_field_name("definition") else {
                return false;
            };
            return ctx.graph.index.ranges(ctx.target).iter().any(|range| {
                range.start_byte <= definition.start_byte()
                    && definition.end_byte() <= range.end_byte
            });
        }
        current = parent;
    }
    false
}

fn handle_attribute_candidate(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let Some(object) = node.child_by_field_name("object") else {
        return;
    };
    let Some(attribute) = node.child_by_field_name("attribute") else {
        return;
    };
    let object_text = slice(object, ctx.source);
    let attribute_text = slice(attribute, ctx.source);
    if let Some(member) = ctx.target_member
        && attribute_text == member
    {
        // A `self.member` / `cls.member` receiver is the current instance / own
        // class — a same-owner site, excluded from external usage counts (#1014
        // facet B). A typed local of the same type is a different instance and
        // stays an external hit.
        let is_same_owner_receiver =
            matches!(object_text, "self" | "cls") && ctx.self_receiver_matches_target(node);
        if is_same_owner_receiver {
            record_self_receiver_hit(attribute, ctx);
        } else if ctx.receiver_binds_target(object_text, node)
            || (object.kind() == "call" && call_result_matches_target(object, ctx))
        {
            record_hit(attribute, ctx);
        } else if member_receiver_match_is_unproven(object, object_text, node, ctx) {
            record_unproven_hit(attribute, ctx);
        }
    }

    let object_binds_target = if ctx.target_is_module {
        imported_root_targets_module(ctx, object, node)
    } else {
        ctx.binds_target(object_text, node)
    };
    if object.kind() == "identifier"
        && object_binds_target
        && (ctx.target_is_module
            || (ctx.target_member.is_none()
                && !ctx.edges.iter().any(|edge| {
                    matches!(edge.kind, ImportEdgeKind::Namespace) && edge.local_name == object_text
                })))
    {
        record_hit(object, ctx);
    }

    if ctx.target_is_module
        && let Some(module_qualifier) = module_attribute_target_hit(node, ctx)
    {
        record_hit(module_qualifier, ctx);
    }

    // A bare member name used as the *object* of an attribute access in the
    // owner class body — e.g. the `x` in `@x.setter`/`@x.deleter` decorating a
    // property `x` — is a usage of that member.
    if let Some(member) = ctx.target_member
        && object.kind() == "identifier"
        && object_text == member
        && ctx.node_directly_in_owner_class_body(object)
    {
        record_hit(object, ctx);
    }

    // Best-effort for an un-inferrable receiver: `recv.member` where `recv`'s
    // type cannot be resolved is attributed to the target when the target's
    // owner is in this file and the member name is unique among local classes
    // (so `recv.member` can only mean the target). `self`/`cls` are handled
    // structurally above; cross-file untyped receivers stay conservative.
    if ctx.member_best_effort_unique
        && let Some(member) = ctx.target_member
        && attribute_text == member
        && object.kind() == "identifier"
        && !matches!(object_text, "self" | "cls")
        && !ctx.receiver_binds_target(object_text, node)
        && ctx.receiver_type_is_unknown(object_text, node)
    {
        record_hit(attribute, ctx);
    }

    if let Some(namespace_target) = namespace_attribute_target_hit(node, ctx) {
        record_hit(namespace_target, ctx);
    }
}

/// Resolve a top-level symbol written through a namespace import and any number
/// of intermediate modules (`K.feature.DISK`, `pkg.core.ops.eye_like`).
///
/// The written path is assembled only from tree-sitter's `attribute` fields.
/// The analyzer's canonical export resolver then proves that the whole path
/// names the exact physical target, so re-export aliases remain supported
/// without comparing rendered source paths or broadening same-name candidates.
fn namespace_attribute_target_hit<'a>(node: Node<'a>, ctx: &ScanCtx<'_>) -> Option<Node<'a>> {
    if ctx.target_member.is_some() {
        return None;
    }
    let (root, attributes) = attribute_chain(node)?;
    let terminal = *attributes.last()?;
    let terminal_name = slice(terminal, ctx.source);
    if terminal_name.is_empty()
        || !ctx
            .seeds
            .iter()
            .any(|(_, seed_name)| seed_name == terminal_name)
    {
        return None;
    }

    let root_name = slice(root, ctx.source);
    if root_name.is_empty() || import_root_shadowed(ctx, root_name, root, node) {
        return None;
    }
    let binder = ctx.python.import_binder_of(ctx.file);
    let binding = binder.bindings.get(root_name)?;
    if binding.kind != ImportKind::Namespace {
        return None;
    }
    let mut written_module = binding.module_specifier.clone();
    for attribute in &attributes[..attributes.len() - 1] {
        let segment = slice(*attribute, ctx.source);
        if segment.is_empty() {
            return None;
        }
        written_module.push('.');
        written_module.push_str(segment);
    }
    if usage_resolve_module_files(ctx.python, ctx.file, &written_module)
        .iter()
        .any(|resolved| {
            ctx.seeds
                .contains(&(resolved.clone(), terminal_name.to_string()))
        })
    {
        return Some(terminal);
    }

    let mut written_fqn = binding.module_specifier.clone();
    for attribute in attributes {
        let segment = slice(attribute, ctx.source);
        if segment.is_empty() {
            return None;
        }
        written_fqn.push('.');
        written_fqn.push_str(segment);
    }
    resolve_fqn_candidates(ctx.python, &written_fqn, |name| {
        ctx.graph.index.definitions(name).collect()
    })
    .into_iter()
    .any(|candidate| &candidate == ctx.target)
    .then_some(terminal)
}

fn imported_root_targets_module(ctx: &ScanCtx<'_>, root: Node<'_>, reference: Node<'_>) -> bool {
    let Some(module_fqn) = imported_module_binding_fqn(ctx, root, reference) else {
        return false;
    };
    usage_resolve_module_files(ctx.python, ctx.file, &module_fqn)
        .into_iter()
        .any(|resolved_file| &resolved_file == ctx.target_source)
}

fn module_attribute_target_hit<'a>(node: Node<'a>, ctx: &ScanCtx<'_>) -> Option<Node<'a>> {
    let (root, attributes) = attribute_chain(node)?;
    if attributes.is_empty() {
        return None;
    }
    let mut module_fqn = imported_module_binding_fqn(ctx, root, node)?;
    for attribute in attributes {
        let segment = slice(attribute, ctx.source);
        if segment.is_empty() {
            return None;
        }
        if module_fqn.ends_with('.') {
            module_fqn.push_str(segment);
        } else {
            module_fqn.push('.');
            module_fqn.push_str(segment);
        }
        let resolved = usage_resolve_module_files(ctx.python, ctx.file, &module_fqn);
        if resolved.is_empty() {
            return None;
        }
        if resolved
            .iter()
            .any(|resolved_file| resolved_file == ctx.target_source)
        {
            return Some(attribute);
        }
    }
    None
}

fn call_result_matches_target(call: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    let Some(target_owner) = ctx.target_owner.as_ref() else {
        return false;
    };
    let scope_facts = ctx.scope_facts_for_node(call);
    call_result_types(
        ctx.graph,
        ctx.python,
        ctx.file,
        ctx.source,
        call,
        scope_facts,
    )
    .into_iter()
    .any(|class| {
        &class == target_owner
            || ctx
                .graph
                .hierarchy
                .map(|provider| provider.get_ancestors(&class))
                .unwrap_or_default()
                .into_iter()
                .any(|ancestor| &ancestor == target_owner)
    })
}

pub fn call_result_types(
    graph: &PythonGraphSource<'_>,
    python: &dyn PythonUsageSource,
    file: &ProjectFile,
    source: &str,
    call: Node<'_>,
    scope_facts: Option<&LocalBindingsSnapshot<String>>,
) -> Vec<CodeUnit> {
    let Some(function) = call.child_by_field_name("function") else {
        return Vec::new();
    };
    let constructed = resolve_constructor_types(graph, python, file, source, function);
    if !constructed.is_empty() {
        return constructed;
    }
    let callable_fqns = resolve_callable_fqns(graph, python, file, source, function, scope_facts);
    if callable_fqns.is_empty() {
        return Vec::new();
    }
    let callables = callable_fqns
        .into_iter()
        .flat_map(|callable_fqn| {
            resolve_fqn_candidates(python, &callable_fqn, |name| {
                graph.index.definitions(name).collect()
            })
        })
        .collect::<Vec<_>>();
    let mut classes = Vec::new();
    for callable in callables.into_iter().filter(CodeUnit::is_function) {
        let Some(raw_type) = callable_return_type_name(graph, python, &callable) else {
            continue;
        };
        if let Some(class) =
            resolve_receiver_type(graph, python, callable.source(), &raw_type, true)
        {
            classes.push(class);
        }
    }
    classes.sort();
    classes.dedup();
    classes
}

fn resolve_callable_fqns(
    graph: &PythonGraphSource<'_>,
    python: &dyn PythonUsageSource,
    file: &ProjectFile,
    source: &str,
    function: Node<'_>,
    scope_facts: Option<&LocalBindingsSnapshot<String>>,
) -> Vec<String> {
    match function.kind() {
        "identifier" => {
            resolve_identifier_callable_fqns(graph, python, file, source, function, scope_facts)
        }
        "attribute" => {
            resolve_attribute_callable_fqns(graph, python, file, source, function, scope_facts)
        }
        _ => Vec::new(),
    }
}

fn resolve_identifier_callable_fqns(
    graph: &PythonGraphSource<'_>,
    python: &dyn PythonUsageSource,
    file: &ProjectFile,
    source: &str,
    function: Node<'_>,
    scope_facts: Option<&LocalBindingsSnapshot<String>>,
) -> Vec<String> {
    let local = slice(function, source);
    if local.is_empty() || scope_facts.is_some_and(|facts| facts.is_shadowed(local)) {
        return Vec::new();
    }
    let binder = python.import_binder_of(file);
    match binder.bindings.get(local) {
        Some(binding) if binding.kind == ImportKind::Named => binding
            .imported_name
            .as_ref()
            .map(|imported| vec![format!("{}.{}", binding.module_specifier, imported)])
            .unwrap_or_default(),
        _ => graph
            .index
            .declarations(file)
            .into_iter()
            .find(|unit| unit.is_function() && unit.identifier() == local)
            .map(|unit| vec![unit.fq_name()])
            .unwrap_or_default(),
    }
}

fn resolve_attribute_callable_fqns(
    graph: &PythonGraphSource<'_>,
    python: &dyn PythonUsageSource,
    file: &ProjectFile,
    source: &str,
    function: Node<'_>,
    scope_facts: Option<&LocalBindingsSnapshot<String>>,
) -> Vec<String> {
    let Some(receiver) = function.child_by_field_name("object") else {
        return Vec::new();
    };
    let Some(method) = function.child_by_field_name("attribute") else {
        return Vec::new();
    };
    let method = slice(method, source);
    if method.is_empty() {
        return Vec::new();
    }
    let mut fqns = attribute_receiver_classes(graph, python, file, source, receiver, scope_facts)
        .into_iter()
        .map(|class| format!("{}.{}", class.fq_name(), method))
        .collect::<Vec<_>>();
    fqns.sort();
    fqns.dedup();
    fqns
}

fn attribute_receiver_classes(
    graph: &PythonGraphSource<'_>,
    python: &dyn PythonUsageSource,
    file: &ProjectFile,
    source: &str,
    receiver: Node<'_>,
    scope_facts: Option<&LocalBindingsSnapshot<String>>,
) -> Vec<CodeUnit> {
    let mut classes = match receiver.kind() {
        "identifier" => {
            identifier_receiver_classes(graph, python, file, source, receiver, scope_facts)
        }
        "attribute" => {
            if let Some(root) = leftmost_identifier(receiver)
                && scope_facts.is_some_and(|facts| facts.is_shadowed(slice(root, source)))
            {
                Vec::new()
            } else {
                resolve_constructor_types(graph, python, file, source, receiver)
            }
        }
        _ => Vec::new(),
    };
    classes.sort();
    classes.dedup();
    classes
}

fn identifier_receiver_classes(
    graph: &PythonGraphSource<'_>,
    python: &dyn PythonUsageSource,
    file: &ProjectFile,
    source: &str,
    receiver: Node<'_>,
    scope_facts: Option<&LocalBindingsSnapshot<String>>,
) -> Vec<CodeUnit> {
    let ident = slice(receiver, source);
    if ident.is_empty() {
        return Vec::new();
    }
    if matches!(ident, "self" | "cls")
        && let Some(class) = enclosing_class_for_node(graph, file, receiver)
    {
        return vec![class];
    }
    if let Some(facts) = scope_facts {
        if let Some(raw_type) = facts
            .resolution_for(ident)
            .as_precise()
            .and_then(|targets| targets.iter().next())
            && let Some(class) = resolve_receiver_type(graph, python, file, raw_type, false)
        {
            return vec![class];
        }
        if facts.is_shadowed(ident) {
            return Vec::new();
        }
    }
    resolve_receiver_type(graph, python, file, ident, false)
        .into_iter()
        .collect()
}

fn enclosing_class_for_node(
    graph: &PythonGraphSource<'_>,
    file: &ProjectFile,
    node: Node<'_>,
) -> Option<CodeUnit> {
    let range = Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: 0,
        end_line: 0,
    };
    let enclosing = graph.index.enclosing_code_unit(file, &range)?;
    // Python's structural model never separately indexes nested
    // function/lambda scopes as their own CodeUnit, so `self`/`cls` can only
    // ever need the enclosing unit itself or (a method's owner) exactly one
    // `parent_of` hop up — `.take(2)` keeps that bound explicit rather than
    // an unbounded walk that could climb past the same-file owner class.
    brokk_bifrost_core::analyzer::usages::common::enclosing_owner_chain(enclosing, |unit| {
        graph.index.parent_of(unit)
    })
    .take(2)
    .find(|unit| unit.is_class() && unit.source() == file)
}

fn attribute_chain<'a>(node: Node<'a>) -> Option<(Node<'a>, Vec<Node<'a>>)> {
    let mut attributes = Vec::new();
    let mut current = node;
    loop {
        if current.kind() != "attribute" {
            return None;
        }
        attributes.push(current.child_by_field_name("attribute")?);
        current = current.child_by_field_name("object")?;
        if current.kind() == "identifier" {
            attributes.reverse();
            return Some((current, attributes));
        }
    }
}

fn imported_module_binding_fqn(
    ctx: &ScanCtx<'_>,
    root: Node<'_>,
    reference: Node<'_>,
) -> Option<String> {
    let root_text = slice(root, ctx.source);
    if root_text.is_empty() {
        return None;
    }
    if import_root_shadowed(ctx, root_text, root, reference) {
        return None;
    }
    let binder = ctx.python.import_binder_of(ctx.file);
    let binding = binder.bindings.get(root_text)?;
    match binding.kind {
        ImportKind::Namespace => Some(binding.module_specifier.clone()),
        ImportKind::Named => {
            let imported = binding.imported_name.as_ref()?;
            let candidate = if binding.module_specifier.ends_with('.') {
                format!("{}{}", binding.module_specifier, imported)
            } else {
                format!("{}.{}", binding.module_specifier, imported)
            };
            (!usage_resolve_module_files(ctx.python, ctx.file, &candidate).is_empty())
                .then_some(candidate)
        }
        _ => None,
    }
}

fn import_root_shadowed(
    ctx: &ScanCtx<'_>,
    root_text: &str,
    root: Node<'_>,
    reference: Node<'_>,
) -> bool {
    ctx.scope_facts_for_node(root)
        .or_else(|| ctx.scope_facts_for_node(reference))
        .is_some_and(|facts| facts.is_shadowed(root_text))
        || enclosing_parameters_shadow(root_text, reference, ctx.source)
}

fn enclosing_parameters_shadow(root_text: &str, reference: Node<'_>, source: &str) -> bool {
    let mut current = reference;
    while let Some(parent) = current.parent() {
        if matches!(parent.kind(), "function_definition" | "lambda") {
            let Some(parameters) = parent.child_by_field_name("parameters") else {
                return false;
            };
            let mut cursor = parameters.walk();
            return parameters.named_children(&mut cursor).any(|parameter| {
                parameter_symbol(parameter, source).as_deref() == Some(root_text)
            });
        }
        current = parent;
    }
    false
}

enum EnclosingParameterType {
    NotDeclared,
    Untyped,
    Typed(String),
}

fn enclosing_runtime_parameter_type(
    name: &str,
    reference: Node<'_>,
    source: &str,
) -> EnclosingParameterType {
    let site_start = reference.start_byte();
    let site_end = reference.end_byte();
    let mut current = reference;
    while let Some(parent) = current.parent() {
        if matches!(parent.kind(), "function_definition" | "lambda")
            && parent
                .child_by_field_name("body")
                .is_some_and(|body| body.start_byte() <= site_start && site_end <= body.end_byte())
            && let Some(parameters) = parent.child_by_field_name("parameters")
        {
            let mut cursor = parameters.walk();
            for parameter in parameters.named_children(&mut cursor) {
                if parameter_symbol(parameter, source).as_deref() != Some(name) {
                    continue;
                }
                return parameter
                    .child_by_field_name("type")
                    .and_then(|annotation| normalized_receiver_type(slice(annotation, source)))
                    .map_or(EnclosingParameterType::Untyped, |raw_type| {
                        EnclosingParameterType::Typed(raw_type)
                    });
            }
        }
        current = parent;
    }
    EnclosingParameterType::NotDeclared
}

fn member_receiver_match_is_unproven(
    object: Node<'_>,
    object_text: &str,
    node: Node<'_>,
    ctx: &ScanCtx<'_>,
) -> bool {
    if matches!(object_text, "self" | "cls") {
        return false;
    }
    match object.kind() {
        "identifier" => {
            ctx.receiver_type_is_unknown(object_text, node) && !ctx.member_best_effort_unique
        }
        "attribute" => true,
        _ => false,
    }
}

pub fn slice<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    brokk_bifrost_core::analyzer::common::node_source_text(node, source)
}

/// Whether `node` is the `function` callee of a call expression (`node(...)`).
fn is_call_callee(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        parent.kind() == "call"
            && parent
                .child_by_field_name("function")
                .is_some_and(|function| function.id() == node.id())
    })
}

pub fn is_declaration_identifier(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    let parent_kind = parent.kind();
    if matches!(
        parent_kind,
        "class_definition" | "function_definition" | "parameters"
    ) && parent
        .child_by_field_name("name")
        .map(|name| name.id() == node.id())
        .unwrap_or(false)
    {
        return true;
    }

    if matches!(
        parent_kind,
        "aliased_import" | "import_from_statement" | "import_statement"
    ) {
        return true;
    }

    parent_kind == "assignment"
        && parent
            .child_by_field_name("left")
            .map(|left| {
                left.start_byte() <= node.start_byte() && node.end_byte() <= left.end_byte()
            })
            .unwrap_or(false)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ModuleBindingKind {
    TargetSymbolImport,
    TargetModuleImport,
    Other,
}

#[derive(Clone, Copy, Debug)]
struct ClassifiedModuleBindingEvent {
    visible_from: usize,
    conditional: bool,
    kind: ModuleBindingKind,
}

pub fn collect_module_binding_timeline(root: Node<'_>, source: &str) -> ModuleBindingTimeline {
    let mut timeline = ModuleBindingTimeline::default();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "function_definition" | "class_definition" => {
                if let Some(name) = node.child_by_field_name("name") {
                    record_module_binding(
                        &mut timeline,
                        slice(name, source),
                        node.end_byte(),
                        binding_is_conditional(node),
                        ModuleBindingEventKind::Other,
                    );
                }
                continue;
            }
            "import_statement" | "import_from_statement" => {
                collect_import_binding_events(node, source, &mut timeline);
                continue;
            }
            "assignment" | "augmented_assignment" | "named_expression" => {
                if let Some(left) = node.child_by_field_name("left") {
                    record_local_binding_targets(
                        left,
                        source,
                        node.end_byte(),
                        binding_is_conditional(node),
                        &mut timeline,
                    );
                }
                continue;
            }
            "for_statement" => {
                if let Some(left) = node.child_by_field_name("left") {
                    record_local_binding_targets(
                        left,
                        source,
                        left.end_byte(),
                        true,
                        &mut timeline,
                    );
                }
            }
            _ => {}
        }

        let mut cursor = node.walk();
        let mut children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
        children.reverse();
        stack.extend(children);
    }
    for events in timeline.values_mut() {
        events.sort_by_key(|event| event.visible_from);
    }
    timeline
}

fn collect_import_binding_events(
    node: Node<'_>,
    source: &str,
    timeline: &mut ModuleBindingTimeline,
) {
    if node.kind() == "import_statement" {
        let mut cursor = node.walk();
        for imported in node.children_by_field_name("name", &mut cursor) {
            let name = imported.child_by_field_name("name").unwrap_or(imported);
            let Some(local) = imported
                .child_by_field_name("alias")
                .or_else(|| first_identifier(name))
            else {
                continue;
            };
            let module = slice(name, source).trim();
            record_module_binding(
                timeline,
                slice(local, source),
                node.end_byte(),
                binding_is_conditional(node),
                ModuleBindingEventKind::ImportModule(module.to_string()),
            );
        }
        return;
    }

    let Some(module_node) = node.child_by_field_name("module_name") else {
        return;
    };
    let module = slice(module_node, source).trim();
    let mut cursor = node.walk();
    for imported in node.children_by_field_name("name", &mut cursor) {
        if imported.kind() == "wildcard_import" {
            continue;
        }
        let name = imported.child_by_field_name("name").unwrap_or(imported);
        let Some(imported_identifier) = last_identifier(name) else {
            continue;
        };
        let imported_name = slice(imported_identifier, source).trim();
        let Some(local) = imported
            .child_by_field_name("alias")
            .or_else(|| last_identifier(name))
        else {
            continue;
        };
        record_module_binding(
            timeline,
            slice(local, source),
            node.end_byte(),
            binding_is_conditional(node),
            ModuleBindingEventKind::FromImport {
                module: module.to_string(),
                imported_name: imported_name.to_string(),
            },
        );
    }
}

fn classify_module_binding_timeline(
    python: &dyn PythonUsageSource,
    file: &ProjectFile,
    timeline: &ModuleBindingTimeline,
    seeds: &BTreeSet<(ProjectFile, String)>,
    edges: &[ImportEdge],
) -> HashMap<String, Vec<ClassifiedModuleBindingEvent>> {
    let mut classified = HashMap::default();
    let mut module_targets: HashMap<String, bool> = HashMap::default();
    let relevant_locals: HashSet<&str> =
        edges.iter().map(|edge| edge.local_name.as_str()).collect();
    for (local, events) in timeline {
        if !relevant_locals.contains(local.as_str()) {
            continue;
        }
        let classified_events = events
            .iter()
            .map(|event| {
                let kind = match &event.kind {
                    ModuleBindingEventKind::ImportModule(module) => {
                        if *module_targets
                            .entry(module.clone())
                            .or_insert_with(|| module_contains_seed(python, file, module, seeds))
                        {
                            ModuleBindingKind::TargetModuleImport
                        } else {
                            ModuleBindingKind::Other
                        }
                    }
                    ModuleBindingEventKind::FromImport {
                        module,
                        imported_name,
                    } => {
                        let direct = usage_resolve_module_files(python, file, module).iter().any(
                            |resolved| seeds.contains(&(resolved.clone(), imported_name.clone())),
                        );
                        let submodule = if module.ends_with('.') {
                            format!("{module}{imported_name}")
                        } else {
                            format!("{module}.{imported_name}")
                        };
                        let imports_target_module =
                            *module_targets.entry(submodule.clone()).or_insert_with(|| {
                                module_contains_seed(python, file, &submodule, seeds)
                            });
                        if direct {
                            ModuleBindingKind::TargetSymbolImport
                        } else if imports_target_module {
                            ModuleBindingKind::TargetModuleImport
                        } else {
                            ModuleBindingKind::Other
                        }
                    }
                    ModuleBindingEventKind::Other => ModuleBindingKind::Other,
                };
                ClassifiedModuleBindingEvent {
                    visible_from: event.visible_from,
                    conditional: event.conditional,
                    kind,
                }
            })
            .collect();
        classified.insert(local.clone(), classified_events);
    }
    classified
}

fn module_contains_seed(
    python: &dyn PythonUsageSource,
    file: &ProjectFile,
    module: &str,
    seeds: &BTreeSet<(ProjectFile, String)>,
) -> bool {
    usage_resolve_module_files(python, file, module)
        .iter()
        .any(|resolved| seeds.iter().any(|(seed_file, _)| seed_file == resolved))
}

fn record_module_binding(
    timeline: &mut ModuleBindingTimeline,
    name: &str,
    visible_from: usize,
    conditional: bool,
    kind: ModuleBindingEventKind,
) {
    let name = name.trim();
    if name.is_empty() {
        return;
    }
    timeline
        .entry(name.to_string())
        .or_default()
        .push(ModuleBindingEvent {
            visible_from,
            conditional,
            kind,
        });
}

fn record_local_binding_targets(
    target: Node<'_>,
    source: &str,
    visible_from: usize,
    conditional: bool,
    timeline: &mut ModuleBindingTimeline,
) {
    let mut stack = vec![target];
    while let Some(node) = stack.pop() {
        if node.kind() == "identifier" {
            record_module_binding(
                timeline,
                slice(node, source),
                visible_from,
                conditional,
                ModuleBindingEventKind::Other,
            );
            continue;
        }
        if matches!(node.kind(), "attribute" | "subscript") {
            continue;
        }
        let mut cursor = node.walk();
        let mut children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
        children.reverse();
        stack.extend(children);
    }
}

fn binding_is_conditional(mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent() {
        if matches!(
            parent.kind(),
            "if_statement"
                | "try_statement"
                | "except_clause"
                | "match_statement"
                | "case_clause"
                | "for_statement"
                | "while_statement"
        ) {
            return true;
        }
        if matches!(
            parent.kind(),
            "module" | "function_definition" | "class_definition"
        ) {
            return false;
        }
        node = parent;
    }
    false
}

fn first_identifier(node: Node<'_>) -> Option<Node<'_>> {
    identifier_extreme(node, false)
}

fn last_identifier(node: Node<'_>) -> Option<Node<'_>> {
    identifier_extreme(node, true)
}

fn identifier_extreme(node: Node<'_>, last: bool) -> Option<Node<'_>> {
    let mut best = None;
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        if node.kind() == "identifier" {
            if best.is_none_or(|current: Node<'_>| {
                if last {
                    node.start_byte() > current.start_byte()
                } else {
                    node.start_byte() < current.start_byte()
                }
            }) {
                best = Some(node);
            }
            continue;
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    best
}

fn reference_is_deferred_function_body(node: Node<'_>) -> bool {
    let site_start = node.start_byte();
    let site_end = node.end_byte();
    let mut current = node;
    while let Some(parent) = current.parent() {
        if matches!(parent.kind(), "function_definition" | "lambda")
            && parent
                .child_by_field_name("body")
                .is_some_and(|body| body.start_byte() <= site_start && site_end <= body.end_byte())
        {
            return true;
        }
        current = parent;
    }
    false
}

pub fn collect_assigned_identifiers(node: Node<'_>, source: &str, out: &mut HashSet<String>) {
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        if node.kind() == "identifier" {
            let text = slice(node, source).trim();
            if !text.is_empty() {
                out.insert(text.to_string());
            }
            continue;
        }

        let mut cursor = node.walk();
        let mut children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
        children.reverse();
        stack.extend(children);
    }
}

pub fn collect_scope_facts_from_parsed_source(
    graph: &PythonGraphSource<'_>,
    python: &dyn PythonUsageSource,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
) -> PythonScopeFacts {
    let mut factory_return_types = collect_factory_return_types_from_root(root, source);
    collect_imported_factory_return_types(graph, python, file, &mut factory_return_types);
    collect_scope_facts_with_factory_returns(graph, file, source, &factory_return_types)
}

fn collect_imported_factory_return_types(
    graph: &PythonGraphSource<'_>,
    python: &dyn PythonUsageSource,
    file: &ProjectFile,
    factory_return_types: &mut HashMap<String, String>,
) {
    let binder = python.import_binder_of(file);
    for (local, binding) in &binder.bindings {
        if !matches!(binding.kind, ImportKind::Named) {
            continue;
        }
        let Some(imported) = binding.imported_name.as_deref() else {
            continue;
        };
        let fqn = format!("{}.{}", binding.module_specifier, imported);
        let units =
            resolve_fqn_candidates(python, &fqn, |name| graph.index.definitions(name).collect());
        for unit in units {
            if unit.is_function() {
                if let Some(return_type) = callable_return_type_name(graph, python, &unit) {
                    factory_return_types
                        .entry(local.clone())
                        .or_insert(return_type);
                }
                continue;
            }
            if !unit.is_class() {
                continue;
            }
            factory_return_types
                .entry(local.clone())
                .or_insert_with(|| unit.identifier().to_string());
            collect_imported_class_method_return_types(
                graph,
                python,
                local,
                &unit,
                factory_return_types,
            );
        }
    }
}

fn collect_imported_class_method_return_types(
    graph: &PythonGraphSource<'_>,
    python: &dyn PythonSource,
    local_class_name: &str,
    class_unit: &CodeUnit,
    factory_return_types: &mut HashMap<String, String>,
) {
    for member in graph.index.direct_children(class_unit) {
        if !member.is_function() {
            continue;
        }
        let Some(return_type) = callable_return_type_name(graph, python, &member) else {
            continue;
        };
        factory_return_types
            .entry(format!("{}.{}", local_class_name, member.identifier()))
            .or_insert(return_type);
    }
}

fn callable_return_type_name(
    graph: &PythonGraphSource<'_>,
    python: &dyn PythonSource,
    callable: &CodeUnit,
) -> Option<String> {
    // The analyzer's already-parsed whole-file tree when it has one. This runs
    // once per imported class member, and the fallback below clones the entire
    // file source and builds a fresh `Parser` per declaration range. Same
    // prepared-syntax fast path C++ resolution uses for the same reason.
    if let Some(prepared) = python.prepared_syntax(callable.source()) {
        #[cfg(any(test, feature = "test-support"))]
        note_callable_return_type_lookup_for_test(true);
        return callable_return_type_name_in_tree(
            graph,
            callable,
            prepared.source(),
            prepared.tree().root_node(),
        );
    }
    #[cfg(any(test, feature = "test-support"))]
    note_callable_return_type_lookup_for_test(false);
    let source = graph.index.indexed_source(callable.source())?;
    declaration_source_slices(graph, callable, &source)
        .into_iter()
        .find_map(|declaration_source| {
            let mut parser = Parser::new();
            parser
                .set_language(&tree_sitter_python::LANGUAGE.into())
                .ok()?;
            let tree = parser.parse(declaration_source, None)?;
            let function = first_function_definition(tree.root_node())?;
            factory_return_type(function, declaration_source)
        })
}

/// How `callable_return_type_name` answered, counted per arm.
///
/// Both arms are counted, not just the slow one: a test that asserted only
/// "no reparses" would pass vacuously on a fixture that never reaches this
/// function at all.
#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CallableReturnTypeLookupCounts {
    /// Answered from the analyzer's already-parsed whole-file tree.
    pub prepared: usize,
    /// Fell back to cloning the file source and building a fresh parser.
    pub reparsed: usize,
}

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static CALLABLE_RETURN_TYPE_LOOKUPS_FOR_TEST: std::cell::Cell<CallableReturnTypeLookupCounts> =
        const { std::cell::Cell::new(CallableReturnTypeLookupCounts { prepared: 0, reparsed: 0 }) };
}

#[cfg(any(test, feature = "test-support"))]
fn note_callable_return_type_lookup_for_test(from_prepared_syntax: bool) {
    CALLABLE_RETURN_TYPE_LOOKUPS_FOR_TEST.with(|counts| {
        let mut observed = counts.get();
        if from_prepared_syntax {
            observed.prepared += 1;
        } else {
            observed.reparsed += 1;
        }
        counts.set(observed);
    });
}

/// Runs `body` and reports which arm each `callable_return_type_name` call
/// took. An analyzer that holds prepared syntax must report zero reparses.
#[cfg(any(test, feature = "test-support"))]
pub fn with_callable_return_type_lookup_counter_for_test<T>(
    body: impl FnOnce() -> T,
) -> (T, CallableReturnTypeLookupCounts) {
    CALLABLE_RETURN_TYPE_LOOKUPS_FOR_TEST.with(|counts| {
        counts.set(CallableReturnTypeLookupCounts::default());
        let result = body();
        let observed = counts.get();
        counts.set(CallableReturnTypeLookupCounts::default());
        (result, observed)
    })
}

/// The declaration walk both arms of [`callable_return_type_name`] share.
///
/// `source` and `root` must be the same snapshot: `factory_return_type` slices
/// `source` at the node's byte offsets, so a whole-file tree needs whole-file
/// source and a per-range reparse needs that range's slice.
fn callable_return_type_name_in_tree(
    graph: &PythonGraphSource<'_>,
    callable: &CodeUnit,
    source: &str,
    root: Node<'_>,
) -> Option<String> {
    let mut ranges = graph.index.ranges(callable);
    ranges.sort_by_key(|range| range.start_byte);
    ranges.into_iter().find_map(|range| {
        let declaration = root.descendant_for_byte_range(range.start_byte, range.end_byte)?;
        let function = first_function_definition(declaration)?;
        factory_return_type(function, source)
    })
}

fn first_function_definition(root: Node<'_>) -> Option<Node<'_>> {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "function_definition" {
            return Some(node);
        }
        let mut cursor = node.walk();
        let mut children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
        children.reverse();
        stack.extend(children);
    }
    None
}

fn collect_scope_facts_with_factory_returns(
    graph: &PythonGraphSource<'_>,
    file: &ProjectFile,
    source: &str,
    factory_return_types: &HashMap<String, String>,
) -> PythonScopeFacts {
    let declarations = graph.index.declarations(file);
    let mut class_facts_by_name: HashMap<String, LocalBindingsSnapshot<String>> =
        HashMap::default();
    for declaration in declarations
        .iter()
        .filter(|declaration| declaration.is_class())
    {
        let Some(declaration_source) = declaration_source(graph, declaration, source) else {
            continue;
        };
        let facts = collect_scope_facts_from_source(
            &declaration_source,
            ScopeFactTraversal::Class,
            true,
            Some(declaration.short_name()),
            factory_return_types,
        );
        class_facts_by_name.insert(
            declaration.short_name().to_string(),
            facts.filtered_visible_bindings(|symbol, _| symbol.starts_with("self.")),
        );
    }

    let mut scope_facts = HashMap::default();
    for declaration in declarations
        .iter()
        .filter(|declaration| declaration.is_function())
    {
        let Some(declaration_source) = declaration_source(graph, declaration, source) else {
            continue;
        };
        // fqname-M4: package-less short_name owner, matched below against
        // `class_facts_by_name` keys built from `short_name()`; `fq.parent()`
        // (`default_parent_fq_name`) would render the package-qualified owner,
        // a different string that would never hit in that map.
        let owner = declaration
            .short_name()
            .rsplit_once('.')
            .map(|(owner, _)| owner);
        let mut facts = collect_scope_facts_from_source(
            &declaration_source,
            ScopeFactTraversal::Function,
            false,
            owner,
            factory_return_types,
        );
        if let Some(owner) = owner
            && let Some(class_facts) = class_facts_by_name.get(owner)
        {
            facts = facts.merged_with_visible(class_facts);
        }
        scope_facts.insert(declaration.clone(), facts);
    }

    // Module-level statements (e.g. a top-level `f = Foo()`) form their own scope.
    // `enclosing_code_unit` resolves a top-level usage to the module CodeUnit, so
    // its bindings must be recorded too, otherwise constructed-local receivers
    // used at module scope resolve to no type.
    for declaration in declarations.iter().filter(|d| d.is_module()) {
        let Some(declaration_source) = declaration_source(graph, declaration, source) else {
            continue;
        };
        let facts = collect_scope_facts_from_source(
            &declaration_source,
            ScopeFactTraversal::Module,
            false,
            None,
            factory_return_types,
        );
        scope_facts.insert(declaration.clone(), facts);
    }
    scope_facts
}

fn declaration_source(
    graph: &PythonGraphSource<'_>,
    declaration: &CodeUnit,
    file_source: &str,
) -> Option<String> {
    let slices = declaration_source_slices(graph, declaration, file_source);
    (!slices.is_empty()).then(|| slices.join("\n\n"))
}

fn declaration_source_slices<'a>(
    graph: &PythonGraphSource<'_>,
    declaration: &CodeUnit,
    file_source: &'a str,
) -> Vec<&'a str> {
    let mut ranges = graph.index.ranges(declaration);
    ranges.sort_by_key(|range| range.start_byte);
    ranges
        .into_iter()
        .filter_map(|range| file_source.get(range.start_byte..range.end_byte))
        .collect()
}

fn collect_scope_facts_from_source(
    source: &str,
    traversal: ScopeFactTraversal,
    allow_self_receivers: bool,
    current_class: Option<&str>,
    factory_return_types: &HashMap<String, String>,
) -> LocalBindingsSnapshot<String> {
    let events = collect_scope_fact_events(source, traversal);
    collect_scope_facts_from_events(
        &events,
        allow_self_receivers,
        current_class,
        factory_return_types,
    )
}

pub fn collect_function_scope_facts_from_node(
    function: Node<'_>,
    source: &str,
) -> LocalBindingsSnapshot<String> {
    let mut events = Vec::new();
    if function.kind() == "lambda" {
        if let Some(parameters) = function.child_by_field_name("parameters") {
            collect_parameter_events(parameters, source, &mut events);
        }
    } else {
        collect_scope_fact_events_from_node(
            function,
            source,
            ScopeFactTraversal::Function,
            &mut events,
        );
    }
    collect_scope_facts_from_events(&events, false, None, &HashMap::default())
}

fn collect_scope_facts_from_events(
    events: &[ScopeFactEvent],
    allow_self_receivers: bool,
    current_class: Option<&str>,
    factory_return_types: &HashMap<String, String>,
) -> LocalBindingsSnapshot<String> {
    let mut engine = LocalInferenceEngine::new(LocalInferenceConfig::default());
    for event in events {
        if let ScopeFactEvent::Parameter { symbol, .. } = event
            && !engine.is_shadowed(symbol)
        {
            engine.declare_shadow(symbol.clone());
        }
    }

    let mut changed = true;
    while changed {
        changed = false;
        let mut aliases = Vec::new();
        for event in events {
            match event {
                ScopeFactEvent::Parameter {
                    symbol,
                    annotation: Some(annotation),
                }
                | ScopeFactEvent::Annotation { symbol, annotation } => {
                    apply_annotation_event(
                        symbol,
                        annotation,
                        allow_self_receivers,
                        &mut engine,
                        &mut changed,
                    );
                }
                ScopeFactEvent::Parameter {
                    annotation: None, ..
                } => {}
                ScopeFactEvent::Assignment { lhs, rhs } => {
                    if !engine.is_shadowed(lhs) {
                        engine.declare_shadow(lhs.clone());
                    }
                    if lhs.starts_with("self.") && !allow_self_receivers {
                        continue;
                    }

                    match rhs {
                        AssignmentRhs::Call(callee) => {
                            if !engine.is_shadowed(callee) {
                                if let Some(receiver_type) = factory_return_type_for_callee(
                                    callee,
                                    current_class,
                                    factory_return_types,
                                ) && engine.resolve_symbol(lhs).is_unknown()
                                {
                                    engine.seed_symbol(lhs.clone(), receiver_type.clone());
                                    changed = true;
                                    continue;
                                }

                                if let Some(receiver_type) = normalized_receiver_type(callee)
                                    && engine.resolve_symbol(lhs).is_unknown()
                                {
                                    engine.seed_symbol(lhs.clone(), receiver_type);
                                    changed = true;
                                    continue;
                                }
                            }
                        }
                        AssignmentRhs::Symbol(rhs_symbol) => {
                            if !engine.is_shadowed(rhs_symbol)
                                && let Some(receiver_type) = normalized_receiver_type(rhs_symbol)
                                && engine.resolve_symbol(lhs).is_unknown()
                            {
                                engine.seed_symbol(lhs.clone(), receiver_type);
                                changed = true;
                                continue;
                            }

                            if let SymbolResolution::Precise(targets) =
                                engine.resolve_symbol(rhs_symbol)
                                && !targets.is_empty()
                            {
                                aliases.push((lhs.clone(), rhs_symbol.clone()));
                            }
                        }
                        AssignmentRhs::Unknown => {}
                    }
                }
            }
        }
        let before = engine.snapshot();
        engine.apply_aliases_until_stable(aliases);
        if engine.snapshot() != before {
            changed = true;
        }
    }

    engine.snapshot()
}

fn factory_return_type_for_callee<'a>(
    callee: &str,
    current_class: Option<&str>,
    factory_return_types: &'a HashMap<String, String>,
) -> Option<&'a String> {
    if let Some(receiver_type) = factory_return_types.get(callee) {
        return Some(receiver_type);
    }
    let class_name = current_class?;
    let method = callee
        .strip_prefix("self.")
        .or_else(|| callee.strip_prefix("cls."))?;
    factory_return_types.get(&format!("{class_name}.{method}"))
}

fn apply_annotation_event(
    symbol: &str,
    annotation: &str,
    allow_self_receivers: bool,
    engine: &mut LocalInferenceEngine<String>,
    changed: &mut bool,
) {
    if symbol.starts_with("self.") && !allow_self_receivers {
        return;
    }
    if let Some(receiver_type) = normalized_receiver_type(annotation)
        && engine.resolve_symbol(symbol).is_unknown()
    {
        engine.seed_symbol(symbol.to_string(), receiver_type);
        *changed = true;
    }
}

enum ScopeFactEvent {
    Parameter {
        symbol: String,
        annotation: Option<String>,
    },
    Annotation {
        symbol: String,
        annotation: String,
    },
    Assignment {
        lhs: String,
        rhs: AssignmentRhs,
    },
}

enum AssignmentRhs {
    Symbol(String),
    Call(String),
    Unknown,
}

#[derive(Clone, Copy)]
enum ScopeFactTraversal {
    Module,
    Function,
    Class,
}

fn collect_scope_fact_events(source: &str, traversal: ScopeFactTraversal) -> Vec<ScopeFactEvent> {
    if source.trim().is_empty() {
        return Vec::new();
    }

    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_python::LANGUAGE.into())
        .is_err()
    {
        return Vec::new();
    }
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };

    let mut events = Vec::new();
    collect_scope_fact_events_from_node(tree.root_node(), source, traversal, &mut events);
    events
}

fn collect_scope_fact_events_from_node(
    root: Node<'_>,
    source: &str,
    traversal: ScopeFactTraversal,
    events: &mut Vec<ScopeFactEvent>,
) {
    let mut stack = vec![(root, false)];
    while let Some((node, inside_function)) = stack.pop() {
        let next_inside_function = match traversal {
            ScopeFactTraversal::Module => {
                if matches!(
                    node.kind(),
                    "function_definition" | "class_definition" | "lambda"
                ) {
                    continue;
                }
                false
            }
            ScopeFactTraversal::Function => match node.kind() {
                "function_definition" if inside_function => continue,
                "function_definition" => true,
                "class_definition" | "lambda" => continue,
                _ => inside_function,
            },
            ScopeFactTraversal::Class => inside_function,
        };
        if matches!(traversal, ScopeFactTraversal::Function) && !next_inside_function {
            let mut cursor = node.walk();
            let mut children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
            children.reverse();
            stack.extend(children.into_iter().map(|child| (child, false)));
            continue;
        }
        match node.kind() {
            "parameters" | "lambda_parameters" => collect_parameter_events(node, source, events),
            "assignment" => collect_assignment_events(node, source, events),
            _ => {}
        }

        let mut cursor = node.walk();
        let mut children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
        children.reverse();
        stack.extend(
            children
                .into_iter()
                .map(|child| (child, next_inside_function)),
        );
    }
}

fn collect_parameter_events(node: Node<'_>, source: &str, events: &mut Vec<ScopeFactEvent>) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "type_parameter" {
            continue;
        }
        let Some(symbol) = parameter_symbol(child, source) else {
            continue;
        };
        if matches!(symbol.as_str(), "self" | "cls" | "/") {
            continue;
        }
        let annotation = child
            .child_by_field_name("type")
            .map(|annotation| slice(annotation, source).trim().to_string())
            .filter(|annotation| !annotation.is_empty());
        events.push(ScopeFactEvent::Parameter { symbol, annotation });
    }
}

fn parameter_symbol(node: Node<'_>, source: &str) -> Option<String> {
    if node.kind() == "identifier" {
        return non_empty_node_text(node, source);
    }
    if let Some(name) = node.child_by_field_name("name") {
        return non_empty_node_text(name, source);
    }
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| child.kind() == "identifier")
        .and_then(|identifier| non_empty_node_text(identifier, source))
}

fn collect_assignment_events(node: Node<'_>, source: &str, events: &mut Vec<ScopeFactEvent>) {
    let Some(left) = node.child_by_field_name("left") else {
        return;
    };
    let Some(lhs) = receiver_symbol(left, source) else {
        return;
    };

    if let Some(annotation) = node
        .child_by_field_name("type")
        .map(|annotation| slice(annotation, source).trim().to_string())
        .filter(|annotation| !annotation.is_empty())
    {
        events.push(ScopeFactEvent::Annotation {
            symbol: lhs,
            annotation,
        });
        return;
    }

    let rhs = node
        .child_by_field_name("right")
        .and_then(|right| rhs_symbol(right, source))
        .unwrap_or(AssignmentRhs::Unknown);
    events.push(ScopeFactEvent::Assignment { lhs, rhs });
}

fn receiver_symbol(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "identifier" | "attribute" => non_empty_node_text(node, source),
        _ => None,
    }
}

fn rhs_symbol(node: Node<'_>, source: &str) -> Option<AssignmentRhs> {
    match node.kind() {
        "identifier" | "attribute" => non_empty_node_text(node, source).map(AssignmentRhs::Symbol),
        "call" => node
            .child_by_field_name("function")
            .or_else(|| node.named_child(0))
            .and_then(|callee| receiver_symbol(callee, source))
            .map(AssignmentRhs::Call),
        _ => None,
    }
}

fn non_empty_node_text(node: Node<'_>, source: &str) -> Option<String> {
    let text = slice(node, source).trim();
    (!text.is_empty()).then(|| text.to_string())
}

fn collect_factory_return_types_from_root(root: Node<'_>, source: &str) -> HashMap<String, String> {
    let mut returns = HashMap::default();
    let mut stack = vec![(root, None::<String>)];
    while let Some((node, class_name)) = stack.pop() {
        match node.kind() {
            "class_definition" => {
                let next_class = node
                    .child_by_field_name("name")
                    .and_then(|name| non_empty_node_text(name, source))
                    .or(class_name);
                push_factory_index_children(node, next_class, &mut stack);
            }
            "function_definition" => {
                if let Some(name) = node
                    .child_by_field_name("name")
                    .and_then(|name| non_empty_node_text(name, source))
                    && let Some(return_type) = factory_return_type(node, source)
                {
                    let key = class_name
                        .as_ref()
                        .map(|class| format!("{class}.{name}"))
                        .unwrap_or(name);
                    returns.insert(key, return_type);
                }
            }
            _ => push_factory_index_children(node, class_name, &mut stack),
        }
    }
    returns
}

fn push_factory_index_children<'tree>(
    node: Node<'tree>,
    class_name: Option<String>,
    stack: &mut Vec<(Node<'tree>, Option<String>)>,
) {
    let mut cursor = node.walk();
    let mut children: Vec<Node<'tree>> = node.named_children(&mut cursor).collect();
    children.reverse();
    stack.extend(
        children
            .into_iter()
            .map(|child| (child, class_name.clone())),
    );
}

fn factory_return_type(function: Node<'_>, source: &str) -> Option<String> {
    if let Some(return_type) = function.child_by_field_name("return_type") {
        let raw = slice(return_type, source).trim();
        return normalized_receiver_type(raw);
    }

    let body = function.child_by_field_name("body")?;
    let mut candidates = HashSet::default();
    let mut saw_return = false;
    let mut saw_unknown_return = false;
    let mut stack = vec![body];
    while let Some(node) = stack.pop() {
        if node != body && matches!(node.kind(), "function_definition" | "class_definition") {
            continue;
        }
        if node.kind() == "return_statement" {
            saw_return = true;
            match node
                .named_child(0)
                .and_then(|value| returned_receiver_type(value, source))
            {
                Some(returned_type) => {
                    candidates.insert(returned_type);
                }
                None => saw_unknown_return = true,
            }
        }
        let mut cursor = node.walk();
        let mut children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
        children.reverse();
        stack.extend(children);
    }
    if !saw_return || saw_unknown_return {
        return None;
    }
    (candidates.len() == 1)
        .then(|| candidates.into_iter().next())
        .flatten()
}

fn returned_receiver_type(node: Node<'_>, source: &str) -> Option<String> {
    let raw = match node.kind() {
        "identifier" => non_empty_node_text(node, source),
        "call" => node
            .child_by_field_name("function")
            .or_else(|| node.named_child(0))
            .filter(|callee| callee.kind() == "identifier")
            .and_then(|callee| non_empty_node_text(callee, source)),
        _ => None,
    }?;
    normalized_receiver_type(&raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn lambda_scope_facts_preserve_untyped_parameter_shadowing() {
        let source = "shadowed = lambda method: method.signature\n";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let mut nodes = vec![tree.root_node()];
        let lambda = loop {
            let node = nodes.pop().unwrap();
            if node.kind() == "lambda" {
                break node;
            }
            let mut cursor = node.walk();
            nodes.extend(node.named_children(&mut cursor));
        };

        let facts = collect_function_scope_facts_from_node(lambda, source);

        assert!(facts.is_shadowed("method"));
        assert!(facts.resolution_for("method").is_unknown());
    }

    #[test]
    fn pre_cancelled_graph_build_skips_python_file_parsing() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::write(root.join("target.py"), "def target():\n    pass\n").unwrap();
        let file = ProjectFile::new(root.clone(), PathBuf::from("target.py"));
        let files = [file.clone()].into_iter().collect();
        let cancellation = CancellationToken::default();
        cancellation.cancel();

        let graph = build_python_graph(&files, &file, Some(&cancellation));

        assert!(graph.parsed.is_empty());
    }

    #[test]
    fn graph_build_parses_only_candidates_and_target_not_transitive_imports() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::write(root.join("target.py"), "from dependency import value\n").unwrap();
        std::fs::write(
            root.join("candidate.py"),
            "from transitively_imported import value\n",
        )
        .unwrap();
        std::fs::write(root.join("dependency.py"), "value = 1\n").unwrap();
        std::fs::write(root.join("transitively_imported.py"), "value = 2\n").unwrap();
        let target = ProjectFile::new(root.clone(), PathBuf::from("target.py"));
        let candidate = ProjectFile::new(root.clone(), PathBuf::from("candidate.py"));
        let dependency = ProjectFile::new(root.clone(), PathBuf::from("dependency.py"));
        let transitive = ProjectFile::new(root.clone(), PathBuf::from("transitively_imported.py"));
        let candidates = [candidate.clone()].into_iter().collect();

        let graph = build_python_graph(&candidates, &target, None);

        assert_eq!(graph.parsed.len(), 2);
        assert!(graph.parsed.contains_key(&target));
        assert!(graph.parsed.contains_key(&candidate));
        assert!(!graph.parsed.contains_key(&dependency));
        assert!(!graph.parsed.contains_key(&transitive));
    }
}
