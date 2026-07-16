use crate::analyzer::usages::graph_core::{ImportEdge, ImportEdgeKind};
use crate::analyzer::usages::local_inference::{
    LocalBindingsSnapshot, LocalInferenceConfig, LocalInferenceEngine, SymbolResolution,
};
use crate::analyzer::usages::model::UsageHit;
use crate::analyzer::usages::python_graph::hits::{
    record_hit, record_import_hit, record_unproven_hit,
};
use crate::analyzer::usages::python_graph::resolver::{
    member_name, normalized_receiver_type, receiver_annotation_matches_target,
    resolve_receiver_type, target_owner_code_unit, top_level_identifier,
};
use crate::analyzer::{
    CodeUnit, IAnalyzer, ModuleBindingEvent, ModuleBindingEventKind, ModuleBindingTimeline,
    ProjectFile, PythonAnalyzer, PythonScopeFacts, Range,
};
use crate::cancellation::CancellationToken;
use crate::hash::{HashMap, HashSet};
use crate::text_utils::compute_line_starts;
use rayon::prelude::*;
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use tree_sitter::{Node, Parser, Tree};

pub(super) struct ParsedFile {
    pub(super) source: Arc<String>,
    pub(super) tree: Tree,
}

pub(crate) struct PythonProjectGraph {
    parsed: HashMap<ProjectFile, ParsedFile>,
}

impl PythonProjectGraph {
    pub(super) fn scan_files(
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

pub(super) fn build_python_graph(
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

pub(super) fn scan_files_for_seeds(
    analyzer: &dyn IAnalyzer,
    py: &PythonAnalyzer,
    graph: &PythonProjectGraph,
    files: &HashSet<ProjectFile>,
    target: &CodeUnit,
    seeds: &BTreeSet<(ProjectFile, String)>,
    cancellation: Option<&CancellationToken>,
) -> ScanResult {
    let collected: Mutex<BTreeSet<UsageHit>> = Mutex::new(BTreeSet::new());
    let unproven_collected: Mutex<BTreeSet<UsageHit>> = Mutex::new(BTreeSet::new());
    let target_short = top_level_identifier(analyzer, target);
    let target_member = member_name(analyzer, target);
    let target_owner = target_owner_code_unit(analyzer, target);
    // A same-file best-effort for unresolvable receivers is only safe when the
    // member name is unambiguous in the target's file (exactly one class there
    // declares it), so `recv.member` can only mean the target.
    let member_unique_in_target_file = target_member.as_deref().is_some_and(|member| {
        let owners: HashSet<CodeUnit> = analyzer
            .declarations(target.source())
            .into_iter()
            .filter(|decl| {
                decl.identifier() == member && target_owner_code_unit(analyzer, decl).is_some()
            })
            .filter_map(|decl| target_owner_code_unit(analyzer, &decl))
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
        let (source_str, tree_ref) = if let Some(parsed) = graph.parsed.get(*file) {
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
            let _scope = crate::profiling::scope("python_graph::matching_edges");
            py.usage_matching_edges(file, seeds)
        };
        let module_bindings = {
            let _scope = crate::profiling::scope("python_graph::module_binding_timeline");
            let raw_module_bindings = py.usage_module_binding_timeline(file, || {
                collect_module_binding_timeline(tree_ref.root_node(), source_str)
            });
            classify_module_binding_timeline(py, file, raw_module_bindings.as_ref(), seeds, &edges)
        };
        let target_self_file = *file == target.source();
        let scope_facts = {
            let _scope = crate::profiling::scope("python_graph::scope_facts");
            py.usage_scope_facts(file, || {
                collect_scope_facts_from_parsed_source(
                    analyzer,
                    py,
                    file,
                    source_str,
                    tree_ref.root_node(),
                )
            })
        };
        let scope_range_index = build_scope_range_index(analyzer, scope_facts.as_ref());

        let mut local_hits = BTreeSet::new();
        let mut local_unproven_hits = BTreeSet::new();
        let line_starts = compute_line_starts(source_str);

        let mut scan_ctx = ScanCtx {
            file,
            source: source_str,
            line_starts: &line_starts,
            analyzer,
            target_short: &target_short,
            target_member: target_member.as_deref(),
            target_owner: target_owner.clone(),
            target_is_module: target.is_module(),
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
            let _scope = crate::profiling::scope("python_graph::scan_tree");
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

pub(super) struct ScanResult {
    pub(super) hits: BTreeSet<UsageHit>,
    pub(super) unproven_hits: BTreeSet<UsageHit>,
}

pub(super) struct ScanCtx<'a> {
    pub(super) file: &'a ProjectFile,
    pub(super) source: &'a str,
    pub(super) line_starts: &'a [usize],
    pub(super) analyzer: &'a dyn IAnalyzer,
    target_short: &'a str,
    target_member: Option<&'a str>,
    target_owner: Option<CodeUnit>,
    target_is_module: bool,
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
    pub(super) hits: &'a mut BTreeSet<UsageHit>,
    pub(super) unproven_hits: &'a mut BTreeSet<UsageHit>,
}

struct ScopeRangeEntry {
    range: Range,
    scope: CodeUnit,
    prefix_max_end: usize,
}

fn build_scope_range_index(
    analyzer: &dyn IAnalyzer,
    scope_facts: &HashMap<CodeUnit, LocalBindingsSnapshot<String>>,
) -> Vec<ScopeRangeEntry> {
    let mut entries = scope_facts
        .keys()
        .flat_map(|scope| {
            analyzer
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
pub(in crate::analyzer::usages) fn enclosing_scope_facts<'a>(
    analyzer: &dyn IAnalyzer,
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
    let enclosing = analyzer.enclosing_code_unit(file, &range)?;
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
        let Some(enclosing) = self.analyzer.enclosing_code_unit(self.file, &range) else {
            return false;
        };
        if &enclosing == target_owner {
            return true;
        }
        if enclosing.is_function() {
            return target_owner_code_unit(self.analyzer, &enclosing).as_ref()
                == Some(target_owner)
                && function_declaration_expression_is_class_scoped(node);
        }
        target_owner_code_unit(self.analyzer, &enclosing).as_ref() == Some(target_owner)
    }

    /// Whether `expr`'s type is genuinely un-inferrable in `node`'s scope (an
    /// unseeded receiver such as an unannotated parameter), as opposed to a
    /// receiver we resolved to some specific — possibly different — type.
    fn receiver_type_is_unknown(&self, expr: &str, node: Node<'_>) -> bool {
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
        if !self.edges.iter().any(|edge| edge.local_name == ident) {
            return false;
        }
        let Some(events) = self.module_bindings.get(ident) else {
            return true;
        };
        let cutoff = if reference_is_deferred_function_body(node) {
            usize::MAX
        } else {
            node.start_byte()
        };
        events
            .iter()
            .rev()
            .find(|event| event.visible_from <= cutoff)
            .is_some_and(|event| event.kind == ModuleBindingKind::TargetImport)
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
        let Some(enclosing) = self.analyzer.enclosing_code_unit(self.file, &range) else {
            return false;
        };
        let enclosing_class = if enclosing.is_class() {
            enclosing
        } else {
            match target_owner_code_unit(self.analyzer, &enclosing) {
                Some(class) => class,
                None => return false,
            }
        };
        if &enclosing_class == target_owner {
            return true;
        }
        self.analyzer
            .type_hierarchy_provider()
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
        let Some(receiver_type) =
            resolve_receiver_type(self.analyzer, self.file, raw_type, self.target_self_file)
        else {
            return false;
        };
        if &receiver_type == target_owner {
            return true;
        }
        self.analyzer
            .type_hierarchy_provider()
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
            "identifier" => handle_identifier_candidate(node, ctx),
            "attribute" => handle_attribute_candidate(node, ctx),
            _ => {}
        }

        let mut cursor = node.walk();
        let mut children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
        children.reverse();
        stack.extend(children);
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
    if text.is_empty() || is_declaration_identifier(node) {
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
    record_hit(node, ctx);
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
        if ctx.receiver_binds_target(object_text, node) {
            record_hit(attribute, ctx);
        } else if member_receiver_match_is_unproven(object, object_text, node, ctx) {
            record_unproven_hit(attribute, ctx);
        }
    }

    if object.kind() == "identifier"
        && ctx.binds_target(object_text, node)
        && (ctx.target_is_module
            || (ctx.target_member.is_none()
                && !ctx.edges.iter().any(|edge| {
                    matches!(edge.kind, ImportEdgeKind::Namespace) && edge.local_name == object_text
                })))
    {
        record_hit(object, ctx);
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

    let namespace_match = ctx.edges.iter().any(|edge| {
        matches!(edge.kind, ImportEdgeKind::Namespace)
            && (edge.local_name == object_text
                || object_text.ends_with(&format!(".{}", edge.local_name)))
            && ctx
                .seeds
                .contains(&(edge.target_file.clone(), attribute_text.to_string()))
    });
    if ctx.target_member.is_none() && namespace_match {
        record_hit(attribute, ctx);
    }
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

pub(in crate::analyzer::usages) fn slice<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source.get(node.start_byte()..node.end_byte()).unwrap_or("")
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

pub(in crate::analyzer::usages) fn is_declaration_identifier(node: Node<'_>) -> bool {
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
    TargetImport,
    Other,
}

#[derive(Clone, Copy, Debug)]
struct ClassifiedModuleBindingEvent {
    visible_from: usize,
    kind: ModuleBindingKind,
}

fn collect_module_binding_timeline(root: Node<'_>, source: &str) -> ModuleBindingTimeline {
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
                    record_local_binding_targets(left, source, node.end_byte(), &mut timeline);
                }
                continue;
            }
            "for_statement" => {
                if let Some(left) = node.child_by_field_name("left") {
                    record_local_binding_targets(left, source, left.end_byte(), &mut timeline);
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
            ModuleBindingEventKind::FromImport {
                module: module.to_string(),
                imported_name: imported_name.to_string(),
            },
        );
    }
}

fn classify_module_binding_timeline(
    py: &PythonAnalyzer,
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
                let targets_query = match &event.kind {
                    ModuleBindingEventKind::ImportModule(module) => *module_targets
                        .entry(module.clone())
                        .or_insert_with(|| module_contains_seed(py, file, module, seeds)),
                    ModuleBindingEventKind::FromImport {
                        module,
                        imported_name,
                    } => {
                        let direct =
                            py.usage_resolve_module_files(file, module)
                                .iter()
                                .any(|resolved| {
                                    seeds.contains(&(resolved.clone(), imported_name.clone()))
                                });
                        let submodule = if module.ends_with('.') {
                            format!("{module}{imported_name}")
                        } else {
                            format!("{module}.{imported_name}")
                        };
                        direct
                            || *module_targets.entry(submodule.clone()).or_insert_with(|| {
                                module_contains_seed(py, file, &submodule, seeds)
                            })
                    }
                    ModuleBindingEventKind::Other => false,
                };
                ClassifiedModuleBindingEvent {
                    visible_from: event.visible_from,
                    kind: if targets_query {
                        ModuleBindingKind::TargetImport
                    } else {
                        ModuleBindingKind::Other
                    },
                }
            })
            .collect();
        classified.insert(local.clone(), classified_events);
    }
    classified
}

fn module_contains_seed(
    py: &PythonAnalyzer,
    file: &ProjectFile,
    module: &str,
    seeds: &BTreeSet<(ProjectFile, String)>,
) -> bool {
    py.usage_resolve_module_files(file, module)
        .iter()
        .any(|resolved| seeds.iter().any(|(seed_file, _)| seed_file == resolved))
}

fn record_module_binding(
    timeline: &mut ModuleBindingTimeline,
    name: &str,
    visible_from: usize,
    kind: ModuleBindingEventKind,
) {
    let name = name.trim();
    if name.is_empty() {
        return;
    }
    timeline
        .entry(name.to_string())
        .or_default()
        .push(ModuleBindingEvent { visible_from, kind });
}

fn record_local_binding_targets(
    target: Node<'_>,
    source: &str,
    visible_from: usize,
    timeline: &mut ModuleBindingTimeline,
) {
    let mut stack = vec![target];
    while let Some(node) = stack.pop() {
        if node.kind() == "identifier" {
            record_module_binding(
                timeline,
                slice(node, source),
                visible_from,
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

pub(in crate::analyzer::usages) fn collect_assigned_identifiers(
    node: Node<'_>,
    source: &str,
    out: &mut HashSet<String>,
) {
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

pub(in crate::analyzer::usages) fn collect_scope_facts_from_parsed_source(
    analyzer: &dyn IAnalyzer,
    py: &PythonAnalyzer,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
) -> PythonScopeFacts {
    let mut factory_return_types = collect_factory_return_types_from_root(root, source);
    collect_imported_factory_return_types(analyzer, py, file, &mut factory_return_types);
    collect_scope_facts_with_factory_returns(analyzer, file, source, &factory_return_types)
}

fn collect_imported_factory_return_types(
    analyzer: &dyn IAnalyzer,
    py: &PythonAnalyzer,
    file: &ProjectFile,
    factory_return_types: &mut HashMap<String, String>,
) {
    let binder = py.import_binder_of(file);
    for (local, binding) in &binder.bindings {
        if !matches!(
            binding.kind,
            crate::analyzer::usages::model::ImportKind::Named
        ) {
            continue;
        }
        let Some(imported) = binding.imported_name.as_deref() else {
            continue;
        };
        let fqn = format!("{}.{}", binding.module_specifier, imported);
        let units = py.resolve_fqn_candidates(&fqn, |name| analyzer.definitions(name).collect());
        for unit in units {
            if unit.is_function() {
                if let Some(return_type) = callable_return_type_name(analyzer, &unit) {
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
                analyzer,
                local,
                &unit,
                factory_return_types,
            );
        }
    }
}

fn collect_imported_class_method_return_types(
    analyzer: &dyn IAnalyzer,
    local_class_name: &str,
    class_unit: &CodeUnit,
    factory_return_types: &mut HashMap<String, String>,
) {
    for member in analyzer.direct_children(class_unit) {
        if !member.is_function() {
            continue;
        }
        let Some(return_type) = callable_return_type_name(analyzer, &member) else {
            continue;
        };
        factory_return_types
            .entry(format!("{}.{}", local_class_name, member.identifier()))
            .or_insert(return_type);
    }
}

fn callable_return_type_name(analyzer: &dyn IAnalyzer, callable: &CodeUnit) -> Option<String> {
    let source = analyzer.indexed_source(callable.source())?;
    declaration_source_slices(analyzer, callable, &source)
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
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    factory_return_types: &HashMap<String, String>,
) -> PythonScopeFacts {
    let declarations = analyzer.declarations(file);
    let mut class_facts_by_name: HashMap<String, LocalBindingsSnapshot<String>> =
        HashMap::default();
    for declaration in declarations
        .iter()
        .filter(|declaration| declaration.is_class())
    {
        let Some(declaration_source) = declaration_source(analyzer, declaration, source) else {
            continue;
        };
        let facts = collect_scope_facts_from_source(
            &declaration_source,
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
        let Some(declaration_source) = declaration_source(analyzer, declaration, source) else {
            continue;
        };
        let owner = declaration
            .short_name()
            .rsplit_once('.')
            .map(|(owner, _)| owner);
        let mut facts = collect_scope_facts_from_source(
            &declaration_source,
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
        let Some(declaration_source) = declaration_source(analyzer, declaration, source) else {
            continue;
        };
        let facts =
            collect_scope_facts_from_source(&declaration_source, false, None, factory_return_types);
        scope_facts.insert(declaration.clone(), facts);
    }
    scope_facts
}

fn declaration_source(
    analyzer: &dyn IAnalyzer,
    declaration: &CodeUnit,
    file_source: &str,
) -> Option<String> {
    let slices = declaration_source_slices(analyzer, declaration, file_source);
    (!slices.is_empty()).then(|| slices.join("\n\n"))
}

fn declaration_source_slices<'a>(
    analyzer: &dyn IAnalyzer,
    declaration: &CodeUnit,
    file_source: &'a str,
) -> Vec<&'a str> {
    let mut ranges = analyzer.ranges(declaration);
    ranges.sort_by_key(|range| range.start_byte);
    ranges
        .into_iter()
        .filter_map(|range| file_source.get(range.start_byte..range.end_byte))
        .collect()
}

fn collect_scope_facts_from_source(
    source: &str,
    allow_self_receivers: bool,
    current_class: Option<&str>,
    factory_return_types: &HashMap<String, String>,
) -> LocalBindingsSnapshot<String> {
    let events = collect_scope_fact_events(source);
    let mut engine = LocalInferenceEngine::new(LocalInferenceConfig::default());
    for event in &events {
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
        for event in &events {
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

fn collect_scope_fact_events(source: &str) -> Vec<ScopeFactEvent> {
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
    collect_scope_fact_events_from_node(tree.root_node(), source, &mut events);
    events
}

fn collect_scope_fact_events_from_node(
    root: Node<'_>,
    source: &str,
    events: &mut Vec<ScopeFactEvent>,
) {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "parameters" => collect_parameter_events(node, source, events),
            "assignment" => collect_assignment_events(node, source, events),
            _ => {}
        }

        let mut cursor = node.walk();
        let mut children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
        children.reverse();
        stack.extend(children);
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
