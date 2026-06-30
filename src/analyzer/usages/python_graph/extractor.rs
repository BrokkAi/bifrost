use crate::analyzer::usages::graph_core::{ImportEdge, ImportEdgeKind};
use crate::analyzer::usages::local_inference::{
    LocalBindingsSnapshot, LocalInferenceConfig, LocalInferenceEngine, SymbolResolution,
};
use crate::analyzer::usages::model::{ExportIndex, ImportBinder, UsageHit};
use crate::analyzer::usages::python_graph::hits::record_hit;
use crate::analyzer::usages::python_graph::resolver::{
    member_name, normalized_receiver_type, receiver_annotation_matches_target,
    resolve_receiver_type, target_owner_code_unit, top_level_identifier,
};
use crate::analyzer::{CodeUnit, IAnalyzer, ProjectFile, PythonAnalyzer, Range};
use crate::hash::{HashMap, HashSet};
use crate::text_utils::compute_line_starts;
use rayon::prelude::*;
use std::collections::{BTreeSet, VecDeque};
use std::sync::{Arc, Mutex};
use tree_sitter::{Node, Parser, Tree};

pub(super) struct ParsedFile {
    pub(super) source: Arc<String>,
    pub(super) tree: Tree,
}

pub(crate) struct PythonProjectGraph {
    parsed: HashMap<ProjectFile, ParsedFile>,
    scoped_files: HashSet<ProjectFile>,
}

impl PythonProjectGraph {
    pub(super) fn scan_files(
        &self,
        candidate_files: &HashSet<ProjectFile>,
        target_file: &ProjectFile,
    ) -> HashSet<ProjectFile> {
        candidate_files
            .iter()
            .filter(|file| self.scoped_files.contains(*file))
            .cloned()
            .chain(std::iter::once(target_file.clone()))
            .collect()
    }
}

struct PythonGraphAdapter<'a> {
    analyzer: &'a PythonAnalyzer,
}

impl<'a> PythonGraphAdapter<'a> {
    fn new(analyzer: &'a PythonAnalyzer) -> Self {
        Self { analyzer }
    }

    /// Parse the scoped import closure once for tree reuse during the forward
    /// scan. Re-export / importer resolution now lives on the analyzer
    /// (`PythonAnalyzer::usage_*`), so this no longer builds a cross-file graph.
    fn build_graph(
        &self,
        candidate_files: &HashSet<ProjectFile>,
        target_file: &ProjectFile,
    ) -> PythonProjectGraph {
        let parser_language = tree_sitter_python::LANGUAGE.into();
        let mut scoped_files: HashSet<ProjectFile> = candidate_files.iter().cloned().collect();
        scoped_files.insert(target_file.clone());

        let mut frontier: VecDeque<ProjectFile> = scoped_files.iter().cloned().collect();
        let mut parsed: HashMap<ProjectFile, ParsedFile> = HashMap::default();

        while let Some(file) = frontier.pop_front() {
            if parsed.contains_key(&file) {
                continue;
            }

            let Ok(source) = file.read_to_string() else {
                continue;
            };
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

            let exports = self.analyzer.export_index_of(&file);
            let binder = self.analyzer.import_binder_of(&file);
            self.enqueue_frontier_files(&file, &exports, &binder, &mut scoped_files, &mut frontier);

            parsed.insert(
                file.clone(),
                ParsedFile {
                    source: Arc::new(source),
                    tree,
                },
            );
        }

        PythonProjectGraph {
            parsed,
            scoped_files,
        }
    }

    fn enqueue_frontier_files(
        &self,
        file: &ProjectFile,
        exports: &ExportIndex,
        binder: &ImportBinder,
        scoped_files: &mut HashSet<ProjectFile>,
        frontier: &mut VecDeque<ProjectFile>,
    ) {
        for entry in exports.exports_by_name.values() {
            if let crate::analyzer::usages::ExportEntry::ReexportedNamed {
                module_specifier, ..
            } = entry
            {
                self.extend_scope(file, module_specifier, scoped_files, frontier);
            }
        }
        for star in &exports.reexport_stars {
            self.extend_scope(file, &star.module_specifier, scoped_files, frontier);
        }
        for binding in binder.bindings.values() {
            self.extend_scope(file, &binding.module_specifier, scoped_files, frontier);
        }
    }

    fn extend_scope(
        &self,
        importing_file: &ProjectFile,
        module_specifier: &str,
        scoped_files: &mut HashSet<ProjectFile>,
        frontier: &mut VecDeque<ProjectFile>,
    ) {
        for resolved in self.resolve_module(importing_file, module_specifier) {
            if scoped_files.insert(resolved.clone()) {
                frontier.push_back(resolved);
            }
        }
    }

    fn resolve_module(
        &self,
        importing_file: &ProjectFile,
        module_specifier: &str,
    ) -> Vec<ProjectFile> {
        self.analyzer
            .resolve_module_files(importing_file, module_specifier)
    }
}

pub(super) fn build_python_graph(
    analyzer: &PythonAnalyzer,
    candidate_files: &HashSet<ProjectFile>,
    target_file: &ProjectFile,
) -> PythonProjectGraph {
    PythonGraphAdapter::new(analyzer).build_graph(candidate_files, target_file)
}

pub(super) fn scan_files_for_seeds(
    analyzer: &dyn IAnalyzer,
    py: &PythonAnalyzer,
    graph: &PythonProjectGraph,
    files: &HashSet<ProjectFile>,
    target: &CodeUnit,
    seeds: &BTreeSet<(ProjectFile, String)>,
) -> BTreeSet<UsageHit> {
    let collected: Mutex<BTreeSet<UsageHit>> = Mutex::new(BTreeSet::new());
    let target_short = top_level_identifier(target).to_string();
    let target_member = member_name(target);
    let target_owner = target_owner_code_unit(analyzer, target);
    let files_vec: Vec<&ProjectFile> = files.iter().collect();
    let parser_language = tree_sitter_python::LANGUAGE.into();

    files_vec.par_iter().for_each(|file| {
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

        let edges = py.usage_matching_edges(file, seeds);
        let local_conflicts = collect_top_level_conflicts(tree_ref.root_node(), source_str);
        let target_self_file = *file == target.source();
        let scope_facts = collect_scope_facts(
            analyzer,
            file,
            &edges,
            target_short.as_str(),
            target_self_file,
        );

        let mut local_hits = BTreeSet::new();
        let line_starts = compute_line_starts(source_str);

        let mut scan_ctx = ScanCtx {
            file,
            source: source_str,
            line_starts: &line_starts,
            analyzer,
            target_short: &target_short,
            target_member: target_member.as_deref(),
            target_owner: target_owner.clone(),
            edges: &edges,
            target_self_file,
            local_conflicts: &local_conflicts,
            scope_facts: &scope_facts,
            hits: &mut local_hits,
        };

        scan_node(tree_ref.root_node(), &mut scan_ctx);

        if !local_hits.is_empty() {
            let mut sink = collected
                .lock()
                .expect("usage hit collector mutex poisoned");
            sink.extend(local_hits);
        }
    });

    collected
        .into_inner()
        .expect("usage hit collector mutex poisoned")
}

pub(super) struct ScanCtx<'a> {
    pub(super) file: &'a ProjectFile,
    pub(super) source: &'a str,
    pub(super) line_starts: &'a [usize],
    pub(super) analyzer: &'a dyn IAnalyzer,
    target_short: &'a str,
    target_member: Option<&'a str>,
    target_owner: Option<CodeUnit>,
    edges: &'a [ImportEdge],
    target_self_file: bool,
    local_conflicts: &'a HashSet<String>,
    scope_facts: &'a HashMap<CodeUnit, LocalBindingsSnapshot<String>>,
    pub(super) hits: &'a mut BTreeSet<UsageHit>,
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
    fn scope_facts_for_node(&self, node: Node<'_>) -> Option<&LocalBindingsSnapshot<String>> {
        enclosing_scope_facts(self.analyzer, self.file, self.scope_facts, node)
    }

    fn binds_target(&self, ident: &str, node: Node<'_>) -> bool {
        if let Some(scope_facts) = self.scope_facts_for_node(node)
            && scope_facts.is_shadowed(ident)
        {
            return false;
        }
        if !self.target_self_file && self.local_conflicts.contains(ident) {
            return false;
        }
        if self.edges.iter().any(|edge| edge.local_name == ident) {
            return true;
        }
        self.target_self_file && ident == self.target_short
    }

    fn receiver_binds_target(&self, expr: &str, node: Node<'_>) -> bool {
        if self.binds_target(expr, node) {
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

fn scan_node(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "import_statement" | "import_from_statement" => continue,
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

fn handle_identifier_candidate(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if ctx.target_member.is_some() {
        return;
    }
    if node
        .parent()
        .is_some_and(|parent| parent.kind() == "attribute")
    {
        return;
    }
    let text = slice(node, ctx.source);
    if text.is_empty() || !ctx.binds_target(text, node) || is_declaration_identifier(node) {
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
        && ctx.receiver_binds_target(object_text, node)
        && attribute_text == member
    {
        record_hit(attribute, ctx);
    }

    let namespace_match = ctx.edges.iter().any(|edge| {
        matches!(edge.kind, ImportEdgeKind::Namespace)
            && (edge.local_name == object_text
                || object_text.ends_with(&format!(".{}", edge.local_name)))
    });
    if ctx.target_member.is_none() && namespace_match && attribute_text == ctx.target_short {
        record_hit(attribute, ctx);
    }
}

pub(in crate::analyzer::usages) fn slice<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source.get(node.start_byte()..node.end_byte()).unwrap_or("")
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

fn collect_top_level_conflicts(root: Node<'_>, source: &str) -> HashSet<String> {
    let mut conflicts = HashSet::default();
    let mut cursor = root.walk();
    for child in root.named_children(&mut cursor) {
        match child.kind() {
            "class_definition" | "function_definition" => {
                if let Some(name) = child.child_by_field_name("name") {
                    let text = slice(name, source).trim();
                    if !text.is_empty() {
                        conflicts.insert(text.to_string());
                    }
                }
            }
            "expression_statement" => {
                if let Some(assignment) = child.named_child(0)
                    && assignment.kind() == "assignment"
                    && let Some(left) = assignment.child_by_field_name("left")
                {
                    collect_assigned_identifiers(left, source, &mut conflicts);
                }
            }
            _ => {}
        }
    }
    conflicts
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

pub(in crate::analyzer::usages) fn collect_scope_facts(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    edges: &[ImportEdge],
    target_short: &str,
    target_self_file: bool,
) -> HashMap<CodeUnit, LocalBindingsSnapshot<String>> {
    let declarations = analyzer.get_declarations(file);
    let mut class_facts_by_name: HashMap<String, LocalBindingsSnapshot<String>> =
        HashMap::default();
    for declaration in declarations
        .iter()
        .filter(|declaration| declaration.is_class())
    {
        let Some(source) = analyzer.get_source(declaration, false) else {
            continue;
        };
        let facts =
            collect_scope_facts_from_source(&source, edges, target_short, target_self_file, true);
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
        let Some(source) = analyzer.get_source(declaration, false) else {
            continue;
        };
        let mut facts =
            collect_scope_facts_from_source(&source, edges, target_short, target_self_file, false);
        if let Some((owner, _)) = declaration.short_name().rsplit_once('.')
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
        let Some(source) = analyzer.get_source(declaration, false) else {
            continue;
        };
        let facts =
            collect_scope_facts_from_source(&source, edges, target_short, target_self_file, false);
        scope_facts.insert(declaration.clone(), facts);
    }
    scope_facts
}

fn collect_scope_facts_from_source(
    source: &str,
    _edges: &[ImportEdge],
    _target_short: &str,
    _target_self_file: bool,
    allow_self_receivers: bool,
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
        .map(AssignmentRhs::Symbol)
        .unwrap_or(AssignmentRhs::Unknown);
    events.push(ScopeFactEvent::Assignment { lhs, rhs });
}

fn receiver_symbol(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "identifier" | "attribute" => non_empty_node_text(node, source),
        _ => None,
    }
}

fn rhs_symbol(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "identifier" | "attribute" => non_empty_node_text(node, source),
        "call" => node
            .child_by_field_name("function")
            .or_else(|| node.named_child(0))
            .and_then(|callee| receiver_symbol(callee, source)),
        _ => None,
    }
}

fn non_empty_node_text(node: Node<'_>, source: &str) -> Option<String> {
    let text = slice(node, source).trim();
    (!text.is_empty()).then(|| text.to_string())
}
