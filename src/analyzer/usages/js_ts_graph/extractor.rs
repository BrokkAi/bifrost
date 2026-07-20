use crate::analyzer::js_ts::imports::require_call_module_specifier;
use crate::analyzer::js_ts::syntax::{
    JsTsLexicalBindingIndex, JsTsLexicalBindingScope, direct_property_definitions,
    is_commonjs_require_declarator, is_declaration_identifier,
    is_lexically_nested_type_declaration, is_object_in_member_expression,
    is_property_key_in_member, nested_type_identifier_parts, slice, static_member_receiver,
};
use crate::analyzer::usages::get_definition::js_ts::{
    ts_resolve_type_text_to_property_owners, ts_type_annotation_text,
};
use crate::analyzer::usages::graph_core::{ImportEdge, ImportEdgeKind};
use crate::analyzer::usages::js_ts_graph::JsTsReceiverFactProvider;
use crate::analyzer::usages::js_ts_graph::hits::{
    record_hit, record_import_hit, record_reexport_hit, record_self_receiver_hit,
    record_unproven_hit,
};
use crate::analyzer::usages::js_ts_graph::resolver::{
    JsTsUsageIndex, browser_global_property_shape, is_static_member, member_name,
    unbound_browser_global_property,
};
use crate::analyzer::usages::local_inference::{LocalInferenceConfig, LocalInferenceEngine};
use crate::analyzer::usages::model::{ExportEntry, ExportIndex, ImportBinder, UsageHit};
use crate::analyzer::usages::parsed_tree::js_ts_tree_sitter_language_for_file;
use crate::analyzer::usages::receiver_analysis::{ReceiverAnalysisBudget, ReceiverAnalysisOutcome};
use crate::analyzer::{AliasResolver, CodeUnit, IAnalyzer, Language, ProjectFile, Range};
use crate::cancellation::CancellationToken;
use crate::hash::{HashMap, HashSet};
use crate::text_utils::compute_line_starts;
use rayon::prelude::*;
use std::collections::BTreeSet;
use std::sync::Mutex;
use tree_sitter::{Node, Parser, Tree};

const TARGET_BINDING: &str = "__target__";
const TARGET_VALUE_BINDING: &str = "__target_value__";
const TARGET_OBJECT_BINDING: &str = "__target_object__";

#[allow(clippy::too_many_arguments)]
pub(super) fn scan_files_for_seeds(
    analyzer: &dyn IAnalyzer,
    index: &JsTsUsageIndex,
    files: &HashSet<ProjectFile>,
    target: &CodeUnit,
    seeds: &BTreeSet<(ProjectFile, String)>,
    language: Language,
    exported_local_property_root: Option<&str>,
    cancellation: Option<&CancellationToken>,
) -> BTreeSet<UsageHit> {
    let collected: Mutex<BTreeSet<UsageHit>> = Mutex::new(BTreeSet::new());
    let unproven_collected: Mutex<BTreeSet<UsageHit>> = Mutex::new(BTreeSet::new());
    let browser_global_shape = (language == Language::JavaScript)
        .then(|| browser_global_property_shape(target))
        .flatten();
    let target_owner = analyzer.parent_of(target);
    let target_member = target_owner
        .as_ref()
        .is_none_or(|owner| !owner.is_module() && !owner.is_file_scope())
        .then(|| member_name(target))
        .flatten();
    let browser_global_object = target_owner
        .is_none()
        .then(|| browser_global_shape.map(|(object, _)| object))
        .flatten();
    let lookup_only_local_property = language == Language::JavaScript
        && target_owner.is_none()
        && target.is_field()
        && exported_local_property_root.is_none()
        && !analyzer.declarations(target.source()).contains(target);
    let direct_local_property =
        lookup_only_local_property || exported_local_property_root.is_some();
    let direct_local_property_ranges = direct_local_property.then(|| analyzer.ranges(target));
    let target_short = target_seed_identifier(target, target_owner.as_ref());
    let reference_needle = target_member.as_deref().unwrap_or(&target_short);
    let target_owner_source = target_owner.as_ref().map(|owner| owner.source().clone());

    let files_vec: Vec<&ProjectFile> = files.iter().collect();

    files_vec.par_iter().for_each(|file| {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return;
        }
        // The resolution maps are analyzer-cached, but the syntax trees are not — parse
        // each scan file here and drop it when this closure returns, so a repeated query
        // re-parses only its candidate closure, never the whole workspace.
        let Ok(source) = file.read_to_string() else {
            return;
        };
        if source.is_empty() {
            return;
        }
        let edges = index.matching_edges_for_importer(file, seeds);
        // A same-file reference must spell the declaration name. Importers may
        // instead spell an exported alias, whose identity is carried by `edges`
        // and `seeds` and is resolved structurally below.
        if edges.is_empty() && !source.contains(reference_needle) {
            return;
        }
        let mut parser = Parser::new();
        let Some(parser_language) = js_ts_tree_sitter_language_for_file(file, language) else {
            return;
        };
        if parser.set_language(&parser_language).is_err() {
            return;
        }
        let Some(tree) = parser.parse(source.as_str(), None) else {
            return;
        };
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return;
        }
        let source_str = source.as_str();
        let tree_ref = &tree;

        let imports = index.binders_by_file.get(file).cloned().unwrap_or_default();
        let aliases = AliasResolver::new(analyzer.project().root().to_path_buf());

        let mut local_hits: BTreeSet<UsageHit> = BTreeSet::new();
        let mut local_unproven_hits: BTreeSet<UsageHit> = BTreeSet::new();
        let line_starts = compute_line_starts(source_str);

        let target_self_file = *file == target.source();
        let mut binding_engine = LocalInferenceEngine::new(LocalInferenceConfig::default());
        for edge in &edges {
            if edge_binds_bare_identifier(edge) {
                binding_engine.seed_symbol(edge.local_name.clone(), TARGET_BINDING);
            }
        }
        if target_self_file {
            binding_engine.seed_symbol(target_short.clone(), TARGET_BINDING);
        }

        let root = tree_ref.root_node();
        let lexical_bindings = ((browser_global_object.is_some() || direct_local_property)
            && target_self_file)
            .then(|| JsTsLexicalBindingIndex::build(root, source_str));
        let browser_global_object = lexical_bindings.as_ref().and_then(|lexical_bindings| {
            unbound_browser_global_property(analyzer, target, root, source_str, lexical_bindings)
                .map(|(object, _)| object)
        });
        let local_property_definitions = lexical_bindings.as_ref().and_then(|lexical_bindings| {
            let target_member = target_member.as_deref()?;
            let target_ranges = direct_local_property_ranges.as_deref()?;
            let definitions = collect_local_property_definitions(
                root,
                source_str,
                target_ranges,
                target_member,
                lexical_bindings,
                exported_local_property_root,
            );
            (!definitions.is_empty()).then_some(definitions)
        });
        let receiver_facts = JsTsReceiverFactProvider::new(
            analyzer,
            analyzer.global_usage_definition_index(),
            language,
            file,
            source_str,
            root,
            imports.clone(),
        );
        let mut scan_ctx = ScanCtx {
            file,
            source: source_str,
            line_starts: &line_starts,
            analyzer,
            target,
            target_short: &target_short,
            target_member: target_member.as_deref(),
            browser_global_object,
            lookup_only_local_property,
            local_property_definitions,
            edges: &edges,
            seeds,
            target_self_file,
            target_is_static_member: is_static_member(target),
            target_owner: target_owner.as_ref(),
            target_owner_source: target_owner_source.as_ref(),
            imports,
            aliases,
            receiver_facts,
            lexical_bindings,
            scope_stack: vec![HashMap::default()],
            binding_engine,
            type_binding_engine: LocalInferenceEngine::new(LocalInferenceConfig::default()),
            hits: &mut local_hits,
            unproven_hits: &mut local_unproven_hits,
        };

        scan_node(tree_ref.root_node(), &mut scan_ctx);

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

    let hits = collected
        .into_inner()
        .expect("usage hit collector mutex poisoned");
    let unproven_hits = unproven_collected
        .into_inner()
        .expect("usage unproven hit collector mutex poisoned");
    hits.into_iter().chain(unproven_hits).collect()
}

pub(super) struct ScanCtx<'a> {
    pub(super) file: &'a ProjectFile,
    pub(super) source: &'a str,
    pub(super) line_starts: &'a [usize],
    pub(super) analyzer: &'a dyn IAnalyzer,
    target: &'a CodeUnit,
    /// Top-level identifier (the class/function/field's own name component).
    target_short: &'a str,
    /// For members, the member name (e.g. `foo` in `BaseClass.foo`); otherwise None.
    target_member: Option<&'a str>,
    /// Exact host object for a parentless browser-global property such as `window.Promise`.
    browser_global_object: Option<&'a str>,
    /// Parentless JS fields omitted from the declaration catalog remain available for
    /// exact, same-file definition lookup and targeted usage scans.
    lookup_only_local_property: bool,
    local_property_definitions: Option<Vec<LocalPropertyDefinition>>,
    /// Import edges from this file that resolve to the target's seed set.
    edges: &'a [ImportEdge],
    /// Exported names that resolve to the target, including local and re-export aliases.
    seeds: &'a BTreeSet<(ProjectFile, String)>,
    /// True when this scan is over the target's own defining file (used to also catch
    /// in-file references that don't go through an import binding).
    target_self_file: bool,
    target_is_static_member: bool,
    target_owner: Option<&'a CodeUnit>,
    target_owner_source: Option<&'a ProjectFile>,
    imports: ImportBinder,
    aliases: AliasResolver,
    receiver_facts: JsTsReceiverFactProvider<'a, 'a>,
    lexical_bindings: Option<JsTsLexicalBindingIndex>,
    scope_stack: Vec<HashMap<String, LocalBinding>>,
    binding_engine: LocalInferenceEngine<&'static str>,
    type_binding_engine: LocalInferenceEngine<()>,
    pub(super) hits: &'a mut BTreeSet<UsageHit>,
    pub(super) unproven_hits: &'a mut BTreeSet<UsageHit>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LocalBinding {
    Other,
    KnownUnrelated,
    TargetReceiver,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LocalPropertyDefinition {
    receiver_root: String,
    receiver_members: Vec<String>,
    scope: JsTsLexicalBindingScope,
    property_range: Range,
}

fn collect_local_property_definitions(
    root: Node<'_>,
    source: &str,
    target_ranges: &[Range],
    target_member: &str,
    lexical_bindings: &JsTsLexicalBindingIndex,
    required_receiver: Option<&str>,
) -> Vec<LocalPropertyDefinition> {
    direct_property_definitions(root, source, target_ranges, target_member)
        .into_iter()
        .filter_map(|fact| {
            let receiver_root = slice(fact.receiver.root, source);
            if required_receiver.is_some_and(|required| {
                receiver_root != required || !fact.receiver.members.is_empty()
            }) {
                return None;
            }
            let scope = lexical_bindings
                .binding_scope_at(receiver_root, fact.receiver.root.start_byte())?;
            let definition = LocalPropertyDefinition {
                receiver_root: receiver_root.to_string(),
                receiver_members: fact
                    .receiver
                    .members
                    .into_iter()
                    .map(|member| slice(member, source).to_string())
                    .collect(),
                scope,
                property_range: fact.property_range,
            };
            Some(definition)
        })
        .collect()
}

fn local_property_read_matches(
    object: Node<'_>,
    property: Node<'_>,
    source: &str,
    lexical_bindings: &JsTsLexicalBindingIndex,
    definitions: &[LocalPropertyDefinition],
) -> bool {
    let Some(receiver) = static_member_receiver(object, source) else {
        return false;
    };
    let receiver_root = slice(receiver.root, source);
    let Some(scope) = lexical_bindings.binding_scope_at(receiver_root, receiver.root.start_byte())
    else {
        return false;
    };
    definitions.iter().any(|definition| {
        definition.receiver_root == receiver_root
            && definition.receiver_members.len() == receiver.members.len()
            && definition
                .receiver_members
                .iter()
                .zip(&receiver.members)
                .all(|(expected, actual)| expected == slice(*actual, source))
            && definition.scope == scope
            && definition.property_range.end_byte <= property.start_byte()
    })
}

impl ScanCtx<'_> {
    fn binds_target(&self, ident: &str) -> bool {
        let local_resolution = self.binding_engine.resolve_symbol(ident);
        if local_resolution.as_precise().is_some_and(|targets| {
            targets.contains(TARGET_BINDING) || targets.contains(TARGET_VALUE_BINDING)
        }) {
            return true;
        }
        if self.binding_engine.is_shadowed(ident) {
            return false;
        }
        if self
            .edges
            .iter()
            .any(|edge| edge.local_name == ident && edge_binds_bare_identifier(edge))
        {
            return true;
        }
        // In the target's own file, the bare class/function name is itself a reference
        // worth reporting (covers `BaseClass.foo()` and `extends BaseClass` written in
        // the same file).
        self.target_self_file && ident == self.target_short
    }

    fn binds_target_type(&self, ident: &str) -> bool {
        if self.type_binding_engine.is_shadowed(ident) {
            return false;
        }
        if self
            .edges
            .iter()
            .any(|edge| edge.local_name == ident && edge_binds_bare_identifier(edge))
        {
            return true;
        }
        self.target_self_file && ident == self.target_short
    }

    fn binds_target_value(&self, ident: &str) -> bool {
        self.binding_engine
            .resolve_symbol(ident)
            .as_precise()
            .is_some_and(|targets| targets.contains(TARGET_VALUE_BINDING))
    }

    fn binds_target_object(&self, ident: &str) -> bool {
        self.binding_engine
            .resolve_symbol(ident)
            .as_precise()
            .is_some_and(|targets| targets.contains(TARGET_OBJECT_BINDING))
    }
}

fn edge_binds_bare_identifier(edge: &ImportEdge) -> bool {
    !matches!(
        edge.kind,
        ImportEdgeKind::Namespace | ImportEdgeKind::CommonJsRequire(_)
    )
}

fn scan_node(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let kind = node.kind();

    let introduces_scope = matches!(
        kind,
        "statement_block"
            | "arrow_function"
            | "function_expression"
            | "generator_function"
            | "function_declaration"
            | "method_definition"
    );
    if introduces_scope {
        ctx.binding_engine.enter_scope();
        ctx.type_binding_engine.enter_scope();
        register_function_parameters(node, ctx);
        ctx.scope_stack.push(HashMap::default());
        register_scope_parameters(node, ctx);
    }
    register_lexical_type_shadow(node, ctx);

    // Skip import statements outright — bindings declared there are not usages.
    if matches!(
        kind,
        "import_statement" | "import_clause" | "import_specifier" | "namespace_import"
    ) {
        if kind == "import_statement" {
            handle_import_statement(node, ctx);
        }
        if introduces_scope {
            ctx.scope_stack.pop();
            ctx.binding_engine.exit_scope();
            ctx.type_binding_engine.exit_scope();
        }
        return;
    }
    // An export specifier's `name` forwards the referenced symbol, whereas its
    // optional `alias` declares the outward-facing name. Retain the forwarding
    // occurrence for IDE references, but classify it separately so agent/search
    // usage results can omit binding-only noise.
    if kind == "export_specifier" {
        handle_export_specifier(node, ctx);
        return;
    }
    if kind == "expression_statement" && is_commonjs_export_statement(node, ctx.source) {
        if let Some(value) = node
            .named_child(0)
            .and_then(|assignment| assignment.child_by_field_name("right"))
        {
            scan_node(value, ctx);
        }
        return;
    }

    if kind == "variable_declarator" && !is_commonjs_require_declarator(node, ctx.source) {
        register_local_binding(node, ctx);
        register_declaration(node, ctx);
    }
    if kind == "for_in_statement" {
        register_for_in_destructuring_bindings(node, ctx);
    }

    match kind {
        "nested_type_identifier" => handle_nested_type_identifier(node, ctx),
        "identifier" | "type_identifier" | "shorthand_property_identifier" => {
            handle_identifier_candidate(node, ctx);
        }
        "member_expression" => handle_member_expression(node, ctx),
        "object" => handle_contextual_object_literal(node, ctx),
        "jsx_opening_element" | "jsx_self_closing_element" => handle_jsx_element(node, ctx),
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        scan_node(child, ctx);
    }

    if introduces_scope {
        ctx.scope_stack.pop();
        ctx.binding_engine.exit_scope();
        ctx.type_binding_engine.exit_scope();
    }
}

fn register_lexical_type_shadow(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if !is_lexically_nested_type_declaration(node) {
        return;
    }
    let Some(name) = node.child_by_field_name("name") else {
        return;
    };
    let text = slice(name, ctx.source);
    if text == ctx.target_short {
        ctx.type_binding_engine.declare_shadow(text.to_string());
    }
}

/// Emit an `Import`-binding hit for each ESM `import` specifier whose local
/// binding resolves to the target (per `ctx.edges`). This makes LSP
/// find-references report the import line, while the call-graph / relevance
/// surfaces (which filter `Import` hits) stay import-free. Members are imported
/// through their owner rather than by their own name, so member targets emit
/// nothing here — mirroring the Python graph's `handle_import_candidate`.
fn handle_import_statement(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if ctx.target_member.is_some() {
        return;
    }
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        match current.kind() {
            // `{ Target }` or `{ Orig as Alias }`: the local binding is the alias
            // when present, else the imported name; the token that *is* the target
            // is always the imported-name node.
            "import_specifier" => {
                let name = current.child_by_field_name("name");
                let local = current.child_by_field_name("alias").or(name);
                if let (Some(name_node), Some(local_node)) = (name, local) {
                    let local_name = slice(local_node, ctx.source);
                    if ctx.edges.iter().any(|edge| edge.local_name == local_name) {
                        record_import_hit(name_node, ctx);
                    }
                }
            }
            // `import Target from "…"`: the default binding is a bare `identifier`
            // child of the clause (named/namespace bindings are their own nodes).
            "import_clause" => {
                let mut cursor = current.walk();
                for child in current.named_children(&mut cursor) {
                    if child.kind() != "identifier" {
                        continue;
                    }
                    let local_name = slice(child, ctx.source);
                    if ctx.edges.iter().any(|edge| {
                        edge.local_name == local_name
                            && matches!(edge.kind, ImportEdgeKind::Default)
                    }) {
                        record_import_hit(child, ctx);
                    }
                }
            }
            _ => {}
        }
        let mut cursor = current.walk();
        for child in current.named_children(&mut cursor) {
            stack.push(child);
        }
    }
}

fn register_local_binding(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let lhs = slice(name_node, ctx.source);
    if lhs.is_empty() {
        return;
    }
    let Some(value_node) = node.child_by_field_name("value") else {
        if is_target_declaration_binding(name_node, lhs, ctx, false) {
            return;
        }
        register_pattern_bindings(name_node, ctx);
        return;
    };

    if matches!(name_node.kind(), "object_pattern" | "array_pattern") {
        register_pattern_bindings(name_node, ctx);
        if name_node.kind() == "object_pattern"
            && (expression_carries_target_object(value_node, ctx)
                || expression_resolves_to_target_owner(value_node, ctx))
        {
            seed_target_destructuring_bindings(name_node, ctx);
        }
        return;
    }

    if is_target_declaration_binding(name_node, lhs, ctx, true) {
        if ctx.target_member.is_some_and(|member| member == lhs) {
            ctx.binding_engine
                .seed_symbol(lhs.to_string(), TARGET_VALUE_BINDING);
        }
        return;
    }

    ctx.binding_engine.declare_shadow(lhs.to_string());

    if expression_carries_target_object(value_node, ctx) {
        ctx.binding_engine
            .seed_symbol(lhs.to_string(), TARGET_OBJECT_BINDING);
        return;
    }
    if expression_resolves_to_target_value(value_node, ctx) {
        ctx.binding_engine
            .seed_symbol(lhs.to_string(), TARGET_VALUE_BINDING);
        return;
    }
    let rhs = match value_node.kind() {
        "identifier" | "type_identifier" => slice(value_node, ctx.source),
        _ => return,
    };
    if rhs.is_empty() || ctx.binding_engine.resolve_symbol(rhs).is_unknown() {
        return;
    }
    ctx.binding_engine.alias_symbol(lhs.to_string(), rhs);
}

/// Records object-pattern field labels when a typed `for .. of` iterable yields the target owner.
fn register_for_in_destructuring_bindings(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if node
        .child_by_field_name("operator")
        .is_none_or(|operator| operator.kind() != "of")
    {
        return;
    }
    let Some(iterable) = node.child_by_field_name("right") else {
        return;
    };
    if !expression_iterates_target_owner(iterable, ctx) {
        return;
    }
    let Some(left) = node.child_by_field_name("left") else {
        return;
    };
    if left.kind() == "object_pattern" {
        let pattern = left;
        seed_target_destructuring_bindings(pattern, ctx);
    }
}

fn seed_target_destructuring_bindings(pattern: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let Some(target_member) = ctx.target_member else {
        return;
    };
    let mut cursor = pattern.walk();
    for property in pattern.named_children(&mut cursor) {
        let (key_node, local_node) = match property.kind() {
            "shorthand_property_identifier_pattern" => (property, property),
            "pair_pattern" => {
                let Some(key_node) = property.child_by_field_name("key") else {
                    continue;
                };
                let Some(value_node) = property.child_by_field_name("value") else {
                    continue;
                };
                let Some(local_node) = direct_pattern_binding(value_node) else {
                    continue;
                };
                (key_node, local_node)
            }
            "object_assignment_pattern" => {
                let Some(left) = property.child_by_field_name("left") else {
                    continue;
                };
                let Some(local_node) = direct_pattern_binding(left) else {
                    continue;
                };
                (left, local_node)
            }
            _ => continue,
        };
        let key = slice(key_node, ctx.source);
        let local = slice(local_node, ctx.source);
        if key == target_member && !local.is_empty() {
            // The pattern key is an immediate field reference. The introduced local is
            // separately seeded only to carry that field value through later expressions.
            record_hit(key_node, ctx);
            ctx.binding_engine
                .seed_symbol(local.to_string(), TARGET_VALUE_BINDING);
        }
    }
}

fn direct_pattern_binding(node: Node<'_>) -> Option<Node<'_>> {
    let binding = match node.kind() {
        "assignment_pattern" | "object_assignment_pattern" => node.child_by_field_name("left")?,
        _ => node,
    };
    matches!(
        binding.kind(),
        "identifier" | "shorthand_property_identifier_pattern"
    )
    .then_some(binding)
}

fn expression_carries_target_object(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    match node.kind() {
        "this" => this_receiver_matches_target(node, ctx),
        "identifier" | "type_identifier" => {
            let text = slice(node, ctx.source);
            ctx.binds_target_object(text)
        }
        "call_expression" => node
            .child_by_field_name("function")
            .and_then(|callee| simple_identifier_text(callee, ctx.source))
            .is_some_and(|callee| ctx.binds_target(callee)),
        _ => false,
    }
}

fn expression_resolves_to_target_value(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    if let Some(text) = simple_identifier_text(node, ctx.source) {
        return ctx.binds_target_value(text);
    }
    if node.kind() != "member_expression" {
        return false;
    }
    let (Some(object), Some(property), Some(target_member)) = (
        node.child_by_field_name("object"),
        node.child_by_field_name("property"),
        ctx.target_member,
    ) else {
        return false;
    };
    slice(property, ctx.source) == target_member && expression_carries_target_object(object, ctx)
}

fn target_seed_identifier(target: &CodeUnit, target_owner: Option<&CodeUnit>) -> String {
    if let Some(owner) = target_owner
        && !owner.is_module()
        && !owner.is_file_scope()
    {
        return owner.identifier().trim_end_matches("$static").to_string();
    }
    if is_static_member(target)
        && let Some((owner, _)) = target.short_name().rsplit_once('.')
        && let Some(owner_name) = owner.rsplit('.').next()
    {
        return owner_name.to_string();
    }
    target.identifier().trim_end_matches("$static").to_string()
}

fn is_target_declaration_binding(
    name_node: Node<'_>,
    lhs: &str,
    ctx: &ScanCtx<'_>,
    allow_owner_fallback: bool,
) -> bool {
    if !ctx.target_self_file
        || (lhs != ctx.target_short && ctx.target_member.is_none_or(|member| lhs != member))
    {
        return false;
    }
    let range = Range {
        start_byte: name_node.start_byte(),
        end_byte: name_node.end_byte(),
        start_line: 0,
        end_line: 0,
    };
    if ctx
        .analyzer
        .ranges(ctx.target)
        .iter()
        .any(|target_range| range_within(&range, target_range))
    {
        return true;
    }
    if !allow_owner_fallback {
        return false;
    }
    if let Some(owner) = ctx.target_owner
        && ctx
            .analyzer
            .ranges(owner)
            .iter()
            .any(|owner_range| range_within(&range, owner_range))
    {
        return true;
    }
    let Some(enclosing) = ctx.analyzer.enclosing_code_unit(ctx.file, &range) else {
        return false;
    };
    if &enclosing == ctx.target {
        return true;
    }
    ctx.target_owner.is_some_and(|owner| &enclosing == owner)
}

fn range_within(inner: &Range, outer: &Range) -> bool {
    outer.start_byte <= inner.start_byte && inner.end_byte <= outer.end_byte
}

fn register_function_parameters(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let Some(parameters) = node.child_by_field_name("parameters") else {
        return;
    };
    register_pattern_bindings(parameters, ctx);
}

fn register_scope_parameters(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let Some(parameters) = node.child_by_field_name("parameters") else {
        return;
    };
    let mut cursor = parameters.walk();
    for child in parameters.named_children(&mut cursor) {
        register_parameter_binding(child, ctx);
    }
}

fn register_parameter_binding(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    match node.kind() {
        "required_parameter" | "optional_parameter" => {
            if let Some(pattern) = node.child_by_field_name("pattern") {
                let binding = if has_target_type_annotation(node, ctx) {
                    LocalBinding::TargetReceiver
                } else {
                    LocalBinding::Other
                };
                collect_pattern_identifiers(pattern, ctx, binding);
            }
        }
        "assignment_pattern" | "object_assignment_pattern" => {
            if let Some(left) = node.child_by_field_name("left") {
                register_parameter_binding(left, ctx);
            }
        }
        "pair_pattern" => {
            if let Some(value) = node.child_by_field_name("value") {
                register_parameter_binding(value, ctx);
            }
        }
        "rest_pattern" | "object_pattern" | "array_pattern" => {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                register_parameter_binding(child, ctx);
            }
        }
        _ => {}
    }
}

fn register_pattern_bindings(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    match node.kind() {
        "identifier" | "shorthand_property_identifier_pattern" => {
            let text = slice(node, ctx.source);
            if text.is_empty() {
                return;
            }
            ctx.binding_engine.declare_shadow(text.to_string());
        }
        "required_parameter" | "optional_parameter" => {
            if let Some(pattern) = node.child_by_field_name("pattern") {
                register_pattern_bindings(pattern, ctx);
            }
        }
        "assignment_pattern" | "object_assignment_pattern" => {
            if let Some(left) = node.child_by_field_name("left") {
                register_pattern_bindings(left, ctx);
            }
        }
        "pair_pattern" => {
            if let Some(value) = node.child_by_field_name("value") {
                register_pattern_bindings(value, ctx);
            }
        }
        "rest_pattern" | "object_pattern" | "array_pattern" => {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                register_pattern_bindings(child, ctx);
            }
        }
        "formal_parameters" => {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                register_pattern_bindings(child, ctx);
            }
        }
        _ => {}
    }
}

fn register_declaration(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let binding = infer_receiver_binding(node, ctx).unwrap_or(LocalBinding::Other);
    collect_pattern_identifiers(name_node, ctx, binding);
}

fn collect_pattern_identifiers(node: Node<'_>, ctx: &mut ScanCtx<'_>, binding: LocalBinding) {
    let Some(scope) = ctx.scope_stack.last_mut() else {
        return;
    };
    collect_pattern_identifiers_into(node, ctx.source, binding, scope);
}

fn collect_pattern_identifiers_into(
    node: Node<'_>,
    source: &str,
    binding: LocalBinding,
    out: &mut HashMap<String, LocalBinding>,
) {
    match node.kind() {
        "identifier" | "shorthand_property_identifier_pattern" => {
            let name = slice(node, source);
            if !name.is_empty() {
                out.insert(name.to_string(), binding);
            }
        }
        "assignment_pattern" | "object_assignment_pattern" => {
            if let Some(left) = node.child_by_field_name("left") {
                collect_pattern_identifiers_into(left, source, binding, out);
            }
        }
        "pair_pattern" => {
            if let Some(value) = node.child_by_field_name("value") {
                collect_pattern_identifiers_into(value, source, binding, out);
            }
        }
        "object_pattern" | "array_pattern" | "rest_pattern" => {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                collect_pattern_identifiers_into(child, source, binding, out);
            }
        }
        _ => {}
    }
}

fn handle_identifier_candidate(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if ctx.target_member.is_some() && ctx.browser_global_object.is_none() {
        return;
    }
    let text = slice(node, ctx.source);
    if text.is_empty() {
        return;
    }
    if ctx.browser_global_object.is_some()
        && ctx
            .lexical_bindings
            .as_ref()
            .is_some_and(|bindings| bindings.is_bound_at(text, node.start_byte()))
    {
        return;
    }
    let binds_target = if node.kind() == "type_identifier" {
        ctx.binds_target_type(text)
    } else {
        ctx.binds_target(text)
    };
    if !binds_target {
        return;
    }
    if is_declaration_identifier(node) {
        return;
    }
    if is_property_key_in_member(node) {
        return;
    }
    if is_object_in_member_expression(node) {
        return;
    }
    record_hit(node, ctx);
}

fn handle_export_specifier(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let Some(name) = node.child_by_field_name("name") else {
        return;
    };
    let exported_name = node.child_by_field_name("alias").unwrap_or(name);
    let exported_name = slice(exported_name, ctx.source);
    if ctx.binds_target(slice(name, ctx.source))
        || ctx
            .seeds
            .contains(&(ctx.file.clone(), exported_name.to_string()))
    {
        record_reexport_hit(name, ctx);
    }
}

fn handle_nested_type_identifier(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let Some((module, name)) = nested_type_identifier_parts(node) else {
        return;
    };
    let name_text = slice(name, ctx.source);
    if name_text.is_empty() {
        return;
    }

    if ctx
        .target_member
        .is_some_and(|target_member| target_member == name_text)
    {
        match type_qualification_owner_match_status(module, ctx) {
            ReceiverMatchStatus::Proven => record_hit(name, ctx),
            ReceiverMatchStatus::Unproven => record_unproven_hit(name, ctx),
            ReceiverMatchStatus::NoMatch => {}
        }
        return;
    }

    if ctx.target_member.is_none()
        && simple_identifier_text(module, ctx.source).is_some_and(|module_text| {
            namespace_member_matches_target(module, module_text, name_text, ctx)
        })
    {
        record_hit(name, ctx);
    }
}

fn type_qualification_owner_match_status(
    module: Node<'_>,
    ctx: &ScanCtx<'_>,
) -> ReceiverMatchStatus {
    if let Some(module_text) = simple_identifier_text(module, ctx.source) {
        return if ctx.binds_target_type(module_text) {
            ReceiverMatchStatus::Proven
        } else {
            ReceiverMatchStatus::NoMatch
        };
    }

    ReceiverMatchStatus::NoMatch
}

fn namespace_member_matches_target(
    object: Node<'_>,
    object_text: &str,
    property_text: &str,
    ctx: &ScanCtx<'_>,
) -> bool {
    if simple_identifier_text(object, ctx.source).is_some()
        && ctx.binding_engine.is_shadowed(object_text)
    {
        return false;
    }
    ctx.edges.iter().any(|edge| {
        edge.local_name == object_text
            && match &edge.kind {
                ImportEdgeKind::Namespace => ctx
                    .seeds
                    .contains(&(edge.target_file.clone(), property_text.to_string())),
                ImportEdgeKind::CommonJsRequire(export_name) => property_text == export_name,
                ImportEdgeKind::Named(_) | ImportEdgeKind::Default => false,
            }
            || match &edge.kind {
                ImportEdgeKind::CommonJsRequire(export_name) => commonjs_nested_member_matches(
                    object_text,
                    property_text,
                    &edge.local_name,
                    export_name,
                ),
                ImportEdgeKind::Namespace | ImportEdgeKind::Named(_) | ImportEdgeKind::Default => {
                    false
                }
            }
    })
}

fn handle_member_expression(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    // member_expression has `object` (expr) and `property` (property_identifier).
    let Some(object) = node.child_by_field_name("object") else {
        return;
    };
    let Some(property) = node.child_by_field_name("property") else {
        return;
    };
    let object_text = slice(object, ctx.source);
    let property_text = slice(property, ctx.source);

    if ctx
        .target_member
        .is_some_and(|target_member| property_text == target_member)
    {
        if let Some((lexical_bindings, definitions)) = ctx
            .lexical_bindings
            .as_ref()
            .zip(ctx.local_property_definitions.as_deref())
        {
            if local_property_read_matches(
                object,
                property,
                ctx.source,
                lexical_bindings,
                definitions,
            ) {
                record_hit(property, ctx);
            }
            return;
        }
        if ctx.lookup_only_local_property {
            return;
        }
    }

    if let (Some(global_object), Some(target_member)) =
        (ctx.browser_global_object, ctx.target_member)
        && property_text == target_member
    {
        if simple_identifier_text(object, ctx.source) == Some(global_object)
            && !ctx
                .lexical_bindings
                .as_ref()
                .is_some_and(|bindings| bindings.is_bound_at(global_object, object.start_byte()))
        {
            record_hit(property, ctx);
        }
        return;
    }

    // `Namespace.Foo` / `require("./mod").Foo` style access. ESM namespace imports
    // still key by the target's local name; CommonJS module-object edges carry the
    // exported property name so aliases such as `module.exports = { Bar: Foo }` work.
    if namespace_member_matches_target(object, object_text, property_text, ctx) {
        record_hit(property, ctx);
        return;
    }

    // `Ky.create()` style access still references the exported `Ky` value. The
    // identifier visitor suppresses member-expression objects to avoid double-counting
    // member targets, so record the object here for non-member target queries.
    if ctx.target_member.is_none()
        && simple_identifier_text(object, ctx.source).is_some()
        && ctx.binds_target(object_text)
    {
        record_hit(object, ctx);
        return;
    }

    if simple_identifier_text(object, ctx.source).is_some() && ctx.binds_target_value(object_text) {
        record_hit(object, ctx);
        return;
    }

    if object.kind() != "this"
        && ctx
            .target_member
            .is_some_and(|member| member == property_text)
        && expression_carries_target_object(object, ctx)
    {
        record_hit(property, ctx);
        return;
    }

    // `this.method()` inside the target owner class: editor references should see it,
    // but scan_usages / call-graph surfaces filter it as an internal receiver hit.
    if let Some(member) = ctx.target_member
        && property_text == member
    {
        if this_receiver_matches_target(object, ctx) {
            if ctx.target.is_field() {
                record_hit(property, ctx);
            } else {
                record_self_receiver_hit(property, ctx);
            }
            return;
        }
        // `BaseClass.staticMethod()` style — object binds to the target's parent class, the
        // property is the requested member.
        match member_object_match_status(object, object_text, ctx) {
            ReceiverMatchStatus::Proven => record_hit(property, ctx),
            ReceiverMatchStatus::Unproven => record_unproven_hit(property, ctx),
            ReceiverMatchStatus::NoMatch => {}
        }
    }
}

fn handle_contextual_object_literal(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let (Some(target_member), Some(target_owner)) = (ctx.target_member, ctx.target_owner) else {
        return;
    };
    let owners = contextual_object_literal_owners(node, ctx);
    if !owners.iter().any(|owner| {
        owner.source() == target_owner.source() && owner.fq_name() == target_owner.fq_name()
    }) {
        return;
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        let Some(name) =
            crate::analyzer::typescript::ts_object_literal_property_name(child, ctx.source)
        else {
            continue;
        };
        if name != target_member {
            continue;
        }
        if let Some(key) = object_literal_property_key_node(child) {
            record_hit(key, ctx);
        }
    }
}

fn contextual_object_literal_owners(node: Node<'_>, ctx: &ScanCtx<'_>) -> Vec<CodeUnit> {
    if let Some(variable) = node
        .parent()
        .filter(|parent| parent.kind() == "variable_declarator")
        && variable
            .child_by_field_name("value")
            .is_some_and(|value| value.id() == node.id())
        && let Some(type_node) = variable.child_by_field_name("type")
    {
        return ts_resolve_type_text_to_property_owners(
            ctx.analyzer,
            ctx.analyzer.global_usage_definition_index(),
            ctx.file,
            ctx.source,
            &ctx.imports,
            &ctx.aliases,
            ts_type_annotation_text(type_node, ctx.source).as_str(),
            0,
        );
    }

    let Some(return_statement) = node
        .parent()
        .filter(|parent| parent.kind() == "return_statement")
    else {
        return Vec::new();
    };
    let mut cursor = return_statement.walk();
    if return_statement
        .named_children(&mut cursor)
        .next()
        .is_none_or(|value| value.id() != node.id())
    {
        return Vec::new();
    }
    let Some(function) = enclosing_function_scope(node) else {
        return Vec::new();
    };
    let Some(type_node) = function.child_by_field_name("return_type") else {
        return Vec::new();
    };
    ts_resolve_type_text_to_property_owners(
        ctx.analyzer,
        ctx.analyzer.global_usage_definition_index(),
        ctx.file,
        ctx.source,
        &ctx.imports,
        &ctx.aliases,
        ts_type_annotation_text(type_node, ctx.source).as_str(),
        0,
    )
}

fn object_literal_property_key_node(property: Node<'_>) -> Option<Node<'_>> {
    match property.kind() {
        "pair" => property
            .child_by_field_name("key")
            .or_else(|| property.named_child(0)),
        "shorthand_property_identifier" => Some(property),
        "method_definition" => property.child_by_field_name("name"),
        _ => None,
    }
}

fn enclosing_function_scope(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        if matches!(
            node.kind(),
            "function_declaration" | "function_expression" | "arrow_function" | "method_definition"
        ) {
            return Some(node);
        }
        node = node.parent()?;
    }
}

fn commonjs_nested_member_matches(
    object_text: &str,
    property_text: &str,
    local_name: &str,
    export_name: &str,
) -> bool {
    let Some((export_object, export_member)) = export_name.rsplit_once('.') else {
        return false;
    };
    property_text == export_member && object_text == format!("{local_name}.{export_object}")
}

fn handle_jsx_element(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if let Some(target_member) = ctx.target_member {
        let mut cursor = node.walk();
        let matching_attributes = node
            .named_children(&mut cursor)
            .filter(|child| child.kind() == "jsx_attribute")
            .filter_map(|attribute| attribute.named_child(0))
            .filter(|name| slice(*name, ctx.source) == target_member)
            .collect::<Vec<_>>();
        if !matching_attributes.is_empty() {
            for name in matching_attributes {
                if ctx
                    .receiver_facts
                    .resolve_jsx_attribute_targets(name, ReceiverAnalysisBudget::default())
                    .is_some_and(|targets| {
                        targets.iter().any(|target| {
                            target.source() == ctx.target.source()
                                && target.fq_name() == ctx.target.fq_name()
                        })
                    })
                {
                    record_hit(name, ctx);
                }
            }
        }
    }

    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let text = slice(name_node, ctx.source);
    if text.is_empty() {
        return;
    }
    // For qualified JSX names (`<Foo.Bar />`), narrow the recorded range to the
    // rightmost identifier so LSP clients highlight just `Bar`. The descent will
    // visit the leaf identifier directly when it isn't a member_expression child;
    // by recording here we ensure JSX qualifications show up regardless.
    if let Some((rightmost, leaf_text)) = rightmost_jsx_identifier(name_node, ctx.source)
        && ctx.binds_target(leaf_text)
    {
        record_hit(rightmost, ctx);
    }
}

/// Walks a JSX element name (identifier or member_expression) and returns the rightmost
/// identifier node together with its text. For `<Foo.Bar />` the leaf is `Bar`.
pub(super) fn rightmost_jsx_identifier<'a>(
    node: Node<'a>,
    source: &'a str,
) -> Option<(Node<'a>, &'a str)> {
    match node.kind() {
        "identifier" | "type_identifier" | "property_identifier" => {
            let text = slice(node, source);
            (!text.is_empty()).then_some((node, text))
        }
        // `Foo.Bar` is a `member_expression` (or `jsx_member_expression` in some
        // grammars) — descend into the rightmost named child.
        _ => {
            let property = node.child_by_field_name("property");
            if let Some(property) = property {
                return rightmost_jsx_identifier(property, source);
            }
            let mut last = None;
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                last = Some(child);
            }
            last.and_then(|child| rightmost_jsx_identifier(child, source))
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReceiverMatchStatus {
    Proven,
    Unproven,
    NoMatch,
}

fn member_object_match_status(
    node: Node<'_>,
    object_text: &str,
    ctx: &ScanCtx<'_>,
) -> ReceiverMatchStatus {
    if ctx.target_is_static_member {
        return if ctx.binds_target(object_text) {
            ReceiverMatchStatus::Proven
        } else {
            ReceiverMatchStatus::NoMatch
        };
    }

    if ctx.target_self_file
        && simple_identifier_text(node, ctx.source).is_some()
        && ctx.binds_target(object_text)
    {
        return ReceiverMatchStatus::Proven;
    }

    if expression_is_target_constructor(node, ctx) {
        return ReceiverMatchStatus::Proven;
    }

    if let Some(binding) = simple_identifier_text(node, ctx.source).and_then(|name| {
        ctx.scope_stack
            .iter()
            .rev()
            .find_map(|scope| scope.get(name))
            .copied()
    }) {
        return match binding {
            LocalBinding::TargetReceiver => ReceiverMatchStatus::Proven,
            LocalBinding::KnownUnrelated => ReceiverMatchStatus::NoMatch,
            LocalBinding::Other => receiver_fact_match_status(node, ctx),
        };
    }

    receiver_fact_match_status(node, ctx)
}

fn receiver_fact_match_status(node: Node<'_>, ctx: &ScanCtx<'_>) -> ReceiverMatchStatus {
    let Some(owner) = ctx.target_owner else {
        return ReceiverMatchStatus::Unproven;
    };
    match ctx
        .receiver_facts
        .resolve_receiver_node(node, ReceiverAnalysisBudget::default())
    {
        ReceiverAnalysisOutcome::Precise(values) => {
            if values.iter().any(|value| {
                let resolved = value.owner();
                resolved.source() == owner.source() && resolved.fq_name() == owner.fq_name()
            }) {
                ReceiverMatchStatus::Proven
            } else if node.kind() == "call_expression" {
                ReceiverMatchStatus::Unproven
            } else {
                ReceiverMatchStatus::NoMatch
            }
        }
        ReceiverAnalysisOutcome::Ambiguous(values) => {
            if values.iter().any(|value| {
                let resolved = value.owner();
                resolved.source() == owner.source() && resolved.fq_name() == owner.fq_name()
            }) {
                ReceiverMatchStatus::Unproven
            } else {
                ReceiverMatchStatus::NoMatch
            }
        }
        ReceiverAnalysisOutcome::Unknown
        | ReceiverAnalysisOutcome::Unsupported { .. }
        | ReceiverAnalysisOutcome::ExceededBudget { .. } => ReceiverMatchStatus::Unproven,
    }
}

fn this_receiver_matches_target(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    if node.kind() != "this" || !ctx.target_self_file {
        return false;
    }
    let Some(owner) = ctx.target_owner else {
        return false;
    };
    let range = Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: 0,
        end_line: 0,
    };
    let Some(enclosing) = ctx.analyzer.enclosing_code_unit(ctx.file, &range) else {
        return false;
    };
    if &enclosing == owner {
        return true;
    }
    ctx.analyzer
        .parent_of(&enclosing)
        .is_some_and(|parent| &parent == owner)
}

pub(super) fn simple_identifier_text<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    match node.kind() {
        "identifier" | "type_identifier" => {
            let text = slice(node, source);
            (!text.is_empty()).then_some(text)
        }
        _ => None,
    }
}

fn infer_receiver_binding(node: Node<'_>, ctx: &ScanCtx<'_>) -> Option<LocalBinding> {
    let value = node.child_by_field_name("value")?;
    if expression_is_target_constructor(value, ctx)
        || expression_resolves_to_target_owner(value, ctx)
        || has_target_type_annotation(node, ctx)
    {
        return Some(LocalBinding::TargetReceiver);
    }
    let name = node.child_by_field_name("name")?;
    if name.kind() == "identifier"
        && value.kind() == "object"
        && node.child_by_field_name("type").is_none()
        && ctx
            .target_owner
            .is_none_or(|owner| slice(name, ctx.source) != owner.identifier())
    {
        return Some(LocalBinding::KnownUnrelated);
    }

    simple_identifier_text(value, ctx.source).map(|ident| {
        ctx.scope_stack
            .iter()
            .rev()
            .find_map(|scope| scope.get(ident))
            .copied()
            .unwrap_or(LocalBinding::Other)
    })
}

fn expression_is_target_constructor(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    match node.kind() {
        "new_expression" => node
            .child_by_field_name("constructor")
            .and_then(|constructor| simple_identifier_text(constructor, ctx.source))
            .is_some_and(|name| ctx.binds_target(name)),
        "identifier" | "type_identifier" => {
            let text = slice(node, ctx.source);
            ctx.binds_target(text)
        }
        _ => false,
    }
}

fn expression_resolves_to_target_owner(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    let Some(owner) = ctx.target_owner else {
        return false;
    };
    matches!(
        ctx.receiver_facts
            .resolve_receiver_node(node, ReceiverAnalysisBudget::default()),
        ReceiverAnalysisOutcome::Precise(values)
            if values.iter().any(|value| {
                let resolved = value.owner();
                resolved.source() == owner.source() && resolved.fq_name() == owner.fq_name()
            })
    )
}

fn expression_iterates_target_owner(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    let Some(owner) = ctx.target_owner else {
        return false;
    };
    if expression_carries_target_object(node, ctx) || expression_resolves_to_target_owner(node, ctx)
    {
        return true;
    }
    matches!(
        ctx.receiver_facts
            .resolve_iterable_element(node, ReceiverAnalysisBudget::default()),
        ReceiverAnalysisOutcome::Precise(values)
            if values.iter().any(|value| {
                let resolved = value.owner();
                resolved.source() == owner.source() && resolved.fq_name() == owner.fq_name()
            })
    )
}

fn has_target_type_annotation(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    node.child_by_field_name("type")
        .or_else(|| node.child_by_field_name("return_type"))
        .is_some_and(|type_node| {
            type_annotation_mentions_target(type_node, ctx)
                || type_annotation_resolves_to_target_owner(type_node, ctx)
        })
        || node
            .child_by_field_name("name")
            .is_some_and(|name| name_subtree_mentions_target_type(name, ctx))
        || node
            .child_by_field_name("pattern")
            .is_some_and(|pattern| name_subtree_mentions_target_type(pattern, ctx))
}

fn type_annotation_resolves_to_target_owner(type_node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    let Some(target_owner) = ctx.target_owner else {
        return false;
    };
    ts_resolve_type_text_to_property_owners(
        ctx.analyzer,
        ctx.analyzer.global_usage_definition_index(),
        ctx.file,
        ctx.source,
        &ctx.imports,
        &ctx.aliases,
        ts_type_annotation_text(type_node, ctx.source).as_str(),
        0,
    )
    .into_iter()
    .any(|owner| {
        owner.source() == target_owner.source() && owner.fq_name() == target_owner.fq_name()
    })
}

fn type_annotation_mentions_target(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    if let Some(text) = simple_identifier_text(node, ctx.source)
        && ctx.binds_target(text)
    {
        if let Some(owner_source) = ctx.target_owner_source {
            if ctx.target_self_file {
                return text == ctx.target_short;
            }
            return ctx
                .edges
                .iter()
                .any(|edge| edge.local_name == text && edge.target_file == *owner_source);
        }
        return true;
    }

    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .any(|child| type_annotation_mentions_target(child, ctx))
}

fn name_subtree_mentions_target_type(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    if node.kind() == "type_annotation" {
        return type_annotation_mentions_target(node, ctx);
    }

    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .any(|child| name_subtree_mentions_target_type(child, ctx))
}

fn simple_identifier_text_for_source<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    match node.kind() {
        "identifier" | "type_identifier" | "property_identifier" => {
            let text = slice(node, source).trim();
            (!text.is_empty()).then_some(text)
        }
        _ => None,
    }
}

fn property_name_text(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "identifier"
        | "type_identifier"
        | "property_identifier"
        | "shorthand_property_identifier"
        | "shorthand_property_identifier_pattern" => {
            let text = slice(node, source)
                .trim()
                .trim_matches('"')
                .trim_matches('\'');
            (!text.is_empty()).then(|| text.to_string())
        }
        "string" => {
            let text = unquote(slice(node, source));
            (!text.is_empty()).then_some(text)
        }
        _ => None,
    }
}

fn first_named_child_of_kind<'a>(node: Node<'a>, kind: &str) -> Option<Node<'a>> {
    if node.kind() == kind {
        return Some(node);
    }
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| child.kind() == kind)
}

// ===================================================================================
// ExportIndex extraction
// ===================================================================================

pub(super) fn compute_export_index(source: &str, tree: &Tree) -> ExportIndex {
    let mut index = ExportIndex::empty();
    let root = tree.root_node();
    let module_object_exports = collect_module_object_exports(root, source);

    for index_id in 0..root.named_child_count() {
        let Some(child) = root.named_child(index_id) else {
            continue;
        };
        if child.kind() == "export_statement" {
            visit_export_statement(child, source, &mut index);
        } else if child.kind() == "expression_statement" {
            visit_commonjs_export_statement(child, source, &mut index);
            visit_module_object_member_export_statement(
                child,
                source,
                &module_object_exports,
                &mut index,
            );
        }
    }

    index
}

fn collect_module_object_exports(root: Node<'_>, source: &str) -> HashSet<String> {
    let mut exports = HashSet::default();
    for index_id in 0..root.named_child_count() {
        let Some(child) = root.named_child(index_id) else {
            continue;
        };
        if child.kind() != "expression_statement" {
            continue;
        }
        let Some(assignment) = first_named_child_of_kind(child, "assignment_expression") else {
            continue;
        };
        let Some(left) = assignment.child_by_field_name("left") else {
            continue;
        };
        if !matches!(
            commonjs_export_target(left, source),
            Some(CommonJsExportTarget::ModuleExports)
        ) {
            continue;
        }
        let Some(right) = assignment.child_by_field_name("right") else {
            continue;
        };
        let Some(local_name) = simple_identifier_text_for_source(right, source) else {
            continue;
        };
        exports.insert(local_name.to_string());
    }
    exports
}

fn visit_commonjs_export_statement(node: Node<'_>, source: &str, index: &mut ExportIndex) {
    let Some(assignment) = first_named_child_of_kind(node, "assignment_expression") else {
        return;
    };
    let Some(left) = assignment.child_by_field_name("left") else {
        return;
    };
    let Some(right) = assignment.child_by_field_name("right") else {
        return;
    };

    match commonjs_export_target(left, source) {
        Some(CommonJsExportTarget::Named(exported_name)) => {
            if let Some(local_name) = local_export_name(right, source)
                .or_else(|| exported_function_name(right, &exported_name))
            {
                index
                    .exports_by_name
                    .insert(exported_name, ExportEntry::Local { local_name });
            }
        }
        Some(CommonJsExportTarget::ModuleExports) => {
            register_module_exports_assignment(right, source, index);
        }
        None => {}
    }
}

fn visit_module_object_member_export_statement(
    node: Node<'_>,
    source: &str,
    module_object_exports: &HashSet<String>,
    index: &mut ExportIndex,
) {
    let Some(assignment) = first_named_child_of_kind(node, "assignment_expression") else {
        return;
    };
    let Some(left) = assignment.child_by_field_name("left") else {
        return;
    };
    let Some((object_name, exported_name)) = local_member_assignment_target(left, source) else {
        return;
    };
    if !module_object_exports.contains(object_name) {
        return;
    }
    let local_name = format!("{object_name}.{exported_name}");
    index
        .exports_by_name
        .insert(exported_name.to_string(), ExportEntry::Local { local_name });
}

fn is_commonjs_export_statement(node: Node<'_>, source: &str) -> bool {
    let Some(assignment) = first_named_child_of_kind(node, "assignment_expression") else {
        return false;
    };
    assignment
        .child_by_field_name("left")
        .is_some_and(|left| commonjs_export_target(left, source).is_some())
}

enum CommonJsExportTarget {
    Named(String),
    ModuleExports,
}

fn commonjs_export_target(node: Node<'_>, source: &str) -> Option<CommonJsExportTarget> {
    if node.kind() != "member_expression" {
        return None;
    }
    let object = node.child_by_field_name("object")?;
    let property = node.child_by_field_name("property")?;
    let property_name = property_name_text(property, source)?;

    if simple_identifier_text_for_source(object, source) == Some("exports") {
        return Some(CommonJsExportTarget::Named(property_name));
    }

    if commonjs_module_exports_object(object, source) {
        return Some(CommonJsExportTarget::Named(property_name));
    }

    if simple_identifier_text_for_source(object, source) == Some("module")
        && property_name == "exports"
    {
        return Some(CommonJsExportTarget::ModuleExports);
    }

    None
}

fn commonjs_module_exports_object(node: Node<'_>, source: &str) -> bool {
    if node.kind() != "member_expression" {
        return false;
    }
    let Some(object) = node.child_by_field_name("object") else {
        return false;
    };
    let Some(property) = node.child_by_field_name("property") else {
        return false;
    };
    simple_identifier_text_for_source(object, source) == Some("module")
        && property_name_text(property, source).as_deref() == Some("exports")
}

fn local_member_assignment_target<'a>(
    node: Node<'_>,
    source: &'a str,
) -> Option<(&'a str, String)> {
    if node.kind() != "member_expression" {
        return None;
    }
    let object = node.child_by_field_name("object")?;
    let property = node.child_by_field_name("property")?;
    let object_name = simple_identifier_text_for_source(object, source)?;
    let property_name = property_name_text(property, source)?;
    Some((object_name, property_name))
}

fn register_module_exports_assignment(right: Node<'_>, source: &str, index: &mut ExportIndex) {
    if right.kind() == "object" {
        register_module_exports_object(right, source, index);
        return;
    }

    if let Some(module_specifier) = require_call_module_specifier(right, source) {
        index
            .reexport_stars
            .push(crate::analyzer::usages::model::ReexportStar { module_specifier });
        return;
    }

    if let Some(local_name) = local_export_name(right, source) {
        index.exports_by_name.insert(
            "default".to_string(),
            ExportEntry::Default {
                local_name: Some(local_name),
            },
        );
    }
}

fn register_module_exports_object(node: Node<'_>, source: &str, index: &mut ExportIndex) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "shorthand_property_identifier" | "shorthand_property_identifier_pattern" => {
                let name = slice(child, source).trim();
                if !name.is_empty() {
                    index.exports_by_name.insert(
                        name.to_string(),
                        ExportEntry::Local {
                            local_name: name.to_string(),
                        },
                    );
                }
            }
            "pair" => {
                let Some(key) = child.child_by_field_name("key") else {
                    continue;
                };
                let Some(value) = child.child_by_field_name("value") else {
                    continue;
                };
                let Some(exported_name) = property_name_text(key, source) else {
                    continue;
                };
                let local_name =
                    local_export_name(value, source).unwrap_or_else(|| exported_name.clone());
                index
                    .exports_by_name
                    .insert(exported_name, ExportEntry::Local { local_name });
            }
            _ => {}
        }
    }
}

fn local_export_name(node: Node<'_>, source: &str) -> Option<String> {
    if let Some(name) = simple_identifier_text_for_source(node, source) {
        return Some(name.to_string());
    }
    if let Some(name) = named_function_expression_name(node, source) {
        return Some(name);
    }
    member_expression_name(node, source)
}

fn default_export_local_name(node: Node<'_>, source: &str) -> Option<String> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find_map(|child| local_export_name(child, source))
}

fn exported_function_name(node: Node<'_>, exported_name: &str) -> Option<String> {
    matches!(node.kind(), "function_expression" | "arrow_function")
        .then(|| exported_name.to_string())
}

fn named_function_expression_name(node: Node<'_>, source: &str) -> Option<String> {
    if node.kind() != "function_expression" {
        return None;
    }
    let name = node.child_by_field_name("name")?;
    simple_identifier_text_for_source(name, source).map(str::to_string)
}

fn member_expression_name(node: Node<'_>, source: &str) -> Option<String> {
    if node.kind() != "member_expression" {
        return None;
    }
    let object = node.child_by_field_name("object")?;
    let property = node.child_by_field_name("property")?;
    if property.kind() == "computed_property_name" {
        return None;
    }
    let object_name = simple_identifier_text_for_source(object, source)
        .map(str::to_string)
        .or_else(|| member_expression_name(object, source))?;
    let property_name = property_name_text(property, source)?;
    Some(format!("{object_name}.{property_name}"))
}

fn visit_export_statement(node: Node<'_>, source: &str, index: &mut ExportIndex) {
    // `export_clause` and `namespace_export` are direct named children, NOT accessible
    // via a `clause` field — find them by iterating named children.
    let export_clause_child = {
        let mut cursor = node.walk();
        node.named_children(&mut cursor)
            .find(|c| c.kind() == "export_clause")
    };

    // export {a, b} from "..."  /  export * from "..."  / export ... from
    if let Some(source_node) = node.child_by_field_name("source") {
        let module_specifier = unquote(slice(source_node, source));
        if let Some(clause) = export_clause_child {
            let mut cursor = clause.walk();
            for spec in clause.named_children(&mut cursor) {
                if spec.kind() != "export_specifier" {
                    continue;
                }
                let imported_name = spec
                    .child_by_field_name("name")
                    .map(|n| slice(n, source).to_string())
                    .unwrap_or_default();
                let exported_name = spec
                    .child_by_field_name("alias")
                    .map(|n| slice(n, source).to_string())
                    .unwrap_or_else(|| imported_name.clone());
                if imported_name.is_empty() || exported_name.is_empty() {
                    continue;
                }
                index.exports_by_name.insert(
                    exported_name,
                    ExportEntry::ReexportedNamed {
                        module_specifier: module_specifier.clone(),
                        imported_name,
                    },
                );
            }
        } else {
            // No clause => `export * from "..."`.
            index
                .reexport_stars
                .push(crate::analyzer::usages::model::ReexportStar { module_specifier });
        }
        return;
    }

    // `export { a, b as c }` (no module specifier => re-binding locals).
    if let Some(clause) = export_clause_child {
        let mut cursor = clause.walk();
        for spec in clause.named_children(&mut cursor) {
            if spec.kind() != "export_specifier" {
                continue;
            }
            let local_name = spec
                .child_by_field_name("name")
                .map(|n| slice(n, source).to_string())
                .unwrap_or_default();
            let exported_name = spec
                .child_by_field_name("alias")
                .map(|n| slice(n, source).to_string())
                .unwrap_or_else(|| local_name.clone());
            if local_name.is_empty() || exported_name.is_empty() {
                continue;
            }
            index
                .exports_by_name
                .insert(exported_name, ExportEntry::Local { local_name });
        }
        return;
    }

    // `export default <expr-or-decl>` and `export <decl>`.
    let is_default = node
        .children(&mut node.walk())
        .any(|child| !child.is_named() && slice(child, source) == "default");

    if let Some(declaration) = node.child_by_field_name("declaration") {
        match declaration.kind() {
            "class_declaration"
            | "abstract_class_declaration"
            | "interface_declaration"
            | "function_declaration"
            | "function_signature" => {
                if let Some(name_node) = declaration.child_by_field_name("name") {
                    let name = slice(name_node, source).to_string();
                    if !name.is_empty() {
                        if is_default {
                            index.exports_by_name.insert(
                                "default".to_string(),
                                ExportEntry::Default {
                                    local_name: Some(name.clone()),
                                },
                            );
                        }
                        index
                            .exports_by_name
                            .insert(name.clone(), ExportEntry::Local { local_name: name });
                    }
                }
            }
            "lexical_declaration" | "variable_declaration" => {
                let mut cursor = declaration.walk();
                for declarator in declaration.named_children(&mut cursor) {
                    if declarator.kind() != "variable_declarator" {
                        continue;
                    }
                    let Some(name_node) = declarator.child_by_field_name("name") else {
                        continue;
                    };
                    let name = slice(name_node, source).to_string();
                    if name.is_empty() {
                        continue;
                    }
                    index
                        .exports_by_name
                        .insert(name.clone(), ExportEntry::Local { local_name: name });
                }
            }
            "enum_declaration" | "type_alias_declaration" | "internal_module" => {
                if let Some(name_node) = declaration.child_by_field_name("name") {
                    let name = slice(name_node, source).to_string();
                    if !name.is_empty() {
                        index
                            .exports_by_name
                            .insert(name.clone(), ExportEntry::Local { local_name: name });
                    }
                }
            }
            _ if is_default => {
                let local_name = local_export_name(declaration, source);
                index
                    .exports_by_name
                    .insert("default".to_string(), ExportEntry::Default { local_name });
            }
            _ => {}
        }
        return;
    }

    if is_default {
        // `export default expr;` with no declaration child — anonymous default.
        let local_name = default_export_local_name(node, source);
        index
            .exports_by_name
            .insert("default".to_string(), ExportEntry::Default { local_name });
    }
}

fn unquote(text: &str) -> String {
    let trimmed = text.trim();
    let stripped = trimmed
        .strip_prefix('"')
        .and_then(|t| t.strip_suffix('"'))
        .or_else(|| {
            trimmed
                .strip_prefix('\'')
                .and_then(|t| t.strip_suffix('\''))
        });
    stripped.unwrap_or(trimmed).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::js_ts::syntax::compute_import_binder;
    use crate::analyzer::usages::ImportKind;

    fn parse_js(source: &str) -> Tree {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_javascript::LANGUAGE.into())
            .unwrap();
        parser.parse(source, None).unwrap()
    }

    #[test]
    fn export_index_named_export() {
        let src = "export class Foo {}\nexport function bar() {}";
        let tree = parse_js(src);
        let idx = compute_export_index(src, &tree);
        assert!(idx.exports_by_name.contains_key("Foo"));
        assert!(idx.exports_by_name.contains_key("bar"));
    }

    #[test]
    fn export_index_named_reexport() {
        let src = "export { Foo as Bar } from './other';";
        let tree = parse_js(src);
        let idx = compute_export_index(src, &tree);
        match idx.exports_by_name.get("Bar") {
            Some(ExportEntry::ReexportedNamed {
                module_specifier,
                imported_name,
            }) => {
                assert_eq!(module_specifier, "./other");
                assert_eq!(imported_name, "Foo");
            }
            other => panic!("expected ReexportedNamed, got {other:?}"),
        }
    }

    #[test]
    fn import_binder_named_default_namespace() {
        let src = r#"
            import Foo, { bar as baz } from "./mod";
            import * as ns from "./other";
        "#;
        let tree = parse_js(src);
        let binder = compute_import_binder(src, &tree);
        assert_eq!(
            binder.bindings.get("Foo").map(|b| b.kind),
            Some(ImportKind::Default)
        );
        assert_eq!(
            binder.bindings.get("baz").map(|b| b.kind),
            Some(ImportKind::Named)
        );
        assert_eq!(
            binder.bindings.get("ns").map(|b| b.kind),
            Some(ImportKind::Namespace)
        );
    }
}
