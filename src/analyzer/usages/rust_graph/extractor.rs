use crate::analyzer::usages::local_inference::{LocalInferenceConfig, LocalInferenceEngine};
use crate::analyzer::usages::model::UsageHit;
use crate::analyzer::usages::rust_graph::hits::{
    member_hit_enclosing, push_member_hit, record_hit, record_module_qualified_hits,
};
use crate::analyzer::usages::rust_graph::resolver::is_trait_owner;
use crate::analyzer::{CodeUnit, IAnalyzer, ProjectFile, RustAnalyzer};
use crate::hash::{HashMap, HashSet};
use crate::text_utils::compute_line_starts;
use rayon::prelude::*;
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use tree_sitter::{Node, Parser, Tree};

struct ParsedFile {
    source: Arc<String>,
    tree: Tree,
}

pub(crate) struct RustProjectGraph {
    parsed: HashMap<ProjectFile, ParsedFile>,
}

/// Parse every Rust file once for tree reuse during the forward scan. Re-export
/// and importer resolution now lives on the analyzer (`RustAnalyzer::usage_*`,
/// see [`super::super::rust_graph`]), so this no longer builds a cross-file graph.
pub(super) fn build_rust_graph(analyzer: &RustAnalyzer) -> RustProjectGraph {
    let parsed: HashMap<ProjectFile, ParsedFile> = analyzer
        .get_analyzed_files()
        .into_iter()
        .collect::<Vec<_>>()
        .par_iter()
        .filter_map(|file| {
            let source = file.read_to_string().ok()?;
            let mut parser = Parser::new();
            parser
                .set_language(&tree_sitter_rust::LANGUAGE.into())
                .ok()?;
            let tree = parser.parse(source.as_str(), None)?;
            Some((
                file.clone(),
                ParsedFile {
                    source: Arc::new(source),
                    tree,
                },
            ))
        })
        .collect();

    RustProjectGraph { parsed }
}

pub(super) fn effective_scan_files(
    analyzer: &RustAnalyzer,
    candidate_files: &HashSet<ProjectFile>,
    target: &CodeUnit,
    seeds: &BTreeSet<(ProjectFile, String)>,
) -> HashSet<ProjectFile> {
    let analyzed = analyzer.get_analyzed_files();
    let filtered_candidates: HashSet<_> = candidate_files
        .iter()
        .filter(|file| analyzed.contains(*file))
        .cloned()
        .collect();

    if !candidate_files.is_empty() && filtered_candidates.is_empty() {
        return [target.source().clone()].into_iter().collect();
    }

    if !filtered_candidates.is_empty() {
        return filtered_candidates;
    }

    analyzer
        .usage_importers(seeds)
        .into_iter()
        .chain(std::iter::once(target.source().clone()))
        .collect()
}

pub(super) fn scan_files_for_target(
    analyzer: &dyn IAnalyzer,
    rust: &RustAnalyzer,
    graph: &RustProjectGraph,
    files: HashSet<ProjectFile>,
    target: &CodeUnit,
    seeds: Option<&BTreeSet<(ProjectFile, String)>>,
) -> BTreeSet<UsageHit> {
    let target_short = target.identifier().to_string();
    let parser_language = tree_sitter_rust::LANGUAGE.into();
    let hits = Mutex::new(BTreeSet::new());
    let files_vec: Vec<_> = files.into_iter().collect();

    files_vec.par_iter().for_each(|file| {
        let owned_source: Option<Arc<String>>;
        let owned_tree: Option<Tree>;
        let (source, tree) = if let Some(parsed) = graph.parsed.get(file) {
            (parsed.source.as_str(), &parsed.tree)
        } else {
            let Ok(source) = file.read_to_string() else {
                return;
            };
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
                owned_source.as_deref().expect("owned source").as_str(),
                owned_tree.as_ref().expect("owned tree"),
            )
        };

        let line_starts = compute_line_starts(source);
        let (direct_names, namespace_names) = match seeds {
            Some(seeds) => rust.usage_binding_names(file, seeds),
            None => (HashSet::default(), HashSet::default()),
        };
        let target_self_file = file == target.source();

        let mut local_hits = BTreeSet::new();
        let mut ctx = ScanCtx {
            file,
            source,
            line_starts: &line_starts,
            analyzer,
            target_short: &target_short,
            direct_names: &direct_names,
            namespace_names: &namespace_names,
            shadowed_names: detect_shadowed_names(
                tree.root_node(),
                source,
                &direct_names,
                &namespace_names,
                &target_short,
                target_self_file,
            ),
            target_self_file,
            hits: &mut local_hits,
        };
        scan_node(tree.root_node(), &mut ctx);
        record_module_qualified_hits(tree.root_node(), &mut ctx);

        if !local_hits.is_empty() {
            let mut sink = hits.lock().expect("poisoned Rust graph collector");
            sink.extend(local_hits);
        }
    });

    hits.into_inner().expect("poisoned Rust graph collector")
}

pub(super) struct ScanCtx<'a> {
    pub(super) file: &'a ProjectFile,
    pub(super) source: &'a str,
    pub(super) line_starts: &'a [usize],
    pub(super) analyzer: &'a dyn IAnalyzer,
    pub(super) target_short: &'a str,
    direct_names: &'a HashSet<String>,
    pub(super) namespace_names: &'a HashSet<String>,
    pub(super) shadowed_names: HashSet<String>,
    target_self_file: bool,
    pub(super) hits: &'a mut BTreeSet<UsageHit>,
}

impl ScanCtx<'_> {
    fn matches_identifier(&self, text: &str) -> bool {
        (self.direct_names.contains(text) && !self.shadowed_names.contains(text))
            || (self.target_self_file
                && text == self.target_short
                && !self.shadowed_names.contains(text))
    }
}

fn scan_node(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    match node.kind() {
        "use_declaration" => return,
        "identifier" | "type_identifier" => {
            let text = node
                .utf8_text(ctx.source.as_bytes())
                .ok()
                .map(str::trim)
                .unwrap_or_default();
            if ctx.matches_identifier(text) && !is_shadowed_identifier(text, node, ctx) {
                record_hit(node, ctx);
            }
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        scan_node(child, ctx);
    }
}

fn is_shadowed_identifier(text: &str, node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    if ctx.shadowed_names.contains(text) {
        return true;
    }
    let start = node.start_byte();
    let end = node.end_byte();
    ctx.analyzer
        .find_nearest_declaration(ctx.file, start, end, text)
        .is_some_and(|decl| {
            decl.identifier == text
                && (decl.range.start_byte != start || decl.range.end_byte != end)
        })
}

fn detect_shadowed_names(
    root: Node<'_>,
    source: &str,
    direct_names: &HashSet<String>,
    namespace_names: &HashSet<String>,
    target_short: &str,
    target_self_file: bool,
) -> HashSet<String> {
    let mut names = direct_names.clone();
    names.extend(namespace_names.iter().cloned());
    if target_self_file {
        names.insert(target_short.to_string());
    }

    let mut shadowed = HashSet::default();
    collect_shadowed_names(
        root,
        source,
        &names,
        target_short,
        target_self_file,
        &mut shadowed,
    );
    shadowed
}

fn collect_shadowed_names(
    node: Node<'_>,
    source: &str,
    names: &HashSet<String>,
    target_short: &str,
    target_self_file: bool,
    shadowed: &mut HashSet<String>,
) {
    match node.kind() {
        "let_declaration" => {
            if let Some(name) = node
                .child_by_field_name("pattern")
                .and_then(|pattern| simple_pattern_name(pattern, source))
                && names.contains(&name)
            {
                shadowed.insert(name);
            }
        }
        "struct_item" | "enum_item" | "type_item" | "function_item" => {
            if let Some(name) = node
                .child_by_field_name("name")
                .and_then(|name| simple_node_text(name, source))
                && names.contains(&name)
                && !(target_self_file && name == target_short)
            {
                shadowed.insert(name);
            }
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_shadowed_names(
            child,
            source,
            names,
            target_short,
            target_self_file,
            shadowed,
        );
    }
}

pub(super) fn scan_files_for_member_target(
    analyzer: &dyn IAnalyzer,
    graph: &RustProjectGraph,
    rust: &RustAnalyzer,
    files: HashSet<ProjectFile>,
    target: &CodeUnit,
    seeds: &BTreeSet<(ProjectFile, String)>,
) -> BTreeSet<UsageHit> {
    let Some(owner) = rust.parent_of(target) else {
        return BTreeSet::new();
    };
    let member_name = target.identifier().to_string();
    let parser_language = tree_sitter_rust::LANGUAGE.into();
    let hits = Mutex::new(BTreeSet::new());

    files.par_iter().for_each(|file| {
        let owned_source: Option<Arc<String>>;
        let owned_tree: Option<Tree>;
        let (source, tree) = if let Some(parsed) = graph.parsed.get(file) {
            (parsed.source.as_str(), &parsed.tree)
        } else {
            let Ok(source) = file.read_to_string() else {
                return;
            };
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
                owned_source.as_deref().expect("owned source").as_str(),
                owned_tree.as_ref().expect("owned tree"),
            )
        };
        let line_starts = compute_line_starts(source);
        let owner_local_names: HashSet<String> = if file == target.source() {
            [owner.identifier().to_string()].into_iter().collect()
        } else {
            rust.usage_binding_local_names(file, seeds)
        };
        let trait_owner = is_trait_owner(rust, &owner);
        let receiver_type_names = if trait_owner {
            rust.trait_implementer_names(&owner, file)
        } else {
            owner_local_names.clone()
        };
        if owner_local_names.is_empty() && receiver_type_names.is_empty() {
            return;
        }
        let self_like_constructors = self_like_constructor_names(rust, &owner);
        let receiver_names =
            infer_receiver_names(source, &receiver_type_names, &self_like_constructors);
        let static_owner_names = owner_local_names;
        if receiver_names.is_empty() && static_owner_names.is_empty() {
            return;
        }

        let mut local_hits = BTreeSet::new();
        let mut ctx = MemberScanCtx {
            analyzer,
            file,
            source,
            line_starts: &line_starts,
            member_name: &member_name,
            receiver_names: &receiver_names,
            receiver_type_names: &receiver_type_names,
            static_owner_names: &static_owner_names,
            hits: &mut local_hits,
        };
        scan_member_node(tree.root_node(), &mut ctx);

        if !local_hits.is_empty() {
            let mut sink = hits.lock().expect("poisoned Rust member collector");
            sink.extend(local_hits);
        }
    });

    hits.into_inner().expect("poisoned Rust member collector")
}

struct MemberScanCtx<'a> {
    analyzer: &'a dyn IAnalyzer,
    file: &'a ProjectFile,
    source: &'a str,
    line_starts: &'a [usize],
    member_name: &'a str,
    receiver_names: &'a Vec<String>,
    receiver_type_names: &'a HashSet<String>,
    static_owner_names: &'a HashSet<String>,
    hits: &'a mut BTreeSet<UsageHit>,
}

fn scan_member_node(node: Node<'_>, ctx: &mut MemberScanCtx<'_>) {
    match node.kind() {
        "field_expression" => record_instance_member_hit(node, ctx),
        "scoped_identifier" | "scoped_type_identifier" => record_static_member_hit(node, ctx),
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        scan_member_node(child, ctx);
    }
}

fn record_instance_member_hit(node: Node<'_>, ctx: &mut MemberScanCtx<'_>) {
    if !field_expression_is_called(node) {
        return;
    }
    let Some(field) = node.child_by_field_name("field") else {
        return;
    };
    if simple_node_text(field, ctx.source).as_deref() != Some(ctx.member_name) {
        return;
    }
    let Some(receiver_name) = node
        .child_by_field_name("value")
        .and_then(|receiver| simple_node_text(receiver, ctx.source))
    else {
        return;
    };
    if !ctx.receiver_names.contains(&receiver_name) {
        return;
    }

    let start = field.start_byte();
    let end = field.end_byte();
    let Some(enclosing) = member_hit_enclosing(ctx.analyzer, ctx.file, ctx.line_starts, start, end)
    else {
        return;
    };
    let receiver_mismatched = ctx
        .analyzer
        .get_source(&enclosing, false)
        .map(|enclosing_source| {
            receiver_explicitly_mismatched(
                ctx.source,
                &enclosing_source,
                ctx.receiver_type_names,
                &receiver_name,
            )
        })
        .unwrap_or(false);
    if receiver_mismatched {
        return;
    }
    push_member_hit(
        ctx.file,
        ctx.source,
        ctx.line_starts,
        start,
        end,
        enclosing,
        ctx.hits,
    );
}

fn field_expression_is_called(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        parent.kind() == "call_expression"
            && parent
                .child_by_field_name("function")
                .is_some_and(|function| same_node(function, node))
    })
}

fn record_static_member_hit(node: Node<'_>, ctx: &mut MemberScanCtx<'_>) {
    let Some(name) = node.child_by_field_name("name") else {
        return;
    };
    if simple_node_text(name, ctx.source).as_deref() != Some(ctx.member_name) {
        return;
    }
    let Some(path) = node.child_by_field_name("path") else {
        return;
    };
    let Some(owner_name) = simple_node_text(path, ctx.source) else {
        return;
    };
    if !ctx.static_owner_names.contains(&owner_name) {
        return;
    }

    let start = name.start_byte();
    let end = name.end_byte();
    let Some(enclosing) = member_hit_enclosing(ctx.analyzer, ctx.file, ctx.line_starts, start, end)
    else {
        return;
    };
    push_member_hit(
        ctx.file,
        ctx.source,
        ctx.line_starts,
        start,
        end,
        enclosing,
        ctx.hits,
    );
}

fn same_node(left: Node<'_>, right: Node<'_>) -> bool {
    left.start_byte() == right.start_byte()
        && left.end_byte() == right.end_byte()
        && left.kind() == right.kind()
}

fn self_like_constructor_names(rust: &RustAnalyzer, owner: &CodeUnit) -> HashSet<String> {
    rust.get_all_declarations()
        .into_iter()
        .filter(|code_unit| code_unit.source() == owner.source())
        .filter(|code_unit| code_unit.is_function())
        .filter(|code_unit| {
            rust.parent_of(code_unit)
                .map(|parent| parent == *owner)
                .unwrap_or(false)
        })
        .filter_map(|code_unit| {
            let source = rust.get_source(&code_unit, false)?;
            let (_, return_ty) = source.split_once("->")?;
            let normalized: String = return_ty.chars().filter(|ch| !ch.is_whitespace()).collect();
            (normalized.contains("Self")
                || normalized.contains(owner.identifier())
                || normalized.contains("Result<Self")
                || normalized.contains(&format!("Result<{}", owner.identifier())))
            .then(|| code_unit.identifier().to_string())
        })
        .collect()
}

fn expanded_receiver_type_names(
    source: &str,
    owner_local_names: &HashSet<String>,
) -> HashSet<String> {
    let mut owner_type_names = owner_local_names.clone();
    let aliases = parse_rust_source(source)
        .map(|tree| collect_type_aliases(tree.root_node(), source))
        .unwrap_or_default();

    loop {
        let mut changed = false;
        for (alias, target) in &aliases {
            if owner_type_names.contains(target) && owner_type_names.insert(alias.clone()) {
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    owner_type_names
}

fn receiver_explicitly_mismatched(
    file_source: &str,
    enclosing_source: &str,
    owner_local_names: &HashSet<String>,
    receiver_name: &str,
) -> bool {
    let owner_type_names = expanded_receiver_type_names(file_source, owner_local_names);
    let Some(tree) = parse_rust_source(enclosing_source) else {
        return false;
    };

    for (name, ty) in collect_explicit_receiver_annotations(tree.root_node(), enclosing_source) {
        if name == receiver_name {
            return ty.as_ref().is_none_or(|ty| !owner_type_names.contains(ty));
        }
    }

    false
}

fn infer_receiver_names(
    source: &str,
    owner_local_names: &HashSet<String>,
    self_like_constructors: &HashSet<String>,
) -> Vec<String> {
    let owner_type_names = expanded_receiver_type_names(source, owner_local_names);
    let bindings = collect_receiver_bindings(source, &owner_type_names, self_like_constructors);
    let mut receivers: Vec<_> = bindings
        .snapshot()
        .matching_symbols(|target| owner_type_names.contains(target))
        .into_iter()
        .collect();
    receivers.sort();
    receivers
}

fn collect_receiver_bindings(
    source: &str,
    owner_type_names: &HashSet<String>,
    self_like_constructors: &HashSet<String>,
) -> LocalInferenceEngine<String> {
    let mut engine = LocalInferenceEngine::new(LocalInferenceConfig::default());
    let Some(tree) = parse_rust_source(source) else {
        return engine;
    };
    let root = tree.root_node();

    let option_field_types = collect_option_field_types(root, source);
    let mut aliases = Vec::new();
    for event in collect_receiver_events(root, source, &option_field_types) {
        match event {
            ReceiverEvent::TypedBinding { name, ty } => {
                if owner_type_names.contains(&ty) {
                    engine.seed_symbol(name, ty);
                }
            }
            ReceiverEvent::Constructed {
                name,
                ty,
                constructor,
            } => {
                let allowed_constructor =
                    constructor.is_none_or(|name| self_like_constructors.contains(&name));
                if owner_type_names.contains(&ty) && allowed_constructor {
                    engine.seed_symbol(name, ty);
                }
            }
            ReceiverEvent::Alias { name, source } => aliases.push((name, source)),
        }
    }
    engine.apply_aliases_until_stable(aliases);

    engine
}

enum ReceiverEvent {
    TypedBinding {
        name: String,
        ty: String,
    },
    Constructed {
        name: String,
        ty: String,
        constructor: Option<String>,
    },
    Alias {
        name: String,
        source: String,
    },
}

fn parse_rust_source(source: &str) -> Option<Tree> {
    if source.trim().is_empty() {
        return None;
    }
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .ok()?;
    parser.parse(source, None)
}

fn collect_type_aliases(root: Node<'_>, source: &str) -> Vec<(String, String)> {
    let mut aliases = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "type_item"
            && let (Some(alias), Some(target)) = (
                node.child_by_field_name("name")
                    .and_then(|name| simple_node_text(name, source)),
                node.child_by_field_name("type")
                    .and_then(|ty| simple_type_name(ty, source)),
            )
        {
            aliases.push((alias, target));
        }

        let mut cursor = node.walk();
        let mut children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
        children.reverse();
        stack.extend(children);
    }
    aliases
}

fn collect_explicit_receiver_annotations(
    root: Node<'_>,
    source: &str,
) -> Vec<(String, Option<String>)> {
    let mut bindings = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "parameter" | "let_declaration" => {
                if let Some((name, ty)) = explicit_receiver_annotation(node, source) {
                    bindings.push((name, ty));
                }
            }
            _ => {}
        }

        let mut cursor = node.walk();
        let mut children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
        children.reverse();
        stack.extend(children);
    }
    bindings
}

fn collect_option_field_types(root: Node<'_>, source: &str) -> HashMap<String, String> {
    let mut fields = HashMap::default();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "field_declaration"
            && let (Some(name), Some(ty)) = (
                node.child_by_field_name("name")
                    .and_then(|name| simple_node_text(name, source)),
                node.child_by_field_name("type")
                    .and_then(|ty| option_inner_type_name(ty, source)),
            )
        {
            fields.insert(name, ty);
        }

        let mut cursor = node.walk();
        let mut children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
        children.reverse();
        stack.extend(children);
    }
    fields
}

fn collect_receiver_events(
    root: Node<'_>,
    source: &str,
    option_field_types: &HashMap<String, String>,
) -> Vec<ReceiverEvent> {
    let mut events = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "parameter" => {
                if let Some((name, ty)) = typed_parameter_binding(node, source) {
                    events.push(ReceiverEvent::TypedBinding { name, ty });
                }
            }
            "let_declaration" => {
                collect_let_receiver_event(node, source, option_field_types, &mut events)
            }
            _ => {}
        }

        let mut cursor = node.walk();
        let mut children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
        children.reverse();
        stack.extend(children);
    }
    events
}

fn collect_let_receiver_event(
    node: Node<'_>,
    source: &str,
    option_field_types: &HashMap<String, String>,
    events: &mut Vec<ReceiverEvent>,
) {
    if let Some((name, ty)) = typed_let_binding(node, source) {
        events.push(ReceiverEvent::TypedBinding { name, ty });
        return;
    }

    if let Some((name, ty)) = self_field_as_ref_let_else_binding(node, source, option_field_types) {
        events.push(ReceiverEvent::TypedBinding { name, ty });
        return;
    }

    let Some(pattern) = node.child_by_field_name("pattern") else {
        return;
    };
    let Some(name) = simple_pattern_name(pattern, source) else {
        return;
    };
    let Some(value) = node.child_by_field_name("value") else {
        return;
    };

    if let Some((ty, constructor)) = constructed_receiver_type(value, source) {
        events.push(ReceiverEvent::Constructed {
            name,
            ty,
            constructor,
        });
    } else if let Some(source) = simple_node_text(value, source) {
        events.push(ReceiverEvent::Alias { name, source });
    }
}

fn typed_parameter_binding(node: Node<'_>, source: &str) -> Option<(String, String)> {
    let name = node
        .child_by_field_name("pattern")
        .and_then(|pattern| simple_pattern_name(pattern, source))?;
    let ty = node
        .child_by_field_name("type")
        .and_then(|ty| simple_type_name(ty, source))?;
    Some((name, ty))
}

fn typed_let_binding(node: Node<'_>, source: &str) -> Option<(String, String)> {
    let name = node
        .child_by_field_name("pattern")
        .and_then(|pattern| simple_pattern_name(pattern, source))?;
    let ty = node
        .child_by_field_name("type")
        .and_then(|ty| simple_type_name(ty, source))?;
    Some((name, ty))
}

fn explicit_receiver_annotation(node: Node<'_>, source: &str) -> Option<(String, Option<String>)> {
    let pattern = node.child_by_field_name("pattern")?;
    let name = simple_pattern_name(pattern, source)?;
    let ty = node.child_by_field_name("type")?;
    Some((name, simple_type_name(ty, source)))
}

fn self_field_as_ref_let_else_binding(
    node: Node<'_>,
    source: &str,
    option_field_types: &HashMap<String, String>,
) -> Option<(String, String)> {
    let pattern = node.child_by_field_name("pattern")?;
    let name = some_tuple_pattern_name(pattern, source)?;
    let value = node.child_by_field_name("value")?;
    let field_name = self_field_as_ref_field_name(value, source)?;
    let ty = option_field_types.get(&field_name)?.clone();
    Some((name, ty))
}

fn some_tuple_pattern_name(node: Node<'_>, source: &str) -> Option<String> {
    if node.kind() != "tuple_struct_pattern" {
        return None;
    }
    let type_name = node
        .child_by_field_name("type")
        .and_then(|ty| simple_node_text(ty, source))?;
    if type_name != "Some" {
        return None;
    }
    let type_id = node.child_by_field_name("type").map(|ty| ty.id());
    let mut cursor = node.walk();
    let identifiers: Vec<_> = node
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "identifier" && Some(child.id()) != type_id)
        .filter_map(|child| simple_node_text(child, source))
        .collect();
    (identifiers.len() == 1).then(|| identifiers[0].clone())
}

fn self_field_as_ref_field_name(node: Node<'_>, source: &str) -> Option<String> {
    if node.kind() != "call_expression" {
        return None;
    }
    let function = node.child_by_field_name("function")?;
    if function.kind() != "field_expression" {
        return None;
    }
    if function
        .child_by_field_name("field")
        .and_then(|field| simple_node_text(field, source))
        .as_deref()
        != Some("as_ref")
    {
        return None;
    }
    let receiver = function.child_by_field_name("value")?;
    if receiver.kind() != "field_expression" {
        return None;
    }
    if receiver
        .child_by_field_name("value")
        .is_some_and(|value| value.kind() == "self")
    {
        receiver
            .child_by_field_name("field")
            .and_then(|field| simple_node_text(field, source))
    } else {
        None
    }
}

fn constructed_receiver_type(node: Node<'_>, source: &str) -> Option<(String, Option<String>)> {
    match node.kind() {
        "struct_expression" => node
            .child_by_field_name("name")
            .and_then(|name| simple_type_name(name, source))
            .map(|name| (name, None)),
        "call_expression" => {
            let function = node.child_by_field_name("function")?;
            match function.kind() {
                "identifier" | "type_identifier" => {
                    simple_node_text(function, source).map(|name| (name, None))
                }
                "scoped_identifier" => {
                    let ty = function
                        .child_by_field_name("path")
                        .and_then(|path| simple_type_name(path, source))?;
                    let constructor = function
                        .child_by_field_name("name")
                        .and_then(|name| simple_node_text(name, source));
                    Some((ty, constructor))
                }
                "field_expression" => function
                    .child_by_field_name("value")
                    .and_then(|value| constructed_receiver_type(value, source)),
                _ => None,
            }
        }
        _ => None,
    }
}

fn option_inner_type_name(node: Node<'_>, source: &str) -> Option<String> {
    if node.kind() != "generic_type" {
        return None;
    }
    if node
        .child_by_field_name("type")
        .and_then(|ty| simple_node_text(ty, source))
        .as_deref()
        != Some("Option")
    {
        return None;
    }
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|child| child.kind() != "type_identifier")
        .find_map(|child| first_simple_type_name(child, source))
}

fn first_simple_type_name(node: Node<'_>, source: &str) -> Option<String> {
    if let Some(name) = simple_type_name(node, source) {
        return Some(name);
    }
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find_map(|child| first_simple_type_name(child, source))
}

fn simple_type_name(node: Node<'_>, source: &str) -> Option<String> {
    matches!(node.kind(), "type_identifier" | "identifier")
        .then(|| simple_node_text(node, source))
        .flatten()
}

fn simple_pattern_name(node: Node<'_>, source: &str) -> Option<String> {
    (node.kind() == "identifier")
        .then(|| simple_node_text(node, source))
        .flatten()
}

fn simple_node_text(node: Node<'_>, source: &str) -> Option<String> {
    let text = source.get(node.start_byte()..node.end_byte())?.trim();
    (!text.is_empty()).then(|| text.to_string())
}
