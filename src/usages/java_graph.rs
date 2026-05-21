use crate::analyzer::{
    AnalyzerDelegate, CodeUnit, IAnalyzer, JavaAnalyzer, Language, MultiAnalyzer, ProjectFile,
    Range,
};
use crate::hash::HashSet;
use crate::text_utils::{compute_line_starts, find_line_index_for_offset};
use crate::usages::local_inference::{LocalInferenceConfig, LocalInferenceEngine};
use crate::usages::model::{FuzzyResult, UsageHit};
use crate::usages::traits::UsageAnalyzer;
use std::collections::BTreeSet;
use tree_sitter::{Node, Parser};

const GRAPH_HIT_CONFIDENCE: f64 = 1.0;
const SNIPPET_CONTEXT_LINES: usize = 3;

#[derive(Default)]
pub struct JavaUsageGraphStrategy {
    _private: (),
}

impl JavaUsageGraphStrategy {
    pub fn new() -> Self {
        Self { _private: () }
    }

    pub fn can_handle(target: &CodeUnit) -> bool {
        target_language(target) == Language::Java
    }
}

impl UsageAnalyzer for JavaUsageGraphStrategy {
    fn find_usages(
        &self,
        analyzer: &dyn IAnalyzer,
        overloads: &[CodeUnit],
        candidate_files: &HashSet<ProjectFile>,
        max_usages: usize,
    ) -> FuzzyResult {
        if overloads.is_empty() {
            return FuzzyResult::empty_success();
        }

        let target = &overloads[0];
        if target_language(target) != Language::Java {
            return FuzzyResult::Failure {
                fq_name: target.fq_name(),
                reason: "JavaUsageGraphStrategy: target is not Java".to_string(),
            };
        }

        let Some(java) = resolve_java_analyzer(analyzer) else {
            return FuzzyResult::Failure {
                fq_name: target.fq_name(),
                reason: "JavaUsageGraphStrategy: analyzer does not expose JavaAnalyzer".to_string(),
            };
        };

        let Some(spec) = TargetSpec::from_target(java, target) else {
            return FuzzyResult::Failure {
                fq_name: target.fq_name(),
                reason: "JavaUsageGraphStrategy: target shape is unsupported".to_string(),
            };
        };

        let files: HashSet<ProjectFile> = candidate_files
            .iter()
            .filter(|file| file.rel_path().extension().and_then(|ext| ext.to_str()) == Some("java"))
            .cloned()
            .chain(std::iter::once(target.source().clone()))
            .collect();

        let mut hits = BTreeSet::new();
        let mut saw_unproven_match = false;
        let mut raw_match_count = 0usize;
        for file in files {
            scan_file(
                java,
                analyzer,
                &file,
                &spec,
                &mut hits,
                &mut saw_unproven_match,
                &mut raw_match_count,
            );
        }

        let hits: BTreeSet<_> = hits
            .into_iter()
            .filter(|hit| &hit.enclosing != target)
            .collect();

        if hits.is_empty() && saw_unproven_match {
            return FuzzyResult::Failure {
                fq_name: target.fq_name(),
                reason: "JavaUsageGraphStrategy: no proven structured hits".to_string(),
            };
        }

        if hits.is_empty() && raw_match_count > 0 {
            return FuzzyResult::success(target.clone(), BTreeSet::new());
        }

        if hits.is_empty() {
            return FuzzyResult::success(target.clone(), BTreeSet::new());
        }

        if hits.len() > max_usages {
            return FuzzyResult::TooManyCallsites {
                short_name: target.short_name().to_string(),
                total_callsites: hits.len(),
                limit: max_usages,
            };
        }

        FuzzyResult::success(target.clone(), hits)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TargetKind {
    Type,
    Constructor,
    Method,
    Field,
}

struct TargetSpec {
    kind: TargetKind,
    owner: CodeUnit,
    accepted_owner_fq_names: HashSet<String>,
    member_name: String,
    method_arity: Option<usize>,
}

impl TargetSpec {
    fn from_target(analyzer: &JavaAnalyzer, target: &CodeUnit) -> Option<Self> {
        if target.is_class() {
            let fq_name = target.fq_name();
            return Some(Self {
                kind: TargetKind::Type,
                owner: target.clone(),
                accepted_owner_fq_names: [fq_name].into_iter().collect(),
                member_name: target.identifier().to_string(),
                method_arity: None,
            });
        }

        let owner = analyzer.parent_of(target)?;
        let kind = if target.is_field() {
            TargetKind::Field
        } else if target.identifier() == owner.identifier() {
            TargetKind::Constructor
        } else {
            TargetKind::Method
        };

        Some(Self {
            kind,
            accepted_owner_fq_names: [owner.fq_name()].into_iter().collect(),
            member_name: target.identifier().to_string(),
            method_arity: (kind == TargetKind::Method || kind == TargetKind::Constructor)
                .then(|| signature_arity(target.signature())),
            owner,
        })
    }
}

fn signature_arity(signature: Option<&str>) -> usize {
    let Some(signature) = signature else {
        return 0;
    };
    let inner = signature
        .strip_prefix('(')
        .and_then(|rest| rest.strip_suffix(')'))
        .unwrap_or(signature)
        .trim();
    if inner.is_empty() {
        return 0;
    }
    inner.split(',').count()
}

fn resolve_java_analyzer(analyzer: &dyn IAnalyzer) -> Option<&JavaAnalyzer> {
    if let Some(java) = (analyzer as &dyn std::any::Any).downcast_ref::<JavaAnalyzer>() {
        return Some(java);
    }

    let multi = (analyzer as &dyn std::any::Any).downcast_ref::<MultiAnalyzer>()?;
    match multi.delegates().get(&Language::Java) {
        Some(AnalyzerDelegate::Java(java)) => Some(java),
        _ => None,
    }
}

fn target_language(target: &CodeUnit) -> Language {
    target
        .source()
        .rel_path()
        .extension()
        .and_then(|ext| ext.to_str())
        .map(Language::from_extension)
        .unwrap_or(Language::None)
}

fn scan_file(
    java: &JavaAnalyzer,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    spec: &TargetSpec,
    hits: &mut BTreeSet<UsageHit>,
    saw_unproven_match: &mut bool,
    raw_match_count: &mut usize,
) {
    let Ok(source) = file.read_to_string() else {
        return;
    };
    if source.is_empty() {
        return;
    }

    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_java::LANGUAGE.into())
        .is_err()
    {
        return;
    }
    let Some(tree) = parser.parse(source.as_str(), None) else {
        return;
    };
    let line_starts = compute_line_starts(&source);

    let mut bindings = LocalInferenceEngine::new(LocalInferenceConfig::default());
    seed_class_binding(java, file, spec, &mut bindings);

    let mut ctx = ScanCtx {
        java,
        analyzer,
        file,
        source: &source,
        line_starts: &line_starts,
        spec,
        bindings: &mut bindings,
        hits,
        saw_unproven_match,
        raw_match_count,
    };
    scan_node(tree.root_node(), &mut ctx);
}

fn seed_class_binding(
    java: &JavaAnalyzer,
    file: &ProjectFile,
    spec: &TargetSpec,
    bindings: &mut LocalInferenceEngine<String>,
) {
    if spec.kind == TargetKind::Type
        || java
            .resolve_type_name_in_file(file, spec.owner.identifier())
            .is_some_and(|resolved| resolved == spec.owner)
    {
        bindings.seed_symbol(spec.owner.identifier().to_string(), spec.owner.fq_name());
    }
}

struct ScanCtx<'a> {
    java: &'a JavaAnalyzer,
    analyzer: &'a dyn IAnalyzer,
    file: &'a ProjectFile,
    source: &'a str,
    line_starts: &'a [usize],
    spec: &'a TargetSpec,
    bindings: &'a mut LocalInferenceEngine<String>,
    hits: &'a mut BTreeSet<UsageHit>,
    saw_unproven_match: &'a mut bool,
    raw_match_count: &'a mut usize,
}

fn scan_node(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let enters_scope = matches!(
        node.kind(),
        "method_declaration"
            | "constructor_declaration"
            | "block"
            | "lambda_expression"
            | "catch_clause"
            | "enhanced_for_statement"
            | "for_statement"
    );

    if enters_scope {
        ctx.bindings.enter_scope();
        seed_declarations(node, ctx);
    } else {
        seed_inline_declarations(node, ctx);
    }

    maybe_record_hit(node, ctx);

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        scan_node(child, ctx);
    }

    if enters_scope {
        ctx.bindings.exit_scope();
    }
}

fn seed_declarations(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    match node.kind() {
        "method_declaration" | "constructor_declaration" => {
            if let Some(parameters) = node.child_by_field_name("parameters") {
                let mut cursor = parameters.walk();
                for child in parameters.named_children(&mut cursor) {
                    if child.kind() == "formal_parameter" {
                        seed_typed_binding(child, ctx);
                    }
                }
            }
        }
        "catch_clause" => {
            if let Some(parameter) = node.child_by_field_name("parameter") {
                seed_typed_binding(parameter, ctx);
            }
        }
        "enhanced_for_statement" => {
            if let Some(name) = node.child_by_field_name("name") {
                ctx.bindings.declare_shadow(node_text(name, ctx.source));
            }
        }
        _ => {}
    }
}

fn seed_inline_declarations(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    match node.kind() {
        "local_variable_declaration" | "field_declaration" => seed_variable_declaration(node, ctx),
        "formal_parameter" => seed_typed_binding(node, ctx),
        _ => {}
    }
}

fn seed_variable_declaration(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let Some(type_node) = node.child_by_field_name("type") else {
        return;
    };
    let mut resolved_type = resolve_type_from_node(type_node, ctx);
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() != "variable_declarator" {
            continue;
        }
        let Some(name) = child.child_by_field_name("name") else {
            continue;
        };
        let binding_name = node_text(name, ctx.source);
        if binding_name.is_empty() {
            continue;
        }

        if resolved_type.is_none()
            && let Some(value) = child.child_by_field_name("value")
        {
            resolved_type = infer_type_from_value(value, ctx);
        }

        if let Some(resolved) = resolved_type.as_ref()
            && ctx
                .spec
                .accepted_owner_fq_names
                .contains(&resolved.fq_name())
        {
            ctx.bindings
                .seed_symbol(binding_name.to_string(), resolved.fq_name());
        } else {
            ctx.bindings.declare_shadow(binding_name.to_string());
        }
    }
}

fn seed_typed_binding(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let Some(name) = node.child_by_field_name("name") else {
        return;
    };
    let binding_name = node_text(name, ctx.source);
    if binding_name.is_empty() {
        return;
    }
    let resolved = node
        .child_by_field_name("type")
        .and_then(|type_node| resolve_type_from_node(type_node, ctx));
    if let Some(resolved) = resolved
        && ctx
            .spec
            .accepted_owner_fq_names
            .contains(&resolved.fq_name())
    {
        ctx.bindings
            .seed_symbol(binding_name.to_string(), resolved.fq_name());
    } else {
        ctx.bindings.declare_shadow(binding_name.to_string());
    }
}

fn maybe_record_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    match ctx.spec.kind {
        TargetKind::Type => maybe_record_type_hit(node, ctx),
        TargetKind::Constructor => maybe_record_constructor_hit(node, ctx),
        TargetKind::Method => maybe_record_method_hit(node, ctx),
        TargetKind::Field => maybe_record_field_hit(node, ctx),
    }
}

fn maybe_record_type_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if !matches!(
        node.kind(),
        "type_identifier" | "scoped_type_identifier" | "generic_type"
    ) {
        return;
    }
    if is_ignored_type_context(node) {
        return;
    }
    let Some(resolved) = resolve_type_from_node(node, ctx) else {
        return;
    };
    if resolved != ctx.spec.owner {
        return;
    }
    push_hit(node, ctx);
}

fn maybe_record_constructor_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if node.kind() != "object_creation_expression" {
        return;
    }
    let Some(type_node) = node.child_by_field_name("type") else {
        return;
    };
    let Some(resolved) = resolve_type_from_node(type_node, ctx) else {
        return;
    };
    if resolved != ctx.spec.owner {
        return;
    }
    push_hit(node, ctx);
}

fn maybe_record_method_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if node.kind() != "method_invocation" {
        return;
    }
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    if node_text(name_node, ctx.source) != ctx.spec.member_name {
        return;
    }
    if let Some(expected_arity) = ctx.spec.method_arity
        && invocation_arity(node) != expected_arity
    {
        return;
    }

    let receiver_matches = if let Some(object) = node.child_by_field_name("object") {
        receiver_matches_target(object, ctx)
    } else {
        same_owner_context(node, ctx) || is_static_import_of_target_method(ctx)
    };

    if receiver_matches {
        push_hit(name_node, ctx);
    } else {
        *ctx.saw_unproven_match = true;
    }
}

fn maybe_record_field_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if node.kind() == "field_access" {
        let Some(field_node) = node.child_by_field_name("field") else {
            return;
        };
        if node_text(field_node, ctx.source) != ctx.spec.member_name {
            return;
        }
        if let Some(object) = node.child_by_field_name("object") {
            if receiver_matches_target(object, ctx) {
                push_hit(field_node, ctx);
            } else {
                *ctx.saw_unproven_match = true;
            }
        }
        return;
    }

    if node.kind() != "identifier" || node_text(node, ctx.source) != ctx.spec.member_name {
        return;
    }
    if same_owner_context(node, ctx) && !is_declaration_name(node) {
        push_hit(node, ctx);
    }
}

fn receiver_matches_target(receiver: Node<'_>, ctx: &mut ScanCtx<'_>) -> bool {
    match receiver.kind() {
        "identifier" => {
            let name = node_text(receiver, ctx.source);
            ctx.bindings
                .resolve_symbol(name)
                .as_precise()
                .is_some_and(|targets| targets.contains(&ctx.spec.owner.fq_name()))
        }
        "type_identifier" | "scoped_type_identifier" | "generic_type" => {
            resolve_type_from_node(receiver, ctx).is_some_and(|resolved| resolved == ctx.spec.owner)
        }
        "this" => {
            owner_matches_target_context(receiver, ctx)
                || anonymous_creation_context_matches_target(receiver, ctx)
        }
        "super" => {
            owner_matches_target_context(receiver, ctx)
                || anonymous_creation_context_matches_target(receiver, ctx)
        }
        _ => false,
    }
}

fn is_static_import_of_target_method(ctx: &ScanCtx<'_>) -> bool {
    let target_fq_name = ctx.spec.owner.fq_name();
    ctx.analyzer
        .import_statements(ctx.file)
        .iter()
        .any(|import| {
            let trimmed = import.trim();
            if !trimmed.starts_with("import static ") {
                return false;
            }
            let path = trimmed
                .strip_prefix("import static ")
                .unwrap_or(trimmed)
                .trim_end_matches(';')
                .trim();
            path == format!("{}.{}", target_fq_name, ctx.spec.member_name)
                || path == format!("{target_fq_name}.*")
        })
}

fn same_owner_context(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    let range = Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: find_line_index_for_offset(ctx.line_starts, node.start_byte()),
        end_line: find_line_index_for_offset(ctx.line_starts, node.end_byte()),
    };
    let Some(enclosing) = ctx.analyzer.enclosing_code_unit(ctx.file, &range) else {
        return false;
    };
    ctx.analyzer
        .parent_of(&enclosing)
        .is_some_and(|owner| owner == ctx.spec.owner)
}

fn owner_matches_target_context(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    let range = Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: find_line_index_for_offset(ctx.line_starts, node.start_byte()),
        end_line: find_line_index_for_offset(ctx.line_starts, node.end_byte()),
    };
    let Some(enclosing) = ctx.analyzer.enclosing_code_unit(ctx.file, &range) else {
        return false;
    };
    let Some(owner) = ctx.analyzer.parent_of(&enclosing) else {
        return false;
    };
    if owner == ctx.spec.owner {
        return true;
    }
    ctx.analyzer
        .type_hierarchy_provider()
        .is_some_and(|provider| provider.get_ancestors(&owner).contains(&ctx.spec.owner))
}

fn anonymous_creation_context_matches_target(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == "object_creation_expression"
            && let Some(type_node) = parent.child_by_field_name("type")
            && resolve_type_from_node(type_node, ctx)
                .is_some_and(|resolved| resolved == ctx.spec.owner)
        {
            return true;
        }
        current = parent.parent();
    }
    false
}

fn invocation_arity(node: Node<'_>) -> usize {
    let Some(arguments) = node.child_by_field_name("arguments") else {
        return 0;
    };
    let mut cursor = arguments.walk();
    arguments.named_children(&mut cursor).count()
}

fn resolve_type_from_node(node: Node<'_>, ctx: &ScanCtx<'_>) -> Option<CodeUnit> {
    let raw = node_text(node, ctx.source);
    if raw.is_empty() {
        return None;
    }
    let normalized = raw
        .split('<')
        .next()
        .unwrap_or(raw)
        .trim()
        .trim_end_matches("[]")
        .trim();
    ctx.java.resolve_type_name_in_file(ctx.file, normalized)
}

fn infer_type_from_value(node: Node<'_>, ctx: &ScanCtx<'_>) -> Option<CodeUnit> {
    match node.kind() {
        "object_creation_expression" => node
            .child_by_field_name("type")
            .and_then(|type_node| resolve_type_from_node(type_node, ctx)),
        "identifier" => {
            let name = node_text(node, ctx.source);
            let targets = ctx.bindings.resolve_symbol(name);
            let fq_name = targets.as_precise()?.iter().next()?;
            ctx.analyzer
                .get_definitions(fq_name)
                .into_iter()
                .find(|unit| unit.is_class())
        }
        _ => None,
    }
}

fn is_ignored_type_context(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    matches!(
        parent.kind(),
        "package_declaration" | "import_declaration" | "class_declaration"
    ) && parent.child_by_field_name("name") == Some(node)
}

fn is_declaration_name(node: Node<'_>) -> bool {
    node.parent()
        .and_then(|parent| parent.child_by_field_name("name"))
        == Some(node)
}

fn push_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    *ctx.raw_match_count += 1;
    let start = node.start_byte();
    let end = node.end_byte();
    let line_idx = find_line_index_for_offset(ctx.line_starts, start);
    let range = Range {
        start_byte: start,
        end_byte: end,
        start_line: line_idx,
        end_line: find_line_index_for_offset(ctx.line_starts, end),
    };
    let Some(enclosing) = ctx.analyzer.enclosing_code_unit(ctx.file, &range) else {
        return;
    };
    ctx.hits.insert(UsageHit::new(
        ctx.file.clone(),
        line_idx + 1,
        start,
        end,
        enclosing,
        GRAPH_HIT_CONFIDENCE,
        build_snippet(ctx.source, ctx.line_starts, line_idx),
    ));
}

fn build_snippet(source: &str, line_starts: &[usize], line_idx: usize) -> String {
    if line_starts.is_empty() {
        return String::new();
    }
    let snippet_start = line_idx.saturating_sub(SNIPPET_CONTEXT_LINES);
    let snippet_end = line_idx
        .saturating_add(SNIPPET_CONTEXT_LINES)
        .min(line_starts.len().saturating_sub(1));

    let mut snippet = String::new();
    for idx in snippet_start..=snippet_end {
        let start = line_starts[idx];
        let end = line_starts.get(idx + 1).copied().unwrap_or(source.len());
        snippet.push_str(source.get(start..end).unwrap_or_default());
    }
    snippet
}

fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source
        .get(node.start_byte()..node.end_byte())
        .unwrap_or_default()
        .trim()
}
