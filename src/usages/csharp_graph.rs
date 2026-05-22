use crate::analyzer::{
    AnalyzerDelegate, CSharpAnalyzer, CodeUnit, IAnalyzer, Language, MultiAnalyzer, ProjectFile,
    Range,
};
use crate::hash::{HashMap, HashSet};
use crate::text_utils::{compute_line_starts, find_line_index_for_offset};
use crate::usages::local_inference::{LocalInferenceConfig, LocalInferenceEngine};
use crate::usages::model::{FuzzyResult, UsageHit};
use crate::usages::traits::UsageAnalyzer;
use std::collections::BTreeSet;
use tree_sitter::{Node, Parser};

const GRAPH_HIT_CONFIDENCE: f64 = 1.0;
const SNIPPET_CONTEXT_LINES: usize = 3;

#[derive(Default)]
pub struct CSharpUsageGraphStrategy {
    _private: (),
}

impl CSharpUsageGraphStrategy {
    pub fn new() -> Self {
        Self { _private: () }
    }

    pub fn can_handle(target: &CodeUnit) -> bool {
        target_language(target) == Language::CSharp
    }
}

impl UsageAnalyzer for CSharpUsageGraphStrategy {
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
        if target_language(target) != Language::CSharp {
            return FuzzyResult::Failure {
                fq_name: target.fq_name(),
                reason: "CSharpUsageGraphStrategy: target is not C#".to_string(),
            };
        }

        let Some(csharp) = resolve_csharp_analyzer(analyzer) else {
            return FuzzyResult::Failure {
                fq_name: target.fq_name(),
                reason: "CSharpUsageGraphStrategy: analyzer does not expose CSharpAnalyzer"
                    .to_string(),
            };
        };

        let Some(spec) = TargetSpec::from_target(analyzer, target) else {
            return FuzzyResult::Failure {
                fq_name: target.fq_name(),
                reason: "CSharpUsageGraphStrategy: target shape is unsupported".to_string(),
            };
        };

        let files: HashSet<ProjectFile> = candidate_files
            .iter()
            .filter(|file| file_language(file) == Language::CSharp)
            .cloned()
            .chain(std::iter::once(target.source().clone()))
            .collect();

        let mut hits = BTreeSet::new();
        let mut saw_unproven_match = false;
        let mut limit_exceeded = false;
        for file in files {
            scan_file(
                csharp,
                analyzer,
                &file,
                &spec,
                max_usages,
                &mut hits,
                &mut saw_unproven_match,
                &mut limit_exceeded,
            );
            if limit_exceeded {
                break;
            }
        }

        if saw_unproven_match && spec.kind != TargetKind::Type {
            return FuzzyResult::Failure {
                fq_name: target.fq_name(),
                reason: "CSharpUsageGraphStrategy: no proven structured hits".to_string(),
            };
        }

        if limit_exceeded || hits.len() > max_usages {
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
    target: CodeUnit,
    kind: TargetKind,
    owner: CodeUnit,
    member_name: String,
    method_arity: Option<usize>,
}

impl TargetSpec {
    fn from_target(analyzer: &dyn IAnalyzer, target: &CodeUnit) -> Option<Self> {
        if target.is_class() {
            return Some(Self {
                target: target.clone(),
                kind: TargetKind::Type,
                owner: target.clone(),
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
            target: target.clone(),
            kind,
            owner,
            member_name: target.identifier().to_string(),
            method_arity: (kind == TargetKind::Method || kind == TargetKind::Constructor)
                .then(|| signature_arity(target.signature())),
        })
    }
}

fn resolve_csharp_analyzer(analyzer: &dyn IAnalyzer) -> Option<&CSharpAnalyzer> {
    if let Some(csharp) = (analyzer as &dyn std::any::Any).downcast_ref::<CSharpAnalyzer>() {
        return Some(csharp);
    }

    let multi = (analyzer as &dyn std::any::Any).downcast_ref::<MultiAnalyzer>()?;
    match multi.delegates().get(&Language::CSharp) {
        Some(AnalyzerDelegate::CSharp(csharp)) => Some(csharp),
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

fn file_language(file: &ProjectFile) -> Language {
    file.rel_path()
        .extension()
        .and_then(|ext| ext.to_str())
        .map(Language::from_extension)
        .unwrap_or(Language::None)
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
    count_top_level_comma_separated(inner)
}

#[allow(clippy::too_many_arguments)]
fn scan_file(
    csharp: &CSharpAnalyzer,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    spec: &TargetSpec,
    max_usages: usize,
    hits: &mut BTreeSet<UsageHit>,
    saw_unproven_match: &mut bool,
    limit_exceeded: &mut bool,
) {
    if *limit_exceeded {
        return;
    }
    let Ok(source) = file.read_to_string() else {
        return;
    };
    if source.is_empty() {
        return;
    }

    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_c_sharp::LANGUAGE.into())
        .is_err()
    {
        return;
    }
    let Some(tree) = parser.parse(source.as_str(), None) else {
        return;
    };
    let line_starts = compute_line_starts(&source);

    let mut ctx = ScanCtx {
        csharp,
        analyzer,
        file,
        source: &source,
        line_starts: &line_starts,
        spec,
        hits,
        saw_unproven_match,
        max_usages,
        limit_exceeded,
        enclosing_cache: HashMap::default(),
    };
    scan_node(tree.root_node(), &mut ctx);
}

struct ScanCtx<'a> {
    csharp: &'a CSharpAnalyzer,
    analyzer: &'a dyn IAnalyzer,
    file: &'a ProjectFile,
    source: &'a str,
    line_starts: &'a [usize],
    spec: &'a TargetSpec,
    hits: &'a mut BTreeSet<UsageHit>,
    saw_unproven_match: &'a mut bool,
    max_usages: usize,
    limit_exceeded: &'a mut bool,
    enclosing_cache: HashMap<(usize, usize), Option<CodeUnit>>,
}

fn scan_node(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if *ctx.limit_exceeded {
        return;
    }

    match ctx.spec.kind {
        TargetKind::Type => scan_type_reference(node, ctx),
        TargetKind::Constructor => scan_constructor_reference(node, ctx),
        TargetKind::Method | TargetKind::Field => {
            scan_member_reference(node, ctx);
            scan_unqualified_member_reference(node, ctx);
        }
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        scan_node(child, ctx);
        if *ctx.limit_exceeded {
            return;
        }
    }
}

fn scan_type_reference(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if !matches!(node.kind(), "identifier" | "type")
        || is_declaration_name(node)
        || !is_type_reference_node(node)
    {
        return;
    }
    if normalize_type_text(node_text(node, ctx.source)) != ctx.spec.member_name {
        return;
    }
    let reference = reference_type_text(node, ctx.source);
    if resolves_to_target(ctx.csharp, ctx.file, &reference, &ctx.spec.target) {
        push_hit(node, ctx);
    }
}

fn scan_constructor_reference(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if node.kind() != "object_creation_expression" {
        return;
    }
    let Some(type_node) = node
        .child_by_field_name("type")
        .or_else(|| first_type_child(node))
    else {
        return;
    };
    if !resolves_to_target(
        ctx.csharp,
        ctx.file,
        node_text(type_node, ctx.source),
        &ctx.spec.owner,
    ) {
        return;
    }
    if ctx
        .spec
        .method_arity
        .is_some_and(|arity| argument_count(node, ctx.source) != arity)
    {
        return;
    }
    push_hit(type_node, ctx);
}

fn scan_member_reference(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if node.kind() != "member_access_expression" {
        return;
    }
    let Some(name_node) = member_access_name(node) else {
        return;
    };
    if node_text(name_node, ctx.source) != ctx.spec.member_name {
        return;
    }
    if ctx.spec.kind == TargetKind::Method
        && let Some(invocation) = enclosing_invocation(node)
        && ctx
            .spec
            .method_arity
            .is_some_and(|arity| argument_count(invocation, ctx.source) != arity)
    {
        return;
    }

    let Some(receiver_node) = member_access_receiver(node) else {
        *ctx.saw_unproven_match = true;
        return;
    };
    let receiver = node_text(receiver_node, ctx.source);
    if receiver.is_empty() {
        *ctx.saw_unproven_match = true;
        return;
    }

    if resolves_to_target(ctx.csharp, ctx.file, receiver, &ctx.spec.owner) {
        push_hit(name_node, ctx);
        return;
    }

    let mut bindings = LocalInferenceEngine::new(LocalInferenceConfig::default());
    seed_bindings_before(
        binding_scope_node(node),
        node.start_byte(),
        ctx.csharp,
        ctx.file,
        ctx.source,
        &mut bindings,
    );
    match bindings.resolve_symbol(receiver) {
        crate::usages::local_inference::SymbolResolution::Precise(targets)
            if targets
                .iter()
                .any(|target| target == &ctx.spec.owner.fq_name()) =>
        {
            push_hit(name_node, ctx);
        }
        crate::usages::local_inference::SymbolResolution::Ambiguous => {
            *ctx.saw_unproven_match = true;
        }
        crate::usages::local_inference::SymbolResolution::Unknown
        | crate::usages::local_inference::SymbolResolution::Precise(_) => {
            *ctx.saw_unproven_match = true;
        }
    }
}

fn scan_unqualified_member_reference(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if node.kind() != "identifier" || is_declaration_name(node) {
        return;
    }
    if node_text(node, ctx.source) != ctx.spec.member_name {
        return;
    }
    if node
        .parent()
        .is_some_and(|parent| parent.kind() == "member_access_expression")
    {
        return;
    }
    match ctx.spec.kind {
        TargetKind::Method
            if node
                .parent()
                .is_some_and(|parent| parent.kind() == "invocation_expression") =>
        {
            *ctx.saw_unproven_match = true;
        }
        TargetKind::Field if !is_type_reference_node(node) => {
            *ctx.saw_unproven_match = true;
        }
        _ => {}
    }
}

fn binding_scope_node(mut node: Node<'_>) -> Node<'_> {
    while let Some(parent) = node.parent() {
        if matches!(
            parent.kind(),
            "method_declaration"
                | "constructor_declaration"
                | "property_declaration"
                | "accessor_declaration"
                | "local_function_statement"
        ) {
            return parent;
        }
        node = parent;
    }
    node
}

fn seed_bindings_before(
    node: Node<'_>,
    cutoff_start: usize,
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    source: &str,
    bindings: &mut LocalInferenceEngine<String>,
) {
    seed_bindings_before_inner(node, cutoff_start, csharp, file, source, bindings);
}

fn seed_bindings_before_inner(
    node: Node<'_>,
    cutoff_start: usize,
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    source: &str,
    bindings: &mut LocalInferenceEngine<String>,
) {
    if node.start_byte() >= cutoff_start {
        return;
    }

    match node.kind() {
        "parameter" => seed_parameter(node, csharp, file, source, bindings),
        "variable_declaration" => seed_variable_declaration(node, csharp, file, source, bindings),
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.start_byte() >= cutoff_start {
            break;
        }
        seed_bindings_before_inner(child, cutoff_start, csharp, file, source, bindings);
    }
}

fn seed_parameter(
    node: Node<'_>,
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    source: &str,
    bindings: &mut LocalInferenceEngine<String>,
) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let Some(type_node) = node.child_by_field_name("type") else {
        return;
    };
    seed_symbol_for_type(name_node, type_node, csharp, file, source, bindings);
}

fn seed_variable_declaration(
    node: Node<'_>,
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    source: &str,
    bindings: &mut LocalInferenceEngine<String>,
) {
    let Some(type_node) = node.child_by_field_name("type") else {
        return;
    };
    let type_text = node_text(type_node, source);

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() != "variable_declarator" {
            continue;
        }
        let Some(name_node) = child.child_by_field_name("name") else {
            continue;
        };
        if type_text == "var" {
            if let Some(initializer_type) = object_created_type(child)
                && let Some(target) =
                    resolve_type_fq_name(csharp, file, node_text(initializer_type, source))
            {
                bindings.seed_symbol(node_text(name_node, source), target);
            } else {
                bindings.declare_shadow(node_text(name_node, source));
            }
        } else {
            seed_symbol_for_type(name_node, type_node, csharp, file, source, bindings);
        }
    }
}

fn seed_symbol_for_type(
    name_node: Node<'_>,
    type_node: Node<'_>,
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    source: &str,
    bindings: &mut LocalInferenceEngine<String>,
) {
    if let Some(target) = resolve_type_fq_name(csharp, file, node_text(type_node, source)) {
        bindings.seed_symbol(node_text(name_node, source), target);
    } else {
        bindings.declare_shadow(node_text(name_node, source));
    }
}

fn object_created_type(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() == "object_creation_expression" {
        return node
            .child_by_field_name("type")
            .or_else(|| first_type_child(node));
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if let Some(found) = object_created_type(child) {
            return Some(found);
        }
    }
    None
}

fn resolves_to_target(
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    reference: &str,
    target: &CodeUnit,
) -> bool {
    let normalized = normalize_type_text(reference);
    csharp
        .resolve_visible_type(file, &normalized)
        .is_some_and(|resolved| resolved == *target)
        || reference_matches_target_fq_name(&normalized, target)
}

fn resolve_type_fq_name(
    csharp: &CSharpAnalyzer,
    file: &ProjectFile,
    reference: &str,
) -> Option<String> {
    let normalized = normalize_type_text(reference);
    if let Some(target) = csharp.resolve_visible_type(file, &normalized) {
        return Some(target.fq_name());
    }
    csharp
        .get_all_declarations()
        .into_iter()
        .find(|unit| unit.is_class() && reference_matches_target_fq_name(&normalized, unit))
        .map(|unit| unit.fq_name())
}

fn reference_matches_target_fq_name(reference: &str, target: &CodeUnit) -> bool {
    reference == target.fq_name() || reference == target.fq_name().replace('$', ".")
}

fn normalize_type_text(reference: &str) -> String {
    let trimmed = reference.trim();
    let without_nullable = trimmed.trim_end_matches('?').trim();
    let without_arrays = without_nullable.trim_end_matches("[]").trim();
    without_arrays
        .split('<')
        .next()
        .unwrap_or(without_arrays)
        .trim()
        .to_string()
}

fn reference_type_text(node: Node<'_>, source: &str) -> String {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if matches!(
            parent.kind(),
            "qualified_name" | "generic_name" | "nullable_type" | "array_type"
        ) {
            current = parent;
            continue;
        }
        break;
    }
    normalize_type_text(node_text(current, source))
}

fn is_type_reference_node(mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent() {
        if parent
            .child_by_field_name("type")
            .is_some_and(|type_node| same_node(type_node, node))
            || parent
                .child_by_field_name("return_type")
                .is_some_and(|type_node| same_node(type_node, node))
        {
            return true;
        }
        if parent.kind() == "type" {
            return true;
        }
        if parent.kind() == "object_creation_expression" {
            return true;
        }
        if matches!(
            parent.kind(),
            "class_declaration"
                | "interface_declaration"
                | "struct_declaration"
                | "record_declaration"
                | "record_struct_declaration"
        ) && !parent
            .child_by_field_name("name")
            .is_some_and(|name| same_node(name, node))
        {
            return true;
        }
        if matches!(
            parent.kind(),
            "qualified_name"
                | "generic_name"
                | "nullable_type"
                | "array_type"
                | "type_argument_list"
                | "base_list"
        ) {
            node = parent;
            continue;
        }
        return false;
    }
    false
}

fn is_declaration_name(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    if matches!(
        parent.kind(),
        "class_declaration"
            | "interface_declaration"
            | "struct_declaration"
            | "record_declaration"
            | "record_struct_declaration"
            | "method_declaration"
            | "constructor_declaration"
            | "property_declaration"
            | "variable_declarator"
            | "using_directive"
    ) && parent
        .child_by_field_name("name")
        .is_some_and(|name| same_node(name, node))
    {
        return true;
    }
    false
}

fn member_access_receiver(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("expression")
        .or_else(|| node.named_child(0))
}

fn member_access_name(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("name").or_else(|| {
        let mut cursor = node.walk();
        let mut last = None;
        for child in node.named_children(&mut cursor) {
            if child.kind() == "identifier" {
                last = Some(child);
            }
        }
        last
    })
}

fn enclosing_invocation(node: Node<'_>) -> Option<Node<'_>> {
    let parent = node.parent()?;
    (parent.kind() == "invocation_expression").then_some(parent)
}

fn first_type_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).find(|child| {
        matches!(
            child.kind(),
            "identifier"
                | "qualified_name"
                | "generic_name"
                | "nullable_type"
                | "array_type"
                | "type"
        )
    })
}

fn argument_count(node: Node<'_>, source: &str) -> usize {
    let Some(arguments) = node
        .child_by_field_name("arguments")
        .or_else(|| first_named_child_of_kind(node, "argument_list"))
    else {
        return 0;
    };
    let inner = node_text(arguments, source)
        .trim()
        .trim_start_matches('(')
        .trim_end_matches(')')
        .trim();
    count_top_level_comma_separated(inner)
}

fn count_top_level_comma_separated(text: &str) -> usize {
    if text.trim().is_empty() {
        return 0;
    }

    let mut count = 1;
    let mut angle_depth: usize = 0;
    let mut paren_depth: usize = 0;
    let mut bracket_depth: usize = 0;
    let mut brace_depth: usize = 0;
    let mut string_quote: Option<char> = None;
    let mut escaped = false;

    for ch in text.chars() {
        if let Some(quote) = string_quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == quote {
                string_quote = None;
            }
            continue;
        }

        match ch {
            '"' | '\'' => string_quote = Some(ch),
            '<' => angle_depth = angle_depth.saturating_add(1),
            '>' if angle_depth > 0 => angle_depth -= 1,
            '(' => paren_depth = paren_depth.saturating_add(1),
            ')' if paren_depth > 0 => paren_depth -= 1,
            '[' => bracket_depth = bracket_depth.saturating_add(1),
            ']' if bracket_depth > 0 => bracket_depth -= 1,
            '{' => brace_depth = brace_depth.saturating_add(1),
            '}' if brace_depth > 0 => brace_depth -= 1,
            ',' if angle_depth == 0
                && paren_depth == 0
                && bracket_depth == 0
                && brace_depth == 0 =>
            {
                count += 1;
            }
            _ => {}
        }
    }

    count
}

fn first_named_child_of_kind<'a>(node: Node<'a>, kind: &str) -> Option<Node<'a>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| child.kind() == kind)
}

fn push_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if *ctx.limit_exceeded {
        return;
    }
    let start = node.start_byte();
    let end = node.end_byte();
    let line_idx = find_line_index_for_offset(ctx.line_starts, start);
    let Some(enclosing) = enclosing_code_unit(node, ctx) else {
        return;
    };
    if enclosing == ctx.spec.target {
        return;
    }
    ctx.hits.insert(UsageHit::new(
        ctx.file.clone(),
        line_idx + 1,
        start,
        end,
        enclosing,
        GRAPH_HIT_CONFIDENCE,
        build_snippet(ctx.source, ctx.line_starts, line_idx),
    ));
    if ctx.hits.len() > ctx.max_usages {
        *ctx.limit_exceeded = true;
    }
}

fn enclosing_code_unit(node: Node<'_>, ctx: &mut ScanCtx<'_>) -> Option<CodeUnit> {
    let key = (node.start_byte(), node.end_byte());
    if let Some(cached) = ctx.enclosing_cache.get(&key) {
        return cached.clone();
    }
    let range = Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: find_line_index_for_offset(ctx.line_starts, node.start_byte()),
        end_line: find_line_index_for_offset(ctx.line_starts, node.end_byte()),
    };
    let enclosing = ctx.analyzer.enclosing_code_unit(ctx.file, &range);
    ctx.enclosing_cache.insert(key, enclosing.clone());
    enclosing
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

fn same_node(left: Node<'_>, right: Node<'_>) -> bool {
    left.start_byte() == right.start_byte() && left.end_byte() == right.end_byte()
}

fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    source
        .get(node.start_byte()..node.end_byte())
        .unwrap_or_default()
        .trim()
}
