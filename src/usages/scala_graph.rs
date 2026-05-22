use crate::analyzer::{
    AnalyzerDelegate, CodeUnit, IAnalyzer, ImportAnalysisProvider, ImportInfo, Language,
    MultiAnalyzer, ProjectFile, Range, ScalaAnalyzer,
};
use crate::hash::{HashMap, HashSet};
use crate::text_utils::{compute_line_starts, find_line_index_for_offset};
use crate::usages::model::{FuzzyResult, UsageHit};
use crate::usages::traits::UsageAnalyzer;
use regex::Regex;
use std::collections::BTreeSet;
use std::sync::LazyLock;
use tree_sitter::{Node, Parser};

const GRAPH_HIT_CONFIDENCE: f64 = 1.0;
const SNIPPET_CONTEXT_LINES: usize = 3;

#[derive(Default)]
pub struct ScalaUsageGraphStrategy {
    _private: (),
}

impl ScalaUsageGraphStrategy {
    pub fn new() -> Self {
        Self { _private: () }
    }

    pub fn can_handle(target: &CodeUnit) -> bool {
        target_language(target) == Language::Scala
    }
}

impl UsageAnalyzer for ScalaUsageGraphStrategy {
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
        if target_language(target) != Language::Scala {
            return FuzzyResult::Failure {
                fq_name: target.fq_name(),
                reason: "ScalaUsageGraphStrategy: target is not Scala".to_string(),
            };
        }

        let Some(scala) = resolve_scala_analyzer(analyzer) else {
            return FuzzyResult::Failure {
                fq_name: target.fq_name(),
                reason: "ScalaUsageGraphStrategy: analyzer does not expose ScalaAnalyzer"
                    .to_string(),
            };
        };

        let Some(spec) = TargetSpec::from_target(scala, target) else {
            return FuzzyResult::Failure {
                fq_name: target.fq_name(),
                reason: "ScalaUsageGraphStrategy: target shape is unsupported".to_string(),
            };
        };

        let files: HashSet<ProjectFile> = candidate_files
            .iter()
            .filter(|file| target_language_file(file) == Language::Scala)
            .cloned()
            .chain(std::iter::once(target.source().clone()))
            .collect();

        let mut hits = BTreeSet::new();
        for file in files {
            scan_file(scala, analyzer, &file, &spec, &mut hits);
            if hits.len() > max_usages {
                return FuzzyResult::TooManyCallsites {
                    short_name: target.short_name().to_string(),
                    total_callsites: hits.len(),
                    limit: max_usages,
                };
            }
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
    owner: Option<CodeUnit>,
    owner_name: Option<String>,
    member_name: String,
    target_fq_name: String,
    owner_fq_name: Option<String>,
    arity: Option<usize>,
}

impl TargetSpec {
    fn from_target(scala: &ScalaAnalyzer, target: &CodeUnit) -> Option<Self> {
        if target.is_class() {
            let owner_name = scala_display_name(target);
            return Some(Self {
                target: target.clone(),
                kind: TargetKind::Type,
                owner: Some(target.clone()),
                member_name: owner_name.clone(),
                target_fq_name: scala_normalized_fq_name(&target.fq_name()),
                owner_fq_name: Some(scala_normalized_fq_name(&target.fq_name())),
                owner_name: Some(owner_name),
                arity: None,
            });
        }

        let owner = owner_of(scala, target);
        let owner_name = owner.as_ref().map(scala_display_name);
        let kind = if target.is_field() {
            TargetKind::Field
        } else if target.is_synthetic() || owner_name.as_deref() == Some(target.identifier()) {
            TargetKind::Constructor
        } else {
            TargetKind::Method
        };
        let arity = target.signature().and_then(signature_arity).or_else(|| {
            scala
                .signatures(target)
                .first()
                .and_then(|sig| signature_arity(sig))
        });
        let member_name = if kind == TargetKind::Constructor {
            owner_name.clone()?
        } else {
            target.identifier().to_string()
        };
        Some(Self {
            target: target.clone(),
            target_fq_name: scala_normalized_fq_name(&target.fq_name()),
            owner_fq_name: owner
                .as_ref()
                .map(|owner| scala_normalized_fq_name(&owner.fq_name())),
            owner,
            owner_name,
            kind,
            member_name,
            arity,
        })
    }
}

fn resolve_scala_analyzer(analyzer: &dyn IAnalyzer) -> Option<&ScalaAnalyzer> {
    if let Some(scala) = (analyzer as &dyn std::any::Any).downcast_ref::<ScalaAnalyzer>() {
        return Some(scala);
    }

    let multi = (analyzer as &dyn std::any::Any).downcast_ref::<MultiAnalyzer>()?;
    match multi.delegates().get(&Language::Scala) {
        Some(AnalyzerDelegate::Scala(scala)) => Some(scala),
        _ => None,
    }
}

fn owner_of(scala: &ScalaAnalyzer, target: &CodeUnit) -> Option<CodeUnit> {
    if let Some((owner_short, _)) = target.short_name().rsplit_once('.') {
        let owner_fq = if target.package_name().is_empty() {
            owner_short.to_string()
        } else {
            format!("{}.{}", target.package_name(), owner_short)
        };
        if let Some(owner) = scala
            .definitions(&owner_fq)
            .find(|unit| unit.is_class())
            .cloned()
        {
            return Some(owner);
        }
    }

    scala
        .all_declarations()
        .filter(|unit| unit.is_class())
        .find(|candidate| {
            scala
                .direct_children(candidate)
                .any(|child| child == target)
        })
        .cloned()
}

fn scan_file(
    scala: &ScalaAnalyzer,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    spec: &TargetSpec,
    hits: &mut BTreeSet<UsageHit>,
) {
    let Ok(source) = file.read_to_string() else {
        return;
    };
    if source.is_empty() {
        return;
    }
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_scala::LANGUAGE.into())
        .is_err()
    {
        return;
    }
    let Some(tree) = parser.parse(source.as_str(), None) else {
        return;
    };
    let line_starts = compute_line_starts(&source);
    let visibility = Visibility::for_file(scala, file, spec);
    let receiver_bindings =
        infer_receivers(&source, analyzer, file, &line_starts, &visibility, spec);
    let mut ctx = ScanCtx {
        scala,
        analyzer,
        file,
        source: &source,
        line_starts: &line_starts,
        spec,
        visibility,
        receiver_bindings,
        hits,
        enclosing_cache: HashMap::default(),
    };
    scan_node(tree.root_node(), &mut ctx);
}

struct Visibility {
    type_names: HashSet<String>,
    owner_names: HashSet<String>,
    direct_member_names: HashSet<String>,
    ambiguous_direct_member_names: HashSet<String>,
}

impl Visibility {
    fn for_file(scala: &ScalaAnalyzer, file: &ProjectFile, spec: &TargetSpec) -> Self {
        let mut visibility = Self {
            type_names: HashSet::default(),
            owner_names: HashSet::default(),
            direct_member_names: HashSet::default(),
            ambiguous_direct_member_names: ambiguous_wildcard_members(scala, file, spec),
        };

        let file_package = package_name_of(scala, file);
        if file == spec.target.source()
            || file_package.as_deref() == Some(spec.target.package_name())
        {
            visibility.type_names.insert(spec.member_name.clone());
            if spec.owner.is_none() {
                visibility
                    .direct_member_names
                    .insert(spec.member_name.clone());
            }
            if let Some(owner_name) = spec.owner_name.as_ref() {
                visibility.owner_names.insert(owner_name.clone());
            }
        }
        if spec
            .owner
            .as_ref()
            .is_some_and(|owner| file_package.as_deref() == Some(owner.package_name()))
            && let Some(owner_name) = spec.owner_name.as_ref()
        {
            visibility.owner_names.insert(owner_name.clone());
        }

        for import in scala.import_info_of(file) {
            visibility.apply_import(import, spec);
        }

        visibility
    }

    fn apply_import(&mut self, import: &ImportInfo, spec: &TargetSpec) {
        let Some(path) = scala_import_path(import) else {
            return;
        };
        let local_name = import
            .identifier
            .as_deref()
            .map(str::to_string)
            .unwrap_or_else(|| path.rsplit('.').next().unwrap_or(path.as_str()).to_string());
        if import.is_wildcard {
            if path == spec.target.package_name() {
                self.type_names.insert(spec.member_name.clone());
                if spec.owner.is_none() {
                    self.direct_member_names.insert(spec.member_name.clone());
                }
            }
            if spec
                .owner
                .as_ref()
                .is_some_and(|owner| path == owner.package_name())
                && let Some(owner_name) = spec.owner_name.as_ref()
            {
                self.owner_names.insert(owner_name.clone());
            }
            if spec
                .owner_fq_name
                .as_ref()
                .is_some_and(|owner_fq| path == *owner_fq)
            {
                self.direct_member_names.insert(spec.member_name.clone());
            }
            return;
        }

        let normalized = scala_normalized_fq_name(&path);
        if normalized == spec.target_fq_name {
            self.type_names.insert(local_name.clone());
        }
        if spec
            .owner_fq_name
            .as_ref()
            .is_some_and(|owner_fq| normalized == *owner_fq)
        {
            self.owner_names.insert(local_name.clone());
        }
        if normalized == spec.target_fq_name && spec.kind != TargetKind::Type {
            self.direct_member_names.insert(local_name);
        }
    }
}

struct ScanCtx<'a> {
    scala: &'a ScalaAnalyzer,
    analyzer: &'a dyn IAnalyzer,
    file: &'a ProjectFile,
    source: &'a str,
    line_starts: &'a [usize],
    spec: &'a TargetSpec,
    visibility: Visibility,
    receiver_bindings: Vec<ReceiverBinding>,
    hits: &'a mut BTreeSet<UsageHit>,
    enclosing_cache: HashMap<(usize, usize), Option<CodeUnit>>,
}

fn scan_node(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if is_identifier_node(node) {
        scan_identifier(node, ctx);
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        scan_node(child, ctx);
    }
}

fn scan_identifier(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if has_ancestor_kind(node, "import_declaration") {
        return;
    }
    let text = node_text(node, ctx.source).trim();
    if text.is_empty() {
        return;
    }

    let proven = match ctx.spec.kind {
        TargetKind::Type => {
            ctx.visibility.type_names.contains(text) && is_type_like_reference(node, ctx.source)
        }
        TargetKind::Constructor => {
            ctx.visibility.type_names.contains(text)
                && is_constructor_like_reference(node, ctx.source)
        }
        TargetKind::Method | TargetKind::Field => member_reference_is_proven(node, text, ctx),
    };
    if proven {
        add_hit(node, ctx);
    }
}

fn member_reference_is_proven(node: Node<'_>, text: &str, ctx: &ScanCtx<'_>) -> bool {
    if ctx.visibility.direct_member_names.contains(text)
        && !ctx.visibility.ambiguous_direct_member_names.contains(text)
        && !has_dot_qualifier(node, ctx.source)
        && !is_shadowed_unqualified(node, text, ctx)
        && member_call_arity_matches(node, ctx)
    {
        return true;
    }

    if text != ctx.spec.member_name {
        return false;
    }

    if ctx.spec.owner.is_none() {
        return dotted_qualifier_before(node, ctx.source)
            .is_some_and(|qualifier| qualifier == ctx.spec.target.package_name());
    }

    let Some(qualifier) = dot_qualifier_before(node, ctx.source) else {
        return !is_shadowed_unqualified(node, text, ctx)
            && enclosing_matches_owner(node, ctx)
            && member_call_arity_matches(node, ctx);
    };
    if qualifier == "this" {
        return enclosing_matches_owner(node, ctx) && member_call_arity_matches(node, ctx);
    }
    if ctx.visibility.owner_names.contains(&qualifier)
        && !is_qualifier_shadowed(node, &qualifier, ctx)
        && member_call_arity_matches(node, ctx)
    {
        return true;
    }
    receiver_binding_matches(node, &qualifier, ctx)
}

struct ReceiverBinding {
    name: String,
    owner_fq_name: String,
    start_byte: usize,
    end_byte: usize,
    enclosing: Option<CodeUnit>,
}

fn receiver_binding_matches(node: Node<'_>, qualifier: &str, ctx: &ScanCtx<'_>) -> bool {
    let Some(target_owner_fq) = ctx.spec.owner_fq_name.as_ref() else {
        return false;
    };
    let usage_enclosing = enclosing_for_node(node, ctx);
    ctx.receiver_bindings.iter().any(|binding| {
        binding.name == qualifier
            && binding.owner_fq_name == *target_owner_fq
            && binding.start_byte <= node.start_byte()
            && binding_scope_matches(binding.enclosing.as_ref(), usage_enclosing.as_ref())
            && !receiver_shadowed_after_binding(binding, node, ctx.source)
            && member_call_arity_matches(node, ctx)
    })
}

fn binding_scope_matches(binding: Option<&CodeUnit>, usage: Option<&CodeUnit>) -> bool {
    let Some(binding) = binding else {
        return false;
    };
    let Some(usage) = usage else {
        return false;
    };
    if binding == usage {
        return true;
    }
    if binding.is_field() && declaration_owner_contains(binding, usage) {
        return true;
    }
    binding.source() == usage.source()
        && binding.package_name() == usage.package_name()
        && usage
            .short_name()
            .strip_prefix(binding.short_name())
            .is_some_and(|rest| rest.starts_with('.'))
}

fn declaration_owner_contains(binding: &CodeUnit, usage: &CodeUnit) -> bool {
    let Some((owner_short, _)) = binding.short_name().rsplit_once('.') else {
        return false;
    };
    binding.source() == usage.source()
        && binding.package_name() == usage.package_name()
        && usage
            .short_name()
            .strip_prefix(owner_short)
            .is_some_and(|rest| rest.starts_with('.'))
}

fn receiver_shadowed_after_binding(
    binding: &ReceiverBinding,
    node: Node<'_>,
    source: &str,
) -> bool {
    if binding.end_byte >= node.start_byte() {
        return false;
    }
    let prefix = &source[binding.end_byte..node.start_byte()];
    shadows_name(prefix, &binding.name)
}

fn ambiguous_wildcard_members(
    scala: &ScalaAnalyzer,
    file: &ProjectFile,
    spec: &TargetSpec,
) -> HashSet<String> {
    if spec.kind == TargetKind::Type {
        return HashSet::default();
    }

    let mut exposing_wildcards = HashSet::default();
    for import in scala.import_info_of(file) {
        if !import.is_wildcard {
            continue;
        }
        let Some(path) = scala_import_path(import) else {
            continue;
        };
        if wildcard_path_could_expose(scala, &path, spec) {
            exposing_wildcards.insert(path);
        }
    }

    let mut ambiguous = HashSet::default();
    if exposing_wildcards.len() > 1 {
        ambiguous.insert(spec.member_name.clone());
    }
    ambiguous
}

fn wildcard_path_could_expose(scala: &ScalaAnalyzer, path: &str, spec: &TargetSpec) -> bool {
    if spec.owner.is_none() {
        return scala
            .definitions(&format!("{path}.{}", spec.member_name))
            .any(|unit| {
                matches!(spec.kind, TargetKind::Method) && unit.is_function()
                    || matches!(spec.kind, TargetKind::Field) && unit.is_field()
            });
    }

    spec.owner_fq_name
        .as_ref()
        .is_some_and(|owner_fq| path == owner_fq)
}

fn enclosing_matches_owner(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    let Some(owner) = ctx.spec.owner.as_ref() else {
        return false;
    };
    let range = Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: node.start_position().row,
        end_line: node.end_position().row,
    };
    let Some(enclosing) = ctx.analyzer.enclosing_code_unit(ctx.file, &range) else {
        return false;
    };
    if enclosing == *owner {
        return true;
    }
    enclosing.source() == owner.source()
        && enclosing.package_name() == owner.package_name()
        && enclosing
            .short_name()
            .strip_prefix(owner.short_name())
            .is_some_and(|rest| rest.starts_with('.'))
}

fn is_shadowed_unqualified(node: Node<'_>, text: &str, ctx: &ScanCtx<'_>) -> bool {
    if has_dot_qualifier(node, ctx.source) {
        return false;
    }
    if is_declaration_identifier(node) {
        return true;
    }

    let scope_start = lexical_scope_start(node, ctx);
    let prefix = &ctx.source[scope_start..node.start_byte()];
    shadows_name(prefix, text)
}

fn is_qualifier_shadowed(node: Node<'_>, qualifier: &str, ctx: &ScanCtx<'_>) -> bool {
    let scope_start = lexical_scope_start(node, ctx);
    let prefix = &ctx.source[scope_start..node.start_byte()];
    shadows_name(prefix, qualifier)
}

fn is_declaration_identifier(node: Node<'_>) -> bool {
    if has_ancestor_kind(node, "parameter") || has_ancestor_kind(node, "parameters") {
        return true;
    }
    let Some(parent) = node.parent() else {
        return false;
    };
    matches!(
        parent.kind(),
        "function_definition"
            | "val_definition"
            | "var_definition"
            | "class_definition"
            | "object_definition"
            | "trait_definition"
            | "enum_definition"
            | "case_clause"
    )
}

fn lexical_scope_start(node: Node<'_>, ctx: &ScanCtx<'_>) -> usize {
    enclosing_for_node(node, ctx)
        .and_then(|unit| {
            ctx.analyzer
                .ranges(&unit)
                .first()
                .map(|range| range.start_byte)
        })
        .unwrap_or(0)
}

fn enclosing_for_node(node: Node<'_>, ctx: &ScanCtx<'_>) -> Option<CodeUnit> {
    let range = Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: node.start_position().row,
        end_line: node.end_position().row,
    };
    ctx.analyzer.enclosing_code_unit(ctx.file, &range)
}

fn shadows_name(prefix: &str, text: &str) -> bool {
    let cleaned = without_closed_brace_blocks(prefix);
    let prefix = cleaned.as_str();
    let escaped = regex::escape(text);
    let declaration = Regex::new(&format!(r#"\b(?:val|var|def)\s+{escaped}\b"#))
        .expect("valid shadow declaration regex");
    if declaration.is_match(prefix) {
        return true;
    }
    let parameter =
        Regex::new(&format!(r#"[\(\,]\s*{escaped}\s*:"#)).expect("valid shadow parameter regex");
    if parameter.is_match(prefix) {
        return true;
    }
    let assignment = Regex::new(&format!(r#"(?m)(?:^|[;\n\r\{{]\s*){escaped}\s="#))
        .expect("valid shadow assignment regex");
    if assignment.is_match(prefix) {
        return true;
    }
    let pattern = Regex::new(&format!(r#"\bcase\s+{escaped}\b"#)).expect("valid pattern regex");
    pattern.is_match(prefix)
}

fn without_closed_brace_blocks(prefix: &str) -> String {
    let mut stack = Vec::new();
    let mut ranges = Vec::new();
    for (idx, ch) in prefix.char_indices() {
        match ch {
            '{' => stack.push(idx),
            '}' => {
                if let Some(start) = stack.pop() {
                    ranges.push(start..idx + ch.len_utf8());
                }
            }
            _ => {}
        }
    }
    if ranges.is_empty() {
        return prefix.to_string();
    }

    ranges.sort_by_key(|range| range.start);
    let mut cleaned = String::with_capacity(prefix.len());
    let mut cursor = 0;
    for range in ranges {
        if cursor < range.start {
            cleaned.push_str(&prefix[cursor..range.start]);
        }
        cursor = cursor.max(range.end);
    }
    if cursor < prefix.len() {
        cleaned.push_str(&prefix[cursor..]);
    }
    cleaned
}

fn add_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    let range = Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: node.start_position().row,
        end_line: node.end_position().row,
    };
    let cache_key = (range.start_byte, range.end_byte);
    let enclosing = if let Some(cached) = ctx.enclosing_cache.get(&cache_key) {
        cached.clone()
    } else {
        let resolved = ctx
            .analyzer
            .enclosing_code_unit(ctx.file, &range)
            .or_else(|| nearest_declaration(ctx.scala, ctx.file));
        ctx.enclosing_cache.insert(cache_key, resolved.clone());
        resolved
    };
    let Some(enclosing) = enclosing else {
        return;
    };
    if enclosing == ctx.spec.target {
        return;
    }
    let line = find_line_index_for_offset(ctx.line_starts, range.start_byte) + 1;
    ctx.hits.insert(UsageHit::new(
        ctx.file.clone(),
        line,
        range.start_byte,
        range.end_byte,
        enclosing,
        GRAPH_HIT_CONFIDENCE,
        snippet_around(ctx.source, ctx.line_starts, line),
    ));
}

fn nearest_declaration(scala: &ScalaAnalyzer, file: &ProjectFile) -> Option<CodeUnit> {
    scala.declarations(file).next().cloned()
}

fn is_identifier_node(node: Node<'_>) -> bool {
    matches!(node.kind(), "identifier" | "type_identifier")
}

fn is_type_like_reference(node: Node<'_>, source: &str) -> bool {
    node.kind() == "type_identifier"
        || is_constructor_like_reference(node, source)
        || parent_kind(node).is_some_and(|kind| {
            matches!(
                kind,
                "type" | "generic_type" | "parameterized_type" | "extends_clause"
            )
        })
}

fn is_constructor_like_reference(node: Node<'_>, source: &str) -> bool {
    let prefix = source[..node.start_byte()].trim_end();
    prefix.ends_with("new")
        || parent_kind(node).is_some_and(|kind| matches!(kind, "call_expression" | "type"))
}

fn member_call_arity_matches(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    if ctx.spec.kind != TargetKind::Method {
        return true;
    }
    let Some(target_arity) = ctx.spec.arity else {
        return true;
    };
    match call_arity_after(node, ctx.source) {
        Some(call_arity) => call_arity == target_arity,
        None => target_arity == 0,
    }
}

fn call_arity_after(node: Node<'_>, source: &str) -> Option<usize> {
    let after = source[node.end_byte()..].trim_start();
    let inner = balanced_parenthesized_prefix(after)?;
    if inner.trim().is_empty() {
        return Some(0);
    }
    Some(split_top_level_commas(inner).count())
}

fn balanced_parenthesized_prefix(source: &str) -> Option<&str> {
    let mut chars = source.char_indices();
    let (_, first) = chars.next()?;
    if first != '(' {
        return None;
    }
    let mut depth = 1usize;
    for (idx, ch) in chars {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(&source[1..idx]);
                }
            }
            _ => {}
        }
    }
    None
}

fn split_top_level_commas(value: &str) -> impl Iterator<Item = &str> {
    let mut depth = 0usize;
    let mut start = 0usize;
    let mut parts = Vec::new();
    for (idx, ch) in value.char_indices() {
        match ch {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                parts.push(value[start..idx].trim());
                start = idx + ch.len_utf8();
            }
            _ => {}
        }
    }
    parts.push(value[start..].trim());
    parts.into_iter().filter(|part| !part.is_empty())
}

fn signature_arity(signature: &str) -> Option<usize> {
    let open = signature.find('(')?;
    let inner = balanced_parenthesized_prefix(&signature[open..])?;
    if inner.trim().is_empty() {
        return Some(0);
    }
    Some(split_top_level_commas(inner).count())
}

fn parent_kind(node: Node<'_>) -> Option<&str> {
    node.parent().map(|parent| parent.kind())
}

fn has_ancestor_kind(node: Node<'_>, kind: &str) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == kind {
            return true;
        }
        current = parent.parent();
    }
    false
}

fn has_dot_qualifier(node: Node<'_>, source: &str) -> bool {
    dot_qualifier_before(node, source).is_some()
}

fn dot_qualifier_before(node: Node<'_>, source: &str) -> Option<String> {
    let before = &source[..node.start_byte()];
    let before = before.trim_end();
    let without_dot = before.strip_suffix('.')?;
    let qualifier: String = without_dot
        .chars()
        .rev()
        .take_while(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '$'))
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    (!qualifier.is_empty()).then_some(qualifier.trim_end_matches('$').to_string())
}

fn dotted_qualifier_before(node: Node<'_>, source: &str) -> Option<String> {
    let before = source[..node.start_byte()].trim_end();
    let without_dot = before.strip_suffix('.')?;
    let qualifier: String = without_dot
        .chars()
        .rev()
        .take_while(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '$' | '.'))
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    (!qualifier.is_empty()).then_some(qualifier.trim_end_matches('$').to_string())
}

fn infer_receivers(
    source: &str,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    line_starts: &[usize],
    visibility: &Visibility,
    spec: &TargetSpec,
) -> Vec<ReceiverBinding> {
    static TYPED_BINDING_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"\b(?:val|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*:\s*([A-Za-z_][A-Za-z0-9_]*)"#)
            .expect("valid regex")
    });
    static CONSTRUCTOR_BINDING_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r#"\b(?:val|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:new\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*[\(\{]"#,
        )
        .expect("valid regex")
    });
    static PARAM_BINDING_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"\(([A-Za-z_][A-Za-z0-9_]*)\s*:\s*([A-Za-z_][A-Za-z0-9_]*)"#)
            .expect("valid regex")
    });

    let mut bindings = Vec::new();
    for captures in TYPED_BINDING_RE.captures_iter(source) {
        let Some(match_range) = captures.get(0) else {
            continue;
        };
        let Some(name) = captures.get(1).map(|m| m.as_str()) else {
            continue;
        };
        let Some(type_name) = captures.get(2).map(|m| m.as_str()) else {
            continue;
        };
        if visibility.owner_names.contains(type_name)
            && let Some(owner_fq_name) = spec.owner_fq_name.as_ref()
        {
            bindings.push(ReceiverBinding {
                name: name.to_string(),
                owner_fq_name: owner_fq_name.clone(),
                start_byte: match_range.start(),
                end_byte: match_range.end(),
                enclosing: enclosing_for_range(
                    analyzer,
                    file,
                    line_starts,
                    match_range.start(),
                    match_range.end(),
                ),
            });
        }
    }
    for captures in CONSTRUCTOR_BINDING_RE.captures_iter(source) {
        let Some(match_range) = captures.get(0) else {
            continue;
        };
        let Some(name) = captures.get(1).map(|m| m.as_str()) else {
            continue;
        };
        let Some(type_name) = captures.get(2).map(|m| m.as_str()) else {
            continue;
        };
        if visibility.owner_names.contains(type_name)
            && let Some(owner_fq_name) = spec.owner_fq_name.as_ref()
        {
            bindings.push(ReceiverBinding {
                name: name.to_string(),
                owner_fq_name: owner_fq_name.clone(),
                start_byte: match_range.start(),
                end_byte: match_range.end(),
                enclosing: enclosing_for_range(
                    analyzer,
                    file,
                    line_starts,
                    match_range.start(),
                    match_range.end(),
                ),
            });
        }
    }
    for captures in PARAM_BINDING_RE.captures_iter(source) {
        let Some(match_range) = captures.get(0) else {
            continue;
        };
        let Some(name) = captures.get(1).map(|m| m.as_str()) else {
            continue;
        };
        let Some(type_name) = captures.get(2).map(|m| m.as_str()) else {
            continue;
        };
        if visibility.owner_names.contains(type_name)
            && let Some(owner_fq_name) = spec.owner_fq_name.as_ref()
        {
            bindings.push(ReceiverBinding {
                name: name.to_string(),
                owner_fq_name: owner_fq_name.clone(),
                start_byte: match_range.start(),
                end_byte: match_range.end(),
                enclosing: enclosing_for_range(
                    analyzer,
                    file,
                    line_starts,
                    match_range.start(),
                    match_range.end(),
                ),
            });
        }
    }
    bindings
}

fn enclosing_for_range(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    line_starts: &[usize],
    start_byte: usize,
    end_byte: usize,
) -> Option<CodeUnit> {
    let start_line = find_line_index_for_offset(line_starts, start_byte);
    let end_line = find_line_index_for_offset(line_starts, end_byte);
    analyzer.enclosing_code_unit(
        file,
        &Range {
            start_byte,
            end_byte,
            start_line,
            end_line,
        },
    )
}

fn package_name_of(scala: &ScalaAnalyzer, file: &ProjectFile) -> Option<String> {
    scala
        .declarations(file)
        .next()
        .map(|unit| unit.package_name().to_string())
}

fn scala_import_path(info: &ImportInfo) -> Option<String> {
    let trimmed = info
        .raw_snippet
        .trim()
        .strip_prefix("import ")
        .unwrap_or(info.raw_snippet.trim())
        .trim();
    if trimmed.is_empty() {
        return None;
    }
    if info.is_wildcard {
        return Some(trimmed.trim_end_matches(".*").to_string());
    }
    Some(
        trimmed
            .split_once(" as ")
            .map(|(path, _)| path)
            .unwrap_or(trimmed)
            .trim()
            .to_string(),
    )
}

fn scala_normalized_fq_name(fq_name: &str) -> String {
    fq_name.replace("$.", ".").trim_end_matches('$').to_string()
}

fn scala_display_name(unit: &CodeUnit) -> String {
    unit.short_name()
        .rsplit('.')
        .next()
        .unwrap_or(unit.short_name())
        .trim_end_matches('$')
        .to_string()
}

fn target_language(target: &CodeUnit) -> Language {
    target_language_file(target.source())
}

fn target_language_file(file: &ProjectFile) -> Language {
    file.rel_path()
        .extension()
        .and_then(|ext| ext.to_str())
        .map(Language::from_extension)
        .unwrap_or(Language::None)
}

fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    &source[node.byte_range()]
}

fn snippet_around(source: &str, line_starts: &[usize], one_based_line: usize) -> String {
    if line_starts.is_empty() {
        return String::new();
    }
    let zero_based = one_based_line.saturating_sub(1);
    let start_line = zero_based.saturating_sub(SNIPPET_CONTEXT_LINES.saturating_sub(1));
    let end_line = (zero_based + SNIPPET_CONTEXT_LINES).min(line_starts.len());
    let start = *line_starts.get(start_line).unwrap_or(&0);
    let end = line_starts
        .get(end_line)
        .copied()
        .unwrap_or(source.len())
        .min(source.len());
    source[start..end].trim().to_string()
}
