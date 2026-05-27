use crate::analyzer::usages::cpp_graph::extractor::ScanCtx;
use crate::analyzer::{
    AnalyzerDelegate, CodeUnit, CodeUnitType, CppAnalyzer, IAnalyzer, Language, MultiAnalyzer,
    ProjectFile, cpp_node_text as node_text, normalize_cpp_whitespace, parse_quoted_include,
    resolve_include_targets,
};
use crate::hash::{HashMap, HashSet};
use std::collections::BTreeSet;
use tree_sitter::Node;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum TargetKind {
    Type,
    Constructor,
    FreeFunction,
    Method,
    GlobalField,
    MemberField,
}

pub(super) struct TargetSpec {
    pub(super) target: CodeUnit,
    pub(super) kind: TargetKind,
    pub(super) owner: Option<CodeUnit>,
    pub(super) member_name: String,
    pub(super) owner_fq_name: Option<String>,
    pub(super) owner_cpp_name: Option<String>,
    pub(super) method_arity: Option<usize>,
}

impl TargetSpec {
    pub(super) fn from_target(analyzer: &dyn IAnalyzer, target: &CodeUnit) -> Option<Self> {
        if target.is_class() {
            return Some(Self::new(
                target.clone(),
                TargetKind::Type,
                Some(target.clone()),
                target.identifier().to_string(),
                None,
            ));
        }

        if target.is_field() {
            let owner = precise_parent_of(analyzer, target);
            let kind = if owner.is_some() {
                TargetKind::MemberField
            } else {
                TargetKind::GlobalField
            };
            return Some(Self::new(
                target.clone(),
                kind,
                owner,
                target.identifier().to_string(),
                None,
            ));
        }

        if target.is_function() {
            let owner = precise_parent_of(analyzer, target);
            let kind = if owner
                .as_ref()
                .is_some_and(|owner| target.identifier() == owner.identifier())
            {
                TargetKind::Constructor
            } else if owner.is_some() {
                TargetKind::Method
            } else {
                TargetKind::FreeFunction
            };
            return Some(Self::new(
                target.clone(),
                kind,
                owner,
                target.identifier().to_string(),
                Some(signature_arity(target.signature())),
            ));
        }

        None
    }

    pub(super) fn new(
        target: CodeUnit,
        kind: TargetKind,
        owner: Option<CodeUnit>,
        member_name: String,
        method_arity: Option<usize>,
    ) -> Self {
        let owner_fq_name = owner.as_ref().map(CodeUnit::fq_name);
        let owner_cpp_name = owner.as_ref().map(cpp_name_for);
        Self {
            target,
            kind,
            owner,
            member_name,
            owner_fq_name,
            owner_cpp_name,
            method_arity,
        }
    }
}

pub(super) struct VisibilityIndex {
    pub(super) visible_by_file: HashMap<ProjectFile, HashSet<CodeUnit>>,
}

impl VisibilityIndex {
    pub(super) fn build(
        cpp: &CppAnalyzer,
        analyzer: &dyn IAnalyzer,
        roots: &HashSet<ProjectFile>,
    ) -> Self {
        let mut files = HashSet::default();
        for file in roots {
            collect_include_closure(cpp, analyzer, file, &mut files);
        }
        let declarations_by_file: HashMap<ProjectFile, BTreeSet<CodeUnit>> = files
            .iter()
            .map(|file| (file.clone(), analyzer.get_declarations(file)))
            .collect();
        let mut visible_by_file = HashMap::default();
        for file in roots {
            let mut visited = HashSet::default();
            let mut visible = HashSet::default();
            collect_visible_declarations(
                cpp,
                analyzer,
                &declarations_by_file,
                file,
                &mut visited,
                &mut visible,
            );
            visible_by_file.insert(file.clone(), visible);
        }
        Self { visible_by_file }
    }

    pub(super) fn is_visible(&self, file: &ProjectFile, target: &CodeUnit) -> bool {
        file == target.source()
            || self
                .visible_by_file
                .get(file)
                .is_some_and(|visible| visible.iter().any(|unit| same_visible_symbol(unit, target)))
    }

    pub(super) fn resolve_type(&self, file: &ProjectFile, raw_name: &str) -> Option<CodeUnit> {
        let normalized = normalize_reference_name(raw_name)?;
        self.visible_by_file
            .get(file)?
            .iter()
            .filter(|unit| unit.kind() == CodeUnitType::Class || is_type_alias(unit))
            .find(|unit| reference_matches_unit(&normalized, unit))
            .cloned()
    }

    pub(super) fn resolves_to_type(
        &self,
        file: &ProjectFile,
        raw_name: &str,
        target: &CodeUnit,
    ) -> bool {
        let Some(resolved) = self.resolve_type(file, raw_name) else {
            return self.text_alias_resolves_to_type(file, raw_name, target);
        };
        same_symbol(&resolved, target)
            || same_visible_symbol(&resolved, target)
            || self
                .alias_target(&resolved)
                .is_some_and(|alias_target| same_visible_symbol(&alias_target, target))
            || self.text_alias_resolves_to_type(file, raw_name, target)
    }

    pub(super) fn alias_target(&self, alias: &CodeUnit) -> Option<CodeUnit> {
        let signature = alias.signature()?;
        let raw_target = signature
            .strip_prefix("using ")
            .and_then(|rest| rest.split_once('=').map(|(_, rhs)| rhs))
            .or_else(|| {
                signature
                    .strip_prefix("typedef ")
                    .and_then(|rest| rest.rsplit_once(' ').map(|(lhs, _)| lhs))
            })?
            .trim()
            .trim_end_matches(';')
            .trim();
        self.visible_by_file
            .get(alias.source())?
            .iter()
            .filter(|unit| unit.kind() == CodeUnitType::Class)
            .find(|unit| reference_matches_unit(raw_target, unit))
            .cloned()
    }

    pub(super) fn text_alias_resolves_to_type(
        &self,
        file: &ProjectFile,
        raw_name: &str,
        target: &CodeUnit,
    ) -> bool {
        let Some(alias_name) = normalize_reference_name(raw_name) else {
            return false;
        };
        self.visible_source_files(file)
            .into_iter()
            .any(|source_file| {
                source_file.read_to_string().is_ok_and(|source| {
                    source.split(';').any(|statement| {
                        alias_statement_matches_target(statement, &alias_name, target)
                    })
                })
            })
    }

    pub(super) fn visible_source_files(&self, file: &ProjectFile) -> HashSet<ProjectFile> {
        let mut files = HashSet::default();
        files.insert(file.clone());
        if let Some(visible) = self.visible_by_file.get(file) {
            files.extend(visible.iter().map(|unit| unit.source().clone()));
        }
        files
    }

    pub(super) fn resolve_named(
        &self,
        file: &ProjectFile,
        raw_name: &str,
        kind: TargetKind,
    ) -> Option<CodeUnit> {
        let normalized = normalize_reference_name(raw_name)?;
        self.visible_by_file
            .get(file)?
            .iter()
            .find(|unit| {
                matches_kind_for_lookup(unit, kind) && reference_matches_unit(&normalized, unit)
            })
            .cloned()
    }

    pub(super) fn contains_named_symbol(
        &self,
        file: &ProjectFile,
        raw_name: &str,
        kind: TargetKind,
        target: &CodeUnit,
    ) -> bool {
        let Some(normalized) = normalize_reference_name(raw_name) else {
            return false;
        };
        self.visible_by_file.get(file).is_some_and(|visible| {
            visible.iter().any(|unit| {
                matches_kind_for_lookup(unit, kind)
                    && reference_matches_unit(&normalized, unit)
                    && same_visible_symbol(unit, target)
            })
        })
    }
}

pub(super) fn collect_include_closure(
    cpp: &CppAnalyzer,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    out: &mut HashSet<ProjectFile>,
) {
    if !out.insert(file.clone()) {
        return;
    }
    for line in analyzer.import_statements(file) {
        let Some(include) = parse_quoted_include(line) else {
            continue;
        };
        for target in resolve_include_targets(cpp.project(), file, &include) {
            collect_include_closure(cpp, analyzer, &target, out);
        }
    }
}

pub(super) fn collect_visible_declarations(
    cpp: &CppAnalyzer,
    analyzer: &dyn IAnalyzer,
    declarations_by_file: &HashMap<ProjectFile, BTreeSet<CodeUnit>>,
    file: &ProjectFile,
    visited: &mut HashSet<ProjectFile>,
    out: &mut HashSet<CodeUnit>,
) {
    if !visited.insert(file.clone()) {
        return;
    }
    if let Some(declarations) = declarations_by_file.get(file) {
        out.extend(declarations.iter().cloned());
    }
    for line in analyzer.import_statements(file) {
        let Some(include) = parse_quoted_include(line) else {
            continue;
        };
        for target in resolve_include_targets(cpp.project(), file, &include) {
            collect_visible_declarations(
                cpp,
                analyzer,
                declarations_by_file,
                &target,
                visited,
                out,
            );
        }
    }
}

pub(super) fn resolve_cpp_analyzer(analyzer: &dyn IAnalyzer) -> Option<&CppAnalyzer> {
    if let Some(cpp) = (analyzer as &dyn std::any::Any).downcast_ref::<CppAnalyzer>() {
        return Some(cpp);
    }
    let multi = (analyzer as &dyn std::any::Any).downcast_ref::<MultiAnalyzer>()?;
    match multi.delegates().get(&Language::Cpp) {
        Some(AnalyzerDelegate::Cpp(cpp)) => Some(cpp),
        _ => None,
    }
}

pub(super) fn signature_arity(signature: Option<&str>) -> usize {
    let Some(signature) = signature else {
        return 0;
    };
    let inner = signature
        .find('(')
        .and_then(|open| {
            signature[open + 1..]
                .find(')')
                .map(|close| &signature[open + 1..open + 1 + close])
        })
        .unwrap_or(signature)
        .trim();
    if inner.is_empty() {
        return 0;
    }
    split_top_level_commas(inner).count()
}

pub(super) fn call_arity(node: Node<'_>) -> usize {
    node.child_by_field_name("arguments")
        .or_else(|| node.child_by_field_name("parameters"))
        .map(|args| args.named_child_count())
        .unwrap_or(0)
}

pub(super) fn constructor_type_node(node: Node<'_>) -> Option<Node<'_>> {
    match node.kind() {
        "new_expression" => node
            .child_by_field_name("type")
            .or_else(|| node.named_child(0)),
        "call_expression" => node.child_by_field_name("function"),
        _ => None,
    }
}

pub(super) fn field_initializer_constructs_target(
    node: Node<'_>,
    ctx: &ScanCtx<'_>,
    owner: &CodeUnit,
) -> bool {
    let Some(name) = node.child_by_field_name("name") else {
        return false;
    };
    let field_name = node_text(name, ctx.source);
    ctx.visibility
        .visible_by_file
        .get(ctx.file)
        .into_iter()
        .flatten()
        .filter(|unit| unit.is_field() && unit.identifier() == field_name)
        .any(|unit| {
            unit.signature().is_some_and(|signature| {
                ctx.visibility.resolves_to_type(ctx.file, signature, owner)
            })
        })
}

pub(super) fn declaration_mentions_type(
    node: Node<'_>,
    ctx: &ScanCtx<'_>,
    owner: &CodeUnit,
) -> bool {
    let Some(type_node) = node.child_by_field_name("type") else {
        return false;
    };
    ctx.visibility
        .resolves_to_type(ctx.file, node_text(type_node, ctx.source), owner)
}

pub(super) fn declaration_constructor_arity(node: Node<'_>, ctx: &ScanCtx<'_>) -> usize {
    let Some(type_node) = node.child_by_field_name("type") else {
        return 0;
    };
    let declaration = node_text(node, ctx.source);
    let type_text = node_text(type_node, ctx.source);
    let Some(after_type) = declaration.split_once(type_text).map(|(_, rest)| rest) else {
        return 0;
    };
    let after_type = after_type.trim();
    if after_type.contains('=') {
        return 1;
    }
    let Some(open_index) = after_type.find(['(', '{']) else {
        return 0;
    };
    let opener = after_type.as_bytes()[open_index] as char;
    let closer = if opener == '(' { ')' } else { '}' };
    let Some(close_index) = after_type[open_index + 1..].find(closer) else {
        return 0;
    };
    let inner = after_type[open_index + 1..open_index + 1 + close_index].trim();
    if inner.is_empty() {
        0
    } else {
        split_top_level_commas(inner).count()
    }
}

pub(super) fn split_top_level_commas(value: &str) -> impl Iterator<Item = &str> {
    struct TopLevelCommaSplit<'a> {
        value: &'a str,
        start: usize,
        angle: usize,
        paren: usize,
        brace: usize,
        bracket: usize,
    }

    impl<'a> Iterator for TopLevelCommaSplit<'a> {
        type Item = &'a str;

        fn next(&mut self) -> Option<Self::Item> {
            if self.start > self.value.len() {
                return None;
            }
            for (offset, ch) in self.value[self.start..].char_indices() {
                let absolute = self.start + offset;
                match ch {
                    '<' => self.angle += 1,
                    '>' => self.angle = self.angle.saturating_sub(1),
                    '(' => self.paren += 1,
                    ')' => self.paren = self.paren.saturating_sub(1),
                    '{' => self.brace += 1,
                    '}' => self.brace = self.brace.saturating_sub(1),
                    '[' => self.bracket += 1,
                    ']' => self.bracket = self.bracket.saturating_sub(1),
                    ',' if self.angle == 0
                        && self.paren == 0
                        && self.brace == 0
                        && self.bracket == 0 =>
                    {
                        let item = self.value[self.start..absolute].trim();
                        self.start = absolute + ch.len_utf8();
                        return Some(item);
                    }
                    _ => {}
                }
            }
            let item = self.value[self.start..].trim();
            self.start = self.value.len() + 1;
            Some(item)
        }
    }

    TopLevelCommaSplit {
        value,
        start: 0,
        angle: 0,
        paren: 0,
        brace: 0,
        bracket: 0,
    }
    .filter(|item| !item.is_empty())
}

pub(super) fn extract_variable_name(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "identifier" | "field_identifier" => {
            let name = node_text(node, source).trim();
            (!name.is_empty()).then(|| name.to_string())
        }
        _ => node
            .child_by_field_name("declarator")
            .or_else(|| node.child_by_field_name("name"))
            .or_else(|| node.named_child(node.named_child_count().saturating_sub(1)))
            .and_then(|child| extract_variable_name(child, source)),
    }
}

pub(super) fn is_declarator_node(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "identifier"
            | "field_identifier"
            | "pointer_declarator"
            | "reference_declarator"
            | "array_declarator"
            | "parenthesized_declarator"
            | "function_declarator"
    )
}

pub(super) fn first_type_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).find(|child| {
        matches!(
            child.kind(),
            "type_identifier"
                | "primitive_type"
                | "qualified_identifier"
                | "scoped_type_identifier"
        )
    })
}

pub(super) fn is_declaration_name(node: Node<'_>) -> bool {
    node.parent()
        .and_then(|parent| parent.child_by_field_name("name"))
        == Some(node)
        || matches!(
            node.parent().map(|parent| parent.kind()),
            Some("function_declarator" | "init_declarator")
        )
}

pub(super) fn has_ancestor_kind(node: Node<'_>, kind: &str) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == kind {
            return true;
        }
        current = parent.parent();
    }
    false
}

pub(super) fn function_terminal_node(node: Node<'_>) -> Node<'_> {
    node.child_by_field_name("field")
        .or_else(|| node.child_by_field_name("name"))
        .unwrap_or(node)
}

pub(super) fn normalize_type_text(value: &str) -> String {
    normalize_cpp_whitespace(value)
        .trim_start_matches("const ")
        .trim_end_matches('*')
        .trim_end_matches('&')
        .trim()
        .to_string()
}

pub(super) fn normalize_reference_name(value: &str) -> Option<String> {
    let normalized = normalize_cpp_reference_text(value);
    (!normalized.is_empty()).then_some(normalized)
}

pub(super) fn normalize_cpp_reference_text(value: &str) -> String {
    let mut text = normalize_cpp_whitespace(value)
        .trim_start_matches("new ")
        .trim()
        .to_string();
    if let Some(index) = text.find(['(', '{']) {
        text.truncate(index);
    }
    if let Some(index) = text.find('<') {
        text.truncate(index);
    }
    text.trim()
        .trim_start_matches("const ")
        .trim_end_matches('*')
        .trim_end_matches('&')
        .trim_matches(':')
        .to_string()
}

pub(super) fn cpp_name_for(unit: &CodeUnit) -> String {
    let short = unit.short_name().replace(['.', '$'], "::");
    if unit.package_name().is_empty() {
        short
    } else {
        format!("{}::{}", unit.package_name(), short)
    }
}

pub(super) fn terminal_name(value: &str) -> &str {
    value
        .rsplit("::")
        .next()
        .unwrap_or(value)
        .rsplit(['.', '-', '>'])
        .next()
        .unwrap_or(value)
        .trim()
}

pub(super) fn name_matches_terminal(value: &str, expected: &str) -> bool {
    terminal_name(&normalize_cpp_reference_text(value)) == expected
}

pub(super) fn name_matches_callable(value: &str, expected: &str) -> bool {
    name_matches_terminal(value, expected)
        || expected.starts_with("operator")
            && terminal_name(&normalize_cpp_reference_text(value)) == "operator"
}

pub(super) fn name_mentions(value: &str, expected: &str) -> bool {
    normalize_cpp_reference_text(value)
        .split("::")
        .any(|part| part == expected)
}

pub(super) fn reference_matches_unit(reference: &str, unit: &CodeUnit) -> bool {
    let cpp_name = cpp_name_for(unit);
    reference == cpp_name
        || terminal_name(reference) == unit.identifier()
            && (unit.package_name().is_empty() || reference == unit.identifier())
}

pub(super) fn matches_kind_for_lookup(unit: &CodeUnit, kind: TargetKind) -> bool {
    match kind {
        TargetKind::Type
        | TargetKind::Constructor
        | TargetKind::Method
        | TargetKind::MemberField => true,
        TargetKind::FreeFunction => unit.is_function(),
        TargetKind::GlobalField => unit.is_field(),
    }
}

pub(super) fn is_type_alias(unit: &CodeUnit) -> bool {
    unit.kind() == CodeUnitType::Field
        && unit.signature().is_some_and(|signature| {
            signature.starts_with("typedef ") || signature.starts_with("using ")
        })
}

pub(super) fn alias_statement_matches_target(
    statement: &str,
    alias_name: &str,
    target: &CodeUnit,
) -> bool {
    let normalized = normalize_cpp_whitespace(statement).trim().to_string();
    if let Some(rest) = normalized.strip_prefix("using ")
        && let Some((alias, rhs)) = rest.split_once('=')
    {
        return alias.trim() == alias_name && type_text_matches_target(rhs, target);
    }
    if let Some(rest) = normalized.strip_prefix("typedef ")
        && let Some((lhs, alias)) = rest.rsplit_once(' ')
    {
        return alias.trim() == alias_name && type_text_matches_target(lhs, target);
    }
    false
}

pub(super) fn type_text_matches_target(type_text: &str, target: &CodeUnit) -> bool {
    let normalized = normalize_cpp_reference_text(type_text.trim().trim_end_matches(';'));
    normalized == cpp_name_for(target) || normalized == target.identifier()
}

pub(super) fn precise_parent_of(
    analyzer: &dyn IAnalyzer,
    code_unit: &CodeUnit,
) -> Option<CodeUnit> {
    let fallback = analyzer.parent_of(code_unit);
    let Some(owner_name) = code_unit
        .short_name()
        .rsplit_once('.')
        .map(|(owner, _)| owner)
    else {
        return fallback;
    };
    analyzer
        .get_all_declarations()
        .into_iter()
        .find(|candidate| {
            candidate.is_class()
                && candidate.source() == code_unit.source()
                && candidate.short_name() == owner_name
                && candidate.package_name() == code_unit.package_name()
        })
        .or_else(|| {
            fallback.filter(|parent| {
                parent.short_name() == owner_name
                    && parent.package_name() == code_unit.package_name()
            })
        })
}

pub(super) fn visible_owner_from_member_name(
    ctx: &ScanCtx<'_>,
    code_unit: &CodeUnit,
) -> Option<CodeUnit> {
    let owner_name = code_unit
        .short_name()
        .rsplit_once('.')
        .map(|(owner, _)| owner)?;
    ctx.visibility
        .visible_by_file
        .get(ctx.file)?
        .iter()
        .find(|candidate| {
            candidate.is_class()
                && candidate.short_name() == owner_name
                && candidate.package_name() == code_unit.package_name()
        })
        .cloned()
}

pub(super) fn same_symbol(left: &CodeUnit, right: &CodeUnit) -> bool {
    left.kind() == right.kind()
        && left.fq_name() == right.fq_name()
        && left.signature() == right.signature()
        && left.source() == right.source()
}

pub(super) fn same_visible_symbol(left: &CodeUnit, right: &CodeUnit) -> bool {
    same_symbol(left, right) || same_logical_symbol(left, right)
}

pub(super) fn same_logical_symbol(left: &CodeUnit, right: &CodeUnit) -> bool {
    left.kind() == right.kind()
        && left.fq_name() == right.fq_name()
        && left.signature() == right.signature()
}
