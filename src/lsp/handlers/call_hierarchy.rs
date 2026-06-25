use std::collections::BTreeMap;
use std::sync::Arc;

use lsp_types::{
    CallHierarchyIncomingCall, CallHierarchyIncomingCallsParams, CallHierarchyItem,
    CallHierarchyOutgoingCall, CallHierarchyOutgoingCallsParams, CallHierarchyPrepareParams,
    Range as LspRange, Uri,
};
use tree_sitter::{Node, Parser, Tree};

use crate::analyzer::common::language_for_file;
use crate::analyzer::usages::get_definition::{
    DefinitionLookupRequest, DefinitionLookupStatus, resolve_definition_batch_with_source,
};
use crate::analyzer::usages::{DEFAULT_MAX_FILES, DEFAULT_MAX_USAGES, UsageFinder, UsageHit};
use crate::analyzer::{
    CodeUnit, CodeUnitType, IAnalyzer, Language, Project, Range, WorkspaceAnalyzer,
};
use crate::lsp::conversion::{
    byte_range_to_lsp_range, path_to_uri_string, position_to_byte_offset,
};
use crate::lsp::handlers::document_symbol::lsp_symbol_parts;
use crate::lsp::handlers::hierarchy_support::{
    cursor_byte_range, hierarchy_item_data, resolve_hierarchy_item_code_unit,
};
use crate::lsp::handlers::util::read_document_for_uri;
use crate::text_utils::compute_line_starts;

const MAX_OUTGOING_CANDIDATES: usize = DEFAULT_MAX_USAGES;

pub fn prepare(
    workspace: &WorkspaceAnalyzer,
    project: &dyn Project,
    params: &CallHierarchyPrepareParams,
) -> Option<Vec<CallHierarchyItem>> {
    let analyzer = workspace.analyzer();
    let uri = &params.text_document_position_params.text_document.uri;
    let (file, content, line_starts) = read_document_for_uri(project, uri)?;
    let offset = position_to_byte_offset(
        &content,
        &line_starts,
        &params.text_document_position_params.position,
    );
    let range = cursor_byte_range(&content, offset);
    let enclosing = analyzer.enclosing_code_unit(&file, &range)?;
    let callable = nearest_call_hierarchy_unit(analyzer, enclosing)?;

    Some(vec![call_hierarchy_item(analyzer, project, &callable)?])
}

pub fn incoming_calls(
    workspace: &WorkspaceAnalyzer,
    project: &dyn Project,
    params: &CallHierarchyIncomingCallsParams,
) -> Option<Vec<CallHierarchyIncomingCall>> {
    let analyzer = workspace.analyzer();
    let target = resolve_item_code_unit(analyzer, project, &params.item)?;

    let hits = UsageFinder::new()
        .find_usages(
            analyzer,
            std::slice::from_ref(&target),
            DEFAULT_MAX_FILES,
            DEFAULT_MAX_USAGES,
        )
        .all_hits();
    let mut grouped: BTreeMap<String, (CodeUnit, Vec<LspRange>)> = BTreeMap::new();
    for hit in hits {
        let caller = nearest_call_hierarchy_unit(analyzer, hit.enclosing.clone())
            .or_else(|| caller_for_hit(analyzer, &hit));
        let Some(caller) = caller else {
            continue;
        };
        if same_symbol(&caller, &target) {
            continue;
        }
        if !is_call_usage_hit(project, &hit) {
            continue;
        }
        let Some(range) = usage_hit_range(project, &hit) else {
            continue;
        };
        grouped
            .entry(unit_key(&caller))
            .or_insert_with(|| (caller, Vec::new()))
            .1
            .push(range);
    }

    Some(
        grouped
            .into_values()
            .filter_map(|(caller, mut from_ranges)| {
                from_ranges.sort_by(compare_lsp_range);
                from_ranges.dedup();
                Some(CallHierarchyIncomingCall {
                    from: call_hierarchy_item(analyzer, project, &caller)?,
                    from_ranges,
                })
            })
            .collect(),
    )
}

pub fn outgoing_calls(
    workspace: &WorkspaceAnalyzer,
    project: &dyn Project,
    params: &CallHierarchyOutgoingCallsParams,
) -> Option<Vec<CallHierarchyOutgoingCall>> {
    let analyzer = workspace.analyzer();
    let caller = resolve_item_code_unit(analyzer, project, &params.item)?;
    if !is_call_hierarchy_unit(&caller) {
        return Some(Vec::new());
    }
    if language_for_file(caller.source()) == Language::Ruby {
        // Ruby outgoing call hierarchy depends on Ruby get_definition support;
        // keep this explicit until https://github.com/BrokkAi/bifrost/issues/266 lands.
        return Some(Vec::new());
    }

    let source = Arc::new(project.read_source(caller.source()).ok()?);
    let line_starts = compute_line_starts(&source);
    let caller_range = analyzer.ranges(&caller).iter().min().copied()?;
    let tree = parse_tree(caller.source(), &source)?;
    let candidates = collect_reference_candidates(
        tree.root_node(),
        language_for_file(caller.source()),
        &caller_range,
    );
    if candidates.is_empty() {
        return Some(Vec::new());
    }

    let requests: Vec<_> = candidates
        .iter()
        .take(MAX_OUTGOING_CANDIDATES)
        .map(|node_range| DefinitionLookupRequest {
            file: caller.source().clone(),
            line: None,
            column: None,
            start_byte: Some(node_range.start_byte),
            end_byte: Some(node_range.end_byte),
        })
        .collect();
    let outcomes = resolve_definition_batch_with_source(
        analyzer,
        requests,
        caller.source().clone(),
        Arc::clone(&source),
    );

    let mut grouped: BTreeMap<String, (CodeUnit, Vec<LspRange>)> = BTreeMap::new();
    for (node_range, outcome) in candidates
        .into_iter()
        .take(MAX_OUTGOING_CANDIDATES)
        .zip(outcomes)
    {
        if outcome.status != DefinitionLookupStatus::Resolved {
            continue;
        }
        for definition in outcome.definitions {
            let Some(callee) = nearest_call_hierarchy_unit(analyzer, definition) else {
                continue;
            };
            if same_symbol(&caller, &callee) {
                continue;
            }
            let lsp_range = byte_range_to_lsp_range(&source, &line_starts, &node_range);
            grouped
                .entry(unit_key(&callee))
                .or_insert_with(|| (callee, Vec::new()))
                .1
                .push(lsp_range);
        }
    }

    Some(
        grouped
            .into_values()
            .filter_map(|(callee, mut from_ranges)| {
                from_ranges.sort_by(compare_lsp_range);
                from_ranges.dedup();
                Some(CallHierarchyOutgoingCall {
                    to: call_hierarchy_item(analyzer, project, &callee)?,
                    from_ranges,
                })
            })
            .collect(),
    )
}

fn nearest_call_hierarchy_unit(analyzer: &dyn IAnalyzer, mut unit: CodeUnit) -> Option<CodeUnit> {
    loop {
        if is_call_hierarchy_unit(&unit) {
            return Some(unit);
        }
        unit = analyzer.parent_of(&unit)?;
    }
}

fn is_call_hierarchy_unit(unit: &CodeUnit) -> bool {
    matches!(unit.kind(), CodeUnitType::Class | CodeUnitType::Function) && !unit.is_synthetic()
}

fn caller_for_hit(analyzer: &dyn IAnalyzer, hit: &UsageHit) -> Option<CodeUnit> {
    analyzer
        .enclosing_code_unit_for_lines(&hit.file, hit.line, hit.line)
        .and_then(|unit| nearest_call_hierarchy_unit(analyzer, unit))
}

fn usage_hit_range(project: &dyn Project, hit: &UsageHit) -> Option<LspRange> {
    let source = project.read_source(&hit.file).ok()?;
    let line_starts = compute_line_starts(&source);
    let range = Range {
        start_byte: hit.start_offset,
        end_byte: hit.end_offset,
        start_line: hit.line,
        end_line: hit.line,
    };
    Some(byte_range_to_lsp_range(&source, &line_starts, &range))
}

fn is_call_usage_hit(project: &dyn Project, hit: &UsageHit) -> bool {
    let source = match project.read_source(&hit.file) {
        Ok(source) => source,
        Err(_) => return false,
    };
    let Some(tree) = parse_tree(&hit.file, &source) else {
        return false;
    };
    let Some(node) = tree
        .root_node()
        .named_descendant_for_byte_range(hit.start_offset, hit.end_offset)
    else {
        return false;
    };
    is_call_reference_candidate(node, language_for_file(&hit.file))
}

fn parse_tree(file: &crate::analyzer::ProjectFile, source: &str) -> Option<Tree> {
    let language = match language_for_file(file) {
        Language::Java => tree_sitter_java::LANGUAGE.into(),
        Language::Go => tree_sitter_go::LANGUAGE.into(),
        Language::Cpp => tree_sitter_cpp::LANGUAGE.into(),
        Language::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
        Language::TypeScript if file.rel_path().extension().is_some_and(|ext| ext == "tsx") => {
            tree_sitter_typescript::LANGUAGE_TSX.into()
        }
        Language::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        Language::Python => tree_sitter_python::LANGUAGE.into(),
        Language::Rust => tree_sitter_rust::LANGUAGE.into(),
        Language::Php => tree_sitter_php::LANGUAGE_PHP.into(),
        Language::Scala => tree_sitter_scala::LANGUAGE.into(),
        Language::CSharp => tree_sitter_c_sharp::LANGUAGE.into(),
        Language::Ruby | Language::None => return None,
    };
    let mut parser = Parser::new();
    parser.set_language(&language).ok()?;
    parser.parse(source, None)
}

fn collect_reference_candidates(
    root: Node<'_>,
    language: Language,
    caller_range: &Range,
) -> Vec<Range> {
    let mut out = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if out.len() >= MAX_OUTGOING_CANDIDATES {
            break;
        }
        if node.end_byte() <= caller_range.start_byte || node.start_byte() >= caller_range.end_byte
        {
            continue;
        }
        if is_nested_callable_node(node, caller_range) {
            continue;
        }
        if node.child_count() == 0 {
            if is_call_reference_candidate(node, language)
                && node.start_byte() >= caller_range.start_byte
                && node.end_byte() <= caller_range.end_byte
                && node.start_byte() < node.end_byte()
            {
                out.push(Range {
                    start_byte: node.start_byte(),
                    end_byte: node.end_byte(),
                    start_line: node.start_position().row,
                    end_line: node.end_position().row,
                });
            }
            continue;
        }
        let mut cursor = node.walk();
        let mut children: Vec<_> = node.named_children(&mut cursor).collect();
        children.reverse();
        for child in children {
            stack.push(child);
        }
    }
    out.sort_by_key(|range| (range.start_byte, range.end_byte));
    out.dedup_by_key(|range| (range.start_byte, range.end_byte));
    out
}

fn is_nested_callable_node(node: Node<'_>, caller_range: &Range) -> bool {
    node.start_byte() > caller_range.start_byte
        && node.end_byte() < caller_range.end_byte
        && matches!(
            node.kind(),
            "function_declaration"
                | "function_definition"
                | "method_declaration"
                | "constructor_declaration"
                | "method_definition"
                | "function_expression"
                | "arrow_function"
                | "lambda_expression"
                | "lambda"
                | "func_literal"
                | "class_declaration"
                | "interface_declaration"
                | "enum_declaration"
                | "record_declaration"
                | "class_definition"
                | "struct_declaration"
                | "union_declaration"
                | "trait_item"
                | "impl_item"
                | "object_definition"
        )
}

fn is_call_reference_candidate(node: Node<'_>, language: Language) -> bool {
    if !is_reference_candidate_kind(node.kind()) {
        return false;
    }
    match language {
        Language::Java => java_call_reference_candidate(node),
        Language::Go => go_call_reference_candidate(node),
        Language::Cpp => cpp_call_reference_candidate(node),
        Language::JavaScript | Language::TypeScript => jsts_call_reference_candidate(node),
        Language::Python => python_call_reference_candidate(node),
        Language::Rust => rust_call_reference_candidate(node),
        Language::Php => php_call_reference_candidate(node),
        Language::Scala => scala_call_reference_candidate(node),
        Language::CSharp => csharp_call_reference_candidate(node),
        Language::Ruby | Language::None => false,
    }
}

fn is_reference_candidate_kind(kind: &str) -> bool {
    matches!(
        kind,
        "identifier"
            | "type_identifier"
            | "field_identifier"
            | "property_identifier"
            | "constant"
            | "scope_resolution"
            | "simple_identifier"
            | "scoped_identifier"
            | "namespace_identifier"
            | "variable_name"
            | "name"
            | "simple_name"
            | "identifier_token"
    )
}

fn java_call_reference_candidate(node: Node<'_>) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        match parent.kind() {
            "method_invocation" if parent.child_by_field_name("name") == Some(current) => {
                return true;
            }
            "object_creation_expression" if parent.child_by_field_name("type") == Some(current) => {
                return true;
            }
            "scoped_type_identifier" | "generic_type" => current = parent,
            _ => return false,
        }
    }
    false
}

fn go_call_reference_candidate(node: Node<'_>) -> bool {
    match node.parent() {
        Some(parent)
            if parent.kind() == "call_expression"
                && parent.child_by_field_name("function") == Some(node) =>
        {
            true
        }
        Some(parent)
            if parent.kind() == "selector_expression"
                && parent.child_by_field_name("field") == Some(node) =>
        {
            parent.parent().is_some_and(|grandparent| {
                grandparent.kind() == "call_expression"
                    && grandparent.child_by_field_name("function") == Some(parent)
            })
        }
        _ => false,
    }
}

fn cpp_call_reference_candidate(node: Node<'_>) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        match parent.kind() {
            "call_expression" if parent.child_by_field_name("function") == Some(current) => {
                return true;
            }
            "new_expression" if parent.start_byte() <= node.start_byte() => return true,
            "qualified_identifier" | "field_expression" => current = parent,
            _ => return false,
        }
    }
    false
}

fn jsts_call_reference_candidate(node: Node<'_>) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        match parent.kind() {
            "call_expression" | "new_expression"
                if parent.child_by_field_name("function") == Some(current) =>
            {
                return true;
            }
            "member_expression"
            | "subscript_expression"
            | "identifier"
            | "property_identifier"
            | "nested_identifier"
            | "qualified_identifier" => current = parent,
            _ => return false,
        }
    }
    false
}

fn python_call_reference_candidate(node: Node<'_>) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        match parent.kind() {
            "call" if parent.child_by_field_name("function") == Some(current) => return true,
            "attribute" if parent.child_by_field_name("attribute") == Some(current) => {
                current = parent;
            }
            _ => return false,
        }
    }
    false
}

fn rust_call_reference_candidate(node: Node<'_>) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        match parent.kind() {
            "call_expression" if parent.child_by_field_name("function") == Some(current) => {
                return true;
            }
            "scoped_identifier" | "field_expression" => current = parent,
            _ => return false,
        }
    }
    false
}

fn php_call_reference_candidate(node: Node<'_>) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        match parent.kind() {
            "function_call_expression"
            | "member_call_expression"
            | "scoped_call_expression"
            | "object_creation_expression" => return true,
            "member_access_expression"
            | "scoped_property_access_expression"
            | "qualified_name"
            | "namespace_name" => current = parent,
            _ => return false,
        }
    }
    false
}

fn scala_call_reference_candidate(node: Node<'_>) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        match parent.kind() {
            "call_expression" if parent.child_by_field_name("function") == Some(current) => {
                return true;
            }
            "field_expression" | "stable_identifier" | "stable_type_identifier" => current = parent,
            _ => return false,
        }
    }
    false
}

fn csharp_call_reference_candidate(node: Node<'_>) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        match parent.kind() {
            "invocation_expression" if parent.child_by_field_name("function") == Some(current) => {
                return true;
            }
            "object_creation_expression" if parent.child_by_field_name("type") == Some(current) => {
                return true;
            }
            "member_access_expression" | "qualified_name" => current = parent,
            _ => return false,
        }
    }
    false
}

fn call_hierarchy_item(
    analyzer: &dyn IAnalyzer,
    project: &dyn Project,
    code_unit: &CodeUnit,
) -> Option<CallHierarchyItem> {
    let content = project.read_source(code_unit.source()).ok()?;
    let line_starts = compute_line_starts(&content);
    let parts = lsp_symbol_parts(analyzer, code_unit, &content, &line_starts, None);
    let uri: Uri = path_to_uri_string(&code_unit.source().abs_path())
        .parse()
        .ok()?;

    Some(CallHierarchyItem {
        name: parts.name,
        kind: parts.kind,
        tags: None,
        detail: parts.detail,
        uri: uri.clone(),
        range: parts.range,
        selection_range: parts.selection_range,
        data: Some(hierarchy_item_data(analyzer, code_unit, &uri)),
    })
}

fn resolve_item_code_unit(
    analyzer: &dyn IAnalyzer,
    project: &dyn Project,
    item: &CallHierarchyItem,
) -> Option<CodeUnit> {
    resolve_hierarchy_item_code_unit(analyzer, project, item.data.as_ref(), &item.uri, |unit| {
        is_call_hierarchy_unit(unit)
    })
}

fn unit_key(unit: &CodeUnit) -> String {
    format!(
        "{}\0{}\0{:?}\0{}",
        unit.source().rel_path().display(),
        unit.fq_name(),
        unit.kind(),
        unit.signature().unwrap_or("")
    )
}

fn same_symbol(left: &CodeUnit, right: &CodeUnit) -> bool {
    left.source() == right.source()
        && left.fq_name() == right.fq_name()
        && left.kind() == right.kind()
        && left.signature() == right.signature()
}

fn compare_lsp_range(left: &LspRange, right: &LspRange) -> std::cmp::Ordering {
    left.start
        .line
        .cmp(&right.start.line)
        .then_with(|| left.start.character.cmp(&right.start.character))
        .then_with(|| left.end.line.cmp(&right.end.line))
        .then_with(|| left.end.character.cmp(&right.end.character))
}
