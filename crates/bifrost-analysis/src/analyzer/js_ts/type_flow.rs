//! JavaScript and TypeScript class-set adapter.
//!
//! All source questions are answered from the analyzer's prepared syntax so
//! unsaved overlays, declaration identities, and the semantic artifact stay
//! on one revision. JavaScript's runtime class surfaces are open: this adapter
//! publishes useful class and positive-member evidence, but never `Absent`.

use std::path::Path;
use std::sync::Arc;

use brokk_bifrost_core::analyzer::prepared_syntax::{PreparedSyntaxSource, PreparedSyntaxTree};
use brokk_bifrost_js_ts::syntax::{
    JsTsImportBinder, JsTsLexicalBindingIndex, compute_import_binder, slice,
};
use brokk_bifrost_js_ts::ts_owners::{
    jsts_constructor_owner_candidates, jsts_identifier_candidates, ts_named_type_candidates,
};
use tree_sitter::Node;

use super::{JavascriptSupport, TypescriptSupport, is_typescript_declaration_path};
use crate::analyzer::js_ts::providers::resolve_js_ts_source;
use crate::analyzer::lexical_definitions::formal_parameter_slots_for_owner_with_nodes;
use crate::analyzer::semantic::{
    AdapterSemanticsVersion, AllocationKind, AllocationSite, CandidateCoverage, ClassHierarchy,
    ClassIdentity, ClassSeed, ExternalMemberDeclaration, MemberAccessKind, MemberAccessQuery,
    MemberDeclaration, MemberLookup, MemberLookupHit, MemoryLocationKind, ProcedureHandle,
    SemanticCallSite, SemanticLocator, SemanticValue, SemanticValueKind, SourceMappingKind,
    SourceSpan, TypeFlowAdapter, UnknownReason, validate_prepared_syntax_for_procedure,
};
use crate::analyzer::semantic_model::{
    SemanticModelMemberTargetDisposition, SemanticModelOverlay, SemanticModelSymbol,
    SemanticModelSymbolKind,
};
use crate::analyzer::tree_walk::push_named_children_reversed;
use crate::analyzer::{
    AnalyzerDefinitionLookup, AnalyzerQueryScope, CodeUnit, CodeUnitIndex, Language, ProjectFile,
    QueryScope, TypeHierarchyProvider, WorkspaceAnalyzer, resolve_analyzer, sort_units,
};
use crate::analyzer::{JavascriptAnalyzer, TypescriptAnalyzer};

fn prepared_for(
    workspace: &WorkspaceAnalyzer,
    language: Language,
    file: &ProjectFile,
) -> Option<Arc<PreparedSyntaxTree>> {
    match language {
        Language::JavaScript => {
            let analyzer = resolve_analyzer::<JavascriptAnalyzer>(workspace.analyzer())?;
            let scope = AnalyzerQueryScope::new(analyzer);
            analyzer.inner().prepared_syntax(scope.token(), file)
        }
        Language::TypeScript => {
            let analyzer = resolve_analyzer::<TypescriptAnalyzer>(workspace.analyzer())?;
            let scope = AnalyzerQueryScope::new(analyzer);
            analyzer.inner().prepared_syntax(scope.token(), file)
        }
        _ => unreachable!("the JS/TS adapter receives only JavaScript or TypeScript"),
    }
}

fn current_prepared_for(
    workspace: &WorkspaceAnalyzer,
    language: Language,
    file: &ProjectFile,
) -> Option<Arc<PreparedSyntaxTree>> {
    let prepared = prepared_for(workspace, language, file)?;
    if !matches!(prepared.backing(), PreparedSyntaxSource::Indexed(_)) {
        return None;
    }
    let matches = match language {
        Language::JavaScript => resolve_analyzer::<JavascriptAnalyzer>(workspace.analyzer())?
            .indexed_source_matches(file, prepared.source()),
        Language::TypeScript => resolve_analyzer::<TypescriptAnalyzer>(workspace.analyzer())?
            .indexed_source_matches(file, prepared.source()),
        _ => unreachable!("the JS/TS adapter receives only JavaScript or TypeScript"),
    };
    matches.then_some(prepared)
}

fn prepared_for_procedure(
    workspace: &WorkspaceAnalyzer,
    language: Language,
    procedure: &ProcedureHandle,
    file: &ProjectFile,
) -> Result<Arc<PreparedSyntaxTree>, UnknownReason> {
    let Some(prepared) = prepared_for(workspace, language, file) else {
        return Err(UnknownReason::UncertainFlow);
    };
    validate_prepared_syntax_for_procedure(workspace, procedure, file, prepared)
}

fn file_for_locator(
    workspace: &WorkspaceAnalyzer,
    locator: &SemanticLocator,
) -> Option<ProjectFile> {
    workspace
        .analyzer()
        .project()
        .file_by_rel_path(Path::new(locator.path().as_str()))
}

fn node_at_span(prepared: &PreparedSyntaxTree, span: SourceSpan) -> Option<Node<'_>> {
    prepared
        .tree()
        .root_node()
        .named_descendant_for_byte_range(span.start_byte() as usize, span.end_byte() as usize)
}

fn overlay_of(workspace: &WorkspaceAnalyzer) -> Option<Arc<SemanticModelOverlay>> {
    workspace
        .analyzer()
        .active_semantic_model_snapshot()
        .and_then(|snapshot| snapshot.semantic_model_overlay().cloned())
}

enum ExternalType {
    Class(ClassIdentity),
    Interface,
}

fn js_ts_external_symbol(symbol: &SemanticModelSymbol) -> bool {
    matches!(symbol.language.as_str(), "javascript" | "typescript")
        && symbol.owner_id.is_none()
        && matches!(
            symbol.kind,
            SemanticModelSymbolKind::Class | SemanticModelSymbolKind::Interface
        )
}

fn external_type_from_symbols<'a>(
    symbols: impl Iterator<Item = &'a SemanticModelSymbol>,
) -> Option<ExternalType> {
    let mut symbols = symbols.filter(|symbol| js_ts_external_symbol(symbol));
    let symbol = symbols.next()?;
    if symbols.next().is_some() {
        return None;
    }
    match symbol.kind {
        SemanticModelSymbolKind::Class => Some(ExternalType::Class(ClassIdentity::External {
            qualified_name: symbol.qualified_name.clone().into_boxed_str(),
            symbol_id: symbol.id.clone().into_boxed_str(),
        })),
        SemanticModelSymbolKind::Interface => Some(ExternalType::Interface),
        _ => unreachable!("external type candidates were filtered to class-like symbols"),
    }
}

/// Resolve a source-spelled external type. Pack aliases are accepted because
/// imports and annotations can legitimately name them, but the identity stays
/// the pack's canonical qualified name.
fn external_type(overlay: Option<&SemanticModelOverlay>, name: &str) -> Option<ExternalType> {
    let matched = overlay?.symbols_named(name);
    external_type_from_symbols(matched.records.into_iter())
}

/// Resolve an intrinsic runtime type such as String or Object. Exact literal
/// identities require the canonical bare pack declaration, never an alias.
fn external_intrinsic_type(
    overlay: Option<&SemanticModelOverlay>,
    name: &str,
) -> Option<ExternalType> {
    let matched = overlay?.symbols_named(name);
    external_type_from_symbols(
        matched
            .records
            .into_iter()
            .filter(|symbol| symbol.name == name && symbol.qualified_name == name),
    )
}

fn external_class(overlay: Option<&SemanticModelOverlay>, name: &str) -> Option<ClassIdentity> {
    match external_type(overlay, name)? {
        ExternalType::Class(identity) => Some(identity),
        ExternalType::Interface => None,
    }
}

fn sort_external_classes(classes: &mut [ClassIdentity]) {
    classes.sort_by(|left, right| {
        let (
            ClassIdentity::External {
                qualified_name: left_name,
                symbol_id: left_id,
            },
            ClassIdentity::External {
                qualified_name: right_name,
                symbol_id: right_id,
            },
        ) = (left, right)
        else {
            unreachable!("external class collections contain only external identities")
        };
        left_name
            .cmp(right_name)
            .then_with(|| left_id.cmp(right_id))
    });
}

fn exact_external_seed(workspace: &WorkspaceAnalyzer, name: &str) -> ClassSeed {
    match external_intrinsic_type(overlay_of(workspace).as_deref(), name) {
        Some(ExternalType::Class(identity)) => ClassSeed::Class(identity),
        Some(ExternalType::Interface) => ClassSeed::Unknown(UnknownReason::OpenTypeBound),
        None => ClassSeed::Unknown(UnknownReason::ExternalNotModeled),
    }
}

fn open_external_seed(workspace: &WorkspaceAnalyzer, name: &str) -> ClassSeed {
    match external_intrinsic_type(overlay_of(workspace).as_deref(), name) {
        Some(ExternalType::Class(identity)) => ClassSeed::ClassWithOpenBound(identity),
        Some(ExternalType::Interface) => ClassSeed::Unknown(UnknownReason::OpenTypeBound),
        None => ClassSeed::Unknown(UnknownReason::ExternalNotModeled),
    }
}

fn constructor_expression<'tree>(node: Node<'tree>) -> Option<Node<'tree>> {
    let parent = node.parent()?;
    if parent.kind() != "new_expression" {
        return None;
    }
    parent
        .child_by_field_name("constructor")
        .or_else(|| parent.child_by_field_name("function"))
        .filter(|constructor| constructor.id() == node.id())
}

fn is_untagged_template(node: Node<'_>) -> bool {
    !node.parent().is_some_and(|parent| {
        parent.kind() == "call_expression"
            && parent
                .child_by_field_name("arguments")
                .is_some_and(|arguments| arguments.id() == node.id())
    })
}

fn declaration_node<'tree>(
    prepared: &'tree PreparedSyntaxTree,
    unit: &CodeUnit,
) -> Option<Node<'tree>> {
    let node = prepared.declaration_node(unit)?;
    if node.kind() == "export_statement" {
        node.child_by_field_name("declaration")
    } else {
        Some(node)
    }
}

fn runtime_class_declaration(
    workspace: &WorkspaceAnalyzer,
    language: Language,
    unit: &CodeUnit,
) -> bool {
    if is_typescript_declaration_path(unit.source().rel_path()) {
        return false;
    }
    let Some(prepared) = current_prepared_for(workspace, language, unit.source()) else {
        return false;
    };
    declaration_node(&prepared, unit).is_some_and(|node| {
        !declaration_is_ambient(node)
            && matches!(
                node.kind(),
                "class_declaration" | "abstract_class_declaration" | "class"
            )
    })
}

fn declaration_is_ambient(mut declaration: Node<'_>) -> bool {
    loop {
        if declaration.kind() == "ambient_declaration" {
            return true;
        }
        let Some(parent) = declaration.parent() else {
            return false;
        };
        declaration = parent;
    }
}

fn workspace_type_is_interface(
    workspace: &WorkspaceAnalyzer,
    language: Language,
    unit: &CodeUnit,
) -> Option<bool> {
    let prepared = current_prepared_for(workspace, language, unit.source())?;
    declaration_node(&prepared, unit).map(|node| node.kind() == "interface_declaration")
}

fn class_has_decorator(class: Node<'_>) -> bool {
    let mut cursor = class.walk();
    class
        .named_children(&mut cursor)
        .any(|child| child.kind() == "decorator")
}

fn class_is_derived(class: Node<'_>) -> bool {
    let mut cursor = class.walk();
    class.named_children(&mut cursor).any(|child| {
        child.kind() == "class_heritage" && {
            let mut heritage_cursor = child.walk();
            child
                .named_children(&mut heritage_cursor)
                .any(|clause| clause.kind() != "implements_clause")
        }
    })
}

fn syntax_is_complete(root: Node<'_>) -> bool {
    if root.has_error() || root.is_missing() {
        return false;
    }
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        for index in (0..node.child_count()).rev() {
            let Some(child) = node.child(index) else {
                continue;
            };
            if child.is_missing() {
                return false;
            }
            stack.push(child);
        }
    }
    true
}

fn node_has_type_only_modifier(node: Node<'_>) -> bool {
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .any(|child| matches!(child.kind(), "type" | "typeof"))
}

fn active_binding_is_value_import(root: Node<'_>, binding_range: crate::analyzer::Range) -> bool {
    let Some(binding) =
        root.named_descendant_for_byte_range(binding_range.start_byte, binding_range.end_byte)
    else {
        return false;
    };
    if binding.start_byte() != binding_range.start_byte
        || binding.end_byte() != binding_range.end_byte
    {
        return false;
    }
    let mut current = binding;
    loop {
        if current.kind() == "import_specifier" && node_has_type_only_modifier(current) {
            return false;
        }
        if current.kind() == "import_statement" {
            return !node_has_type_only_modifier(current);
        }
        let Some(parent) = current.parent() else {
            return false;
        };
        current = parent;
    }
}

fn constructor_is_inside_with(mut constructor: Node<'_>) -> bool {
    while let Some(parent) = constructor.parent() {
        if parent.kind() == "with_statement" {
            return true;
        }
        constructor = parent;
    }
    false
}

fn contains_direct_eval(prepared: &PreparedSyntaxTree) -> bool {
    let mut stack = vec![prepared.tree().root_node()];
    while let Some(node) = stack.pop() {
        if node.kind() == "call_expression"
            && node
                .child_by_field_name("function")
                .is_some_and(|function| {
                    function.kind() == "identifier" && slice(function, prepared.source()) == "eval"
                })
        {
            return true;
        }
        push_named_children_reversed(node, &mut stack);
    }
    false
}

fn constructor_has_value_return(constructor: Node<'_>) -> bool {
    let Some(body) = constructor.child_by_field_name("body") else {
        return true;
    };
    let mut stack = vec![body];
    while let Some(node) = stack.pop() {
        if node.id() != body.id()
            && matches!(
                node.kind(),
                "function_declaration"
                    | "function_expression"
                    | "generator_function_declaration"
                    | "generator_function"
                    | "arrow_function"
                    | "method_definition"
                    | "class_declaration"
                    | "abstract_class_declaration"
                    | "class"
            )
        {
            continue;
        }
        if node.kind() == "return_statement" && node.named_child_count() != 0 {
            return true;
        }
        push_named_children_reversed(node, &mut stack);
    }
    false
}

enum ConstructorSeedVerdict {
    Exact,
    Open,
    Unresolved,
}

#[allow(clippy::too_many_arguments)]
fn constructor_seed_verdict(
    workspace: &WorkspaceAnalyzer,
    language: Language,
    call_file: &ProjectFile,
    constructor: Node<'_>,
    unit: &CodeUnit,
    lexical: &JsTsLexicalBindingIndex,
    imports: &JsTsImportBinder,
    call_prepared: &PreparedSyntaxTree,
    source: &str,
) -> ConstructorSeedVerdict {
    let Some(prepared) = current_prepared_for(workspace, language, unit.source()) else {
        return ConstructorSeedVerdict::Unresolved;
    };
    let Some(class) = declaration_node(&prepared, unit) else {
        return ConstructorSeedVerdict::Unresolved;
    };
    let Some(name_node) = class.child_by_field_name("name") else {
        return ConstructorSeedVerdict::Unresolved;
    };
    let name = slice(constructor, source);
    if constructor_is_inside_with(constructor)
        || contains_direct_eval(call_prepared)
        || (unit.source() != call_file && contains_direct_eval(&prepared))
    {
        return ConstructorSeedVerdict::Unresolved;
    }
    let binding_ranges = lexical.binding_identifier_ranges_at(name, constructor.start_byte());
    let exact_binding = if unit.source() == call_file {
        binding_ranges.len() == 1
            && binding_ranges[0].start_byte == name_node.start_byte()
            && binding_ranges[0].end_byte == name_node.end_byte()
    } else {
        let target_name = slice(name_node, prepared.source());
        let target_lexical =
            JsTsLexicalBindingIndex::build(prepared.tree().root_node(), prepared.source());
        imports.binding(name).is_some()
            && !imports.has_competing_static_imports(name)
            && !imports.was_truncated(name)
            && binding_ranges.len() == 1
            && active_binding_is_value_import(call_prepared.tree().root_node(), binding_ranges[0])
            && !target_lexical.is_binding_reassigned_at(target_name, name_node.start_byte())
    };
    if !exact_binding || lexical.is_binding_reassigned_at(name, constructor.start_byte()) {
        return ConstructorSeedVerdict::Unresolved;
    }
    if !syntax_is_complete(class) {
        return ConstructorSeedVerdict::Open;
    }
    if class.kind() != "class_declaration" || class_has_decorator(class) || class_is_derived(class)
    {
        return ConstructorSeedVerdict::Open;
    }
    let Some(body) = class.child_by_field_name("body") else {
        return ConstructorSeedVerdict::Open;
    };
    let constructors = {
        let mut cursor = body.walk();
        body.named_children(&mut cursor)
            .filter(|child| {
                child.kind() == "method_definition"
                    && child
                        .child_by_field_name("name")
                        .is_some_and(|name| slice(name, prepared.source()) == "constructor")
            })
            .collect::<Vec<_>>()
    };
    match constructors.as_slice() {
        [] => ConstructorSeedVerdict::Exact,
        [constructor] if !constructor_has_value_return(*constructor) => {
            ConstructorSeedVerdict::Exact
        }
        [_] => ConstructorSeedVerdict::Open,
        _ => ConstructorSeedVerdict::Unresolved,
    }
}

fn constructed_class(
    workspace: &WorkspaceAnalyzer,
    language: Language,
    procedure: &ProcedureHandle,
    call: &SemanticCallSite,
) -> ClassSeed {
    let semantics = procedure.semantics();
    let callee = semantics
        .value(call.callee)
        .expect("a call site's callee value is retained");
    let mapping = semantics
        .source_mapping(callee.source)
        .expect("a callee value retains a source mapping");
    if mapping.kind != SourceMappingKind::Exact {
        return ClassSeed::NotApplicable;
    }
    let Some(file) = file_for_locator(workspace, &mapping.locator) else {
        return ClassSeed::NotApplicable;
    };
    let prepared = match prepared_for_procedure(workspace, language, procedure, &file) {
        Ok(prepared) => prepared,
        Err(reason) => return ClassSeed::Unknown(reason),
    };
    let Some(constructor) = node_at_span(&prepared, mapping.locator.anchor().span()) else {
        return ClassSeed::NotApplicable;
    };
    if constructor_expression(constructor).is_none() {
        return ClassSeed::NotApplicable;
    }
    if !matches!(constructor.kind(), "identifier" | "type_identifier") {
        return ClassSeed::Unknown(UnknownReason::UnresolvedCall);
    }
    let source = prepared.source();
    let name = slice(constructor, source);
    let lexical = JsTsLexicalBindingIndex::build(prepared.tree().root_node(), source);
    let imports = compute_import_binder(source, prepared.tree());
    let Some(host) = resolve_js_ts_source(workspace.analyzer(), language) else {
        return ClassSeed::Unknown(UnknownReason::UncertainFlow);
    };
    let lookup = AnalyzerDefinitionLookup::new(workspace.analyzer(), language);
    let mut candidates = jsts_constructor_owner_candidates(
        host,
        &lookup,
        &file,
        language,
        source,
        &imports,
        host.alias_resolver().as_ref(),
        constructor,
        true,
    );
    if candidates
        .iter()
        .any(|unit| current_prepared_for(workspace, language, unit.source()).is_none())
    {
        return ClassSeed::Unknown(UnknownReason::UncertainFlow);
    }
    let resolved_candidates = candidates.len();
    candidates.retain(|unit| runtime_class_declaration(workspace, language, unit));
    if candidates.len() != resolved_candidates {
        return ClassSeed::Unknown(UnknownReason::OpenTypeBound);
    }
    sort_units(&mut candidates);
    candidates.dedup();
    match candidates.as_slice() {
        [unit] => {
            let identity = ClassIdentity::Workspace(unit.clone());
            match constructor_seed_verdict(
                workspace,
                language,
                &file,
                constructor,
                unit,
                &lexical,
                &imports,
                &prepared,
                source,
            ) {
                ConstructorSeedVerdict::Exact => ClassSeed::Class(identity),
                ConstructorSeedVerdict::Open => ClassSeed::ClassWithOpenBound(identity),
                ConstructorSeedVerdict::Unresolved => {
                    ClassSeed::Unknown(UnknownReason::UnresolvedCall)
                }
            }
        }
        [] => {
            let external_name = if let Some(binding) = imports.binding(name) {
                let binding_ranges =
                    lexical.binding_identifier_ranges_at(name, constructor.start_byte());
                if imports.has_competing_static_imports(name)
                    || imports.was_truncated(name)
                    || binding_ranges.len() != 1
                    || !active_binding_is_value_import(
                        prepared.tree().root_node(),
                        binding_ranges[0],
                    )
                    || lexical.is_binding_reassigned_at(name, constructor.start_byte())
                {
                    return ClassSeed::Unknown(UnknownReason::UnresolvedCall);
                }
                binding.imported_name.as_deref().unwrap_or(name)
            } else {
                if lexical.is_bound_at(name, constructor.start_byte()) {
                    return ClassSeed::Unknown(UnknownReason::UnresolvedCall);
                }
                name
            };
            match external_type(overlay_of(workspace).as_deref(), external_name) {
                Some(ExternalType::Class(identity)) => ClassSeed::ClassWithOpenBound(identity),
                Some(ExternalType::Interface) => ClassSeed::Unknown(UnknownReason::OpenTypeBound),
                None => ClassSeed::Unknown(UnknownReason::ExternalNotModeled),
            }
        }
        _ => ClassSeed::Unknown(UnknownReason::AmbiguousCallee),
    }
}

fn constant_class(
    workspace: &WorkspaceAnalyzer,
    language: Language,
    procedure: &ProcedureHandle,
    value: &SemanticValue,
) -> ClassSeed {
    let mapping = procedure
        .semantics()
        .source_mapping(value.source)
        .expect("a constant value retains a source mapping");
    if mapping.kind != SourceMappingKind::Exact {
        return ClassSeed::NotApplicable;
    }
    let Some(file) = file_for_locator(workspace, &mapping.locator) else {
        return ClassSeed::NotApplicable;
    };
    let prepared = match prepared_for_procedure(workspace, language, procedure, &file) {
        Ok(prepared) => prepared,
        Err(reason) => return ClassSeed::Unknown(reason),
    };
    let Some(node) = node_at_span(&prepared, mapping.locator.anchor().span()) else {
        return ClassSeed::NotApplicable;
    };
    match node.kind() {
        "string" => exact_external_seed(workspace, "String"),
        "template_string" if is_untagged_template(node) => exact_external_seed(workspace, "String"),
        "true" | "false" => exact_external_seed(workspace, "Boolean"),
        // Both grammars use `number` for Number and BigInt tokens. The
        // payload-free semantic Constant cannot distinguish them.
        "number" | "null" => ClassSeed::Unknown(UnknownReason::OpenTypeBound),
        "undefined" => {
            let lexical =
                JsTsLexicalBindingIndex::build(prepared.tree().root_node(), prepared.source());
            let _shadowed = lexical.is_bound_at("undefined", node.start_byte());
            ClassSeed::Unknown(UnknownReason::OpenTypeBound)
        }
        _ => ClassSeed::NotApplicable,
    }
}

fn retained_value_class(
    workspace: &WorkspaceAnalyzer,
    language: Language,
    procedure: &ProcedureHandle,
    value: &SemanticValue,
) -> ClassSeed {
    if !matches!(
        value.kind,
        SemanticValueKind::Callable | SemanticValueKind::Temporary
    ) {
        return ClassSeed::NotApplicable;
    }
    let Some(mapping) = procedure.semantics().source_mapping(value.source) else {
        return ClassSeed::NotApplicable;
    };
    if mapping.kind != SourceMappingKind::Exact {
        return ClassSeed::NotApplicable;
    }
    let Some(file) = file_for_locator(workspace, &mapping.locator) else {
        return ClassSeed::NotApplicable;
    };
    let prepared = match prepared_for_procedure(workspace, language, procedure, &file) {
        Ok(prepared) => prepared,
        Err(reason) => return ClassSeed::Unknown(reason),
    };
    let Some(node) = node_at_span(&prepared, mapping.locator.anchor().span()) else {
        return ClassSeed::NotApplicable;
    };
    let is_open_runtime_origin = |candidate: Node<'_>| {
        matches!(
            candidate.kind(),
            "function_declaration"
                | "generator_function_declaration"
                | "function_expression"
                | "generator_function"
                | "arrow_function"
                | "class"
                | "class_declaration"
                | "abstract_class_declaration"
                | "regex"
        )
    };
    if is_open_runtime_origin(node) {
        return ClassSeed::Unknown(UnknownReason::OpenTypeBound);
    }
    if !matches!(node.kind(), "identifier" | "type_identifier") {
        return ClassSeed::NotApplicable;
    }

    let source = prepared.source();
    let lexical = JsTsLexicalBindingIndex::build(prepared.tree().root_node(), source);
    let name = slice(node, source);
    for binding in lexical.binding_identifier_ranges_at(name, node.start_byte()) {
        let Some(binding_node) = prepared
            .tree()
            .root_node()
            .named_descendant_for_byte_range(binding.start_byte, binding.end_byte)
        else {
            continue;
        };
        if binding_node.start_byte() != binding.start_byte
            || binding_node.end_byte() != binding.end_byte
        {
            continue;
        }
        let Some(declaration) = binding_node.parent() else {
            continue;
        };
        let binding_is_name = declaration
            .child_by_field_name("name")
            .is_some_and(|name| name.id() == binding_node.id());
        match declaration.kind() {
            "variable_declarator" if binding_is_name => {
                if declaration
                    .child_by_field_name("value")
                    .is_some_and(is_open_runtime_origin)
                {
                    return ClassSeed::Unknown(UnknownReason::OpenTypeBound);
                }
            }
            "function_declaration"
            | "generator_function_declaration"
            | "class_declaration"
            | "abstract_class_declaration"
                if binding_is_name =>
            {
                return ClassSeed::Unknown(UnknownReason::OpenTypeBound);
            }
            _ => {}
        }
    }
    ClassSeed::NotApplicable
}

fn object_literal_has_proto_setter(object: Node<'_>, source: &str) -> bool {
    let mut cursor = object.walk();
    object.named_children(&mut cursor).any(|entry| {
        if entry.kind() != "pair" {
            return false;
        }
        let Some(key) = entry.child_by_field_name("key") else {
            return false;
        };
        match key.kind() {
            "property_identifier" => {
                key.named_child_count() != 0 || slice(key, source) == "__proto__"
            }
            // The runtime StringValue, not the source token, selects the
            // `__proto__` setter. Until the shared syntax layer publishes
            // decoded property strings, reject every string/computed pair
            // rather than letting an escaped spelling manufacture Object.
            "string" | "computed_property_name" => true,
            _ => false,
        }
    })
}

fn allocation_class(
    workspace: &WorkspaceAnalyzer,
    language: Language,
    procedure: &ProcedureHandle,
    allocation: &AllocationSite,
) -> ClassSeed {
    let semantics = procedure.semantics();
    if semantics.call_sites().iter().any(|call| {
        call.result == Some(allocation.result) || call.normal_results.contains(&allocation.result)
    }) {
        return ClassSeed::NotApplicable;
    }
    let mapping = semantics
        .source_mapping(allocation.source)
        .expect("an allocation retains a source mapping");
    if mapping.kind != SourceMappingKind::Exact {
        return ClassSeed::NotApplicable;
    }
    let Some(file) = file_for_locator(workspace, &mapping.locator) else {
        return ClassSeed::NotApplicable;
    };
    let prepared = match prepared_for_procedure(workspace, language, procedure, &file) {
        Ok(prepared) => prepared,
        Err(reason) => return ClassSeed::Unknown(reason),
    };
    let Some(node) = node_at_span(&prepared, mapping.locator.anchor().span()) else {
        return ClassSeed::NotApplicable;
    };
    match (&allocation.kind, node.kind()) {
        (AllocationKind::Array, "array") => exact_external_seed(workspace, "Array"),
        (AllocationKind::Object, "object")
            if object_literal_has_proto_setter(node, prepared.source()) =>
        {
            ClassSeed::Unknown(UnknownReason::OpenTypeBound)
        }
        (AllocationKind::Object, "object") => exact_external_seed(workspace, "Object"),
        (AllocationKind::Object, "new_expression") => {
            let Some(constructor) = node
                .child_by_field_name("constructor")
                .or_else(|| node.child_by_field_name("function"))
            else {
                return ClassSeed::Unknown(UnknownReason::UnresolvedCall);
            };
            if constructor.kind() != "identifier"
                || slice(constructor, prepared.source()) != "Error"
            {
                return ClassSeed::Unknown(UnknownReason::UnresolvedCall);
            }
            let lexical =
                JsTsLexicalBindingIndex::build(prepared.tree().root_node(), prepared.source());
            if lexical.is_bound_at("Error", constructor.start_byte()) {
                return ClassSeed::Unknown(UnknownReason::UnresolvedCall);
            }
            open_external_seed(workspace, "Error")
        }
        _ => ClassSeed::NotApplicable,
    }
}

fn declared_parameter_class(
    workspace: &WorkspaceAnalyzer,
    language: Language,
    procedure: &ProcedureHandle,
    ordinal: u32,
) -> ClassSeed {
    if language != Language::TypeScript {
        return ClassSeed::NotApplicable;
    }
    let semantics = procedure.semantics();
    let Some(file) = file_for_locator(workspace, semantics.locator()) else {
        return ClassSeed::NotApplicable;
    };
    let prepared = match prepared_for_procedure(workspace, language, procedure, &file) {
        Ok(prepared) => prepared,
        Err(reason) => return ClassSeed::Unknown(reason),
    };
    let Some(mut callable) = node_at_span(&prepared, semantics.locator().anchor().span()) else {
        return ClassSeed::NotApplicable;
    };
    while !matches!(
        callable.kind(),
        "function_declaration"
            | "function_expression"
            | "generator_function_declaration"
            | "generator_function"
            | "arrow_function"
            | "method_definition"
    ) {
        let Some(parent) = callable.parent() else {
            return ClassSeed::NotApplicable;
        };
        callable = parent;
    }
    let Some(slots) =
        formal_parameter_slots_for_owner_with_nodes(language, callable, prepared.source())
    else {
        return ClassSeed::NotApplicable;
    };
    let parameter = slots
        .into_iter()
        .filter(|(slot, _)| !slot.receiver && !slot.names.iter().any(|name| name == "this"))
        .nth(ordinal as usize)
        .map(|(_, node)| node);
    let Some(parameter) = parameter else {
        return ClassSeed::NotApplicable;
    };
    let Some(mut annotation) = parameter.child_by_field_name("type") else {
        return ClassSeed::NotApplicable;
    };
    if annotation.kind() == "type_annotation" {
        let Some(inner) = annotation.named_child(0) else {
            return ClassSeed::NotApplicable;
        };
        annotation = inner;
    }
    if !matches!(
        annotation.kind(),
        "identifier" | "type_identifier" | "nested_type_identifier"
    ) {
        return ClassSeed::Unknown(UnknownReason::OpenTypeBound);
    }
    let imports = compute_import_binder(prepared.source(), prepared.tree());
    let Some(host) = resolve_js_ts_source(workspace.analyzer(), language) else {
        return ClassSeed::Unknown(UnknownReason::UncertainFlow);
    };
    let lookup = AnalyzerDefinitionLookup::new(workspace.analyzer(), language);
    let mut candidates = if annotation.kind() == "nested_type_identifier" {
        ts_named_type_candidates(
            host,
            &lookup,
            &file,
            prepared.source(),
            &imports,
            host.alias_resolver().as_ref(),
            annotation,
            false,
        )
    } else {
        let name = slice(annotation, prepared.source());
        jsts_identifier_candidates(
            host,
            &lookup,
            language,
            &file,
            prepared.source(),
            &imports,
            host.alias_resolver().as_ref(),
            name,
            false,
        )
    };
    sort_units(&mut candidates);
    candidates.dedup();
    match candidates.as_slice() {
        [unit] if unit.is_class() => match workspace_type_is_interface(workspace, language, unit) {
            Some(false) => ClassSeed::ClassWithOpenBound(ClassIdentity::Workspace(unit.clone())),
            Some(true) => ClassSeed::Unknown(UnknownReason::OpenTypeBound),
            None => ClassSeed::Unknown(UnknownReason::UncertainFlow),
        },
        [] if annotation.kind() != "nested_type_identifier" => {
            let name = slice(annotation, prepared.source());
            match external_type(overlay_of(workspace).as_deref(), name) {
                Some(ExternalType::Class(identity)) => ClassSeed::ClassWithOpenBound(identity),
                Some(ExternalType::Interface) => ClassSeed::Unknown(UnknownReason::OpenTypeBound),
                None => ClassSeed::Unknown(UnknownReason::ExternalNotModeled),
            }
        }
        [] => ClassSeed::Unknown(UnknownReason::OpenTypeBound),
        [_] => ClassSeed::Unknown(UnknownReason::OpenTypeBound),
        _ => ClassSeed::Unknown(UnknownReason::AmbiguousCallee),
    }
}

fn member_name_at_node(mut node: Node<'_>, source: &str) -> Option<Box<str>> {
    loop {
        match node.kind() {
            // A semantic source span may select the key or a string fragment
            // rather than the complete access. Walk to the nearest access so
            // computed properties remain suppressed in every case.
            "subscript_expression" => return None,
            "member_expression" => {
                let property = node.child_by_field_name("property")?;
                return matches!(
                    property.kind(),
                    "property_identifier" | "private_property_identifier"
                )
                .then(|| slice(property, source))
                .filter(|name| !name.is_empty())
                .map(Box::from);
            }
            _ => node = node.parent()?,
        }
    }
}

fn accessed_member(
    workspace: &WorkspaceAnalyzer,
    language: Language,
    procedure: &ProcedureHandle,
    site: MemberAccessQuery<'_>,
) -> Option<Box<str>> {
    let semantics = procedure.semantics();
    let locator = match site {
        MemberAccessQuery::Call(call) => {
            let callee = semantics.value(call.callee)?;
            let mapping = semantics.source_mapping(callee.source)?;
            (mapping.kind == SourceMappingKind::Exact).then_some(&mapping.locator)?
        }
        MemberAccessQuery::Load(location) => {
            let MemoryLocationKind::Field { member, .. } = &location.kind else {
                return None;
            };
            member
        }
    };
    let file = file_for_locator(workspace, locator)?;
    let prepared = prepared_for_procedure(workspace, language, procedure, &file).ok()?;
    let node = node_at_span(&prepared, locator.anchor().span())?;
    member_name_at_node(node, prepared.source())
}

fn ancestors(
    workspace: &WorkspaceAnalyzer,
    language: Language,
    unit: &CodeUnit,
) -> Option<Vec<CodeUnit>> {
    match language {
        Language::JavaScript => {
            Some(resolve_analyzer::<JavascriptAnalyzer>(workspace.analyzer())?.get_ancestors(unit))
        }
        Language::TypeScript => {
            Some(resolve_analyzer::<TypescriptAnalyzer>(workspace.analyzer())?.get_ancestors(unit))
        }
        _ => unreachable!("the JS/TS adapter receives only JavaScript or TypeScript"),
    }
}

fn present(declaration: MemberDeclaration) -> MemberLookup {
    MemberLookup::Present(MemberLookupHit {
        declaration,
        dispatch_coverage: CandidateCoverage::Open,
    })
}

fn is_ordinary_instance_method(node: Node<'_>) -> bool {
    if node.kind() != "method_definition" || node.child_by_field_name("body").is_none() {
        return false;
    }
    let mut cursor = node.walk();
    !node
        .children(&mut cursor)
        .any(|child| matches!(child.kind(), "static" | "get" | "set"))
}

fn workspace_instance_method(prepared: &PreparedSyntaxTree, unit: &CodeUnit) -> bool {
    declaration_node(prepared, unit).is_some_and(is_ordinary_instance_method)
}

fn external_member_lookup(
    overlay: &SemanticModelOverlay,
    symbol_id: &str,
    member: &str,
) -> MemberLookup {
    let matched = overlay.member_target_on_owner(symbol_id, member);
    let all_records_are_instance_methods = matched
        .records
        .iter()
        .all(|record| record.kind == SemanticModelSymbolKind::Method && !record.is_static());
    let records = matched
        .records
        .into_iter()
        .filter(|record| record.kind == SemanticModelSymbolKind::Method && !record.is_static())
        .collect::<Vec<_>>();
    match matched.disposition {
        SemanticModelMemberTargetDisposition::Unique if records.len() == 1 => {
            present(MemberDeclaration::External(ExternalMemberDeclaration::new(
                records
                    .into_iter()
                    .map(|record| Box::from(record.id.as_str())),
            )))
        }
        SemanticModelMemberTargetDisposition::Conflict
            if all_records_are_instance_methods
                && !records.is_empty()
                && overlay.member_present_on_owner(symbol_id, member) =>
        {
            present(MemberDeclaration::External(ExternalMemberDeclaration::new(
                records
                    .into_iter()
                    .map(|record| Box::from(record.id.as_str())),
            )))
        }
        SemanticModelMemberTargetDisposition::Unique
        | SemanticModelMemberTargetDisposition::Incomplete
        | SemanticModelMemberTargetDisposition::Conflict
        | SemanticModelMemberTargetDisposition::Absent => {
            MemberLookup::Unknown(UnknownReason::PackIncomplete)
        }
    }
}

fn member_lookup(
    workspace: &WorkspaceAnalyzer,
    language: Language,
    class: &ClassIdentity,
    member: &str,
) -> MemberLookup {
    match class {
        ClassIdentity::Workspace(unit) => {
            let Some(workspace_ancestors) = ancestors(workspace, language, unit) else {
                return MemberLookup::Unknown(UnknownReason::UncertainFlow);
            };
            let overlay = overlay_of(workspace);
            let Some(host) = resolve_js_ts_source(workspace.analyzer(), language) else {
                return MemberLookup::Unknown(UnknownReason::UncertainFlow);
            };
            for owner in std::iter::once(unit.clone()).chain(workspace_ancestors.iter().cloned()) {
                let Some(prepared) = current_prepared_for(workspace, language, owner.source())
                else {
                    return MemberLookup::Unknown(UnknownReason::UncertainFlow);
                };
                let mut matches = prepared
                    .direct_children(&owner)
                    .iter()
                    .filter(|child| {
                        child.terminal_name() == member
                            && workspace_instance_method(&prepared, child)
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                if !matches.is_empty() {
                    sort_units(&mut matches);
                    let Some(declaration) = matches.into_iter().next() else {
                        unreachable!("matches was checked as non-empty")
                    };
                    return present(MemberDeclaration::Workspace(declaration));
                }
            }
            let mut external_bases = Vec::new();
            for owner in std::iter::once(unit).chain(workspace_ancestors.iter()) {
                let direct_ancestors = host.get_direct_ancestors(owner);
                for raw in host.raw_supertypes_of(owner) {
                    if direct_ancestors
                        .iter()
                        .any(|base| base.terminal_name() == raw || base.fq_name_str() == raw)
                    {
                        continue;
                    }
                    let Some(base) = external_class(overlay.as_deref(), &raw) else {
                        return MemberLookup::Unknown(UnknownReason::UnresolvedBase);
                    };
                    external_bases.push(base);
                }
            }
            sort_external_classes(&mut external_bases);
            external_bases.dedup();
            for base in external_bases {
                let ClassIdentity::External { symbol_id, .. } = base else {
                    unreachable!("external_bases contains only external identities")
                };
                let Some(overlay) = overlay.as_deref() else {
                    unreachable!("an external base was resolved through this overlay")
                };
                match external_member_lookup(overlay, &symbol_id, member) {
                    present @ MemberLookup::Present(_) => return present,
                    MemberLookup::Unknown(UnknownReason::PackIncomplete) => {}
                    MemberLookup::Unknown(reason) => return MemberLookup::Unknown(reason),
                    MemberLookup::DeclarationAbsent => {
                        unreachable!("external model lookup is declaration-complete or unknown")
                    }
                    MemberLookup::Absent => {
                        unreachable!("the JS/TS external lookup never proves runtime absence")
                    }
                }
            }
            MemberLookup::Unknown(UnknownReason::DynamicAttributes)
        }
        ClassIdentity::External { symbol_id, .. } => {
            let Some(overlay) = overlay_of(workspace) else {
                return MemberLookup::Unknown(UnknownReason::ExternalNotModeled);
            };
            external_member_lookup(&overlay, symbol_id, member)
        }
    }
}

fn class_hierarchy(
    workspace: &WorkspaceAnalyzer,
    language: Language,
    class: &ClassIdentity,
) -> ClassHierarchy {
    let ClassIdentity::Workspace(unit) = class else {
        return ClassHierarchy::unknown();
    };
    if current_prepared_for(workspace, language, unit.source()).is_none() {
        return ClassHierarchy::unknown();
    }
    let Some(host) = resolve_js_ts_source(workspace.analyzer(), language) else {
        return ClassHierarchy::unknown();
    };
    let Some(mut workspace_ancestors) = ancestors(workspace, language, unit) else {
        return ClassHierarchy::unknown();
    };
    if workspace_ancestors
        .iter()
        .any(|ancestor| current_prepared_for(workspace, language, ancestor.source()).is_none())
    {
        return ClassHierarchy::unknown();
    }
    sort_units(&mut workspace_ancestors);
    workspace_ancestors.dedup();
    let overlay = overlay_of(workspace);
    let mut unresolved_base = false;
    let mut external_ancestors = Vec::new();
    for owner in std::iter::once(unit).chain(workspace_ancestors.iter()) {
        let direct_ancestors = host.get_direct_ancestors(owner);
        for raw in host.raw_supertypes_of(owner) {
            if direct_ancestors
                .iter()
                .any(|base| base.terminal_name() == raw || base.fq_name_str() == raw)
            {
                continue;
            }
            match external_class(overlay.as_deref(), &raw) {
                Some(base) => external_ancestors.push(base),
                None => unresolved_base = true,
            }
        }
    }
    sort_external_classes(&mut external_ancestors);
    external_ancestors.dedup();
    ClassHierarchy {
        ancestors: workspace_ancestors
            .into_iter()
            .map(ClassIdentity::Workspace)
            .chain(external_ancestors)
            .collect(),
        // JavaScript permits subclasses and prototype mutation outside the
        // indexed workspace; a finite workspace descendant list is never a
        // closed-world proof.
        descendants: None,
        unresolved_base,
        dynamic_attributes: true,
    }
}

macro_rules! impl_js_ts_type_flow_adapter {
    ($support:ty, $language:expr, $name:literal, $version:literal) => {
        impl TypeFlowAdapter for $support {
            fn language(&self) -> Language {
                $language
            }

            fn semantics_version(&self) -> AdapterSemanticsVersion {
                AdapterSemanticsVersion::hash_bytes($name, $version)
                    .expect("adapter name is non-empty")
            }

            fn constructed_class(
                &self,
                workspace: &WorkspaceAnalyzer,
                procedure: &ProcedureHandle,
                call: &SemanticCallSite,
            ) -> ClassSeed {
                constructed_class(workspace, $language, procedure, call)
            }

            fn constant_class(
                &self,
                workspace: &WorkspaceAnalyzer,
                procedure: &ProcedureHandle,
                value: &SemanticValue,
            ) -> ClassSeed {
                constant_class(workspace, $language, procedure, value)
            }

            fn allocation_class(
                &self,
                workspace: &WorkspaceAnalyzer,
                procedure: &ProcedureHandle,
                allocation: &AllocationSite,
            ) -> ClassSeed {
                allocation_class(workspace, $language, procedure, allocation)
            }

            fn retained_value_class(
                &self,
                workspace: &WorkspaceAnalyzer,
                procedure: &ProcedureHandle,
                value: &SemanticValue,
            ) -> ClassSeed {
                retained_value_class(workspace, $language, procedure, value)
            }

            fn declared_parameter_class(
                &self,
                workspace: &WorkspaceAnalyzer,
                procedure: &ProcedureHandle,
                ordinal: u32,
            ) -> ClassSeed {
                declared_parameter_class(workspace, $language, procedure, ordinal)
            }

            fn accessed_member(
                &self,
                workspace: &WorkspaceAnalyzer,
                procedure: &ProcedureHandle,
                site: MemberAccessQuery<'_>,
            ) -> Option<Box<str>> {
                accessed_member(workspace, $language, procedure, site)
            }

            fn member_lookup(
                &self,
                workspace: &WorkspaceAnalyzer,
                _kind: MemberAccessKind,
                class: &ClassIdentity,
                member: &str,
            ) -> MemberLookup {
                member_lookup(workspace, $language, class, member)
            }

            fn class_hierarchy(
                &self,
                workspace: &WorkspaceAnalyzer,
                class: &ClassIdentity,
            ) -> ClassHierarchy {
                class_hierarchy(workspace, $language, class)
            }
        }
    };
}

impl_js_ts_type_flow_adapter!(
    JavascriptSupport,
    Language::JavaScript,
    "javascript-type-flow",
    b"javascript-type-flow-open-runtime-v2"
);
impl_js_ts_type_flow_adapter!(
    TypescriptSupport,
    Language::TypeScript,
    "typescript-type-flow",
    b"typescript-type-flow-open-runtime-v2"
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::AnalyzerConfig;
    use crate::analyzer::semantic::{CancellationToken, SemanticBudget, SemanticRequest};
    use crate::inline_project::InlineTestProject;
    use tree_sitter::{Parser, Tree};

    fn parse_javascript(source: &str) -> Tree {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_javascript::LANGUAGE.into())
            .expect("JavaScript grammar");
        parser.parse(source, None).expect("JavaScript tree")
    }

    fn parse_typescript(source: &str) -> Tree {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            .expect("TypeScript grammar");
        parser.parse(source, None).expect("TypeScript tree")
    }

    fn first_kind<'tree>(root: Node<'tree>, kind: &str) -> Node<'tree> {
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            if node.kind() == kind {
                return node;
            }
            for index in (0..node.named_child_count()).rev() {
                if let Some(child) = node.named_child(index) {
                    stack.push(child);
                }
            }
        }
        panic!("missing {kind}")
    }

    fn active_import_is_value(source: &str) -> bool {
        let tree = parse_typescript(source);
        let use_byte = source.rfind("C()").expect("constructor use");
        let lexical = JsTsLexicalBindingIndex::build(tree.root_node(), source);
        let ranges = lexical.binding_identifier_ranges_at("C", use_byte);
        ranges.len() == 1 && active_binding_is_value_import(tree.root_node(), ranges[0])
    }

    #[test]
    fn constructor_import_proof_rejects_shadow_and_type_only_bindings() {
        assert!(active_import_is_value("import { C } from './c'; new C();"));
        assert!(!active_import_is_value(
            "import type { C } from './c'; new C();"
        ));
        assert!(!active_import_is_value(
            "import { C } from './c'; function root(C: unknown) { new C(); }"
        ));
    }

    #[test]
    fn derived_class_detection_handles_both_grammar_shapes() {
        let javascript = parse_javascript("class Base {} class Child extends Base {}");
        let typescript = parse_typescript(
            "interface Shape {} class Base {} class Child extends Base implements Shape {}",
        );
        let js_child = first_kind(javascript.root_node(), "class_heritage")
            .parent()
            .expect("heritage has class parent");
        let ts_child = first_kind(typescript.root_node(), "extends_clause")
            .parent()
            .expect("extends has heritage parent")
            .parent()
            .expect("heritage has class parent");

        assert!(class_is_derived(js_child));
        assert!(class_is_derived(ts_child));
    }

    #[test]
    fn malformed_classes_and_ambient_files_cannot_support_exactness() {
        let malformed = parse_javascript("class Broken { constructor(,) {} }");
        let class = first_kind(malformed.root_node(), "class_declaration");
        assert!(!syntax_is_complete(class));
        let ambient = parse_typescript("declare class Ambient {}");
        let ambient_class = first_kind(ambient.root_node(), "class_declaration");

        for path in [
            "types/widget.d.ts",
            "types/widget.d.mts",
            "types/widget.d.cts",
        ] {
            assert!(is_typescript_declaration_path(Path::new(path)), "{path}");
        }
        assert!(!is_typescript_declaration_path(Path::new(
            "types/widget.ts"
        )));
        assert!(declaration_is_ambient(ambient_class));
    }

    #[test]
    fn computed_members_and_proto_setter_stay_open() {
        let source = "receiver['run'](); receiver.run(); ({ __proto__: null });";
        let tree = parse_javascript(source);
        let subscript = first_kind(tree.root_node(), "subscript_expression");
        let computed_fragment = first_kind(subscript, "string_fragment");
        let member = first_kind(tree.root_node(), "member_expression");
        let object = first_kind(tree.root_node(), "object");

        assert_eq!(member_name_at_node(subscript, source), None);
        assert_eq!(member_name_at_node(computed_fragment, source), None);
        assert_eq!(member_name_at_node(member, source).as_deref(), Some("run"));
        assert!(object_literal_has_proto_setter(object, source));
    }

    #[test]
    fn only_ordinary_instance_methods_are_positive_workspace_members() {
        for (source, expected) in [
            ("class C { run() {} }", true),
            ("class C { static run() {} }", false),
            ("class C { get run() { return 1; } }", false),
            ("class C { set run(value) {} }", false),
        ] {
            let tree = parse_javascript(source);
            let method = first_kind(tree.root_node(), "method_definition");
            assert_eq!(is_ordinary_instance_method(method), expected, "{source}");
        }
        let field = parse_javascript("class C { run = () => {}; }");
        assert!(!is_ordinary_instance_method(first_kind(
            field.root_node(),
            "field_definition"
        )));
    }

    #[test]
    fn inherited_workspace_method_is_present_while_the_hierarchy_stays_open() {
        const SOURCE: &str = "class Base { inherited() {} }\nclass Child extends Base {}\nexport function root(value) { value.inherited(); }\n";

        for (language, path) in [
            (Language::JavaScript, "app.js"),
            (Language::TypeScript, "app.ts"),
        ] {
            let project = InlineTestProject::with_language(language)
                .file(path, SOURCE)
                .build();
            let file = project.file(path);
            let workspace = project.workspace_analyzer(AnalyzerConfig::default());
            let lookup = AnalyzerDefinitionLookup::new(workspace.analyzer(), language);
            let one_class = |name: &str| {
                let candidates = lookup
                    .file_identifier(&file, name)
                    .into_iter()
                    .filter(CodeUnit::is_class)
                    .collect::<Vec<_>>();
                assert_eq!(
                    candidates.len(),
                    1,
                    "fixture has one {language:?} {name} class: {candidates:#?}"
                );
                candidates.into_iter().next().expect("one class candidate")
            };
            let base = one_class("Base");
            let child = one_class("Child");
            let child_identity = ClassIdentity::Workspace(child);

            let MemberLookup::Present(hit) =
                member_lookup(&workspace, language, &child_identity, "inherited")
            else {
                panic!("a fully resolved workspace ancestor supplies inherited")
            };
            let MemberDeclaration::Workspace(declaration) = hit.declaration else {
                panic!("the inherited declaration is workspace-backed")
            };
            assert_eq!(declaration.fq_name(), "Base.inherited");
            assert_eq!(hit.dispatch_coverage, CandidateCoverage::Open);

            let hierarchy = class_hierarchy(&workspace, language, &child_identity);
            assert_eq!(
                hierarchy.ancestors,
                vec![ClassIdentity::Workspace(base)],
                "the structured base identity is retained"
            );
            assert_eq!(hierarchy.descendants, None);
            assert!(!hierarchy.unresolved_base, "Base resolves in the workspace");
            assert!(
                hierarchy.dynamic_attributes,
                "JS/TS hierarchy facts never close the runtime member surface"
            );
        }
    }

    #[test]
    fn qualified_typescript_class_annotation_retains_its_direct_class() {
        let source = "namespace Domain { export class Declared {} }\nexport function root(value: Domain.Declared) { return value; }\n";
        let project = InlineTestProject::with_language(Language::TypeScript)
            .file("app.ts", source)
            .build();
        let file = project.file("app.ts");
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let artifact = workspace
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("TypeScript semantic materialization succeeds")
            .available_value()
            .cloned()
            .expect("TypeScript semantic artifact is available");
        let procedure = artifact
            .procedures()
            .iter()
            .find(|procedure| {
                procedure
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("root")
            })
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("fixture retains root procedure");

        let seed = declared_parameter_class(&workspace, Language::TypeScript, &procedure, 0);
        let ClassSeed::ClassWithOpenBound(identity) = seed else {
            panic!("qualified annotation must retain its direct class: {seed:?}")
        };
        assert_eq!(identity.qualified_name(), "Domain.Declared");
    }

    fn assert_prepared_revision_guard(
        language: Language,
        path: &str,
        original: &str,
        changed: &str,
    ) {
        let project = InlineTestProject::with_language(language)
            .file(path, original)
            .build();
        let file = project.file(path);
        let workspace = project.workspace_analyzer(AnalyzerConfig::default());
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::default();
        let artifact = workspace
            .materialize_program_semantics(
                &file,
                &mut SemanticRequest::new(&mut budget, &cancellation),
            )
            .expect("JS/TS semantic materialization succeeds")
            .available_value()
            .cloned()
            .expect("JS/TS semantic artifact is available");
        let procedure = artifact
            .procedures()
            .first()
            .and_then(|procedure| artifact.procedure_handle(procedure.id()))
            .expect("fixture has one procedure");

        assert!(prepared_for_procedure(&workspace, language, &procedure, &file).is_ok());

        std::fs::write(file.abs_path(), changed).expect("change fixture content");
        let changed_workspace = project.workspace_analyzer(AnalyzerConfig::default());
        assert_eq!(
            prepared_for_procedure(&changed_workspace, language, &procedure, &file)
                .expect_err("changed content cannot validate an old artifact"),
            UnknownReason::UncertainFlow
        );
    }

    #[test]
    fn prepared_syntax_validator_rejects_changed_javascript_and_typescript_content() {
        assert_prepared_revision_guard(
            Language::JavaScript,
            "app.js",
            "function target() { return 1; }\n",
            "function target() { return 2; }\n",
        );
        assert_prepared_revision_guard(
            Language::TypeScript,
            "app.ts",
            "function target(): number { return 1; }\n",
            "function target(): number { return 2; }\n",
        );
    }
}
