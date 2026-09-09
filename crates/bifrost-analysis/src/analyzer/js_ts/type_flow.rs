//! JavaScript and TypeScript class-set adapter.
//!
//! All source questions are answered from the analyzer's prepared syntax so
//! unsaved overlays, declaration identities, and the semantic artifact stay
//! on one revision. Missing members become authoritative only after a bounded
//! class-wide survey proves that the runtime surface is closed.

use std::path::Path;
use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};

use brokk_bifrost_core::analyzer::prepared_syntax::{PreparedSyntaxSource, PreparedSyntaxTree};
use brokk_bifrost_core::analyzer::usages::receiver_analysis::{
    ReceiverAnalysisBudget, ReceiverAnalysisOutcome, ReceiverValue,
};
use brokk_bifrost_js_ts::graph::receiver_analysis::{
    JsTsReceiverFactProvider, JsTsReceiverSyntaxIndexBuild,
    build_js_ts_receiver_syntax_index_bounded,
};
use brokk_bifrost_js_ts::syntax::{
    JsTsImportBinder, JsTsLexicalBindingIndex, compute_import_binder, slice,
    static_member_property, static_member_receiver, static_property_name,
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
    SourceSpan, StableDigest, TypeFlowAdapter, UnknownReason,
    validate_prepared_syntax_for_procedure,
};
use crate::analyzer::semantic_model::{
    SemanticModelOverlay, SemanticModelSymbol, SemanticModelSymbolKind,
};
use crate::analyzer::tree_walk::push_named_children_reversed;
use crate::analyzer::{
    AnalyzerDefinitionLookup, AnalyzerQueryScope, CodeUnit, CodeUnitIndex, KeyedPoolSafeMemo,
    Language, ProjectFile, QueryReadIncomplete, QueryScope, WorkspaceAnalyzer, resolve_analyzer,
    sort_units,
};
use crate::analyzer::{JavascriptAnalyzer, TypescriptAnalyzer};
use crate::cancellation::CancellationToken;
use crate::hash::{HashMap, HashSet};

/// Maximum named syntax nodes consumed by the class-independent JS/TS member
/// mutation survey once per request. All member lookups in that request share
/// the completed survey; exhausting this request-wide allowance makes its
/// coverage truncated for every lookup rather than restarting the allowance
/// for each queried member.
const MAX_JS_TS_MEMBER_SURFACE_NODES: usize = 200_000;

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

fn external_class_surface_is_closed(overlay: &SemanticModelOverlay, class: &ClassIdentity) -> bool {
    let ClassIdentity::External { symbol_id, .. } = class else {
        return false;
    };
    let owners = overlay.symbols_with_id(symbol_id).records;
    let [owner] = owners.as_slice() else {
        return false;
    };
    js_ts_external_symbol(owner)
        && owner.kind == SemanticModelSymbolKind::Class
        && !owner.provenance.ambiguous
        && overlay.owner_surface(owner).proves_absence()
        && overlay.gapped(&owner.qualified_name).is_none()
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

#[allow(clippy::too_many_arguments)]
fn exact_runtime_class_binding(
    call_file: &ProjectFile,
    expression: Node<'_>,
    unit: &CodeUnit,
    lexical: &JsTsLexicalBindingIndex,
    imports: &JsTsImportBinder,
    call_prepared: &PreparedSyntaxTree,
    target_prepared: &PreparedSyntaxTree,
) -> bool {
    let Some(class) = declaration_node(target_prepared, unit) else {
        return false;
    };
    let Some(name_node) = class.child_by_field_name("name") else {
        return false;
    };
    let name = slice(expression, call_prepared.source());
    let binding_ranges = lexical.binding_identifier_ranges_at(name, expression.start_byte());
    if lexical.is_binding_reassigned_at(name, expression.start_byte()) {
        return false;
    }
    if unit.source() == call_file {
        return binding_ranges.len() == 1
            && binding_ranges[0].start_byte == name_node.start_byte()
            && binding_ranges[0].end_byte == name_node.end_byte();
    }
    let target_name = slice(name_node, target_prepared.source());
    let target_lexical = JsTsLexicalBindingIndex::build(
        target_prepared.tree().root_node(),
        target_prepared.source(),
    );
    imports.binding(name).is_some()
        && !imports.has_competing_static_imports(name)
        && !imports.was_truncated(name)
        && binding_ranges.len() == 1
        && active_binding_is_value_import(call_prepared.tree().root_node(), binding_ranges[0])
        && !target_lexical.is_binding_reassigned_at(target_name, name_node.start_byte())
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

fn class_constructor_has_value_return(class: Node<'_>, source: &str) -> bool {
    let Some(body) = class.child_by_field_name("body") else {
        return true;
    };
    let mut cursor = body.walk();
    body.named_children(&mut cursor).any(|member| {
        member.kind() == "method_definition"
            && member.child_by_field_name("name").is_some_and(|name| {
                name.kind() == "property_identifier" && slice(name, source) == "constructor"
            })
            && constructor_has_value_return(member)
    })
}

fn workspace_construction_chain_is_exact(
    workspace: &WorkspaceAnalyzer,
    language: Language,
    unit: &CodeUnit,
) -> bool {
    let closure = workspace_surface_closure(workspace, language, unit);
    if closure.owners.is_empty()
        || !closure.external_bases.is_empty()
        || closure.coverage != JsTsSurfaceCoverage::Closed
    {
        return false;
    }
    closure.owners.iter().all(|owner| {
        let Some(prepared) = current_prepared_for(workspace, language, owner.source()) else {
            return false;
        };
        let Some(class) = declaration_node(&prepared, owner) else {
            return false;
        };
        syntax_is_complete(class)
            && !subtree_has_decorator(class)
            && !class_constructor_has_value_return(class, prepared.source())
    })
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
) -> ConstructorSeedVerdict {
    let Some(prepared) = current_prepared_for(workspace, language, unit.source()) else {
        return ConstructorSeedVerdict::Unresolved;
    };
    let Some(class) = declaration_node(&prepared, unit) else {
        return ConstructorSeedVerdict::Unresolved;
    };
    if constructor_is_inside_with(constructor)
        || contains_direct_eval(call_prepared)
        || (unit.source() != call_file && contains_direct_eval(&prepared))
    {
        return ConstructorSeedVerdict::Unresolved;
    }
    if !exact_runtime_class_binding(
        call_file,
        constructor,
        unit,
        lexical,
        imports,
        call_prepared,
        &prepared,
    ) {
        return ConstructorSeedVerdict::Unresolved;
    }
    if !syntax_is_complete(class) {
        return ConstructorSeedVerdict::Open;
    }
    if class.kind() != "class_declaration"
        || class_has_decorator(class)
        || (class_is_derived(class)
            && !workspace_construction_chain_is_exact(workspace, language, unit))
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
            let overlay = overlay_of(workspace);
            match external_type(overlay.as_deref(), external_name) {
                Some(ExternalType::Class(identity))
                    if overlay.as_deref().is_some_and(|overlay| {
                        external_class_surface_is_closed(overlay, &identity)
                    }) =>
                {
                    ClassSeed::Class(identity)
                }
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
            // rather than the complete access. Walk to the nearest access and
            // accept only the names the shared structural helper resolves.
            "member_expression" | "subscript_expression" => {
                return static_member_property(node, source).map(|(_, name)| name.into_boxed_str());
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

fn workspace_instance_member_name(
    prepared: &PreparedSyntaxTree,
    unit: &CodeUnit,
) -> Option<String> {
    let declaration = declaration_node(prepared, unit)?;
    if node_has_static_modifier(declaration) {
        return None;
    }
    declaration
        .child_by_field_name("name")
        .or_else(|| declaration.child_by_field_name("property"))
        .and_then(|name| static_property_name(name, prepared.source()))
        .map(|(_, name)| name)
}

fn external_member_lookup(
    overlay: &SemanticModelOverlay,
    symbol_id: &str,
    kind: MemberAccessKind,
    member: &str,
) -> MemberLookup {
    let owners = overlay.symbols_with_id(symbol_id).records;
    let [owner] = owners.as_slice() else {
        return MemberLookup::Unknown(UnknownReason::PackIncomplete);
    };
    if !js_ts_external_symbol(owner)
        || owner.kind != SemanticModelSymbolKind::Class
        || owner.provenance.ambiguous
    {
        return MemberLookup::Unknown(UnknownReason::PackIncomplete);
    }
    let surface = overlay.owner_surface(owner);
    let member_surface_is_gapped = surface.closure.iter().any(|candidate_owner| {
        overlay
            .gapped_member_surface(&candidate_owner.qualified_name, member)
            .is_some()
    });
    for candidate_owner in &surface.closure {
        let records = overlay
            .members_of(&candidate_owner.id)
            .records
            .into_iter()
            .filter(|symbol| symbol.name == member && !symbol.is_static())
            .collect::<Vec<_>>();
        if records.is_empty() {
            continue;
        }
        if records.iter().any(|symbol| symbol.provenance.ambiguous) {
            return MemberLookup::Unknown(UnknownReason::PackIncomplete);
        }
        let relevant = records
            .iter()
            .copied()
            .filter(|symbol| {
                matches!(
                    (kind, symbol.kind),
                    (MemberAccessKind::Call, SemanticModelSymbolKind::Method)
                        | (
                            MemberAccessKind::Load,
                            SemanticModelSymbolKind::Method
                                | SemanticModelSymbolKind::Field
                                | SemanticModelSymbolKind::Property
                        )
                )
            })
            .collect::<Vec<_>>();
        if relevant.is_empty() {
            return MemberLookup::Unknown(UnknownReason::DynamicAttributes);
        }
        return present(MemberDeclaration::External(ExternalMemberDeclaration::new(
            relevant
                .into_iter()
                .map(|symbol| symbol.id.clone().into_boxed_str()),
        )));
    }
    if surface.gaps.is_empty() && !member_surface_is_gapped {
        MemberLookup::Absent
    } else {
        MemberLookup::Unknown(UnknownReason::PackIncomplete)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum JsTsSurfaceCoverage {
    Closed,
    Open(UnknownReason),
    Truncated,
}

impl JsTsSurfaceCoverage {
    fn include(&mut self, next: Self) {
        if matches!(self, Self::Truncated) {
            return;
        }
        match next {
            Self::Closed => {}
            Self::Truncated => *self = Self::Truncated,
            Self::Open(reason) => {
                if matches!(self, Self::Closed) || matches!(&reason, UnknownReason::UncertainFlow) {
                    *self = Self::Open(reason);
                }
            }
        }
    }

    fn reason(self) -> Option<UnknownReason> {
        match self {
            Self::Closed => None,
            Self::Open(reason) => Some(reason),
            Self::Truncated => Some(UnknownReason::Truncated),
        }
    }
}

#[derive(Debug, Default)]
struct JsTsClassMutations {
    named: HashSet<Box<str>>,
    coverage: Option<JsTsSurfaceCoverage>,
}

#[derive(Debug)]
struct JsTsMemberSurfaceSummary {
    by_class: HashMap<ClassIdentity, JsTsClassMutations>,
    unresolved_named: HashSet<Box<str>>,
    coverage: JsTsSurfaceCoverage,
}

impl Default for JsTsMemberSurfaceSummary {
    fn default() -> Self {
        Self {
            by_class: HashMap::default(),
            unresolved_named: HashSet::default(),
            coverage: JsTsSurfaceCoverage::Closed,
        }
    }
}

enum JsTsMutationTargets {
    Exact(Vec<ClassIdentity>),
    NotInstance,
    Open,
    Truncated,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct JsTsMemberSurfaceMemoKey {
    language: Language,
    language_content: StableDigest,
    project_generation: u64,
    semantic_overlay: Option<Box<str>>,
    max_nodes: usize,
}

#[derive(Debug, Default)]
pub(crate) struct JsTsMemberSurfaceRequestMemo {
    summaries: KeyedPoolSafeMemo<JsTsMemberSurfaceMemoKey, JsTsMemberSurfaceSummary>,
    #[cfg(test)]
    survey_count: AtomicUsize,
}

impl JsTsMemberSurfaceRequestMemo {
    fn cell(
        &self,
        key: &JsTsMemberSurfaceMemoKey,
    ) -> Arc<brokk_bifrost_core::analyzer::pool_memo::PoolSafeMemo<JsTsMemberSurfaceSummary>> {
        self.summaries.cell(key)
    }

    fn record_survey(&self) {
        #[cfg(test)]
        self.survey_count.fetch_add(1, Ordering::Relaxed);
    }

    #[cfg(test)]
    fn survey_count(&self) -> usize {
        self.survey_count.load(Ordering::Relaxed)
    }
}

impl JsTsMemberSurfaceSummary {
    fn record(&mut self, targets: JsTsMutationTargets, member: Option<Box<str>>) {
        match targets {
            JsTsMutationTargets::Exact(classes) => {
                for class in classes {
                    let mutations = self.by_class.entry(class).or_default();
                    if let Some(member) = &member {
                        mutations.named.insert(member.clone());
                    } else {
                        let coverage = mutations
                            .coverage
                            .get_or_insert(JsTsSurfaceCoverage::Closed);
                        coverage
                            .include(JsTsSurfaceCoverage::Open(UnknownReason::DynamicAttributes));
                    }
                }
            }
            JsTsMutationTargets::NotInstance => {}
            JsTsMutationTargets::Open => {
                if let Some(member) = member {
                    self.unresolved_named.insert(member);
                } else {
                    self.coverage
                        .include(JsTsSurfaceCoverage::Open(UnknownReason::DynamicAttributes));
                }
            }
            JsTsMutationTargets::Truncated => {
                self.coverage.include(JsTsSurfaceCoverage::Truncated);
            }
        }
    }

    fn reason_for(&self, classes: &[ClassIdentity], member: &str) -> Option<UnknownReason> {
        if self.unresolved_named.contains(member)
            || classes.iter().any(|class| {
                self.by_class
                    .get(class)
                    .is_some_and(|mutations| mutations.named.contains(member))
            })
        {
            return Some(UnknownReason::DynamicAttributes);
        }
        let mut coverage = self.coverage.clone();
        for class in classes {
            if let Some(class_coverage) = self
                .by_class
                .get(class)
                .and_then(|mutations| mutations.coverage.clone())
            {
                coverage.include(class_coverage);
            }
        }
        coverage.reason()
    }
}

struct WorkspaceSurfaceClosure {
    owners: Vec<CodeUnit>,
    external_bases: Vec<ClassIdentity>,
    coverage: JsTsSurfaceCoverage,
}

fn runtime_base_expression(class: Node<'_>) -> Result<Option<Node<'_>>, ()> {
    if let Some(superclass) = class.child_by_field_name("superclass") {
        return Ok(Some(superclass));
    }
    let mut class_cursor = class.walk();
    let Some(heritage) = class
        .named_children(&mut class_cursor)
        .find(|child| child.kind() == "class_heritage")
    else {
        return Ok(None);
    };
    let mut heritage_cursor = heritage.walk();
    let heritage_children = heritage
        .named_children(&mut heritage_cursor)
        .filter(|child| child.kind() != "implements_clause")
        .collect::<Vec<_>>();
    let [heritage_child] = heritage_children.as_slice() else {
        return if heritage_children.is_empty() {
            Ok(None)
        } else {
            Err(())
        };
    };
    if heritage_child.kind() != "extends_clause" {
        return Ok(Some(*heritage_child));
    }
    let mut value_cursor = heritage_child.walk();
    let values = heritage_child
        .children_by_field_name("value", &mut value_cursor)
        .collect::<Vec<_>>();
    match values.as_slice() {
        [value] => Ok(Some(*value)),
        _ => Err(()),
    }
}

#[allow(clippy::too_many_arguments)]
fn resolve_class_expression(
    workspace: &WorkspaceAnalyzer,
    language: Language,
    host: &dyn brokk_bifrost_js_ts::providers::JsTsSource,
    lookup: &AnalyzerDefinitionLookup<'_>,
    file: &ProjectFile,
    prepared: &PreparedSyntaxTree,
    imports: &JsTsImportBinder,
    lexical: &JsTsLexicalBindingIndex,
    expression: Node<'_>,
) -> Result<ClassIdentity, UnknownReason> {
    if !matches!(expression.kind(), "identifier" | "type_identifier") {
        return Err(UnknownReason::UnresolvedBase);
    }
    let source = prepared.source();
    let name = slice(expression, source);
    let mut candidates = jsts_constructor_owner_candidates(
        host,
        lookup,
        file,
        language,
        source,
        imports,
        host.alias_resolver().as_ref(),
        expression,
        true,
    );
    if candidates
        .iter()
        .any(|unit| current_prepared_for(workspace, language, unit.source()).is_none())
    {
        return Err(UnknownReason::UncertainFlow);
    }
    candidates.retain(|unit| runtime_class_declaration(workspace, language, unit));
    sort_units(&mut candidates);
    candidates.dedup();
    match candidates.as_slice() {
        [unit] => {
            let Some(target_prepared) = current_prepared_for(workspace, language, unit.source())
            else {
                return Err(UnknownReason::UncertainFlow);
            };
            if exact_runtime_class_binding(
                file,
                expression,
                unit,
                lexical,
                imports,
                prepared,
                &target_prepared,
            ) {
                return Ok(ClassIdentity::Workspace(unit.clone()));
            }
            return Err(UnknownReason::UnresolvedBase);
        }
        [] => {}
        _ => return Err(UnknownReason::UnresolvedBase),
    }

    let external_name = if let Some(binding) = imports.binding(name) {
        let binding_ranges = lexical.binding_identifier_ranges_at(name, expression.start_byte());
        if imports.has_competing_static_imports(name)
            || imports.was_truncated(name)
            || binding_ranges.len() != 1
            || !active_binding_is_value_import(prepared.tree().root_node(), binding_ranges[0])
            || lexical.is_binding_reassigned_at(name, expression.start_byte())
        {
            return Err(UnknownReason::UnresolvedBase);
        }
        binding.imported_name.as_deref().unwrap_or(name)
    } else {
        if lexical.is_bound_at(name, expression.start_byte()) {
            return Err(UnknownReason::UnresolvedBase);
        }
        name
    };
    external_class(overlay_of(workspace).as_deref(), external_name)
        .ok_or(UnknownReason::UnresolvedBase)
}

fn workspace_surface_closure(
    workspace: &WorkspaceAnalyzer,
    language: Language,
    unit: &CodeUnit,
) -> WorkspaceSurfaceClosure {
    let Some(host) = resolve_js_ts_source(workspace.analyzer(), language) else {
        return WorkspaceSurfaceClosure {
            owners: Vec::new(),
            external_bases: Vec::new(),
            coverage: JsTsSurfaceCoverage::Open(UnknownReason::UncertainFlow),
        };
    };
    let lookup = AnalyzerDefinitionLookup::new(workspace.analyzer(), language);
    let mut owners = Vec::new();
    let mut external_bases = Vec::new();
    let mut seen = HashSet::default();
    let mut stack = vec![unit.clone()];
    let mut coverage = JsTsSurfaceCoverage::Closed;
    while let Some(owner) = stack.pop() {
        if !seen.insert(owner.clone()) {
            coverage.include(JsTsSurfaceCoverage::Open(UnknownReason::UnresolvedBase));
            continue;
        }
        let Some(prepared) = current_prepared_for(workspace, language, owner.source()) else {
            coverage.include(JsTsSurfaceCoverage::Open(UnknownReason::UncertainFlow));
            continue;
        };
        let Some(class) = declaration_node(&prepared, &owner) else {
            coverage.include(JsTsSurfaceCoverage::Open(UnknownReason::UncertainFlow));
            continue;
        };
        owners.push(owner.clone());
        let base = match runtime_base_expression(class) {
            Ok(base) => base,
            Err(()) => {
                coverage.include(JsTsSurfaceCoverage::Open(UnknownReason::UnresolvedBase));
                continue;
            }
        };
        let Some(base) = base else {
            continue;
        };
        let imports = compute_import_binder(prepared.source(), prepared.tree());
        let lexical =
            JsTsLexicalBindingIndex::build(prepared.tree().root_node(), prepared.source());
        match resolve_class_expression(
            workspace,
            language,
            host,
            &lookup,
            owner.source(),
            &prepared,
            &imports,
            &lexical,
            base,
        ) {
            Ok(ClassIdentity::Workspace(base)) => stack.push(base),
            Ok(base @ ClassIdentity::External { .. }) => external_bases.push(base),
            Err(reason) => coverage.include(JsTsSurfaceCoverage::Open(reason)),
        }
    }
    sort_external_classes(&mut external_bases);
    external_bases.dedup();
    WorkspaceSurfaceClosure {
        owners,
        external_bases,
        coverage,
    }
}

fn node_has_static_modifier(node: Node<'_>) -> bool {
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .any(|child| child.kind() == "static")
}

fn subtree_has_decorator(root: Node<'_>) -> bool {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "decorator" {
            return true;
        }
        if node.id() != root.id()
            && matches!(
                node.kind(),
                "class_declaration" | "abstract_class_declaration" | "class"
            )
        {
            continue;
        }
        push_named_children_reversed(node, &mut stack);
    }
    false
}

fn class_member_shape(
    prepared: &PreparedSyntaxTree,
    unit: &CodeUnit,
    member: &str,
) -> (bool, JsTsSurfaceCoverage) {
    let Some(class) = declaration_node(prepared, unit) else {
        return (
            false,
            JsTsSurfaceCoverage::Open(UnknownReason::UncertainFlow),
        );
    };
    if !syntax_is_complete(class) {
        return (false, JsTsSurfaceCoverage::Truncated);
    }
    let mut coverage = JsTsSurfaceCoverage::Closed;
    if subtree_has_decorator(class) {
        coverage.include(JsTsSurfaceCoverage::Open(UnknownReason::DynamicAttributes));
    }
    let Some(body) = class.child_by_field_name("body") else {
        return (false, JsTsSurfaceCoverage::Truncated);
    };
    let mut contains_member = false;
    let mut cursor = body.walk();
    for declaration in body.named_children(&mut cursor) {
        if node_has_static_modifier(declaration) {
            continue;
        }
        if declaration.kind() == "index_signature" {
            coverage.include(JsTsSurfaceCoverage::Open(UnknownReason::DynamicAttributes));
            continue;
        }
        if !matches!(
            declaration.kind(),
            "method_definition"
                | "method_signature"
                | "abstract_method_signature"
                | "field_definition"
                | "public_field_definition"
                | "property_signature"
        ) {
            continue;
        }
        let name = declaration
            .child_by_field_name("name")
            .or_else(|| declaration.child_by_field_name("property"));
        match name.and_then(|name| static_property_name(name, prepared.source())) {
            Some((_, name)) if name == member => contains_member = true,
            Some(_) => {}
            None => coverage.include(JsTsSurfaceCoverage::Open(UnknownReason::DynamicAttributes)),
        }
    }
    (contains_member, coverage)
}

#[allow(clippy::too_many_arguments)]
fn resolve_prototype_class(
    workspace: &WorkspaceAnalyzer,
    language: Language,
    host: &dyn brokk_bifrost_js_ts::providers::JsTsSource,
    lookup: &AnalyzerDefinitionLookup<'_>,
    file: &ProjectFile,
    prepared: &PreparedSyntaxTree,
    imports: &JsTsImportBinder,
    lexical: &JsTsLexicalBindingIndex,
    expression: Node<'_>,
) -> Option<Result<ClassIdentity, UnknownReason>> {
    let receiver = static_member_receiver(expression, prepared.source())?;
    if receiver.members.len() != 1 || slice(receiver.members[0], prepared.source()) != "prototype" {
        return None;
    }
    Some(resolve_class_expression(
        workspace,
        language,
        host,
        lookup,
        file,
        prepared,
        imports,
        lexical,
        receiver.root,
    ))
}

fn definitely_not_instance(expression: Node<'_>, source: &str) -> bool {
    let Some(receiver) = static_member_receiver(expression, source) else {
        return false;
    };
    let root = slice(receiver.root, source);
    (root == "globalThis")
        || (root == "exports" && receiver.members.is_empty())
        || (root == "module"
            && receiver.members.len() == 1
            && slice(receiver.members[0], source) == "exports")
}

fn instance_class(value: ReceiverValue) -> Option<ClassIdentity> {
    match value {
        ReceiverValue::AllocationSite { ty, .. }
        | ReceiverValue::InstanceType(ty)
        | ReceiverValue::CurrentReceiver(ty) => Some(ClassIdentity::Workspace(ty)),
        ReceiverValue::FactoryReturn { value, .. } => instance_class(*value),
        ReceiverValue::ClassOrStaticObject(_) | ReceiverValue::ModuleOrExportObject(_) => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn mutation_targets(
    workspace: &WorkspaceAnalyzer,
    language: Language,
    host: &dyn brokk_bifrost_js_ts::providers::JsTsSource,
    lookup: &AnalyzerDefinitionLookup<'_>,
    file: &ProjectFile,
    prepared: &PreparedSyntaxTree,
    imports: &JsTsImportBinder,
    lexical: &JsTsLexicalBindingIndex,
    provider: &JsTsReceiverFactProvider<'_, '_>,
    expression: Node<'_>,
) -> JsTsMutationTargets {
    if let Some(prototype) = resolve_prototype_class(
        workspace, language, host, lookup, file, prepared, imports, lexical, expression,
    ) {
        return match prototype {
            Ok(class) => JsTsMutationTargets::Exact(vec![class]),
            Err(UnknownReason::Truncated | UnknownReason::UncertainFlow) => {
                JsTsMutationTargets::Truncated
            }
            Err(_) => JsTsMutationTargets::Open,
        };
    }
    if definitely_not_instance(expression, prepared.source()) {
        return JsTsMutationTargets::NotInstance;
    }
    match provider.resolve_receiver_node(expression, ReceiverAnalysisBudget::default()) {
        ReceiverAnalysisOutcome::Precise(values) | ReceiverAnalysisOutcome::Ambiguous(values) => {
            let mut classes = values
                .into_iter()
                .filter_map(instance_class)
                .collect::<Vec<_>>();
            let mut seen = HashSet::default();
            classes.retain(|class| seen.insert(class.clone()));
            if classes.is_empty() {
                JsTsMutationTargets::NotInstance
            } else {
                JsTsMutationTargets::Exact(classes)
            }
        }
        ReceiverAnalysisOutcome::ExceededBudget { .. } => JsTsMutationTargets::Truncated,
        ReceiverAnalysisOutcome::Unknown | ReceiverAnalysisOutcome::Unsupported { .. } => {
            JsTsMutationTargets::Open
        }
    }
}

fn unshadowed_builtin_member(
    callee: Node<'_>,
    source: &str,
    lexical: &JsTsLexicalBindingIndex,
) -> Option<(String, String)> {
    let receiver = static_member_receiver(callee, source)?;
    if receiver.members.len() != 1 {
        return None;
    }
    let root = slice(receiver.root, source);
    if !matches!(root, "Object" | "Reflect" | "Proxy")
        || lexical.is_bound_at(root, callee.start_byte())
    {
        return None;
    }
    Some((
        root.to_owned(),
        slice(receiver.members[0], source).to_owned(),
    ))
}

fn call_arguments(call: Node<'_>) -> Vec<Node<'_>> {
    let Some(arguments) = call.child_by_field_name("arguments") else {
        return Vec::new();
    };
    let mut cursor = arguments.walk();
    arguments.named_children(&mut cursor).collect()
}

fn object_literal_member_names(object: Node<'_>, source: &str) -> Result<Vec<Box<str>>, ()> {
    if object.kind() != "object" {
        return Err(());
    }
    let mut names = Vec::new();
    let mut cursor = object.walk();
    for entry in object.named_children(&mut cursor) {
        let name = match entry.kind() {
            "pair" => entry.child_by_field_name("key"),
            "method_definition" => entry.child_by_field_name("name"),
            "shorthand_property_identifier" => {
                let name = slice(entry, source);
                if name.is_empty() {
                    return Err(());
                }
                names.push(Box::from(name));
                continue;
            }
            _ => return Err(()),
        };
        let Some((_, name)) = name.and_then(|name| static_property_name(name, source)) else {
            return Err(());
        };
        if name == "__proto__" {
            return Err(());
        }
        names.push(name.into_boxed_str());
    }
    Ok(names)
}

#[allow(clippy::too_many_arguments)]
fn scan_surface_call(
    summary: &mut JsTsMemberSurfaceSummary,
    workspace: &WorkspaceAnalyzer,
    language: Language,
    host: &dyn brokk_bifrost_js_ts::providers::JsTsSource,
    lookup: &AnalyzerDefinitionLookup<'_>,
    file: &ProjectFile,
    prepared: &PreparedSyntaxTree,
    imports: &JsTsImportBinder,
    lexical: &JsTsLexicalBindingIndex,
    provider: &JsTsReceiverFactProvider<'_, '_>,
    call: Node<'_>,
) {
    let Some(callee) = call
        .child_by_field_name("function")
        .or_else(|| call.child_by_field_name("constructor"))
    else {
        return;
    };
    let arguments = call_arguments(call);
    let builtin = unshadowed_builtin_member(callee, prepared.source(), lexical);
    match builtin
        .as_ref()
        .map(|(root, member)| (root.as_str(), member.as_str()))
    {
        Some(("Object", "assign")) => {
            let Some(target) = arguments.first().copied() else {
                return;
            };
            let targets = || {
                mutation_targets(
                    workspace, language, host, lookup, file, prepared, imports, lexical, provider,
                    target,
                )
            };
            for source in arguments.iter().skip(1).copied() {
                match object_literal_member_names(source, prepared.source()) {
                    Ok(names) => {
                        for name in names {
                            summary.record(targets(), Some(name));
                        }
                    }
                    Err(()) => summary.record(targets(), None),
                }
            }
        }
        Some(("Object", "defineProperty")) => {
            let Some(target) = arguments.first().copied() else {
                return;
            };
            let targets = mutation_targets(
                workspace, language, host, lookup, file, prepared, imports, lexical, provider,
                target,
            );
            let member = arguments
                .get(1)
                .and_then(|key| static_property_name(*key, prepared.source()))
                .map(|(_, name)| name.into_boxed_str());
            summary.record(targets, member);
        }
        Some(("Object", "defineProperties" | "setPrototypeOf"))
        | Some(("Reflect", "defineProperty" | "set" | "setPrototypeOf")) => {
            let Some(target) = arguments.first().copied() else {
                return;
            };
            let targets = mutation_targets(
                workspace, language, host, lookup, file, prepared, imports, lexical, provider,
                target,
            );
            summary.record(targets, None);
        }
        Some(("Proxy", "revocable")) => {
            let Some(target) = arguments.first().copied() else {
                return;
            };
            let targets = mutation_targets(
                workspace, language, host, lookup, file, prepared, imports, lexical, provider,
                target,
            );
            summary.record(targets, None);
        }
        _ => {
            let Some((_, member)) = static_member_property(callee, prepared.source()) else {
                return;
            };
            if !matches!(member.as_str(), "__defineGetter__" | "__defineSetter__") {
                return;
            }
            let Some(target) = callee.child_by_field_name("object") else {
                return;
            };
            let targets = mutation_targets(
                workspace, language, host, lookup, file, prepared, imports, lexical, provider,
                target,
            );
            let member = arguments
                .first()
                .and_then(|key| static_property_name(*key, prepared.source()))
                .map(|(_, name)| name.into_boxed_str());
            summary.record(targets, member);
        }
    }
}

fn member_surface_survey(
    workspace: &WorkspaceAnalyzer,
    language: Language,
    max_nodes: usize,
    cancellation: Option<&CancellationToken>,
) -> Option<JsTsMemberSurfaceSummary> {
    if cancellation.is_some_and(CancellationToken::is_cancelled) {
        return None;
    }
    let mut summary = JsTsMemberSurfaceSummary::default();
    let Some(host) = resolve_js_ts_source(workspace.analyzer(), language) else {
        summary
            .coverage
            .include(JsTsSurfaceCoverage::Open(UnknownReason::UncertainFlow));
        return Some(summary);
    };
    let lookup = AnalyzerDefinitionLookup::new(workspace.analyzer(), language);
    let mut files = host.all_files();
    files.sort();
    let mut remaining = max_nodes;
    for file in files {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return None;
        }
        let Some(prepared) = current_prepared_for(workspace, language, &file) else {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return None;
            }
            summary
                .coverage
                .include(JsTsSurfaceCoverage::Open(UnknownReason::UncertainFlow));
            continue;
        };
        if !syntax_is_complete(prepared.tree().root_node()) {
            summary.coverage.include(JsTsSurfaceCoverage::Truncated);
            continue;
        }
        let syntax_index = match build_js_ts_receiver_syntax_index_bounded(
            prepared.tree().root_node(),
            prepared.source(),
            cancellation,
            remaining,
        ) {
            JsTsReceiverSyntaxIndexBuild::Complete { index, visited } => {
                remaining = remaining.saturating_sub(visited);
                index
            }
            JsTsReceiverSyntaxIndexBuild::ExceededScope { .. } => {
                summary.coverage.include(JsTsSurfaceCoverage::Truncated);
                break;
            }
            JsTsReceiverSyntaxIndexBuild::Cancelled => return None,
        };
        let imports = compute_import_binder(prepared.source(), prepared.tree());
        let lexical =
            JsTsLexicalBindingIndex::build(prepared.tree().root_node(), prepared.source());
        let provider = JsTsReceiverFactProvider::new_with_syntax_index(
            host,
            &lookup,
            language,
            &file,
            prepared.source(),
            prepared.tree().root_node(),
            imports.clone(),
            syntax_index,
        );
        let mut stack = vec![prepared.tree().root_node()];
        while let Some(node) = stack.pop() {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return None;
            }
            if node.kind() == "assignment_expression"
                && let Some(left) = node.child_by_field_name("left")
                && matches!(left.kind(), "member_expression" | "subscript_expression")
            {
                if let Some(prototype) = resolve_prototype_class(
                    workspace, language, host, &lookup, &file, &prepared, &imports, &lexical, left,
                ) {
                    let targets = match prototype {
                        Ok(class) => JsTsMutationTargets::Exact(vec![class]),
                        Err(UnknownReason::Truncated | UnknownReason::UncertainFlow) => {
                            JsTsMutationTargets::Truncated
                        }
                        Err(_) => JsTsMutationTargets::Open,
                    };
                    summary.record(targets, None);
                } else if let Some(object) = left.child_by_field_name("object") {
                    let targets = mutation_targets(
                        workspace, language, host, &lookup, &file, &prepared, &imports, &lexical,
                        &provider, object,
                    );
                    let member = static_member_property(left, prepared.source())
                        .map(|(_, name)| name.into_boxed_str())
                        // An ordinary assignment to the legacy accessor can
                        // replace the receiver's prototype and expose any
                        // member supplied by that object.
                        .filter(|name| name.as_ref() != "__proto__");
                    summary.record(targets, member);
                }
            } else if node.kind() == "call_expression" {
                scan_surface_call(
                    &mut summary,
                    workspace,
                    language,
                    host,
                    &lookup,
                    &file,
                    &prepared,
                    &imports,
                    &lexical,
                    &provider,
                    node,
                );
            } else if node.kind() == "new_expression"
                && let Some(constructor) = node
                    .child_by_field_name("constructor")
                    .or_else(|| node.child_by_field_name("function"))
                && constructor.kind() == "identifier"
                && slice(constructor, prepared.source()) == "Proxy"
                && !lexical.is_bound_at("Proxy", constructor.start_byte())
                && let Some(target) = call_arguments(node).first().copied()
            {
                let targets = mutation_targets(
                    workspace, language, host, &lookup, &file, &prepared, &imports, &lexical,
                    &provider, target,
                );
                summary.record(targets, None);
            }
            push_named_children_reversed(node, &mut stack);
        }
    }
    Some(summary)
}

struct JsTsMemberSurfaceRequest {
    memo: Arc<JsTsMemberSurfaceRequestMemo>,
    key: JsTsMemberSurfaceMemoKey,
    cancellation: Option<CancellationToken>,
    semantic_snapshot: Option<Arc<crate::analyzer::semantic_model::ActiveSemanticModelSnapshot>>,
}

fn member_surface_request(
    workspace: &WorkspaceAnalyzer,
    language: Language,
    max_nodes: usize,
) -> Option<JsTsMemberSurfaceRequest> {
    let semantic_snapshot = workspace.analyzer().active_semantic_model_snapshot();
    let semantic_overlay = semantic_snapshot
        .as_ref()
        .and_then(|snapshot| snapshot.semantic_model_overlay())
        .map(|overlay| Box::<str>::from(overlay.active_model_set_hash()));
    let project_generation = workspace.analyzer().project().analysis_generation();
    let (memo, language_content, cancellation) = match language {
        Language::JavaScript => {
            let analyzer = resolve_analyzer::<JavascriptAnalyzer>(workspace.analyzer())?;
            let inner = analyzer.inner();
            (
                inner.active_query_request_memo::<JsTsMemberSurfaceRequestMemo>()?,
                inner.language_content_identity(),
                inner.active_query_cancellation(),
            )
        }
        Language::TypeScript => {
            let analyzer = resolve_analyzer::<TypescriptAnalyzer>(workspace.analyzer())?;
            let inner = analyzer.inner();
            (
                inner.active_query_request_memo::<JsTsMemberSurfaceRequestMemo>()?,
                inner.language_content_identity(),
                inner.active_query_cancellation(),
            )
        }
        _ => unreachable!("the JS/TS adapter receives only JavaScript or TypeScript"),
    };
    Some(JsTsMemberSurfaceRequest {
        memo,
        key: JsTsMemberSurfaceMemoKey {
            language,
            language_content,
            project_generation,
            semantic_overlay,
            max_nodes,
        },
        cancellation,
        semantic_snapshot,
    })
}

fn truncated_member_surface_summary() -> Arc<JsTsMemberSurfaceSummary> {
    Arc::new(JsTsMemberSurfaceSummary {
        coverage: JsTsSurfaceCoverage::Truncated,
        ..JsTsMemberSurfaceSummary::default()
    })
}

fn member_surface_summary(
    workspace: &WorkspaceAnalyzer,
    language: Language,
    max_nodes: usize,
) -> Arc<JsTsMemberSurfaceSummary> {
    let Some(request) = member_surface_request(workspace, language, max_nodes) else {
        return member_surface_survey(workspace, language, max_nodes, None)
            .map(Arc::new)
            .unwrap_or_else(truncated_member_surface_summary);
    };
    let cell = request.memo.cell(&request.key);
    let wait_cancellation = request.cancellation.clone();
    let build_cancellation = request.cancellation;
    let semantic_snapshot = request.semantic_snapshot;
    let memo = Arc::clone(&request.memo);
    let keep_going = || {
        wait_cancellation
            .as_ref()
            .is_none_or(|token| !token.is_cancelled())
    };
    let summary = cell.get_or_build_on_dedicated_pool_while(&keep_going, move || {
        let _semantic_scope = AnalyzerQueryScope::with_active_semantic_model_snapshot(
            workspace.analyzer(),
            semantic_snapshot,
        );
        let _cancellation_scope = build_cancellation
            .as_ref()
            .map(|token| AnalyzerQueryScope::with_cancellation(workspace.analyzer(), token));
        memo.record_survey();
        member_surface_survey(workspace, language, max_nodes, build_cancellation.as_ref())
    });
    summary.unwrap_or_else(|| {
        workspace
            .analyzer()
            .record_query_incomplete(QueryReadIncomplete::Cancelled);
        truncated_member_surface_summary()
    })
}

fn workspace_member_lookup(
    workspace: &WorkspaceAnalyzer,
    language: Language,
    kind: MemberAccessKind,
    unit: &CodeUnit,
    member: &str,
    max_nodes: usize,
) -> MemberLookup {
    let closure = workspace_surface_closure(workspace, language, unit);
    let mut contains_member = false;
    let mut coverage = closure.coverage;
    for owner in &closure.owners {
        let Some(prepared) = current_prepared_for(workspace, language, owner.source()) else {
            coverage.include(JsTsSurfaceCoverage::Open(UnknownReason::UncertainFlow));
            continue;
        };
        let mut matches = prepared
            .direct_children(owner)
            .iter()
            .filter(|child| {
                workspace_instance_method(&prepared, child)
                    && workspace_instance_member_name(&prepared, child).as_deref() == Some(member)
            })
            .cloned()
            .collect::<Vec<_>>();
        if !matches.is_empty() {
            sort_units(&mut matches);
            return present(MemberDeclaration::Workspace(matches.remove(0)));
        }
        let (owner_contains_member, owner_coverage) = class_member_shape(&prepared, owner, member);
        contains_member |= owner_contains_member
            || prepared.direct_children(owner).iter().any(|child| {
                workspace_instance_member_name(&prepared, child).as_deref() == Some(member)
            });
        coverage.include(owner_coverage);
    }
    let overlay = overlay_of(workspace);
    let mut external_reason = None;
    for base in &closure.external_bases {
        let ClassIdentity::External { symbol_id, .. } = base else {
            unreachable!("external base identities are exact model symbols")
        };
        let Some(overlay) = overlay.as_deref() else {
            external_reason = Some(UnknownReason::UnresolvedBase);
            continue;
        };
        match external_member_lookup(overlay, symbol_id, kind, member) {
            present @ MemberLookup::Present(_) => return present,
            MemberLookup::Absent => {}
            MemberLookup::Unknown(reason) => external_reason = Some(reason),
            MemberLookup::DeclarationAbsent => {
                unreachable!("external model surfaces are complete, absent, or unknown")
            }
        }
    }
    let survey = member_surface_summary(workspace, language, max_nodes);
    let mut classes = closure
        .owners
        .iter()
        .cloned()
        .map(ClassIdentity::Workspace)
        .collect::<Vec<_>>();
    classes.extend(closure.external_bases);
    if contains_member {
        return MemberLookup::Unknown(UnknownReason::DynamicAttributes);
    }
    if let Some(reason) = survey.reason_for(&classes, member) {
        return MemberLookup::Unknown(reason);
    }
    if let Some(reason) = coverage.reason().or(external_reason) {
        return MemberLookup::Unknown(reason);
    }
    MemberLookup::Absent
}

fn member_lookup_with_surface_limit(
    workspace: &WorkspaceAnalyzer,
    language: Language,
    kind: MemberAccessKind,
    class: &ClassIdentity,
    member: &str,
    max_nodes: usize,
) -> MemberLookup {
    match class {
        ClassIdentity::Workspace(unit) => {
            workspace_member_lookup(workspace, language, kind, unit, member, max_nodes)
        }
        ClassIdentity::External { symbol_id, .. } => {
            let Some(overlay) = overlay_of(workspace) else {
                return MemberLookup::Unknown(UnknownReason::ExternalNotModeled);
            };
            let modeled = external_member_lookup(&overlay, symbol_id, kind, member);
            if matches!(modeled, MemberLookup::Present(_)) {
                return modeled;
            }
            let survey = member_surface_summary(workspace, language, max_nodes);
            if let Some(reason) = survey.reason_for(std::slice::from_ref(class), member) {
                return MemberLookup::Unknown(reason);
            }
            modeled
        }
    }
}

fn member_lookup(
    workspace: &WorkspaceAnalyzer,
    language: Language,
    kind: MemberAccessKind,
    class: &ClassIdentity,
    member: &str,
) -> MemberLookup {
    member_lookup_with_surface_limit(
        workspace,
        language,
        kind,
        class,
        member,
        MAX_JS_TS_MEMBER_SURFACE_NODES,
    )
}

fn class_hierarchy(
    workspace: &WorkspaceAnalyzer,
    language: Language,
    class: &ClassIdentity,
) -> ClassHierarchy {
    let ClassIdentity::Workspace(unit) = class else {
        return ClassHierarchy::unknown();
    };
    let closure = workspace_surface_closure(workspace, language, unit);
    let unresolved_base = closure.coverage.reason().is_some_and(|reason| {
        matches!(
            reason,
            UnknownReason::UnresolvedBase | UnknownReason::UncertainFlow
        )
    });
    ClassHierarchy {
        ancestors: closure
            .owners
            .into_iter()
            .skip(1)
            .map(ClassIdentity::Workspace)
            .chain(closure.external_bases)
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
                kind: MemberAccessKind,
                class: &ClassIdentity,
                member: &str,
            ) -> MemberLookup {
                member_lookup(workspace, $language, kind, class, member)
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
    b"javascript-type-flow-closed-surface-v3"
);
impl_js_ts_type_flow_adapter!(
    TypescriptSupport,
    Language::TypeScript,
    "typescript-type-flow",
    b"typescript-type-flow-closed-surface-v3"
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::semantic::{CancellationToken, SemanticBudget, SemanticRequest};
    use crate::analyzer::{AnalyzerConfig, OverlayProject, Project};
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
    fn literal_computed_members_are_named_while_proto_setters_stay_open() {
        let source = "receiver['run'](); receiver.run(); ({ __proto__: null });";
        let tree = parse_javascript(source);
        let subscript = first_kind(tree.root_node(), "subscript_expression");
        let computed_fragment = first_kind(subscript, "string_fragment");
        let member = first_kind(tree.root_node(), "member_expression");
        let object = first_kind(tree.root_node(), "object");

        assert_eq!(
            member_name_at_node(subscript, source).as_deref(),
            Some("run")
        );
        assert_eq!(
            member_name_at_node(computed_fragment, source).as_deref(),
            Some("run")
        );
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

            let MemberLookup::Present(hit) = member_lookup(
                &workspace,
                language,
                MemberAccessKind::Call,
                &child_identity,
                "inherited",
            ) else {
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
    fn exhausted_member_surface_survey_is_typed_as_truncated() {
        for (language, path) in [
            (Language::JavaScript, "app.js"),
            (Language::TypeScript, "app.ts"),
        ] {
            let project = InlineTestProject::with_language(language)
                .file(path, "class Closed {}\n")
                .build();
            let workspace = project.workspace_analyzer(AnalyzerConfig::default());
            let _scope = AnalyzerQueryScope::new(workspace.analyzer());
            let class = workspace
                .analyzer()
                .get_definitions("Closed")
                .into_iter()
                .find(CodeUnit::is_class)
                .map(ClassIdentity::Workspace)
                .expect("fixture has one Closed class");
            assert_eq!(
                member_lookup_with_surface_limit(
                    &workspace,
                    language,
                    MemberAccessKind::Call,
                    &class,
                    "nope",
                    0,
                ),
                MemberLookup::Unknown(UnknownReason::Truncated)
            );
        }
    }

    #[test]
    fn member_surface_survey_runs_once_per_request_and_resurveys_after_overlay_edit() {
        const CLOSED: &str = "class Surface {}\n";
        const OPEN: &str = "class Surface { [globalThis.key]() {} }\n";

        for (language, path) in [
            (Language::JavaScript, "app.js"),
            (Language::TypeScript, "app.ts"),
        ] {
            let project = InlineTestProject::with_language(language)
                .file(path, CLOSED)
                .build();
            let disk_workspace = project.workspace_analyzer(AnalyzerConfig::default());
            let live = Arc::new(OverlayProject::new(project.project_dyn()));
            let live_project: Arc<dyn Project> = live.clone();
            let workspace = disk_workspace.clone_with_project(live_project);
            let class = workspace
                .analyzer()
                .get_definitions("Surface")
                .into_iter()
                .find(CodeUnit::is_class)
                .map(ClassIdentity::Workspace)
                .expect("fixture has one Surface class");

            let first_scope = AnalyzerQueryScope::new(workspace.analyzer());
            let first_request =
                member_surface_request(&workspace, language, MAX_JS_TS_MEMBER_SURFACE_NODES)
                    .expect("an explicit query scope owns the JS/TS surface memo");
            let first = member_lookup(&workspace, language, MemberAccessKind::Call, &class, "nope");
            let repeated =
                member_lookup(&workspace, language, MemberAccessKind::Call, &class, "nope");
            assert_eq!(first, MemberLookup::Absent);
            assert_eq!(repeated, first);
            assert_eq!(first_request.memo.survey_count(), 1);
            drop(first_scope);

            assert!(live.set(project.file(path).abs_path(), OPEN.to_owned()));
            let second_scope = AnalyzerQueryScope::new(workspace.analyzer());
            let second_request =
                member_surface_request(&workspace, language, MAX_JS_TS_MEMBER_SURFACE_NODES)
                    .expect("the new query scope owns a fresh JS/TS surface memo");
            assert_ne!(
                second_request.key.language_content, first_request.key.language_content,
                "an overlay edit must rotate prepared-syntax identity"
            );
            assert!(!Arc::ptr_eq(&first_request.memo, &second_request.memo));
            assert_eq!(
                member_lookup(&workspace, language, MemberAccessKind::Call, &class, "nope",),
                MemberLookup::Unknown(UnknownReason::UncertainFlow)
            );
            assert_eq!(second_request.memo.survey_count(), 1);
            drop(second_scope);
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
