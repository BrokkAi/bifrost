//! Python class-set adapter: the per-language seeds and member lookup the
//! type-flow engine cannot derive from the language-neutral semantic IR.
//!
//! Every answer comes from structured sources: the semantic IR's exact source
//! mappings, the analyzer's prepared tree-sitter syntax, `resolve_type_batch`
//! for callee and annotation resolution, the declaration index for class
//! members, and the active semantic-model overlay for external classes. No
//! source text is parsed or scanned here; reading a node's text at an
//! AST-provided span is structured access.

use std::path::Path;
use std::sync::Arc;

use brokk_bifrost_core::analyzer::prepared_syntax::PreparedSyntaxTree;
use brokk_bifrost_python::syntax::python_plain_string_literal;
use tree_sitter::Node;

use super::PythonAnalyzer;
use crate::analyzer::lexical_definitions::{PythonMethodBinding, formal_parameter_slots_for_owner};
use crate::analyzer::semantic::type_flow::{
    ClassHierarchy, ClassIdentity, ClassSeed, DynamicFieldWrite, GuardArmSide, MemberAccessQuery,
    MemberLookup, NarrowingVerdict, TypeFlowAdapter, UnknownReason,
};
use crate::analyzer::semantic::{
    AllocationSite, GuardFact, GuardPredicate, MemoryLocationKind, ProcedureHandle, ProcedureKind,
    SemanticCallSite, SemanticLocator, SemanticValue, SourceMappingKind, SourcePosition,
    SourceSpan, ValueId,
};
use crate::analyzer::semantic_model::{
    SemanticModelMemberTargetDisposition, SemanticModelOverlay, SemanticModelOverlayDisposition,
    SemanticModelSymbolKind,
};
use crate::analyzer::usages::get_type::{
    TypeLookupRequest, TypeLookupStatus, TypeLookupType, resolve_type_batch,
};
use crate::analyzer::{
    AnalyzerQueryScope, CodeUnit, CodeUnitIndex, Language, ProjectFile, QueryScope,
    TypeHierarchyProvider, WorkspaceAnalyzer, resolve_analyzer,
};
use crate::hash::{HashMap, HashSet};

/// The Python [`TypeFlowAdapter`]. Zero-sized: every method receives the
/// workspace it consults.
pub struct PythonTypeFlowAdapter;

/// One name-resolution cache, local to a single adapter call.
type ExternalClassCache = HashMap<Box<str>, Option<ClassIdentity>>;

fn python_analyzer(workspace: &WorkspaceAnalyzer) -> &PythonAnalyzer {
    resolve_analyzer::<PythonAnalyzer>(workspace.analyzer())
        .expect("PythonTypeFlowAdapter serves only workspaces that analyze Python")
}

fn overlay_of(workspace: &WorkspaceAnalyzer) -> Option<Arc<SemanticModelOverlay>> {
    workspace
        .analyzer()
        .active_semantic_model_snapshot()
        .and_then(|snapshot| snapshot.semantic_model_overlay().cloned())
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

fn prepared_for(python: &PythonAnalyzer, file: &ProjectFile) -> Arc<PreparedSyntaxTree> {
    let scope = AnalyzerQueryScope::new(python);
    python
        .inner
        .prepared_syntax(scope.token(), file)
        .expect("a materialized procedure's file has prepared syntax")
}

fn node_at_span(prepared: &PreparedSyntaxTree, span: SourceSpan) -> Option<Node<'_>> {
    prepared
        .tree()
        .root_node()
        .named_descendant_for_byte_range(span.start_byte() as usize, span.end_byte() as usize)
}

fn node_text_at(prepared: &PreparedSyntaxTree, span: SourceSpan) -> Option<Box<str>> {
    let node = node_at_span(prepared, span)?;
    node.utf8_text(prepared.source().as_bytes())
        .ok()
        .map(Box::from)
}

fn span_for_node(node: Node<'_>) -> SourceSpan {
    SourceSpan::new(
        SourcePosition::new(
            node.start_byte() as u32,
            node.start_position().row as u32,
            node.start_position().column as u32,
        ),
        SourcePosition::new(
            node.end_byte() as u32,
            node.end_position().row as u32,
            node.end_position().column as u32,
        ),
    )
    .expect("a tree-sitter node range is a valid source span")
}

fn range_for_span(span: SourceSpan) -> crate::analyzer::Range {
    crate::analyzer::Range {
        start_byte: span.start_byte() as usize,
        end_byte: span.end_byte() as usize,
        start_line: span.start().line() as usize,
        end_line: span.end().line() as usize,
    }
}

fn enclosing_workspace_class(
    workspace: &WorkspaceAnalyzer,
    procedure: &ProcedureHandle,
) -> Option<CodeUnit> {
    let locator = procedure.semantics().locator();
    let file = file_for_locator(workspace, locator)?;
    let mut unit = workspace
        .analyzer()
        .enclosing_code_unit(&file, &range_for_span(locator.anchor().span()))?;
    loop {
        if unit.is_class() {
            return Some(unit);
        }
        unit = workspace.analyzer().parent_of(&unit)?;
    }
}

fn class_node_for_unit<'tree>(
    python: &PythonAnalyzer,
    prepared: &'tree PreparedSyntaxTree,
    unit: &CodeUnit,
) -> Option<Node<'tree>> {
    python.ranges(unit).into_iter().find_map(|range| {
        let node = prepared
            .tree()
            .root_node()
            .named_descendant_for_byte_range(range.start_byte, range.end_byte)?;
        match node.kind() {
            "class_definition" => Some(node),
            "decorated_definition" => node
                .named_child(0)
                .filter(|definition| definition.kind() == "class_definition"),
            _ => node
                .parent()
                .filter(|parent| parent.kind() == "class_definition"),
        }
    })
}

fn definition_name<'source>(node: Node<'_>, source: &'source str) -> Option<&'source str> {
    let definition = if node.kind() == "decorated_definition" {
        let mut cursor = node.walk();
        node.named_children(&mut cursor)
            .find(|child| child.kind() == "function_definition")?
    } else {
        node
    };
    definition
        .child_by_field_name("name")?
        .utf8_text(source.as_bytes())
        .ok()
}

fn assignment_name<'source>(node: Node<'_>, source: &'source str) -> Option<&'source str> {
    let node = if node.kind() == "expression_statement" {
        node.named_child(0)?
    } else {
        node
    };
    if !matches!(node.kind(), "assignment" | "augmented_assignment") {
        return None;
    }
    let left = node.child_by_field_name("left")?;
    (left.kind() == "identifier")
        .then(|| left.utf8_text(source.as_bytes()).ok())
        .flatten()
}

fn setattr_write(node: Node<'_>, source: &str) -> Option<DynamicFieldWrite> {
    let function = node.child_by_field_name("function")?;
    if function.kind() != "identifier" || function.utf8_text(source.as_bytes()).ok()? != "setattr" {
        return None;
    }
    let arguments = node.child_by_field_name("arguments")?;
    let mut cursor = arguments.walk();
    let actuals = arguments.named_children(&mut cursor).collect::<Vec<_>>();
    let Some(name) = actuals.get(1) else {
        return Some(DynamicFieldWrite::Any);
    };
    Some(
        python_plain_string_literal(*name, source)
            .map(|name| DynamicFieldWrite::Member(name.into()))
            .unwrap_or(DynamicFieldWrite::Any),
    )
}

fn dictionary_write(node: Node<'_>, source: &str) -> Option<DynamicFieldWrite> {
    let left = node.child_by_field_name("left")?;
    if left.kind() != "subscript" {
        return None;
    }
    let value = left.child_by_field_name("value")?;
    if value.kind() != "attribute" {
        return None;
    }
    let attribute = value.child_by_field_name("attribute")?;
    if attribute.utf8_text(source.as_bytes()).ok()? != "__dict__" {
        return None;
    }
    let subscript = left.child_by_field_name("subscript")?;
    Some(
        python_plain_string_literal(subscript, source)
            .map(|name| DynamicFieldWrite::Member(name.into()))
            .unwrap_or(DynamicFieldWrite::Any),
    )
}

/// The overlay's unique class symbol for `name`, when exactly one active pack
/// record publishes it as a class.
fn external_class(
    overlay: Option<&SemanticModelOverlay>,
    name: &str,
    cache: &mut ExternalClassCache,
) -> Option<ClassIdentity> {
    if let Some(cached) = cache.get(name) {
        return cached.clone();
    }
    let resolved = overlay.and_then(|overlay| {
        let matches = overlay.symbols_named(name);
        if matches.disposition != SemanticModelOverlayDisposition::Unique {
            return None;
        }
        let [symbol] = matches.records.as_slice() else {
            return None;
        };
        (symbol.kind == SemanticModelSymbolKind::Class).then(|| ClassIdentity::External {
            qualified_name: name.into(),
            symbol_id: symbol.id.clone().into_boxed_str(),
        })
    });
    cache.insert(name.into(), resolved.clone());
    resolved
}

fn external_seed(
    overlay: Option<&SemanticModelOverlay>,
    name: &str,
    cache: &mut ExternalClassCache,
) -> ClassSeed {
    match external_class(overlay, name, cache) {
        Some(identity) => ClassSeed::Class(identity),
        None => ClassSeed::Unknown(UnknownReason::ExternalNotModeled),
    }
}

/// Interpret one type lookup as a class seed: exactly one type whose single
/// definition is a class is a workspace class; a definition-free type the
/// overlay knows as a unique class is an external class. Functions and
/// unresolved names are not classes; competing answers are ambiguous.
fn class_seed_from_types(
    overlay: Option<&SemanticModelOverlay>,
    types: &[TypeLookupType],
) -> ClassSeed {
    let [lookup] = types else {
        return if types.is_empty() {
            ClassSeed::NotApplicable
        } else {
            ClassSeed::Unknown(UnknownReason::AmbiguousCallee)
        };
    };
    match lookup.definitions.as_slice() {
        [definition] if definition.is_class() => {
            ClassSeed::Class(ClassIdentity::Workspace(definition.clone()))
        }
        [_not_a_class] => ClassSeed::NotApplicable,
        [] => {
            let mut cache = ExternalClassCache::default();
            external_class(overlay, &lookup.fqn, &mut cache)
                .map(ClassSeed::Class)
                .unwrap_or(ClassSeed::NotApplicable)
        }
        _ => ClassSeed::Unknown(UnknownReason::AmbiguousCallee),
    }
}

/// Resolve the expression at `span` in `file` and interpret it as a class seed.
fn resolve_class_at_span(
    workspace: &WorkspaceAnalyzer,
    file: ProjectFile,
    span: SourceSpan,
) -> ClassSeed {
    let mut outcomes = resolve_type_batch(
        workspace.analyzer(),
        vec![TypeLookupRequest {
            file,
            source: None,
            line: None,
            column: None,
            start_byte: Some(span.start_byte() as usize),
            end_byte: Some(span.end_byte() as usize),
        }],
    );
    let outcome = outcomes.pop().expect("one request produces one outcome");
    match outcome.status {
        // The interactive receiver-resolution budget bounds analyzer-side
        // semantic work (scope and definition walks), not the dataflow
        // solver, so its exhaustion is a semantic-budget fact.
        TypeLookupStatus::ExceededBudget(_) => {
            return ClassSeed::Unknown(UnknownReason::SemanticBudget);
        }
        TypeLookupStatus::Ambiguous => {
            return ClassSeed::Unknown(UnknownReason::AmbiguousCallee);
        }
        TypeLookupStatus::Resolved
        | TypeLookupStatus::NoType
        | TypeLookupStatus::UnsupportedLanguage
        | TypeLookupStatus::InvalidLocation
        | TypeLookupStatus::NotFound => {}
    }
    class_seed_from_types(overlay_of(workspace).as_deref(), &outcome.types)
}

impl PythonTypeFlowAdapter {
    fn guard_value_node<'tree>(
        &self,
        procedure: &ProcedureHandle,
        value: ValueId,
        prepared: &'tree PreparedSyntaxTree,
    ) -> Option<Node<'tree>> {
        let value = procedure.semantics().value(value)?;
        let mapping = procedure.semantics().source_mapping(value.source)?;
        if mapping.kind != SourceMappingKind::Exact {
            return None;
        }
        node_at_span(prepared, mapping.locator.anchor().span())
    }

    fn guard_classes(
        &self,
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
        value: ValueId,
    ) -> Option<Vec<ClassIdentity>> {
        let semantic_value = procedure.semantics().value(value)?;
        let mapping = procedure
            .semantics()
            .source_mapping(semantic_value.source)?;
        if mapping.kind != SourceMappingKind::Exact {
            return None;
        }
        let file = file_for_locator(workspace, &mapping.locator)?;
        let prepared = prepared_for(python_analyzer(workspace), &file);
        let node = self.guard_value_node(procedure, value, &prepared)?;
        let nodes = if node.kind() == "tuple" {
            let mut cursor = node.walk();
            node.named_children(&mut cursor).collect::<Vec<_>>()
        } else {
            vec![node]
        };
        if nodes.is_empty() {
            return None;
        }
        nodes
            .into_iter()
            .map(|class| {
                let span = span_for_node(class);
                match resolve_class_at_span(workspace, file.clone(), span) {
                    ClassSeed::Class(class) => Some(class),
                    ClassSeed::Unknown(_) | ClassSeed::NotApplicable => None,
                }
            })
            .collect()
    }

    fn instance_relation(
        &self,
        workspace: &WorkspaceAnalyzer,
        atom: &ClassIdentity,
        expected: &[ClassIdentity],
    ) -> Option<bool> {
        let hierarchy = self.class_hierarchy(workspace, atom);
        if expected
            .iter()
            .any(|class| class == atom || hierarchy.ancestors.contains(class))
        {
            return Some(true);
        }
        (!hierarchy.unresolved_base).then_some(false)
    }

    fn workspace_member_lookup(
        &self,
        workspace: &WorkspaceAnalyzer,
        python: &PythonAnalyzer,
        unit: &CodeUnit,
        member: &str,
    ) -> MemberLookup {
        let ancestors = python.get_ancestors(unit);
        // A dynamic-attribute hook anywhere on the hierarchy means no static
        // member list is complete.
        for owner in std::iter::once(unit).chain(ancestors.iter()) {
            if python
                .direct_children(owner)
                .iter()
                .any(|child| matches!(child.terminal_name(), "__getattr__" | "__getattribute__"))
            {
                return MemberLookup::Unknown(UnknownReason::DynamicAttributes);
            }
        }
        // A raw base the hierarchy resolver did not enter must be answered by
        // the pack overlay or the member list is not known to be complete.
        let overlay = overlay_of(workspace);
        let mut cache = ExternalClassCache::default();
        let direct = python.get_direct_ancestors(unit);
        let mut external_bases = Vec::new();
        for raw in python.inner.raw_supertypes_of(unit) {
            let resolved = direct
                .iter()
                .any(|ancestor| ancestor.terminal_name() == raw || ancestor.fq_name_str() == raw);
            if resolved {
                continue;
            }
            match external_class(overlay.as_deref(), &raw, &mut cache) {
                Some(identity) => external_bases.push(identity),
                None => return MemberLookup::Unknown(UnknownReason::UnresolvedBase),
            }
        }
        for owner in std::iter::once(unit).chain(ancestors.iter()) {
            if python
                .direct_children(owner)
                .iter()
                .any(|child| child.terminal_name() == member)
            {
                return MemberLookup::Present;
            }
        }
        for base in &external_bases {
            let ClassIdentity::External { symbol_id, .. } = base else {
                unreachable!("external_bases holds only external identities")
            };
            let Some(overlay) = overlay.as_deref() else {
                unreachable!("an external base resolved only through the overlay")
            };
            match overlay
                .member_target_on_owner(symbol_id, member)
                .disposition
            {
                SemanticModelMemberTargetDisposition::Unique => return MemberLookup::Present,
                SemanticModelMemberTargetDisposition::Conflict
                    if overlay.member_present_on_owner(symbol_id, member) =>
                {
                    return MemberLookup::Present;
                }
                SemanticModelMemberTargetDisposition::Incomplete
                | SemanticModelMemberTargetDisposition::Conflict => {
                    return MemberLookup::Unknown(UnknownReason::PackIncomplete);
                }
                SemanticModelMemberTargetDisposition::Absent => {}
            }
        }
        MemberLookup::Absent
    }
}

impl TypeFlowAdapter for PythonTypeFlowAdapter {
    fn language(&self) -> Language {
        Language::Python
    }

    fn constructed_class(
        &self,
        workspace: &WorkspaceAnalyzer,
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
        resolve_class_at_span(workspace, file, mapping.locator.anchor().span())
    }

    fn constant_class(
        &self,
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
        value: &SemanticValue,
    ) -> ClassSeed {
        let python = python_analyzer(workspace);
        let semantics = procedure.semantics();
        let mapping = semantics
            .source_mapping(value.source)
            .expect("a constant value retains a source mapping");
        if mapping.kind != SourceMappingKind::Exact {
            return ClassSeed::NotApplicable;
        }
        let Some(file) = file_for_locator(workspace, &mapping.locator) else {
            return ClassSeed::NotApplicable;
        };
        let prepared = prepared_for(python, &file);
        let Some(node) = node_at_span(&prepared, mapping.locator.anchor().span()) else {
            return ClassSeed::NotApplicable;
        };
        let name = match node.kind() {
            "integer" => "builtins.int",
            "float" => "builtins.float",
            "string" | "concatenated_string" => "builtins.str",
            "true" | "false" => "builtins.bool",
            "none" => "types.NoneType",
            _ => return ClassSeed::NotApplicable,
        };
        let mut cache = ExternalClassCache::default();
        external_seed(overlay_of(workspace).as_deref(), name, &mut cache)
    }

    fn allocation_class(
        &self,
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
        allocation: &AllocationSite,
    ) -> ClassSeed {
        let python = python_analyzer(workspace);
        let semantics = procedure.semantics();
        // An allocation that shares its result with a call site is the
        // same-file `A()` shape; `constructed_class` answers for the call.
        let shared_with_call = semantics.call_sites().iter().any(|call| {
            call.result == Some(allocation.result)
                || call.normal_results.contains(&allocation.result)
        });
        if shared_with_call {
            return ClassSeed::NotApplicable;
        }
        let mapping = semantics
            .source_mapping(allocation.source)
            .expect("an allocation retains a source mapping");
        let Some(file) = file_for_locator(workspace, &mapping.locator) else {
            return ClassSeed::NotApplicable;
        };
        let prepared = prepared_for(python, &file);
        let Some(node) = node_at_span(&prepared, mapping.locator.anchor().span()) else {
            return ClassSeed::NotApplicable;
        };
        let name = match node.kind() {
            "list" | "list_comprehension" => "builtins.list",
            "dictionary" | "dictionary_comprehension" => "builtins.dict",
            "set" | "set_comprehension" => "builtins.set",
            "tuple" => "builtins.tuple",
            "generator_expression" => "typing.Generator",
            _ => return ClassSeed::NotApplicable,
        };
        let mut cache = ExternalClassCache::default();
        external_seed(overlay_of(workspace).as_deref(), name, &mut cache)
    }

    fn declared_parameter_class(
        &self,
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
        ordinal: u32,
    ) -> ClassSeed {
        let python = python_analyzer(workspace);
        let semantics = procedure.semantics();
        let Some(file) = file_for_locator(workspace, semantics.locator()) else {
            return ClassSeed::NotApplicable;
        };
        let prepared = prepared_for(python, &file);
        let Some(callable) = node_at_span(&prepared, semantics.locator().anchor().span()) else {
            return ClassSeed::NotApplicable;
        };
        let Some(layout) =
            formal_parameter_slots_for_owner(Language::Python, callable, prepared.source())
        else {
            return ClassSeed::NotApplicable;
        };
        // The lowering mints the receiver as a `Receiver` value and numbers
        // only the remaining slots, so a method's or constructor's parameter
        // ordinal N names slot N + 1.
        let first_slot_is_receiver =
            matches!(
                semantics.kind(),
                ProcedureKind::Method | ProcedureKind::Constructor
            ) && !matches!(layout.python_binding, Some(PythonMethodBinding::Static));
        let index = ordinal as usize + usize::from(first_slot_is_receiver);
        let Some(slot) = layout.slots.get(index) else {
            return ClassSeed::NotApplicable;
        };
        let declaration = callable
            .named_descendant_for_byte_range(
                slot.declaration_range.start_byte,
                slot.declaration_range.end_byte,
            )
            .unwrap_or(callable);
        let type_node = match declaration.kind() {
            "typed_parameter" | "typed_default_parameter" => {
                declaration.child_by_field_name("type")
            }
            _ => None,
        };
        // The grammar wraps the annotation in a `type` node; the expression
        // inside must be a bare or dotted name. Optional, unions, subscripts,
        // and quoted annotations declare no single class.
        let Some(type_node) = type_node else {
            return ClassSeed::NotApplicable;
        };
        let annotation = if type_node.kind() == "type" {
            let Some(inner) = type_node.named_child(0) else {
                return ClassSeed::NotApplicable;
            };
            inner
        } else {
            type_node
        };
        if !matches!(annotation.kind(), "identifier" | "attribute") {
            return ClassSeed::NotApplicable;
        }
        resolve_class_at_span(
            workspace,
            file,
            SourceSpan::new(
                crate::analyzer::semantic::SourcePosition::new(
                    annotation.start_byte() as u32,
                    annotation.start_position().row as u32,
                    annotation.start_position().column as u32,
                ),
                crate::analyzer::semantic::SourcePosition::new(
                    annotation.end_byte() as u32,
                    annotation.end_position().row as u32,
                    annotation.end_position().column as u32,
                ),
            )
            .expect("a tree-sitter node range is a valid source span"),
        )
    }

    fn accessed_member(
        &self,
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
        site: MemberAccessQuery<'_>,
    ) -> Option<Box<str>> {
        let python = python_analyzer(workspace);
        let semantics = procedure.semantics();
        match site {
            MemberAccessQuery::Call(call) => {
                let callee = semantics
                    .value(call.callee)
                    .expect("a call site's callee value is retained");
                let mapping = semantics
                    .source_mapping(callee.source)
                    .expect("a callee value retains a source mapping");
                let file = file_for_locator(workspace, &mapping.locator)?;
                let prepared = prepared_for(python, &file);
                let node = node_at_span(&prepared, mapping.locator.anchor().span())?;
                if node.kind() != "attribute" {
                    return None;
                }
                let attribute = node.child_by_field_name("attribute")?;
                attribute
                    .utf8_text(prepared.source().as_bytes())
                    .ok()
                    .map(Box::from)
            }
            MemberAccessQuery::Load(location) => {
                let MemoryLocationKind::Field { member, .. } = &location.kind else {
                    return None;
                };
                let file = file_for_locator(workspace, member)?;
                let prepared = prepared_for(python, &file);
                node_text_at(&prepared, member.anchor().span())
            }
        }
    }

    fn member_lookup(
        &self,
        workspace: &WorkspaceAnalyzer,
        class: &ClassIdentity,
        member: &str,
    ) -> MemberLookup {
        let python = python_analyzer(workspace);
        match class {
            ClassIdentity::Workspace(unit) => {
                self.workspace_member_lookup(workspace, python, unit, member)
            }
            ClassIdentity::External { symbol_id, .. } => {
                let Some(overlay) = overlay_of(workspace) else {
                    return MemberLookup::Unknown(UnknownReason::ExternalNotModeled);
                };
                match overlay
                    .member_target_on_owner(symbol_id, member)
                    .disposition
                {
                    SemanticModelMemberTargetDisposition::Unique => MemberLookup::Present,
                    SemanticModelMemberTargetDisposition::Conflict
                        if overlay.member_present_on_owner(symbol_id, member) =>
                    {
                        MemberLookup::Present
                    }
                    SemanticModelMemberTargetDisposition::Absent => MemberLookup::Absent,
                    SemanticModelMemberTargetDisposition::Incomplete
                    | SemanticModelMemberTargetDisposition::Conflict => {
                        MemberLookup::Unknown(UnknownReason::PackIncomplete)
                    }
                }
            }
        }
    }

    fn enclosing_class(
        &self,
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
    ) -> Option<ClassIdentity> {
        enclosing_workspace_class(workspace, procedure).map(ClassIdentity::Workspace)
    }

    fn class_hierarchy(
        &self,
        workspace: &WorkspaceAnalyzer,
        class: &ClassIdentity,
    ) -> ClassHierarchy {
        let ClassIdentity::Workspace(unit) = class else {
            return ClassHierarchy::unknown();
        };
        let python = python_analyzer(workspace);
        let workspace_ancestors = python.get_ancestors(unit);
        let mut ancestors = workspace_ancestors
            .iter()
            .cloned()
            .map(ClassIdentity::Workspace)
            .collect::<Vec<_>>();
        let mut unresolved_base = false;
        let overlay = overlay_of(workspace);
        let mut external_cache = ExternalClassCache::default();
        for owner in std::iter::once(unit).chain(workspace_ancestors.iter()) {
            let direct = python.get_direct_ancestors(owner);
            for raw in python.inner.raw_supertypes_of(owner) {
                if direct.iter().any(|ancestor| {
                    ancestor.terminal_name() == raw || ancestor.fq_name_str() == raw
                }) {
                    continue;
                }
                match external_class(overlay.as_deref(), &raw, &mut external_cache) {
                    Some(identity) if !ancestors.contains(&identity) => ancestors.push(identity),
                    Some(_) => {}
                    None => unresolved_base = true,
                }
            }
        }

        let mut descendants = Vec::new();
        let mut seen = HashSet::default();
        let mut pending = python
            .get_direct_descendants(unit)
            .into_iter()
            .collect::<Vec<_>>();
        while let Some(descendant) = pending.pop() {
            if !seen.insert(descendant.clone()) {
                continue;
            }
            pending.extend(python.get_direct_descendants(&descendant));
            descendants.push(ClassIdentity::Workspace(descendant));
        }

        let dynamic_attributes =
            std::iter::once(unit)
                .chain(workspace_ancestors.iter())
                .any(|owner| {
                    python.direct_children(owner).iter().any(|child| {
                        matches!(
                            child.terminal_name(),
                            "__getattr__" | "__getattribute__" | "__setattr__"
                        )
                    })
                });
        ancestors.sort_by(|left, right| left.qualified_name().cmp(right.qualified_name()));
        descendants.sort_by(|left, right| left.qualified_name().cmp(right.qualified_name()));
        ClassHierarchy {
            ancestors,
            descendants: Some(descendants),
            unresolved_base,
            dynamic_attributes,
        }
    }

    fn field_slot_is_complete(
        &self,
        workspace: &WorkspaceAnalyzer,
        class: &ClassIdentity,
        member: &str,
    ) -> bool {
        let ClassIdentity::Workspace(unit) = class else {
            return false;
        };
        let python = python_analyzer(workspace);
        let file = unit.source();
        let prepared = prepared_for(python, file);
        let Some(class) = class_node_for_unit(python, &prepared, unit) else {
            return false;
        };
        if class
            .parent()
            .is_some_and(|parent| parent.kind() == "decorated_definition")
        {
            return false;
        }
        let Some(body) = class.child_by_field_name("body") else {
            return false;
        };
        let mut cursor = body.walk();
        for child in body.named_children(&mut cursor) {
            if assignment_name(child, prepared.source()) == Some(member) {
                return false;
            }
            if matches!(child.kind(), "function_definition" | "decorated_definition")
                && definition_name(child, prepared.source()) == Some(member)
            {
                return false;
            }
        }
        true
    }

    fn dynamic_field_writes(
        &self,
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
    ) -> Vec<DynamicFieldWrite> {
        let python = python_analyzer(workspace);
        let semantics = procedure.semantics();
        let Some(file) = file_for_locator(workspace, semantics.locator()) else {
            return vec![DynamicFieldWrite::Any];
        };
        let prepared = prepared_for(python, &file);
        let Some(callable) = node_at_span(&prepared, semantics.locator().anchor().span()) else {
            return vec![DynamicFieldWrite::Any];
        };
        let root_id = callable.id();
        let mut writes = Vec::new();
        let mut stack = vec![callable];
        while let Some(node) = stack.pop() {
            if node.id() != root_id
                && matches!(
                    node.kind(),
                    "function_definition" | "class_definition" | "lambda"
                )
            {
                continue;
            }
            if node.kind() == "call"
                && let Some(write) = setattr_write(node, prepared.source())
            {
                writes.push(write);
            }
            if matches!(node.kind(), "assignment" | "augmented_assignment")
                && let Some(write) = dictionary_write(node, prepared.source())
            {
                writes.push(DynamicFieldWrite::Member("__dict__".into()));
                writes.push(write);
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        writes
    }

    fn narrowing_verdict(
        &self,
        workspace: &WorkspaceAnalyzer,
        procedure: &ProcedureHandle,
        guard: &GuardFact,
        atom: &ClassIdentity,
        arm: GuardArmSide,
    ) -> NarrowingVerdict {
        let predicate_holds = match guard.predicate {
            GuardPredicate::InstanceOf { classes, .. } => {
                let Some(classes) = self.guard_classes(workspace, procedure, classes) else {
                    return NarrowingVerdict::Unknown;
                };
                let Some(relation) = self.instance_relation(workspace, atom, &classes) else {
                    return NarrowingVerdict::Unknown;
                };
                relation
            }
            GuardPredicate::HasMember { member, .. } => {
                let Some(value) = procedure.semantics().value(member) else {
                    return NarrowingVerdict::Unknown;
                };
                let Some(mapping) = procedure.semantics().source_mapping(value.source) else {
                    return NarrowingVerdict::Unknown;
                };
                let Some(file) = file_for_locator(workspace, &mapping.locator) else {
                    return NarrowingVerdict::Unknown;
                };
                let prepared = prepared_for(python_analyzer(workspace), &file);
                let Some(node) = node_at_span(&prepared, mapping.locator.anchor().span()) else {
                    return NarrowingVerdict::Unknown;
                };
                let Some(member) = python_plain_string_literal(node, prepared.source()) else {
                    return NarrowingVerdict::Unknown;
                };
                match self.member_lookup(workspace, atom, member) {
                    MemberLookup::Present => true,
                    MemberLookup::Absent => false,
                    MemberLookup::Unknown(_) => return NarrowingVerdict::Unknown,
                }
            }
            GuardPredicate::NullComparison { null_on_true } => {
                (atom.qualified_name() == "types.NoneType") == null_on_true
            }
            GuardPredicate::ConstantBoolean { .. }
            | GuardPredicate::ConstantEquality { .. }
            | GuardPredicate::Opaque { .. } => return NarrowingVerdict::Unknown,
        };
        if predicate_holds == matches!(arm, GuardArmSide::True) {
            NarrowingVerdict::Keep
        } else {
            NarrowingVerdict::Drop
        }
    }
}
