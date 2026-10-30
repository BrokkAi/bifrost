//! Exact Go assignment-conversion type identity from source and model facts.
//!
//! Go's semantic IR deliberately marks writes into already-declared bindings
//! as conversions when lowering cannot prove their source and target types are
//! identical. This module owns the bounded positive proof that can recover
//! identity later: one exact modeled result type, one explicit binding type,
//! and one parser/import/shadow resolution. Any missing fact abstains.

use crate::analyzer::go::package_identity::GoOverlayPackages;

use brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelCallableKey;

use brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay;

use brokk_bifrost_analysis::analyzer::semantic_model::TypeRef;

use crate::analyzer::usages::get_definition::go::parse_go_tree;

use brokk_bifrost_core::analyzer::usages::reference_site::smallest_named_node_covering;

use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;

use brokk_bifrost_core::analyzer::model::CodeUnitType;

use crate::analyzer::GoAnalyzer;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_core::analyzer::query_token::QueryScope;

use brokk_bifrost_core::analyzer::model::Range;

use brokk_bifrost_core::analyzer::model::StructuredTypeIdentity;

use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;

use brokk_bifrost_core::analyzer::model::{StructuredTypeNodeId, StructuredTypeNodeView};
use brokk_bifrost_core::analyzer::structural::native_obligation::{
    NativeResultObligation, NativeResultObligationBasis,
};
use brokk_bifrost_core::hash::HashMap;
use brokk_bifrost_core::path_utils::rel_path_string;
use brokk_bifrost_go::declarations::{go_structured_type_identity, is_predeclared_go_type};
use brokk_bifrost_go::references::go_name_shadowed_at_with_scope;
use tree_sitter::Node;

/// Exact source larger than this is outside the bounded result-binding proof.
pub const GO_MODELED_RESULT_BINDING_TYPE_PROOF_MAX_SOURCE_BYTES: usize = 1024 * 1024;

/// Maximum syntax work the lexical-shadow half of one proof may consume.
pub const GO_MODELED_RESULT_BINDING_TYPE_PROOF_MAX_STEPS: usize = 100_000;

/// Prove the native Go B5 obligation for one resolved declaration and result
/// port. The caller supplies a target that the structured resolver already
/// selected; this function only checks the target's declaration metadata and
/// source-owned predeclared `error` identity. An unresolved or ambiguous
/// declaration deliberately returns `None`.
pub fn go_native_error_result_obligation(
    analyzer: &dyn IAnalyzer,
    target: &CodeUnit,
    result_ordinal: u32,
) -> Option<NativeResultObligation> {
    if target.source().declaration_language() != Language::Go {
        return None;
    }
    let ordinal = usize::try_from(result_ordinal).ok()?;
    let metadata = analyzer.signature_metadata(target);
    let [metadata] = metadata.as_slice() else {
        return None;
    };
    let identity = metadata.result_type_identity(ordinal)?;
    let Some(StructuredTypeNodeView::Named(name)) = identity.view(identity.root_id()) else {
        return None;
    };
    if name.is_absolute()
        || !name.lexical_scope().is_empty()
        || name.path() != [String::from("error")]
    {
        return None;
    }

    let go = resolve_analyzer::<GoAnalyzer>(analyzer)?;
    let source = analyzer.indexed_source(target.source())?;
    if source.len() > GO_MODELED_RESULT_BINDING_TYPE_PROOF_MAX_SOURCE_BYTES {
        return None;
    }
    let tree = parse_go_tree(&source)?;
    let root = tree.root_node();
    let declaration = go_target_declaration_node(root, analyzer.ranges_of(target))?;
    if declaration.has_error() {
        return None;
    };
    let result_type = go_result_type_node(declaration, ordinal)?;
    if go_type_parameter_binds_error(declaration, &source) {
        return None;
    }

    let scope = AnalyzerQueryScope::new(analyzer);
    let (imports, _dot_imports) = go.definition_import_namespaces(scope.token(), target.source());
    let packages = GoOverlayPackages::new(None);
    let mut context = GoTypeIdentityContext {
        go,
        packages: &packages,
        source: &source,
        root,
        type_byte: result_type.start_byte(),
        imports,
        package: go.go_package_of(target.source()),
        remaining_shadow_steps: go_shadow_step_limit(&source),
    };
    if !context.predeclared_name_is_exact("error") {
        return None;
    }

    Some(NativeResultObligation::fallible_status(
        result_ordinal,
        NativeResultObligationBasis::StaticSignature,
    ))
}

/// Prove the native Go B5 obligation for a function-valued call whose local
/// value flow has a known indexed result type but no declaration dispatch arm.
/// The callee expression is resolved through the structured Go definition
/// resolver; unresolved values and modeled-only values abstain.
pub fn go_native_error_function_value_obligation(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    range: Range,
    result_ordinal: u32,
) -> Option<NativeResultObligation> {
    let identity =
        crate::analyzer::usages::get_definition::go::go_function_value_result_type_identity(
            analyzer,
            file,
            range,
            usize::try_from(result_ordinal).ok()?,
        )?;
    let Some(StructuredTypeNodeView::Named(name)) = identity.view(identity.root_id()) else {
        return None;
    };
    if name.is_absolute()
        || !name.lexical_scope().is_empty()
        || name.path() != [String::from("error")]
    {
        return None;
    }
    Some(NativeResultObligation::fallible_status(
        result_ordinal,
        NativeResultObligationBasis::StaticSignature,
    ))
}

/// Return the reviewed standard-library identities whose Go documentation
/// guarantees that `Write`-family methods never return a non-nil error.
///
/// The owner/member pair is the resolver's exact import-path-qualified Go
/// identity (for example `bytes.Buffer.Write`), not a method-name heuristic.
/// The contracts were checked against the package documentation:
/// `https://pkg.go.dev/bytes#Buffer`, `https://pkg.go.dev/strings#Builder`,
/// and `https://pkg.go.dev/hash#Hash`; each listed method documents an always
/// nil error, while `hash.Hash.Write` says that it never returns an error.
pub fn go_native_obligation_exclusion(owner_fqn: &str, member: &str) -> Option<&'static str> {
    let excluded = match owner_fqn {
        // bytes.Buffer Write, WriteString, WriteByte and WriteRune all
        // document that their returned error is always nil.
        "bytes.Buffer" => matches!(member, "Write" | "WriteString" | "WriteByte" | "WriteRune"),
        // strings.Builder has the same no-error contract for these methods.
        "strings.Builder" => {
            matches!(member, "Write" | "WriteString" | "WriteByte" | "WriteRune")
        }
        // The hash.Hash interface documentation states: "It never returns an
        // error." This excludes only the exact interface method identity.
        "hash.Hash" => member == "Write",
        _ => false,
    };
    excluded.then_some("native_excluded_stdlib_never_error")
}

fn go_target_declaration_node<'tree>(root: Node<'tree>, ranges: Vec<Range>) -> Option<Node<'tree>> {
    let mut stack = vec![root];
    let mut exact = None;
    let mut enclosing: Option<(usize, Node<'tree>)> = None;
    while let Some(node) = stack.pop() {
        let declaration = matches!(
            node.kind(),
            "function_declaration" | "method_declaration" | "method_elem" | "func_literal"
        );
        if declaration {
            let start = node.start_byte();
            let end = node.end_byte();
            if ranges
                .iter()
                .any(|range| range.start_byte == start && range.end_byte == end)
            {
                exact = Some(node);
                break;
            }
            for range in &ranges {
                if range.start_byte <= start && end <= range.end_byte {
                    let width = end - start;
                    if enclosing.as_ref().is_none_or(|(best, _)| width < *best) {
                        enclosing = Some((width, node));
                    }
                }
            }
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    exact.or_else(|| enclosing.map(|(_, node)| node))
}

pub(crate) fn go_result_type_node(declaration: Node<'_>, ordinal: usize) -> Option<Node<'_>> {
    let result = declaration.child_by_field_name("result")?;
    if result.kind() != "parameter_list" {
        return (ordinal == 0).then_some(result);
    }
    let mut current_ordinal = 0usize;
    let mut cursor = result.walk();
    for parameter in result.named_children(&mut cursor) {
        if !matches!(
            parameter.kind(),
            "parameter_declaration" | "variadic_parameter_declaration"
        ) {
            continue;
        }
        let mut names = parameter.walk();
        let named_count = parameter
            .named_children(&mut names)
            .filter(|child| child.kind() == "identifier")
            .count()
            .max(1);
        if ordinal < current_ordinal.saturating_add(named_count) {
            return parameter.child_by_field_name("type");
        }
        current_ordinal = current_ordinal.saturating_add(named_count);
    }
    None
}

fn go_type_parameter_binds_error(declaration: Node<'_>, source: &str) -> bool {
    let Some(parameters) = declaration.child_by_field_name("type_parameters") else {
        return false;
    };
    let mut stack = vec![parameters];
    while let Some(node) = stack.pop() {
        if node.kind().starts_with("type_parameter") {
            let mut children = node.walk();
            if node
                .named_children(&mut children)
                .find(|child| child.kind() == "identifier")
                .is_some_and(|name| name.utf8_text(source.as_bytes()).ok() == Some("error"))
            {
                return true;
            }
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    false
}

/// Prove whether a parser-selected Go type name is the predeclared type with
/// the same spelling. `Some(false)` is a proven shadow or a different name;
/// `None` means the declaration/index facts needed for an exact answer are not
/// available. Callers use that distinction to keep unresolved native failure
/// branches open instead of treating an incomplete lookup as a negative fact.
pub(crate) fn go_predeclared_type_name_is_exact(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    type_node: Node<'_>,
    name: &str,
) -> Option<bool> {
    if !is_predeclared_go_type(name) {
        return Some(false);
    }
    if type_node.has_error() || type_node.is_missing() {
        return None;
    }
    let go = resolve_analyzer::<GoAnalyzer>(analyzer)?;
    if !go.workspace_declaration_identities_authoritative() {
        return None;
    }
    let scope = AnalyzerQueryScope::new(analyzer);
    let (imports, dot_imports) = go.definition_import_namespaces(scope.token(), file);
    if !dot_imports.is_empty() || imports.contains_key(name) {
        return Some(false);
    }
    match go_name_shadowed_at_with_scope(root, source, type_node.start_byte(), name, || true) {
        Some(true) => return Some(false),
        Some(false) => {}
        None => return None,
    }
    match go.predeclared_builtin_shadow_status_limited(&rel_path_string(file), name, 256, || true) {
        Some(true) => Some(false),
        Some(false) => Some(true),
        None => None,
    }
}

/// Conservative query work to charge before a proof-cache miss.
///
/// The charge includes the exact source bytes consumed by parsing plus the
/// explicit capped allowance admitted by the lexical-shadow walk. `None`
/// means the source is outside the proof's supported size boundary.
pub fn go_modeled_result_binding_type_identity_proof_work(source: &str) -> Option<usize> {
    (source.len() <= GO_MODELED_RESULT_BINDING_TYPE_PROOF_MAX_SOURCE_BYTES)
        .then(|| source.len().saturating_add(go_shadow_step_limit(source)))
}

fn go_shadow_step_limit(source: &str) -> usize {
    source
        .len()
        .saturating_mul(4)
        .clamp(1, GO_MODELED_RESULT_BINDING_TYPE_PROOF_MAX_STEPS)
}

/// Whether one modeled Go result and one explicitly typed binding have the
/// same exact type at the binding's source declaration.
///
/// `binding` is the source range of the binding identifier, not an assignment
/// occurrence. The model target is already the oracle's typed callable key;
/// this function never reconstructs it from a rendered signature. A partial
/// declaration pack may prove a callable it positively publishes, but model
/// conflicts, ambiguous facts, inferred bindings, unresolved imports,
/// shadowed predeclared names, and unsupported type shapes all return `false`.
#[allow(clippy::too_many_arguments)]
pub fn go_modeled_result_binding_type_identity_is_exact(
    analyzer: &dyn IAnalyzer,
    overlay: &SemanticModelOverlay,
    file: &ProjectFile,
    source: &str,
    binding: Range,
    target: SemanticModelCallableKey<'_>,
    result_ordinal: usize,
) -> bool {
    if target.language != "go"
        || go_modeled_result_binding_type_identity_proof_work(source).is_none()
    {
        return false;
    }
    let Some(parameter_count) = usize::try_from(target.parameter_count).ok() else {
        return false;
    };
    let packages = GoOverlayPackages::new(Some(overlay));
    let Some(result_type) = packages.callable_result_type_ref(
        target.owner,
        target.member,
        target.has_receiver,
        parameter_count,
        result_ordinal,
    ) else {
        return false;
    };
    go_explicit_binding_matches_modeled_result(
        analyzer,
        &packages,
        file,
        source,
        binding,
        &result_type,
    )
}

#[allow(clippy::too_many_arguments)]
fn go_explicit_binding_matches_modeled_result(
    analyzer: &dyn IAnalyzer,
    packages: &GoOverlayPackages<'_>,
    file: &ProjectFile,
    source: &str,
    binding: Range,
    result_type: &TypeRef,
) -> bool {
    let Some(go) = resolve_analyzer::<GoAnalyzer>(analyzer) else {
        return false;
    };
    let Some(tree) = parse_go_tree(source) else {
        return false;
    };
    let root = tree.root_node();
    if root.has_error() {
        return false;
    }
    let Some(type_node) = explicit_binding_type_node(root, binding) else {
        return false;
    };
    let Some(target_type) = go_structured_type_identity(type_node, source) else {
        return false;
    };

    let scope = AnalyzerQueryScope::new(analyzer);
    let (imports, _dot_imports) = go.definition_import_namespaces(scope.token(), file);
    let package = go.go_package_of(file);
    let mut context = GoTypeIdentityContext {
        go,
        packages,
        source,
        root,
        type_byte: type_node.start_byte(),
        imports,
        package,
        remaining_shadow_steps: go_shadow_step_limit(source),
    };
    modeled_result_matches_target(result_type, &target_type, &mut context)
}

fn explicit_binding_type_node(root: Node<'_>, binding: Range) -> Option<Node<'_>> {
    if binding.start_byte >= binding.end_byte {
        return None;
    }
    let name = smallest_named_node_covering(root, binding.start_byte, binding.end_byte)?;
    if name.start_byte() != binding.start_byte
        || name.end_byte() != binding.end_byte
        || name.kind() != "identifier"
    {
        return None;
    }
    let declaration = name.parent()?;
    if !matches!(declaration.kind(), "var_spec" | "parameter_declaration")
        || !node_has_field_child(declaration, "name", name)
        || (declaration.kind() == "parameter_declaration"
            && parameter_has_generic_callable_context(declaration))
    {
        return None;
    }
    let type_node = declaration.child_by_field_name("type")?;
    (name.end_byte() <= type_node.start_byte()).then_some(type_node)
}

fn parameter_has_generic_callable_context(parameter: Node<'_>) -> bool {
    let mut owner = parameter.parent();
    while let Some(node) = owner {
        if matches!(
            node.kind(),
            "func_literal" | "function_declaration" | "method_declaration"
        ) {
            if node.child_by_field_name("type_parameters").is_some() {
                return true;
            }
            let Some(receiver) = node.child_by_field_name("receiver") else {
                return false;
            };
            let mut stack = vec![receiver];
            while let Some(current) = stack.pop() {
                if current.kind() == "type_arguments" {
                    return true;
                }
                let mut cursor = current.walk();
                stack.extend(current.named_children(&mut cursor));
            }
            return false;
        }
        owner = node.parent();
    }
    true
}

fn node_has_field_child(parent: Node<'_>, field: &str, target: Node<'_>) -> bool {
    brokk_bifrost_core::analyzer::structural::adapter_helpers::is_field_of(parent, target, field)
}

struct GoTypeIdentityContext<'tree, 'source, 'context, 'overlay> {
    go: &'context GoAnalyzer,
    packages: &'context GoOverlayPackages<'overlay>,
    source: &'source str,
    root: Node<'tree>,
    type_byte: usize,
    imports: HashMap<String, Vec<String>>,
    package: Option<String>,
    remaining_shadow_steps: usize,
}

enum TypeMatchFrame<'a> {
    Type(&'a TypeRef, StructuredTypeNodeId),
    DeclaredName(&'a str, StructuredTypeNodeId),
    PredeclaredName(&'a str, StructuredTypeNodeId),
}

fn modeled_result_matches_target(
    modeled: &TypeRef,
    target: &StructuredTypeIdentity,
    context: &mut GoTypeIdentityContext<'_, '_, '_, '_>,
) -> bool {
    let mut frames = vec![TypeMatchFrame::Type(modeled, target.root_id())];
    while let Some(frame) = frames.pop() {
        match frame {
            TypeMatchFrame::Type(modeled, target_id) => match modeled {
                TypeRef::Named {
                    name,
                    arguments,
                    nullable,
                } => {
                    if *nullable || !arguments.is_empty() {
                        return false;
                    }
                    frames.push(TypeMatchFrame::PredeclaredName(name, target_id));
                }
                TypeRef::Declared {
                    id,
                    arguments,
                    nullable,
                } => {
                    if *nullable {
                        return false;
                    }
                    if arguments.is_empty() {
                        frames.push(TypeMatchFrame::DeclaredName(id, target_id));
                        continue;
                    }
                    let Some(StructuredTypeNodeView::Generic {
                        base,
                        arguments: target_arguments,
                    }) = target.view(target_id)
                    else {
                        return false;
                    };
                    if arguments.len() != target_arguments.len() {
                        return false;
                    }
                    frames.push(TypeMatchFrame::DeclaredName(id, base));
                    frames.extend(
                        arguments
                            .iter()
                            .zip(target_arguments)
                            .rev()
                            .map(|(argument, target)| TypeMatchFrame::Type(argument, *target)),
                    );
                }
                TypeRef::Pointer { element } => {
                    let Some(StructuredTypeNodeView::Pointer(target)) = target.view(target_id)
                    else {
                        return false;
                    };
                    frames.push(TypeMatchFrame::Type(element, target));
                }
                TypeRef::Slice { element } => {
                    let Some(StructuredTypeNodeView::Slice(target)) = target.view(target_id) else {
                        return false;
                    };
                    frames.push(TypeMatchFrame::Type(element, target));
                }
                TypeRef::Map { key, value } => {
                    let Some(StructuredTypeNodeView::Map {
                        key: target_key,
                        value: target_value,
                    }) = target.view(target_id)
                    else {
                        return false;
                    };
                    frames.push(TypeMatchFrame::Type(value, target_value));
                    frames.push(TypeMatchFrame::Type(key, target_key));
                }
                // StructuredTypeIdentity deliberately does not retain array
                // lengths, channel directions, function layouts, or language
                // model substitutions. Those shapes cannot establish exact Go
                // identity at this boundary.
                TypeRef::TypeParameter { .. }
                | TypeRef::Array { .. }
                | TypeRef::ByRef { .. }
                | TypeRef::FixedArray { .. }
                | TypeRef::Channel { .. }
                | TypeRef::Wildcard { .. }
                | TypeRef::Tuple { .. }
                | TypeRef::Function { .. }
                | TypeRef::Projection { .. }
                | TypeRef::Unknown => return false,
            },
            TypeMatchFrame::DeclaredName(declaration_id, target_id) => {
                let Some(qualified_name) = context
                    .packages
                    .declared_type_qualified_name(declaration_id)
                else {
                    return false;
                };
                let Some(StructuredTypeNodeView::Named(target_name)) = target.view(target_id)
                else {
                    return false;
                };
                if target_name.is_absolute()
                    || !target_name.lexical_scope().is_empty()
                    || !context.declared_name_matches(target_name.path(), &qualified_name)
                {
                    return false;
                }
            }
            TypeMatchFrame::PredeclaredName(name, target_id) => {
                let Some(StructuredTypeNodeView::Named(target_name)) = target.view(target_id)
                else {
                    return false;
                };
                if target_name.is_absolute() || !target_name.lexical_scope().is_empty() {
                    return false;
                }
                let [target_component] = target_name.path() else {
                    return false;
                };
                if target_component != name || !context.predeclared_name_is_exact(name) {
                    return false;
                }
            }
        }
    }
    true
}

impl GoTypeIdentityContext<'_, '_, '_, '_> {
    fn declared_name_matches(&mut self, path: &[String], modeled_name: &str) -> bool {
        match path {
            [name] => {
                !self.lexically_shadowed(name)
                    && self.package.as_ref().is_some_and(|package| {
                        let candidate = format!("{package}.{name}");
                        candidate == modeled_name
                            && self.same_package_declared_type_is_exact(&candidate)
                    })
            }
            [qualifier, name] => {
                if self.lexically_shadowed(qualifier) {
                    return false;
                }
                let Some([import_path]) = self.imports.get(qualifier).map(Vec::as_slice) else {
                    return false;
                };
                format!("{import_path}.{name}") == modeled_name
            }
            _ => false,
        }
    }

    fn same_package_declared_type_is_exact(&self, candidate: &str) -> bool {
        if !self.go.workspace_declaration_identities_authoritative() {
            return false;
        }
        let mut definitions = self.go.definitions(candidate);
        let Some(declaration) = definitions.next() else {
            return false;
        };
        declaration.kind() == CodeUnitType::Class && definitions.next().is_none()
    }

    fn predeclared_name_is_exact(&mut self, name: &str) -> bool {
        if !is_predeclared_go_type(name)
            || self.lexically_shadowed(name)
            || self.imports.contains_key(name)
            || !self.go.workspace_declaration_identities_authoritative()
        {
            return false;
        }
        self.package.as_ref().is_some_and(|package| {
            self.go
                .definitions(&format!("{package}.{name}"))
                .next()
                .is_none()
        })
    }

    fn lexically_shadowed(&mut self, name: &str) -> bool {
        go_name_shadowed_at_with_scope(self.root, self.source, self.type_byte, name, || {
            let admitted = self.remaining_shadow_steps > 0;
            self.remaining_shadow_steps = self.remaining_shadow_steps.saturating_sub(1);
            admitted
        })
        .unwrap_or(true)
    }
}

use ValueTypeBarrierDecision::{ProvenMatch, ProvenNonMatch, Undecided};
use ValueTypeBarrierReason::{IncompleteType, UnknownType};
use brokk_bifrost_analysis::analyzer::semantic::{
    ValueTypeBarrierDecision, ValueTypeBarrierReason, ValueTypePredicate,
};
use brokk_bifrost_analysis::analyzer::store::resolution_operation::{
    SelectedNativeDefinition, SelectedNativeReferenceTypes, SelectedNativeTypes,
};
use brokk_bifrost_core::analyzer::resolution_facts::IntrinsicTypeKind;

pub(super) enum CarrierType {
    Decision(ValueTypeBarrierDecision),
    Named(CodeUnit),
}

// Interpret only selected identities. A rendered type name is never proof.
pub(super) fn go_selected_carrier_type(
    answer: &SelectedNativeReferenceTypes,
    predicate: ValueTypePredicate,
) -> CarrierType {
    let selected =
        match brokk_bifrost_analysis::analyzer::native_points::selected_value_type_for_barrier(
            &answer.answer,
            answer.query_result_slot,
        ) {
            Ok(selected) => selected,
            Err(reason) => return CarrierType::Decision(Undecided(reason)),
        };
    let SelectedNativeTypes::Ready {
        intrinsic, nominal, ..
    } = &answer.value_types
    else {
        return CarrierType::Decision(Undecided(IncompleteType));
    };
    let Some(ty) = selected else {
        return CarrierType::Decision(Undecided(UnknownType));
    };
    if ty.indirection() != 0 {
        return CarrierType::Decision(ProvenNonMatch);
    }
    if let Some(descriptor) = intrinsic
        .iter()
        .find(|descriptor| descriptor.identity() == ty.identity())
    {
        // Untyped constants have LanguageBuiltin descriptors and do not kill.
        // Interfaces (including any) carry arbitrary dynamic values and abstain.
        let name = descriptor.spelling();
        if matches!(name, "any" | "error" | "comparable" | "interface{}")
            || descriptor.kind() == IntrinsicTypeKind::Structural
        {
            return CarrierType::Decision(Undecided(UnknownType));
        }
        let matches = descriptor.kind() == IntrinsicTypeKind::Primitive
            && match predicate {
                ValueTypePredicate::IntrinsicBool => name == "bool",
                ValueTypePredicate::IntrinsicNumeric => matches!(
                    name,
                    "int"
                        | "int8"
                        | "int16"
                        | "int32"
                        | "int64"
                        | "uint"
                        | "uint8"
                        | "uint16"
                        | "uint32"
                        | "uint64"
                        | "uintptr"
                        | "float32"
                        | "float64"
                        | "byte"
                        | "rune"
                ),
                ValueTypePredicate::FieldlessEnum => false,
            };
        return CarrierType::Decision(if matches { ProvenMatch } else { ProvenNonMatch });
    }
    if let Some((_, SelectedNativeDefinition::Unit(unit))) = nominal
        .iter()
        .find(|(identity, _)| *identity == ty.identity())
    {
        return CarrierType::Named(unit.clone());
    }
    CarrierType::Decision(Undecided(UnknownType))
}

/// A nominal declaration still needs its structured declaration category checked.
pub(super) enum ObservedCarrierType {
    Type(brokk_bifrost_analysis::analyzer::semantic::ObservedValueType),
    Named(CodeUnit),
}

/// Translate the selected public native answer without consulting native slots.
pub(super) fn go_observed_value_type(answer: &SelectedNativeReferenceTypes) -> ObservedCarrierType {
    use ObservedCarrierType::Type;
    use brokk_bifrost_analysis::analyzer::resolution::FactProjectedTypeNodeForm;
    use brokk_bifrost_analysis::analyzer::semantic::{ObservedValueType, ValueShape};
    let selected =
        match brokk_bifrost_analysis::analyzer::native_points::selected_value_type_for_barrier(
            &answer.answer,
            answer.query_result_slot,
        ) {
            Ok(Some(ty)) => ty,
            Ok(None) => return Type(ObservedValueType::Undecided(UnknownType)),
            Err(reason) => return Type(ObservedValueType::Undecided(reason)),
        };
    let SelectedNativeTypes::Ready {
        intrinsic, nominal, ..
    } = &answer.value_types
    else {
        return Type(ObservedValueType::Undecided(IncompleteType));
    };
    if selected.indirection() != 0 {
        return Type(ObservedValueType::NonNamed(ValueShape::Pointer));
    }
    let mut identity = selected.identity();
    // Aliases are edges between selected slots, never names to parse.
    for shape in answer.answer.projected_type_shapes() {
        let Some(root) = shape
            .nodes()
            .iter()
            .find(|node| node.slot() == shape.root_slot())
        else {
            continue;
        };
        if root.identity() != identity {
            continue;
        }
        let mut node = root;
        let mut remaining = shape.nodes().len();
        loop {
            if remaining == 0 {
                return Type(ObservedValueType::Undecided(IncompleteType));
            }
            remaining -= 1;
            if node.indirection() != 0 {
                return Type(ObservedValueType::NonNamed(ValueShape::Pointer));
            }
            match node.form() {
                FactProjectedTypeNodeForm::Slice(_) => {
                    return Type(ObservedValueType::NonNamed(ValueShape::Slice));
                }
                FactProjectedTypeNodeForm::Array(_) => {
                    return Type(ObservedValueType::NonNamed(ValueShape::Array));
                }
                FactProjectedTypeNodeForm::Map { .. } => {
                    return Type(ObservedValueType::NonNamed(ValueShape::Map));
                }
                FactProjectedTypeNodeForm::Unsupported => {
                    return Type(ObservedValueType::Undecided(UnknownType));
                }
                FactProjectedTypeNodeForm::Alias(child) => {
                    let Some(next) = shape
                        .nodes()
                        .iter()
                        .find(|candidate| candidate.slot() == *child)
                    else {
                        return Type(ObservedValueType::Undecided(IncompleteType));
                    };
                    node = next;
                }
                FactProjectedTypeNodeForm::Leaf | FactProjectedTypeNodeForm::Applied(_) => {
                    identity = node.identity();
                    break;
                }
            }
        }
    }
    if let Some(descriptor) = intrinsic.iter().find(|item| item.identity() == identity) {
        // These are selected universe descriptors, not source or display spellings.
        if matches!(descriptor.spelling(), "any" | "error" | "comparable") {
            return Type(ObservedValueType::NonNamed(ValueShape::Interface));
        }
        match descriptor.kind() {
            IntrinsicTypeKind::Slice => {
                return Type(ObservedValueType::NonNamed(ValueShape::Slice));
            }
            IntrinsicTypeKind::Array => {
                return Type(ObservedValueType::NonNamed(ValueShape::Array));
            }
            IntrinsicTypeKind::Primitive => {
                return Type(ObservedValueType::Named {
                    canonical: descriptor.spelling().to_owned(),
                });
            }
            IntrinsicTypeKind::Structural if descriptor.spelling() == "function-type" => {
                return Type(ObservedValueType::NonNamed(ValueShape::Function));
            }
            _ => return Type(ObservedValueType::Undecided(UnknownType)),
        }
    }
    match nominal
        .iter()
        .find(|(candidate, _)| *candidate == identity)
        .map(|(_, definition)| definition)
    {
        Some(SelectedNativeDefinition::Unit(unit)) => ObservedCarrierType::Named(unit.clone()),
        Some(SelectedNativeDefinition::Intrinsic { canonical_name, .. }) => {
            Type(ObservedValueType::Named {
                canonical: canonical_name.clone(),
            })
        }
        _ => Type(ObservedValueType::Undecided(UnknownType)),
    }
}

#[cfg(test)]
mod tests {

    use crate::analyzer::go::type_identity_proof::*;

    use brokk_bifrost_core::analyzer::model::Language;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_analysis::test_support::AnalyzerFixture;

    fn binding_range(source: &str, name: &str) -> Range {
        let start_byte = source.find(name).expect("binding name");
        Range {
            start_byte,
            end_byte: start_byte + name.len(),
            start_line: 0,
            end_line: 0,
        }
    }

    fn binding_matches(
        fixture: &AnalyzerFixture,
        source: &str,
        binding: &str,
        result: &TypeRef,
    ) -> bool {
        let file = ProjectFile::new(fixture.project_root(), "main.go");
        let packages = GoOverlayPackages::new(None);
        go_explicit_binding_matches_modeled_result(
            fixture.analyzer.analyzer(),
            &packages,
            &file,
            source,
            binding_range(source, binding),
            result,
        )
    }

    #[test]
    fn expression_case_type_shadow_ends_before_sibling_and_post_switch_bindings() {
        let source = r#"package main
func run(choice int) {
    switch choice {
    case 0:
        type error struct{}
        var shadowed error
        _ = shadowed
    case 1:
        var sibling error
        _ = sibling
    }
    var after error
    _ = after
}
"#;
        let fixture = AnalyzerFixture::new_for_language(
            Language::Go,
            &[("go.mod", "module example.com/app\n"), ("main.go", source)],
        );

        assert!(
            !binding_matches(&fixture, source, "shadowed", &TypeRef::named("error")),
            "a case-local type must shadow the universe error type within its own clause"
        );
        assert!(
            binding_matches(&fixture, source, "sibling", &TypeRef::named("error")),
            "a case-local type must not poison a sibling clause's exact type proof"
        );
        assert!(
            binding_matches(&fixture, source, "after", &TypeRef::named("error")),
            "a case-local type must not poison the post-switch exact type proof"
        );
    }

    #[test]
    fn explicit_unshadowed_error_is_exact_but_inference_and_wrapper_changes_abstain() {
        let source = r#"package main

func run() {
    var exact error
    var inferred = exact
    var boxed any
}
"#;
        let fixture = AnalyzerFixture::new_for_language(
            Language::Go,
            &[("go.mod", "module example.com/app\n"), ("main.go", source)],
        );

        assert!(binding_matches(
            &fixture,
            source,
            "exact",
            &TypeRef::named("error")
        ));
        assert!(!binding_matches(
            &fixture,
            source,
            "inferred",
            &TypeRef::named("error")
        ));
        assert!(!binding_matches(
            &fixture,
            source,
            "boxed",
            &TypeRef::named("error")
        ));
        assert!(!binding_matches(
            &fixture,
            source,
            "boxed",
            &TypeRef::Pointer {
                element: Box::new(TypeRef::named("error")),
            }
        ));
    }

    #[test]
    fn lexical_type_const_and_parameter_shadows_keep_predeclared_error_open() {
        for (source, label) in [
            (
                r#"package main
func run() {
    type error struct{}
    var typed error
}
"#,
                "local type",
            ),
            (
                r#"package main
func run() {
    const error = 1
    var typed error
}
"#,
                "local const",
            ),
            (
                r#"package main
func run(error int) {
    var typed error
}
"#,
                "parameter",
            ),
        ] {
            let fixture = AnalyzerFixture::new_for_language(
                Language::Go,
                &[("go.mod", "module example.com/app\n"), ("main.go", source)],
            );
            assert!(
                !binding_matches(&fixture, source, "typed", &TypeRef::named("error")),
                "{label} must shadow the universe type"
            );
        }
    }

    #[test]
    fn package_declaration_in_another_file_and_import_binding_shadow_error() {
        let package_source = r#"package main
func run() {
    var typed error
}
"#;
        let package_fixture = AnalyzerFixture::new_for_language(
            Language::Go,
            &[
                ("go.mod", "module example.com/app\n"),
                ("main.go", package_source),
                ("shadow.go", "package main\ntype error struct{}\n"),
            ],
        );
        assert!(!binding_matches(
            &package_fixture,
            package_source,
            "typed",
            &TypeRef::named("error")
        ));

        let import_source = r#"package main
import error "net"
func run() {
    var typed error
}
"#;
        let import_fixture = AnalyzerFixture::new_for_language(
            Language::Go,
            &[
                ("go.mod", "module example.com/app\n"),
                ("main.go", import_source),
            ],
        );
        assert!(!binding_matches(
            &import_fixture,
            import_source,
            "typed",
            &TypeRef::named("error")
        ));
    }

    #[test]
    fn variadic_and_generic_parameter_bindings_abstain() {
        for (source, label) in [
            (
                r#"package main
func run(typed ...error) {}
"#,
                "variadic parameter",
            ),
            (
                r#"package main
func run[error interface{ ~int }](typed error) {}
"#,
                "generic parameter",
            ),
        ] {
            let fixture = AnalyzerFixture::new_for_language(
                Language::Go,
                &[("go.mod", "module example.com/app\n"), ("main.go", source)],
            );
            assert!(
                !binding_matches(&fixture, source, "typed", &TypeRef::named("error")),
                "{label} must stay outside the exact binding proof"
            );
        }
    }

    #[test]
    fn declared_name_resolution_uses_exact_import_alias_and_rejects_shadowing() {
        fn resolved(source: &str, extra_file: Option<(&str, &str)>, modeled_name: &str) -> bool {
            let mut files = vec![("go.mod", "module example.com/app\n"), ("main.go", source)];
            files.extend(extra_file);
            let fixture = AnalyzerFixture::new_for_language(Language::Go, &files);
            let analyzer = fixture.analyzer.analyzer();
            let go = resolve_analyzer::<GoAnalyzer>(analyzer).expect("Go analyzer");
            let file = ProjectFile::new(fixture.project_root(), "main.go");
            let binding = binding_range(source, "conn");
            let tree = parse_go_tree(source).expect("Go tree");
            let root = tree.root_node();
            let type_node = explicit_binding_type_node(root, binding).expect("explicit type");
            let identity = go_structured_type_identity(type_node, source).expect("type identity");
            let StructuredTypeNodeView::Named(name) =
                identity.view(identity.root_id()).expect("identity root")
            else {
                panic!("qualified type is named")
            };
            let scope = AnalyzerQueryScope::new(analyzer);
            let (imports, _) = go.definition_import_namespaces(scope.token(), &file);
            let packages = GoOverlayPackages::new(None);
            GoTypeIdentityContext {
                go,
                packages: &packages,
                source,
                root,
                type_byte: type_node.start_byte(),
                imports,
                package: go.go_package_of(&file),
                remaining_shadow_steps: go_shadow_step_limit(source),
            }
            .declared_name_matches(name.path(), modeled_name)
        }

        assert!(resolved(
            r#"package main
import network "net"
func run() {
    var conn network.Listener
}
"#,
            None,
            "net.Listener",
        ));
        assert!(!resolved(
            r#"package main
import network "net"
func run(network int) {
    var conn network.Listener
}
"#,
            None,
            "net.Listener",
        ));
        assert!(resolved(
            r#"package main
type Name struct{}
func run() {
    var conn Name
}
"#,
            None,
            "example.com/app.Name",
        ));
        assert!(!resolved(
            r#"package main
func Name() {}
func run() {
    var conn Name
}
"#,
            None,
            "example.com/app.Name",
        ));
        assert!(!resolved(
            r#"package main
type Name struct{}
func run() {
    var conn Name
}
"#,
            Some(("duplicate.go", "package main\ntype Name int\n")),
            "example.com/app.Name",
        ));
    }
}
