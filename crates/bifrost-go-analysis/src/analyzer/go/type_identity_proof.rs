//! Exact Go assignment-conversion type identity from source and model facts.
//!
//! Go's semantic IR deliberately marks writes into already-declared bindings
//! as conversions when lowering cannot prove their source and target types are
//! identical. This module owns the bounded positive proof that can recover
//! identity later: one exact modeled result type, one explicit binding type,
//! and native declaration resolution. Any missing fact abstains.

use brokk_bifrost_core::analyzer::usages::reference_site::smallest_named_node_covering_with_scope;

use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_core::analyzer::code_unit_index::CodeUnitIndex;

use crate::analyzer::GoAnalyzer;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use brokk_bifrost_core::analyzer::query_token::QueryScope;

use brokk_bifrost_core::analyzer::model::Range;

use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;

use brokk_bifrost_core::analyzer::model::StructuredTypeNodeView;
use brokk_bifrost_core::analyzer::structural::native_obligation::{
    NativeResultObligation, NativeResultObligationBasis,
};
use brokk_bifrost_core::path_utils::rel_path_string;
use brokk_bifrost_go::declarations::is_predeclared_go_type;
use brokk_bifrost_go::references::go_name_shadowed_at_with_scope;
use tree_sitter::Node;

/// Source bound for the retained native error-result obligation.
const GO_NATIVE_ERROR_OBLIGATION_MAX_SOURCE_BYTES: usize = 1024 * 1024;

/// Syntax bound for the retained native error-result obligation.
const GO_NATIVE_ERROR_OBLIGATION_MAX_STEPS: usize = 100_000;

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
    if source.len() > GO_NATIVE_ERROR_OBLIGATION_MAX_SOURCE_BYTES {
        return None;
    }
    let tree =
        crate::analyzer::usages::get_definition::go::parse_go_tree_for_proof(analyzer, &source)?;
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
    let mut remaining_shadow_steps = go_shadow_step_limit(&source);
    let shadowed =
        go_name_shadowed_at_with_scope(root, &source, result_type.start_byte(), "error", || {
            let admitted = remaining_shadow_steps > 0;
            remaining_shadow_steps = remaining_shadow_steps.saturating_sub(1);
            admitted
        })
        .unwrap_or(true);
    if shadowed
        || imports.contains_key("error")
        || !go.workspace_declaration_identities_authoritative()
        || !go
            .go_package_of(target.source())
            .is_some_and(|package| go.definitions(&format!("{package}.error")).next().is_none())
    {
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
    cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
) -> Option<NativeResultObligation> {
    let identity =
        crate::analyzer::usages::get_definition::go::go_function_value_result_type_identity(
            analyzer,
            file,
            range,
            usize::try_from(result_ordinal).ok()?,
            cancellation,
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

/// Native static type proof for an exact explicit binding. Prepared syntax is
/// shared with the analyzer request; type text is never parsed or resolved here.
pub fn go_explicit_binding_type_identity(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    binding: Range,
    cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
) -> brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution<
    Option<brokk_bifrost_analysis::analyzer::resolution::CanonicalTypeIdentity>,
> {
    go_explicit_binding_declared_type(analyzer, file, source, binding, cancellation)
        .map(|selected| selected.canonical)
}

pub(crate) struct GoExplicitBindingDeclaredType {
    pub canonical: Option<brokk_bifrost_analysis::analyzer::resolution::CanonicalTypeIdentity>,
    pub nominal: Option<CodeUnit>,
}

pub(crate) fn go_explicit_binding_declared_type(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    binding: Range,
    cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
) -> brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution<
    GoExplicitBindingDeclaredType,
> {
    use super::native_points::{GoNativePointRequest, GoNativePointRequestOpen};
    use brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution;
    let unknown = || BoundedResolution::Complete {
        value: GoExplicitBindingDeclaredType {
            canonical: None,
            nominal: None,
        },
        work: Default::default(),
    };
    if cancellation.is_cancelled() {
        return BoundedResolution::Cancelled {
            work: Default::default(),
        };
    }
    let Some(go) = resolve_analyzer::<GoAnalyzer>(analyzer) else {
        return unknown();
    };
    let scope = AnalyzerQueryScope::new(analyzer);
    let Some(syntax) = go.inner.prepared_syntax(scope.token(), file) else {
        return unknown();
    };
    if syntax.source() != source {
        return unknown();
    }
    let Some(text) = source.get(binding.start_byte..binding.end_byte) else {
        return unknown();
    };
    let site = brokk_bifrost_core::analyzer::usages::reference_site::ResolvedReferenceSite {
        path: rel_path_string(file),
        text: text.into(),
        range: binding,
        focus_start_byte: binding.start_byte,
        focus_end_byte: binding.end_byte,
    };
    let opened = match GoNativePointRequest::open_for_file(
        go,
        file,
        analyzer.semantic_model_overlay(),
        cancellation,
    ) {
        Ok(opened) => opened,
        Err(error) => {
            analyzer.record_query_failure(error);
            return unknown();
        }
    };
    match opened {
        GoNativePointRequestOpen::Ready(mut request) => request.explicit_binding_type(
            brokk_bifrost_analysis::analyzer::languages::BoundedReceiverQuery {
                analyzer,
                file,
                source,
                tree: Some(syntax.tree()),
                site: &site,
                budget: Default::default(),
                cancellation: Some(cancellation),
            },
            binding,
        ),
        GoNativePointRequestOpen::Cancelled => BoundedResolution::Cancelled {
            work: Default::default(),
        },
        GoNativePointRequestOpen::Unavailable { .. } => {
            analyzer.mark_execution_dependent();
            unknown()
        }
    }
}

/// Lower one provider-pinned callable once and export only canonical scalars.
#[allow(clippy::type_complexity)]
pub fn go_selected_callable_result_type_identities(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    member: &brokk_bifrost_analysis::analyzer::semantic_model::overlay::ModelSymbolRef,
    cancellation: &brokk_bifrost_core::cancellation::CancellationToken,
) -> Option<(
    Vec<Option<brokk_bifrost_analysis::analyzer::resolution::CanonicalTypeIdentity>>,
    usize,
)> {
    use super::native_points::{GoNativePointRequest, GoNativePointRequestOpen};
    let go = resolve_analyzer::<GoAnalyzer>(analyzer)?;
    let opened = GoNativePointRequest::open_for_file(
        go,
        file,
        analyzer.semantic_model_overlay(),
        cancellation,
    );
    let opened = match opened {
        Ok(opened) => opened,
        Err(error) => {
            analyzer.record_query_failure(error);
            return None;
        }
    };
    match opened {
        GoNativePointRequestOpen::Ready(request) => {
            request.selected_callable_result_type_identities(member, cancellation)
        }
        GoNativePointRequestOpen::Cancelled => None,
        GoNativePointRequestOpen::Unavailable { .. } => {
            analyzer.mark_execution_dependent();
            None
        }
    }
}

fn go_shadow_step_limit(source: &str) -> usize {
    source
        .len()
        .saturating_mul(4)
        .clamp(1, GO_NATIVE_ERROR_OBLIGATION_MAX_STEPS)
}

pub(super) fn explicit_binding_type_node(
    root: Node<'_>,
    binding: Range,
    mut scope_step: impl FnMut() -> bool,
) -> Option<Node<'_>> {
    if binding.start_byte >= binding.end_byte {
        return None;
    }
    let name = smallest_named_node_covering_with_scope(
        root,
        binding.start_byte,
        binding.end_byte,
        &mut scope_step,
    )?;
    if name.start_byte() != binding.start_byte
        || name.end_byte() != binding.end_byte
        || name.kind() != "identifier"
    {
        return None;
    }
    let declaration = name.parent()?;
    if !matches!(declaration.kind(), "var_spec" | "parameter_declaration")
        || declaration.has_error()
        || !node_has_field_child(declaration, "name", name)
        || (declaration.kind() == "parameter_declaration"
            && parameter_has_generic_callable_context(declaration, &mut scope_step))
    {
        return None;
    }
    let type_node = declaration.child_by_field_name("type")?;
    if type_node.has_error() {
        return None;
    }
    (name.end_byte() <= type_node.start_byte()).then_some(type_node)
}

fn parameter_has_generic_callable_context(
    parameter: Node<'_>,
    scope_step: &mut impl FnMut() -> bool,
) -> bool {
    let mut owner = parameter.parent();
    while let Some(node) = owner {
        if !scope_step() {
            return true;
        }
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
                if !scope_step() {
                    return true;
                }
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
