//! Bounded Rust actual-to-formal conversion proofs.
//!
//! Selected nominal types share bounded source-backed alias expansion and
//! generic/default substitution. Canonical identities feed exact conversions,
//! builtin reference deref/reborrow and array-reference unsizing. This does not
//! model borrow checking, arbitrary lifetimes or user `Deref` implementations;
//! unsupported types and substitutions remain unknown.

use brokk_bifrost_analysis::analyzer::lexical_definitions::LexicalBindingResolution;

use brokk_bifrost_core::analyzer::usages::model::ImportKind;

use brokk_bifrost_analysis::analyzer::usages::call_conversion::ArgumentTypeConversion;

use brokk_bifrost_analysis::analyzer::usages::call_conversion::CallArgumentConversionProver;

use brokk_bifrost_analysis::analyzer::usages::call_conversion::ConversionKind;

use brokk_bifrost_analysis::analyzer::usages::call_conversion::ConversionSyntax;

use crate::analyzer::usages::call_conversion::ConversionUnknown;

use brokk_bifrost_analysis::analyzer::usages::call_conversion::ResolvedConversionType;

use brokk_bifrost_analysis::analyzer::usages::call_conversion::{
    RustConversionType, RustProjectedType,
};

use brokk_bifrost_analysis::analyzer::usages::call_conversion::RustPrimitive;

use brokk_bifrost_analysis::analyzer::usages::call_conversion::{
    CallConversionCache, CallConversionContext, ConversionSource,
};
use std::sync::Arc;

use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupRequest;

use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus;

use brokk_bifrost_analysis::analyzer::usages::get_definition::resolve_definition_batch_with_source_tree;

use brokk_bifrost_analysis::analyzer::i_analyzer::{AnalyzerQueryScope, QueryScope};

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_core::analyzer::model::ProjectFile;

use crate::analyzer::RustAnalyzer;

use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;
use brokk_bifrost_core::analyzer::tree_walk::root_node;
use brokk_bifrost_rust::declarations::rust_node_text;
use brokk_bifrost_rust::ownership::{
    rust_dereference_operand, rust_node_is_in_unsafe_context, rust_reference_expression_value,
    rust_reference_is_mutable, rust_reference_type_referent,
};
use tree_sitter::Node;

pub(crate) mod selected_type;

const MAX_TYPE_DEPTH: usize = 16;
const MAX_SELECTED_TYPE_WORK: usize = 256;

/// One operation's source/model work and active model aliases. Every recursive
/// entry is charged under MAX_TYPE_DEPTH, so the alias stack is bounded by 16.
#[derive(Debug)]
struct SelectedTypeWork {
    remaining: usize,
    aliases: Vec<(String, String)>,
}

impl SelectedTypeWork {
    fn new(remaining: usize) -> Self {
        Self {
            remaining,
            aliases: Vec::new(),
        }
    }
}

pub(crate) static CALL_ARGUMENT_CONVERSION_PROVER: RustCallArgumentConversionProver =
    RustCallArgumentConversionProver;

pub(crate) struct RustCallArgumentConversionProver;

impl CallArgumentConversionProver for RustCallArgumentConversionProver {
    fn requires_complete_signature_for_argument_proofs(&self) -> bool {
        false
    }

    fn validate_owner(&self, owner: Node<'_>) -> Result<(), ConversionUnknown> {
        let mut current = Some(owner);
        while let Some(node) = current {
            if has_non_lifetime_parameters(node) || has_type_where_predicates(node) {
                return Err(ConversionUnknown::GenericSubstitution);
            }
            current = node.parent();
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn prove_argument(
        &self,
        analyzer: &dyn IAnalyzer,
        sources: &CallConversionContext<'_>,
        file: &ProjectFile,
        actual: Node<'_>,
        source: &str,
        formal_file: &ProjectFile,
        formal: Node<'_>,
        formal_source: &str,
    ) -> Result<ArgumentTypeConversion, ConversionUnknown> {
        let rust = resolve_analyzer::<RustAnalyzer>(analyzer)
            .ok_or(ConversionUnknown::UnsupportedLanguage)?;
        let _scope = AnalyzerQueryScope::new(rust);
        // A proof asks route questions (glob imports, prelude and crate roots).
        // It can run while an RQL request retains a selected Rust operation, so
        // it holds its own lazily opened query frame, as other route consumers
        // do, instead of taking the unframed path that such an operation refuses.
        brokk_bifrost_rust::graph_support::with_usage_read_frame(rust, || {
            let actual_context = RustTypeContext {
                analyzer,
                sources,
                file,
                source,
                root: root_node(actual),
            };
            let formal_context = RustTypeContext {
                analyzer,
                sources,
                file: formal_file,
                source: formal_source,
                root: root_node(formal),
            };

            actual_context.supported_type_context(actual)?;
            formal_context.supported_type_context(formal)?;
            let source_type = actual_context.expression_type(actual, 0)?;
            let target_node = formal
                .child_by_field_name("type")
                .ok_or(ConversionUnknown::UnresolvedTargetType)?;
            let target_type = formal_context.type_from_node(target_node, 0)?;
            let kind = conversion_kind(&source_type, &target_type)
                .ok_or(ConversionUnknown::UnsupportedConversion)?;

            Ok(ArgumentTypeConversion {
                hierarchy: None,
                source: ResolvedConversionType::Rust(source_type),
                target: ResolvedConversionType::Rust(target_type),
                kind,
            })
        })
    }

    /// Deref coercion is the one argument coercion that runs user code (a
    /// `Deref` impl). It needs a reference actual and an expected reference
    /// type, possibly an element of an expected tuple or array. Unsizing,
    /// reborrow, pointer, function-pointer and never-type coercions run no
    /// user code. Either side counts as a reference unless proven otherwise.
    fn unknown_conversion_may_run_user_code(
        &self,
        analyzer: &dyn IAnalyzer,
        sources: &CallConversionCache,
        actual: Option<ConversionSyntax<'_>>,
        formal: Option<ConversionSyntax<'_>>,
    ) -> bool {
        let sources = &CallConversionContext::reference(sources);
        // An unknown formal may hold a reference, so the actual alone
        // answers; an unknown actual may run user code whatever the formal.
        let Some(actual) = actual else {
            return true;
        };
        let Some(rust) = resolve_analyzer::<RustAnalyzer>(analyzer) else {
            return true;
        };
        let _scope = AnalyzerQueryScope::new(rust);
        // Like the proof, this answer asks route questions; see prove_argument.
        brokk_bifrost_rust::graph_support::with_usage_read_frame(rust, || {
            if let Some(formal) = formal {
                let actual_context = RustTypeContext {
                    analyzer,
                    sources,
                    file: actual.file,
                    source: actual.source,
                    root: root_node(actual.node),
                };
                let formal_context = RustTypeContext {
                    analyzer,
                    sources,
                    file: formal.file,
                    source: formal.source,
                    root: root_node(formal.node),
                };
                if formal_context.formal_is_inferred_from_actual(
                    formal.node,
                    actual,
                    &actual_context,
                ) {
                    return false;
                }
                if let Ok(actual_type) = actual_context.expression_type(actual.node, 0)
                    && let Some(formal_node) = formal.node.child_by_field_name("type")
                    && let Ok(formal_type) = formal_context.type_from_node(formal_node, 0)
                {
                    let mut actual_type = &actual_type;
                    let mut formal_type = &formal_type;
                    while let (
                        RustConversionType::Reference {
                            referent: actual, ..
                        },
                        RustConversionType::Reference {
                            referent: formal, ..
                        },
                    ) = (actual_type, formal_type)
                    {
                        actual_type = actual;
                        formal_type = formal;
                    }
                    if same_type(actual_type, formal_type) {
                        return false;
                    }
                }
            }
            if let Some(formal) = formal {
                let actual_context = RustTypeContext {
                    analyzer,
                    sources,
                    file: actual.file,
                    source: actual.source,
                    root: root_node(actual.node),
                };
                let formal_context = RustTypeContext {
                    analyzer,
                    sources,
                    file: formal.file,
                    source: formal.source,
                    root: root_node(formal.node),
                };
                if let Some(identity) = actual_context.expression_opaque_identity(actual.node, 0)
                    && formal
                        .node
                        .child_by_field_name("type")
                        .and_then(|node| formal_context.opaque_type_identity(node, 0))
                        .as_ref()
                        == Some(&identity)
                {
                    return false;
                }
            }
            actual_may_deref_through_user_impl(analyzer, sources, actual)
                && formal.is_none_or(|formal| formal_may_hold_reference(analyzer, sources, formal))
        })
    }
}

/// Whether `actual` may deref-coerce through a user `Deref` impl: it is a
/// reference whose innermost referent may be a nominal type with a `Deref`
/// impl, or its type is unknown. A by-value actual cannot deref-coerce, and a
/// reference to a primitive, `str`, slice, array or tuple has no user `Deref`
/// to run (a reference to a reference derefs through the builtin impl).
fn actual_may_deref_through_user_impl(
    analyzer: &dyn IAnalyzer,
    sources: &CallConversionContext<'_>,
    actual: ConversionSyntax<'_>,
) -> bool {
    let context = RustTypeContext {
        analyzer,
        sources,
        file: actual.file,
        source: actual.source,
        root: root_node(actual.node),
    };
    if context.is_standard_noncoercing_macro_operand(actual.node) {
        return false;
    }
    if context.supported_macro_context(actual.node).is_err() {
        return true;
    }
    let shape = context.expression_shape(actual.node, 0);
    match shape.innermost {
        Innermost::Unknown => true,
        Innermost::Nominal => shape.reference,
        Innermost::Builtin => false,
    }
}

/// The written type of the named field `name` of the struct `resolved`.
fn declared_field_type<'d>(resolved: &'d ResolvedDeclaration, name: &str) -> Option<Node<'d>> {
    let body = resolved.node().ok()?.child_by_field_name("body")?;
    if body.kind() == "ordered_field_declaration_list" {
        let index = name.parse::<usize>().ok()?;
        return body
            .children_by_field_name("type", &mut body.walk())
            .nth(index);
    }
    if body.kind() != "field_declaration_list" {
        return None;
    }
    let declared = body.named_children(&mut body.walk()).find(|declared| {
        declared.kind() == "field_declaration"
            && declared
                .child_by_field_name("name")
                .is_some_and(|declared_name| {
                    rust_node_text(declared_name, &resolved.source).trim() == name
                })
    })?;
    declared.child_by_field_name("type")
}

/// What an actual's type is, as far as deref coercion is concerned.
#[derive(Clone, Copy)]
struct DerefShape {
    /// The type is a reference, possibly to further references.
    reference: bool,
    innermost: Innermost,
}

impl DerefShape {
    fn from_exact(mut ty: &RustConversionType) -> Self {
        let mut reference = false;
        while let RustConversionType::Reference { referent, .. } = ty {
            reference = true;
            ty = referent;
        }
        Self {
            reference,
            innermost: match ty {
                RustConversionType::Declaration(_)
                | RustConversionType::AppliedDeclaration { .. }
                | RustConversionType::Model { .. } => Innermost::Nominal,
                _ => Innermost::Builtin,
            },
        }
    }

    const UNKNOWN: Self = Self {
        reference: false,
        innermost: Innermost::Unknown,
    };
}

/// One selected result's exact type and conservative deref shape.
struct RustResultProof {
    exact: Result<RustConversionType, ConversionUnknown>,
    shape: DerefShape,
}

/// The referent under every reference layer.
#[derive(Clone, Copy)]
enum Innermost {
    /// A primitive, `str`, array, slice, tuple, unit, never, pointer or
    /// function pointer: no user `Deref` impl exists for it.
    Builtin,
    /// One struct, enum or union, which may implement `Deref`.
    Nominal,
    /// A type parameter, alias, trait, unresolved path or unread syntax.
    Unknown,
}

/// Whether the formal's type may be a reference, or a tuple or array that
/// holds one. A type alias, an associated type, a type parameter, a trait or
/// an unresolved path may resolve to a reference. An argument-position `impl
/// Trait` is an anonymous parameter inferred from its own actual alone, so no
/// coercion applies to it. A generic nominal is by value whatever its type
/// arguments: coercion never reaches into them.
fn formal_may_hold_reference(
    analyzer: &dyn IAnalyzer,
    sources: &CallConversionContext<'_>,
    formal: ConversionSyntax<'_>,
) -> bool {
    let Some(type_node) = formal.node.child_by_field_name("type") else {
        return true;
    };
    let context = RustTypeContext {
        analyzer,
        sources,
        file: formal.file,
        source: formal.source,
        root: root_node(type_node),
    };
    if context.supported_macro_context(type_node).is_err() {
        return true;
    }
    let mut pending = vec![type_node];
    while let Some(node) = pending.pop() {
        if node.has_error() || node.is_missing() {
            return true;
        }
        match node.kind() {
            "reference_type" => return true,
            "tuple_type" => pending.extend(
                node.named_children(&mut node.walk())
                    .filter(|child| !child.is_extra()),
            ),
            "array_type" => match node.child_by_field_name("element") {
                Some(element) => pending.push(element),
                None => return true,
            },
            "unit_type" | "never_type" | "pointer_type" | "function_type" | "abstract_type" => {}
            "primitive_type" => {
                if context.primitive_type(node).is_err() {
                    return true;
                }
            }
            "type_identifier" | "scoped_type_identifier" => {
                if !context.names_value_type_declaration(node) {
                    return true;
                }
            }
            "generic_type" => match node.child_by_field_name("type") {
                Some(base) if context.names_value_type_declaration(base) => {}
                _ => return true,
            },
            _ => return true,
        }
    }
    false
}

/// Share structured actual-type evidence with modeled generic impl selection.
pub(crate) fn expression_conversion_type(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
) -> Result<RustConversionType, ConversionUnknown> {
    if matches!(node.kind(), "string_literal" | "raw_string_literal") {
        return Ok(RustConversionType::Reference {
            mutable: false,
            referent: Box::new(RustConversionType::Primitive(RustPrimitive::Str)),
        });
    }
    let cache = CallConversionCache::default();
    let sources = &CallConversionContext::reference(&cache);
    let rust = resolve_analyzer::<RustAnalyzer>(analyzer)
        .expect("Rust conversion types require a Rust analyzer");
    // Type evidence asks route questions; see prove_argument.
    brokk_bifrost_rust::graph_support::with_usage_read_frame(rust, || {
        RustTypeContext {
            analyzer,
            sources,
            file,
            source,
            root: root_node(node),
        }
        .expression_type(node, 0)
    })
}

/// Interpret one structurally selected explicit trait argument.
pub(crate) fn type_conversion_type(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
) -> Result<RustConversionType, ConversionUnknown> {
    let cache = CallConversionCache::default();
    let sources = &CallConversionContext::reference(&cache);
    let rust = resolve_analyzer::<RustAnalyzer>(analyzer)
        .expect("Rust conversion types require a Rust analyzer");
    // Type evidence asks route questions; see prove_argument.
    brokk_bifrost_rust::graph_support::with_usage_read_frame(rust, || {
        RustTypeContext {
            analyzer,
            sources,
            file,
            source,
            root: root_node(node),
        }
        .type_from_node(node, 0)
    })
}

/// New query-only projection; complete conversion memos never see this path.
pub(crate) fn call_qualifying_type(
    analyzer: &dyn IAnalyzer,
    sources: &CallConversionCache,
    file: &ProjectFile,
    source: &str,
    call: Node<'_>,
) -> Result<
    Option<brokk_bifrost_analysis::analyzer::usages::call_conversion::RustQualifyingTypeProof>,
    ConversionUnknown,
> {
    use brokk_bifrost_analysis::analyzer::i_analyzer::QueryReadReceipt;
    use brokk_bifrost_analysis::analyzer::usages::call_conversion::RustQualifyingTypeProof;
    let sources = &CallConversionContext::reference(sources);
    let context = RustTypeContext {
        analyzer,
        sources,
        file,
        source,
        root: root_node(call),
    };
    let mut proofs = ProjectedTypeReads::default();
    let (result, receipt) = QueryReadReceipt::capture_deferred(analyzer, || {
        if call.kind() != "call_expression" || call.has_error() {
            return Err(ConversionUnknown::UnsupportedExpression);
        }
        let function = call
            .child_by_field_name("function")
            .ok_or(ConversionUnknown::UnsupportedExpression)?;
        let function = if function.kind() == "generic_function" {
            function
                .child_by_field_name("function")
                .ok_or(ConversionUnknown::UnsupportedExpression)?
        } else {
            function
        };
        if function.kind() == "field_expression" {
            return Err(ConversionUnknown::UnsupportedExpression);
        }
        let Some(qualifier) = function.child_by_field_name("path") else {
            context.free_function_declaration(function)?;
            return Ok(None);
        };
        let member = function
            .child_by_field_name("name")
            .ok_or(ConversionUnknown::UnsupportedExpression)?;
        let mut work = SelectedTypeWork::new(MAX_SELECTED_TYPE_WORK);
        let expression = selected_type::alias_type_expr(
            qualifier,
            file,
            &Arc::from(source),
            &mut work.remaining,
        )
        .ok_or_else(|| context.selected_type_stop(ConversionUnknown::BudgetExhausted))?;
        let ty = match context.selected_type_expression_carrier::<RustProjectedType>(
            expression,
            0,
            &mut work,
            &mut proofs,
        ) {
            Ok(ty) => ty,
            Err(reason) => {
                if context.free_function_declaration(function).is_ok() {
                    return Ok(None);
                }
                return Err(reason);
            }
        };
        let arity = call
            .child_by_field_name("arguments")
            .ok_or(ConversionUnknown::UnsupportedExpression)?
            .named_children(&mut call.walk())
            .filter(|node| !node.is_extra())
            .count();
        match &ty {
            RustProjectedType::Model {
                model_set, symbol, ..
            } => {
                use brokk_bifrost_analysis::analyzer::semantic_model::{
                    SemanticModelArgumentBinding, SemanticModelCallApplication,
                    SemanticModelCallableKey,
                };
                let snapshot = analyzer
                    .active_semantic_model_snapshot()
                    .ok_or(ConversionUnknown::UnresolvedTargetType)?;
                if snapshot.active_models().active_model_set_hash() != model_set {
                    return Err(ConversionUnknown::UnresolvedTargetType);
                }
                let overlay = snapshot
                    .semantic_model_overlay()
                    .ok_or(ConversionUnknown::UnresolvedTargetType)?;
                let owner = overlay
                    .symbols_with_id_in_family(symbol, "rust")
                    .unique()
                    .ok_or(ConversionUnknown::AmbiguousBinding)?;
                let parameter_count =
                    u32::try_from(arity).map_err(|_| ConversionUnknown::UnsupportedExpression)?;
                let application = SemanticModelCallApplication::positional(parameter_count);
                let callable = overlay
                    .callable_for_application(
                        SemanticModelCallableKey::new(
                            "rust",
                            &owner.qualified_name,
                            rust_node_text(member, source),
                            false,
                            parameter_count,
                        ),
                        &application,
                    )
                    .unique()
                    .ok_or(ConversionUnknown::AmbiguousBinding)?;
                if callable.owner_id.as_deref() != Some(symbol.as_str()) || !callable.is_static || !callable.callable_family_complete || !brokk_bifrost_analysis::analyzer::semantic_model::overlay::member_is_callable(&callable) { return Err(ConversionUnknown::UnsupportedExpression); }
                let signature = callable
                    .structured_signature
                    .as_ref()
                    .ok_or(ConversionUnknown::UnsupportedExpression)?;
                if !matches!(brokk_bifrost_analysis::analyzer::semantic_model::overlay::bind_semantic_model_arguments(signature, &application), SemanticModelArgumentBinding::Exact { .. }) { return Err(ConversionUnknown::UnsupportedExpression); }
            }
            RustProjectedType::Declaration(owner)
            | RustProjectedType::AppliedDeclaration {
                declaration: owner, ..
            } => {
                let resolved = context
                    .resolve_declaration(member)
                    .map_err(source_type_error)?;
                let declaration = resolved.node()?;
                let implementation = declaration
                    .parent()
                    .and_then(|list| list.parent())
                    .filter(|owner| owner.kind() == "impl_item")
                    .ok_or(ConversionUnknown::UnsupportedExpression)?;
                let owner_node = implementation
                    .child_by_field_name("type")
                    .ok_or(ConversionUnknown::UnsupportedExpression)?;
                let parameters = declaration
                    .child_by_field_name("parameters")
                    .ok_or(ConversionUnknown::UnsupportedExpression)?;
                if parameters
                    .named_children(&mut parameters.walk())
                    .any(|parameter| parameter.kind() == "self_parameter")
                {
                    return Err(ConversionUnknown::UnsupportedExpression);
                }
                let owner_context = RustTypeContext {
                    analyzer,
                    sources,
                    file: resolved.unit.source(),
                    source: &resolved.source,
                    root: resolved.tree.root_node(),
                };
                let selected_owner = owner_context
                    .resolve_declaration(
                        owner_node.child_by_field_name("type").unwrap_or(owner_node),
                    )
                    .map_err(source_type_error)?;
                if selected_owner.unit.declaration_id() != owner.declaration_id() {
                    return Err(ConversionUnknown::UnsupportedExpression);
                }
                if declaration.has_error()
                    || implementation.has_error()
                    || has_type_where_predicates(declaration)
                {
                    return Err(ConversionUnknown::GenericSubstitution);
                }
                if has_non_lifetime_parameters(implementation) {
                    // The shared impl binder proves an unconstrained, one-to-one
                    // application; projected holes need no conversion proof.
                    owner_context.impl_parameter_arguments(declaration, &ty)?;
                    if let Some(parent) = implementation.parent() {
                        CALL_ARGUMENT_CONVERSION_PROVER.validate_owner(parent)?;
                    }
                } else {
                    CALL_ARGUMENT_CONVERSION_PROVER.validate_owner(declaration)?;
                    let actual = ty.clone().into_complete()?;
                    let declared = owner_context.type_from_node(owner_node, 0)?;
                    if !same_type(&actual, &declared) {
                        return Err(ConversionUnknown::GenericSubstitution);
                    }
                }
            }
            _ => return Err(ConversionUnknown::UnsupportedExpression),
        }
        Ok(Some(ty))
    });
    match result {
        Ok(Some(ty)) => {
            proofs.components.push((Vec::new(), Arc::new(receipt)));
            Ok(Some(RustQualifyingTypeProof {
                ty,
                components: proofs.components,
            }))
        }
        Ok(None) => {
            receipt.replay(analyzer);
            Ok(None)
        }
        Err(reason) => {
            receipt.replay(analyzer);
            Err(reason)
        }
    }
}

/// Compare a concrete model argument with parser/resolver type evidence.
/// Only concrete contradictions return Some(false). Unsupported nominal or
/// generic substitutions return None and keep the entire selection open.
pub(crate) fn matches_model_type(
    actual: &RustConversionType,
    model: &crate::analyzer::semantic_model::TypeRef,
) -> Option<bool> {
    use crate::analyzer::semantic_model::{TypeRef, TypeRefReferenceKind};
    let mut pending = vec![(actual, model)];
    while let Some((actual, model)) = pending.pop() {
        match model {
            TypeRef::ByRef {
                element,
                reference_kind: TypeRefReferenceKind::Lvalue,
            } => match actual {
                RustConversionType::Reference {
                    mutable: false,
                    referent,
                } => pending.push((referent, element)),
                RustConversionType::Primitive(_) => return Some(false),
                _ => return None,
            },
            TypeRef::Named {
                name, arguments, ..
            } if arguments.is_empty() => {
                let expected = modeled_primitive(name)?;
                match actual {
                    RustConversionType::Primitive(actual) => {
                        if *actual != expected {
                            return Some(false);
                        }
                    }
                    RustConversionType::Reference { .. } => return Some(false),
                    _ => return None,
                }
            }
            _ => return None,
        }
    }
    Some(true)
}

/// A resolved declaration and the parsed file that holds it.
struct ResolvedDeclaration {
    unit: CodeUnit,
    parsed: Arc<ConversionSource>,
    range: std::ops::Range<usize>,
}

impl std::ops::Deref for ResolvedDeclaration {
    type Target = ConversionSource;
    fn deref(&self) -> &Self::Target {
        &self.parsed
    }
}

impl ResolvedDeclaration {
    fn node(&self) -> Result<Node<'_>, ConversionUnknown> {
        self.tree
            .root_node()
            .named_descendant_for_byte_range(self.range.start, self.range.end)
            .filter(|node| node.byte_range() == self.range)
            .ok_or(ConversionUnknown::UnresolvedTargetType)
    }
}

#[derive(Default)]
struct OperatorCandidatesMemo {
    entries:
        std::sync::Mutex<std::collections::HashMap<String, std::sync::Arc<OperatorCandidates>>>,
}

struct OperatorCandidates {
    headers: Result<Vec<(ProjectFile, std::ops::Range<usize>)>, ConversionUnknown>,
    reads: brokk_bifrost_analysis::analyzer::usages::common::QueryMemoReads,
}

// The interpreter owns traversal and substitution. Carriers own construction
// and whether a failed child remains a hole or stops the complete proof.
trait SelectedTypeCarrier: Clone {
    type Proofs: Default;
    fn bind(_proofs: &mut Self::Proofs, _name: &str, _index: usize) {}
    fn binding(_proofs: &mut Self::Proofs, _name: &str) {}
    fn binding_scope(_proofs: &Self::Proofs) -> usize {
        0
    }
    fn finish_binding_scope(_proofs: &mut Self::Proofs, _scope: usize) {}
    fn alias_target(_proofs: &mut Self::Proofs) {}
    fn primitive(value: RustPrimitive) -> Self;
    fn declaration(value: CodeUnit) -> Self;
    fn applied(declaration: CodeUnit, arguments: Vec<Self>) -> Self;
    fn model(model_set: String, symbol: String, arguments: Vec<Self>) -> Self;
    fn reference(mutable: bool, referent: Self) -> Self;
    fn array(element: Self, length: u64) -> Self;
    fn slice(element: Self) -> Self;
    fn tuple(elements: Vec<Self>) -> Self;
    fn unit() -> Self;
    fn children(&self) -> &[Self];
    fn applied_parts(&self) -> Option<(&CodeUnit, &[Self])>;
    fn child(
        analyzer: &dyn IAnalyzer,
        proofs: &mut Self::Proofs,
        index: usize,
        evaluate: impl FnOnce(&mut Self::Proofs) -> Result<Self, ConversionUnknown>,
    ) -> Result<Self, ConversionUnknown>;
}
macro_rules! selected_type_constructors {
    () => {
        fn primitive(value: RustPrimitive) -> Self {
            Self::Primitive(value)
        }
        fn declaration(value: CodeUnit) -> Self {
            Self::Declaration(value)
        }
        fn applied(declaration: CodeUnit, arguments: Vec<Self>) -> Self {
            Self::AppliedDeclaration {
                declaration,
                arguments,
            }
        }
        fn model(model_set: String, symbol: String, arguments: Vec<Self>) -> Self {
            Self::Model {
                model_set,
                symbol,
                arguments,
            }
        }
        fn reference(mutable: bool, referent: Self) -> Self {
            Self::Reference {
                mutable,
                referent: Box::new(referent),
            }
        }
        fn array(element: Self, length: u64) -> Self {
            Self::Array {
                element: Box::new(element),
                length,
            }
        }
        fn slice(element: Self) -> Self {
            Self::Slice {
                element: Box::new(element),
            }
        }
        fn tuple(elements: Vec<Self>) -> Self {
            Self::Tuple(elements)
        }
        fn unit() -> Self {
            Self::Unit
        }
        fn applied_parts(&self) -> Option<(&CodeUnit, &[Self])> {
            match self {
                Self::AppliedDeclaration {
                    declaration,
                    arguments,
                } => Some((declaration, arguments)),
                _ => None,
            }
        }
        fn children(&self) -> &[Self] {
            match self {
                Self::AppliedDeclaration { arguments, .. }
                | Self::Model { arguments, .. }
                | Self::Tuple(arguments) => arguments,
                Self::Reference { referent, .. } => std::slice::from_ref(referent.as_ref()),
                Self::Array { element, .. } | Self::Slice { element } => {
                    std::slice::from_ref(element.as_ref())
                }
                _ => &[],
            }
        }
    };
}
impl SelectedTypeCarrier for RustConversionType {
    type Proofs = ();
    selected_type_constructors!();
    fn child(
        _analyzer: &dyn IAnalyzer,
        proofs: &mut (),
        _index: usize,
        evaluate: impl FnOnce(&mut ()) -> Result<Self, ConversionUnknown>,
    ) -> Result<Self, ConversionUnknown> {
        evaluate(proofs)
    }
}

#[derive(Default)]
struct ProjectedTypeReads {
    path: Vec<usize>,
    bindings: Vec<(Vec<usize>, String, Vec<ProjectedTypeComponent>)>,
    components: Vec<ProjectedTypeComponent>,
}

type ProjectedTypeComponent = (
    Vec<usize>,
    Arc<brokk_bifrost_analysis::analyzer::i_analyzer::QueryReadReceipt>,
);

impl SelectedTypeCarrier for RustProjectedType {
    type Proofs = ProjectedTypeReads;
    selected_type_constructors!();
    fn bind(proofs: &mut Self::Proofs, name: &str, index: usize) {
        let mut origin = proofs.path.clone();
        origin.push(index);
        // Bindings own input receipts, relative to their value. Expansion can
        // rearrange, duplicate or erase these inputs without leaving receipts
        // at their original positions in the resulting type.
        let components = proofs
            .components
            .iter()
            .filter_map(|(path, receipt)| {
                path.strip_prefix(origin.as_slice())
                    .map(|suffix| (suffix.to_vec(), Arc::clone(receipt)))
            })
            .collect();
        proofs
            .bindings
            .push((proofs.path.clone(), name.to_owned(), components));
    }
    fn binding(proofs: &mut Self::Proofs, name: &str) {
        let inherited = proofs
            .bindings
            .iter()
            .enumerate()
            .filter(|(_, (scope, binding, _))| binding == name && proofs.path.starts_with(scope))
            .max_by_key(|(ordinal, (scope, _, _))| (scope.len(), *ordinal))
            .map(|(_, (_, _, components))| components.clone())
            .unwrap_or_default();
        proofs
            .components
            .extend(inherited.into_iter().map(|(suffix, receipt)| {
                let mut destination = proofs.path.clone();
                destination.extend(suffix);
                (destination, receipt)
            }));
    }
    fn binding_scope(proofs: &Self::Proofs) -> usize {
        proofs.bindings.len()
    }
    fn finish_binding_scope(proofs: &mut Self::Proofs, scope: usize) {
        proofs.bindings.truncate(scope);
    }
    fn alias_target(proofs: &mut Self::Proofs) {
        // Only target components are output components. Bound input receipts
        // survive in bindings and are copied solely where the target uses them.
        proofs
            .components
            .retain(|(path, _)| path.len() <= proofs.path.len() || !path.starts_with(&proofs.path));
    }
    fn child(
        analyzer: &dyn IAnalyzer,
        proofs: &mut Self::Proofs,
        index: usize,
        evaluate: impl FnOnce(&mut Self::Proofs) -> Result<Self, ConversionUnknown>,
    ) -> Result<Self, ConversionUnknown> {
        proofs.path.push(index);
        let (result, receipt) =
            brokk_bifrost_analysis::analyzer::i_analyzer::QueryReadReceipt::capture_deferred(
                analyzer,
                || evaluate(proofs),
            );
        proofs
            .components
            .push((proofs.path.clone(), Arc::new(receipt)));
        proofs.path.pop();
        match result {
            Err(reason @ (ConversionUnknown::Cancelled | ConversionUnknown::BudgetExhausted)) => {
                Err(reason)
            }
            Err(reason) => Ok(Self::Unknown(reason)),
            value => value,
        }
    }
}

struct RustTypeContext<'a, 'tree> {
    analyzer: &'a dyn IAnalyzer,
    sources: &'a CallConversionContext<'a>,
    file: &'a ProjectFile,
    source: &'a str,
    root: Node<'tree>,
}

impl<'a, 'tree> RustTypeContext<'a, 'tree> {
    fn type_from_node(
        &self,
        node: Node<'tree>,
        depth: usize,
    ) -> Result<RustConversionType, ConversionUnknown> {
        let mut work = SelectedTypeWork::new(MAX_SELECTED_TYPE_WORK);
        self.type_from_node_with_budget(node, depth, &mut work)
    }

    fn type_from_node_with_budget(
        &self,
        node: Node<'tree>,
        depth: usize,
        work: &mut SelectedTypeWork,
    ) -> Result<RustConversionType, ConversionUnknown> {
        self.charge_selected_type(depth, work)?;
        if node.has_error() || node.is_missing() {
            return Err(ConversionUnknown::UnsupportedConversion);
        }
        match node.kind() {
            "primitive_type" => {
                if self.name_is_shadowed(node) {
                    self.nominal_type(node)
                } else {
                    self.primitive_type(node)
                }
            }
            "unit_type" => Ok(RustConversionType::Unit),
            "reference_type" => {
                let referent = rust_reference_type_referent(node)
                    .ok_or(ConversionUnknown::UnresolvedTargetType)?;
                Ok(RustConversionType::Reference {
                    mutable: rust_reference_is_mutable(node),
                    referent: Box::new(self.type_from_node_with_budget(
                        referent,
                        depth + 1,
                        work,
                    )?),
                })
            }
            "array_type" => {
                let element = node
                    .child_by_field_name("element")
                    .ok_or(ConversionUnknown::UnresolvedTargetType)?;
                let element = self.type_from_node_with_budget(element, depth + 1, work)?;
                match node.child_by_field_name("length") {
                    Some(length_node) => {
                        let (length, suffix) =
                            crate::analyzer::rust::semantic::rust_integer_literal_parts(
                                self.source,
                                length_node,
                            )
                            .ok_or(ConversionUnknown::UnsupportedConversion)?;
                        if !matches!(suffix, "" | "usize") {
                            return Err(ConversionUnknown::UnsupportedConversion);
                        }
                        let length = u64::try_from(length)
                            .map_err(|_| ConversionUnknown::UnsupportedConversion)?;
                        Ok(RustConversionType::Array {
                            element: Box::new(element),
                            length,
                        })
                    }
                    None => Ok(RustConversionType::Slice {
                        element: Box::new(element),
                    }),
                }
            }
            "tuple_type" => {
                let mut cursor = node.walk();
                let mut elements = Vec::new();
                for child in node.named_children(&mut cursor) {
                    if child.is_extra() {
                        continue;
                    }
                    elements.push(self.type_from_node_with_budget(child, depth + 1, work)?);
                }
                Ok(RustConversionType::Tuple(elements))
            }
            "generic_type" => self.selected_type(node, depth, work),
            "generic_function" | "qualified_type" | "higher_ranked_trait_bound" => {
                Err(ConversionUnknown::GenericSubstitution)
            }
            "type_identifier"
            | "identifier"
            | "scoped_type_identifier"
            | "scoped_identifier"
            | "self"
            | "crate"
            | "super" => self.selected_type(node, depth, work),
            _ => Err(ConversionUnknown::UnsupportedConversion),
        }
    }

    fn selected_type(
        &self,
        node: Node<'tree>,
        depth: usize,
        work: &mut SelectedTypeWork,
    ) -> Result<RustConversionType, ConversionUnknown> {
        let expression = selected_type::alias_type_expr(
            node,
            self.file,
            &Arc::from(self.source),
            &mut work.remaining,
        )
        .ok_or_else(|| self.selected_type_stop(ConversionUnknown::BudgetExhausted))?;
        self.selected_type_expression(expression, depth, work)
    }

    fn selected_type_expression(
        &self,
        expression: selected_type::AliasTypeExpr,
        depth: usize,
        work: &mut SelectedTypeWork,
    ) -> Result<RustConversionType, ConversionUnknown> {
        self.selected_type_expression_carrier::<RustConversionType>(
            expression,
            depth,
            work,
            &mut (),
        )
    }

    fn selected_type_expression_carrier<C: SelectedTypeCarrier>(
        &self,
        expression: selected_type::AliasTypeExpr,
        depth: usize,
        work: &mut SelectedTypeWork,
        proofs: &mut C::Proofs,
    ) -> Result<C, ConversionUnknown> {
        self.charge_selected_type(depth, work)?;
        let cancellation = self
            .analyzer
            .active_query_cancellation()
            .unwrap_or_default();
        let expression = selected_type::expand_alias_head_with_work(
            self.analyzer,
            expression,
            &cancellation,
            0,
            true,
            Some(&mut work.remaining),
        )
        .map_err(|route| match route {
            selected_type::ExternalRoute::Unavailable if cancellation.is_cancelled() => {
                self.selected_type_stop(ConversionUnknown::Cancelled)
            }
            selected_type::ExternalRoute::Unavailable => {
                self.selected_type_stop(ConversionUnknown::BudgetExhausted)
            }
            _ => ConversionUnknown::GenericSubstitution,
        })?;
        if let selected_type::AliasTypeExpr::Reference { mutable, referent } = expression {
            return Ok(C::reference(
                mutable,
                C::child(self.analyzer, proofs, 0, |proofs| {
                    self.selected_type_expression_carrier(*referent, depth + 1, work, proofs)
                })?,
            ));
        }
        let (site, arguments) = match expression {
            selected_type::AliasTypeExpr::Constructor { site, arguments }
            | selected_type::AliasTypeExpr::Shape { site, arguments } => (site, arguments),
            _ => return Err(ConversionUnknown::GenericSubstitution),
        };
        let parsed = self
            .sources
            .source(self.analyzer, &site.file)
            .ok_or(ConversionUnknown::UnresolvedTargetType)?;
        if parsed.source.as_ref() != site.source.as_ref() {
            return Err(ConversionUnknown::UnresolvedTargetType);
        }
        let node = parsed
            .tree
            .root_node()
            .named_descendant_for_byte_range(site.start, site.end)
            .filter(|node| node.byte_range() == (site.start..site.end) && node.kind() == site.kind)
            .ok_or(ConversionUnknown::UnresolvedTargetType)?;
        let context = RustTypeContext {
            analyzer: self.analyzer,
            sources: self.sources,
            file: &site.file,
            source: &parsed.source,
            root: parsed.tree.root_node(),
        };
        let types = arguments
            .into_iter()
            .filter(|argument| !matches!(argument, selected_type::AliasTypeExpr::Lifetime))
            .enumerate()
            .map(|(index, argument)| {
                C::child(self.analyzer, proofs, index, |proofs| {
                    context.selected_type_expression_carrier(argument, depth + 1, work, proofs)
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        match node.kind() {
            "unit_type" => return Ok(C::unit()),
            "tuple_type" => return Ok(C::tuple(types)),
            "array_type" => {
                let [element] = types.as_slice() else {
                    return Err(ConversionUnknown::GenericSubstitution);
                };
                return match node.child_by_field_name("length") {
                    Some(length) => {
                        let (value, suffix) =
                            super::semantic::rust_integer_literal_parts(&parsed.source, length)
                                .ok_or(ConversionUnknown::UnsupportedConversion)?;
                        if !matches!(suffix, "" | "usize") {
                            return Err(ConversionUnknown::UnsupportedConversion);
                        }
                        Ok(C::array(
                            element.clone(),
                            u64::try_from(value)
                                .map_err(|_| ConversionUnknown::UnsupportedConversion)?,
                        ))
                    }
                    None => Ok(C::slice(element.clone())),
                };
            }
            _ => {}
        }
        if node.kind() == "primitive_type" && types.is_empty() {
            return context.primitive_type(node).map(|value| match value {
                RustConversionType::Primitive(value) => C::primitive(value),
                _ => unreachable!(),
            });
        }
        if context.standard_nominal_name(node).is_some() {
            let RustConversionType::Model { symbol, .. } = context.nominal_type(node)? else {
                return Err(ConversionUnknown::GenericSubstitution);
            };
            return context
                .complete_selected_model_type_carrier(&symbol, types, depth, work, proofs);
        }
        let resolved =
            match context.resolve_declaration(node.child_by_field_name("name").unwrap_or(node)) {
                Ok(resolved) => resolved,
                Err(_) => {
                    return context.selected_model_type_carrier(node, types, depth, work, proofs);
                }
            };
        let declaration = resolved.node()?;
        if declaration.has_error()
            || !matches!(
                declaration.kind(),
                "struct_item" | "enum_item" | "union_item"
            )
        {
            return Err(ConversionUnknown::UnresolvedTargetType);
        }
        if let Some(parent) = declaration.parent() {
            RustTypeContext {
                analyzer: self.analyzer,
                sources: self.sources,
                file: resolved.unit.source(),
                source: &resolved.source,
                root: resolved.tree.root_node(),
            }
            .supported_type_context(parent)?;
        }
        if types.is_empty() {
            Ok(C::declaration(resolved.unit))
        } else {
            Ok(C::applied(resolved.unit, types))
        }
    }

    fn selected_model_type_carrier<C: SelectedTypeCarrier>(
        &self,
        node: Node<'tree>,
        arguments: Vec<C>,
        depth: usize,
        work: &mut SelectedTypeWork,
        proofs: &mut C::Proofs,
    ) -> Result<C, ConversionUnknown> {
        use brokk_bifrost_analysis::analyzer::semantic_model::{
            SemanticModelSymbolKind, overlay::RustReexportNamespace,
        };
        let selected_node = node;
        let node = node.child_by_field_name("name").unwrap_or(node);
        let mut outcomes = resolve_definition_batch_with_source_tree(
            self.analyzer,
            vec![DefinitionLookupRequest {
                file: self.file.clone(),
                line: None,
                column: None,
                start_byte: Some(node.start_byte()),
                end_byte: Some(node.end_byte()),
            }],
            self.file.clone(),
            Arc::from(self.source),
            None,
        );
        let outcome = outcomes
            .pop()
            .ok_or(ConversionUnknown::UnresolvedTargetType)?;
        // Activation identity belongs to both admission and refusal. The scope
        // route below is the same proof used by source alias expansion; a model
        // spelling alone never establishes an external source reference.
        let snapshot = self.analyzer.active_semantic_model_snapshot();
        let symbol = if outcome.status == DefinitionLookupStatus::UnresolvableImportBoundary {
            let source = Arc::from(self.source);
            let cancellation = self
                .analyzer
                .active_query_cancellation()
                .unwrap_or_default();
            let selected_type::ExternalRoute::Selected(route) =
                selected_type::selected_external_route(
                    self.analyzer,
                    self.file,
                    &source,
                    selected_node,
                    &cancellation,
                )
            else {
                return Err(ConversionUnknown::UnresolvedTargetType);
            };
            let overlay = snapshot
                .as_ref()
                .and_then(|snapshot| snapshot.semantic_model_overlay())
                .map(Arc::as_ref);
            let crates = super::crate_identity::RustOverlayCrates::new(overlay);
            crates
                .referenceable_symbol_in_namespace(&route, RustReexportNamespace::TypeOrModule)
                .ok_or(ConversionUnknown::UnresolvedTargetType)?
        } else {
            if outcome.status != DefinitionLookupStatus::Resolved
                || !outcome.diagnostics.is_empty()
                || !outcome.definitions.is_empty()
                || outcome.lexical_definition.is_some()
            {
                return Err(ConversionUnknown::UnresolvedTargetType);
            }
            let [symbol] = outcome.modeled_definitions.as_slice() else {
                return Err(ConversionUnknown::AmbiguousBinding);
            };
            Arc::clone(symbol)
        };
        if !matches!(
            symbol.kind,
            SemanticModelSymbolKind::Struct
                | SemanticModelSymbolKind::Enum
                | SemanticModelSymbolKind::Union
                | SemanticModelSymbolKind::TypeAlias
        ) {
            return Err(ConversionUnknown::UnresolvedTargetType);
        }
        self.complete_selected_model_type_carrier(&symbol.id, arguments, depth, work, proofs)
    }

    /// One canonical default-completion path for written standard types,
    /// external nominal declarations and modeled return applications.
    fn complete_selected_model_type_carrier<C: SelectedTypeCarrier>(
        &self,
        symbol_id: &str,
        mut arguments: Vec<C>,
        depth: usize,
        work: &mut SelectedTypeWork,
        proofs: &mut C::Proofs,
    ) -> Result<C, ConversionUnknown> {
        use brokk_bifrost_analysis::analyzer::semantic_model::GenericParameterDefault;
        self.charge_selected_type(depth, work)?;
        // Snapshot acquisition records Models, including activation absence.
        let snapshot = self
            .analyzer
            .active_semantic_model_snapshot()
            .ok_or(ConversionUnknown::UnresolvedTargetType)?;
        let overlay = snapshot
            .semantic_model_overlay()
            .ok_or(ConversionUnknown::UnresolvedTargetType)?;
        let symbol = overlay
            .symbols_with_id_in_family(symbol_id, "rust")
            .unique()
            .ok_or(ConversionUnknown::GenericSubstitution)?;
        use brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelSymbolKind;
        // Modules and abstract declarations cannot prove a concrete target.
        // Aliases instead require their structured target below.
        if matches!(
            symbol.kind,
            SemanticModelSymbolKind::Module
                | SemanticModelSymbolKind::Trait
                | SemanticModelSymbolKind::Interface
        ) {
            return Err(ConversionUnknown::GenericSubstitution);
        }
        let declaration =
            brokk_bifrost_analysis::analyzer::semantic_model::overlay::owner_declaration(
                snapshot.active_models(),
                &symbol,
            )
            .ok_or(ConversionUnknown::GenericSubstitution)?;
        let target = if symbol.kind == SemanticModelSymbolKind::TypeAlias {
            Some(
                declaration
                    .alias_target
                    .as_ref()
                    .ok_or(ConversionUnknown::GenericSubstitution)?,
            )
        } else {
            None
        };
        if target.is_some() {
            let model_set = snapshot.active_models().active_model_set_hash();
            if work
                .aliases
                .iter()
                .any(|(set, id)| set == model_set && id == &symbol.id)
            {
                return Err(ConversionUnknown::GenericSubstitution);
            }
            work.aliases.push((model_set.to_owned(), symbol.id.clone()));
        }
        // Keep alias-local bindings and the active stack scoped even when a
        // missing default, a partial target or a budget stop returns early.
        let proof_scope = C::binding_scope(proofs);
        let result = (|| {
            if arguments.len() > declaration.type_parameters.len() {
                return Err(ConversionUnknown::GenericSubstitution);
            }
            let mut bindings = declaration
                .type_parameters
                .iter()
                .cloned()
                .zip(arguments.iter().cloned())
                .collect::<std::collections::HashMap<_, _>>();
            for (index, name) in declaration
                .type_parameters
                .iter()
                .take(arguments.len())
                .enumerate()
            {
                C::bind(proofs, name, index);
            }
            for index in arguments.len()..declaration.type_parameters.len() {
                let Some(GenericParameterDefault::Type { r#type }) = declaration
                    .type_parameter_defaults
                    .get(index)
                    .and_then(Option::as_ref)
                else {
                    return Err(ConversionUnknown::GenericSubstitution);
                };
                let value = C::child(self.analyzer, proofs, index, |proofs| {
                    self.modeled_return_conversion_with_bindings_carrier(
                        r#type,
                        depth + 1,
                        &bindings,
                        work,
                        proofs,
                    )
                })?;
                bindings.insert(declaration.type_parameters[index].clone(), value.clone());
                C::bind(proofs, &declaration.type_parameters[index], index);
                arguments.push(value);
            }
            if let Some(target) = target {
                C::alias_target(proofs);
                self.modeled_return_conversion_with_bindings_carrier(
                    target,
                    depth + 1,
                    &bindings,
                    work,
                    proofs,
                )
            } else {
                Ok(C::model(
                    snapshot.active_models().active_model_set_hash().to_owned(),
                    symbol.id.clone(),
                    arguments,
                ))
            }
        })();
        C::finish_binding_scope(proofs, proof_scope);
        if target.is_some() {
            let removed = work.aliases.pop();
            debug_assert!(removed.is_some_and(|(set, id)| set
                == snapshot.active_models().active_model_set_hash()
                && id == symbol.id));
        }
        result
    }

    // Charge canonical work rather than provider misses, so memo hits do not
    // change where an identical expansion stops. Bindings are charged before
    // cloning because substituted defaults can otherwise grow exponentially.
    fn selected_type_stop(&self, reason: ConversionUnknown) -> ConversionUnknown {
        // A stopped expansion must not certify a retained policy/unit product,
        // even when an outer consumer reports only a generic unknown result.
        self.analyzer.refuse_read_reuse();
        reason
    }

    fn charge_selected_type(
        &self,
        depth: usize,
        work: &mut SelectedTypeWork,
    ) -> Result<(), ConversionUnknown> {
        if self
            .analyzer
            .active_query_cancellation()
            .as_ref()
            .is_some_and(brokk_bifrost_core::cancellation::CancellationToken::is_cancelled)
        {
            return Err(self.selected_type_stop(ConversionUnknown::Cancelled));
        }
        if depth >= MAX_TYPE_DEPTH {
            return Err(self.selected_type_stop(ConversionUnknown::BudgetExhausted));
        }
        work.remaining = work
            .remaining
            .checked_sub(1)
            .ok_or_else(|| self.selected_type_stop(ConversionUnknown::BudgetExhausted))?;
        Ok(())
    }

    fn charge_selected_binding<C: SelectedTypeCarrier>(
        &self,
        value: &C,
        depth: usize,
        work: &mut SelectedTypeWork,
    ) -> Result<(), ConversionUnknown> {
        let mut pending = vec![(value, depth)];
        while let Some((value, depth)) = pending.pop() {
            self.charge_selected_type(depth, work)?;
            let children = value.children();
            if children.len() > work.remaining {
                return Err(self.selected_type_stop(ConversionUnknown::BudgetExhausted));
            }
            pending.extend(children.iter().rev().map(|child| (child, depth + 1)));
        }
        Ok(())
    }

    fn primitive_type(&self, node: Node<'tree>) -> Result<RustConversionType, ConversionUnknown> {
        let spelling = rust_node_text(node, self.source).trim();
        let primitive =
            primitive_for_spelling(spelling).ok_or(ConversionUnknown::UnsupportedConversion)?;
        if self.name_is_shadowed(node) {
            return Err(ConversionUnknown::UnsupportedConversion);
        }
        Ok(RustConversionType::Primitive(primitive))
    }

    fn name_has_lexical_competitor(&self, node: Node<'tree>, spelling: &str) -> bool {
        let rust = resolve_analyzer::<RustAnalyzer>(self.analyzer)
            .expect("Rust conversion requires a Rust analyzer");
        let scope = brokk_bifrost_rust::lexical_scope::rust_lexical_scope_index_with(
            rust.inner.adapter().lexical_caches(),
            self.root,
            self.source,
        );
        let imports = brokk_bifrost_rust::lexical_scope::visible_import_binder_in_tree_with(
            rust.inner.adapter().lexical_caches(),
            self.root,
            self.source,
            node.start_byte(),
        );
        if scope.item_bound_in_enclosing_scope(spelling, node.start_byte())
            || imports.bindings.values().any(|binding| {
                binding.kind == ImportKind::Glob && {
                    let scope = AnalyzerQueryScope::new(rust);
                    brokk_bifrost_rust::graph_support::reference_context_of(
                        rust,
                        scope.token(),
                        self.file,
                    )
                    .glob_may_bind_name(binding, spelling)
                    .unwrap_or(true)
                }
            })
        {
            return true;
        }
        let mut ancestor = node.parent();
        while let Some(scope) = ancestor {
            if scope
                .child_by_field_name("type_parameters")
                .is_some_and(|parameters| {
                    parameters
                        .named_children(&mut parameters.walk())
                        .any(|parameter| {
                            parameter.child_by_field_name("name").is_some_and(|name| {
                                rust_node_text(name, self.source).trim() == spelling
                            })
                        })
                })
            {
                return true;
            }
            ancestor = scope.parent();
        }
        false
    }

    fn name_is_shadowed(&self, node: Node<'tree>) -> bool {
        let spelling = rust_node_text(node, self.source).trim();
        if self.name_has_lexical_competitor(node, spelling) {
            return true;
        }
        let rust = resolve_analyzer::<RustAnalyzer>(self.analyzer)
            .expect("Rust conversion requires a Rust analyzer");
        let imports = brokk_bifrost_rust::lexical_scope::visible_import_binder_in_tree_with(
            rust.inner.adapter().lexical_caches(),
            self.root,
            self.source,
            node.start_byte(),
        );
        imports.bindings.contains_key(spelling) && {
            let paths = brokk_bifrost_rust::lexical_scope::visible_import_paths_in_tree_with(
                rust.inner.adapter().lexical_caches(),
                self.root,
                self.source,
                node.start_byte(),
                spelling,
            );
            paths.is_empty()
                || paths.iter().any(|path| {
                    let parts = path.iter().map(String::as_str).collect::<Vec<_>>();
                    parts.last() != Some(&spelling)
                        || !matches!(
                            parts.as_slice(),
                            ["std" | "alloc", "string", "String"]
                                | ["std" | "alloc", "vec", "Vec"]
                                | ["std" | "alloc", "boxed", "Box"]
                                | ["std" | "core", "option", "Option"]
                                | ["std" | "core", "result", "Result"]
                        )
                        || imports.bindings.contains_key(parts[0])
                        || self.name_has_lexical_competitor(node, parts[0])
                })
        }
    }

    fn prelude_contains_type(&self, name: &str) -> bool {
        let rust = resolve_analyzer::<RustAnalyzer>(self.analyzer)
            .expect("Rust conversion requires a Rust analyzer");
        let scope = AnalyzerQueryScope::new(rust);
        brokk_bifrost_rust::graph_support::reference_context_of(rust, scope.token(), self.file)
            .implicit_prelude_contains_type(name)
            .is_ok_and(|contains| contains)
    }

    fn standard_type_for_path(&self, node: Node<'tree>, parts: &[&str]) -> Option<&'static str> {
        let name = match parts {
            ["std" | "alloc", "string", "String"] => "String",
            ["std" | "alloc", "vec", "Vec"] => "Vec",
            ["std" | "alloc", "boxed", "Box"] => "Box",
            ["std" | "core", "option", "Option"] => "Option",
            ["std" | "core", "result", "Result"] => "Result",
            ["std" | "core", "ops", name] => match *name {
                "Add" => "Add",
                "Sub" => "Sub",
                "Mul" => "Mul",
                "Div" => "Div",
                "Rem" => "Rem",
                "BitAnd" => "BitAnd",
                "BitOr" => "BitOr",
                "BitXor" => "BitXor",
                "Shl" => "Shl",
                "Shr" => "Shr",
                _ => return None,
            },
            _ => return None,
        };
        let root = parts[0];
        if self.name_has_lexical_competitor(node, root) {
            return None;
        }
        let rust = resolve_analyzer::<RustAnalyzer>(self.analyzer)?;
        let imports = brokk_bifrost_rust::lexical_scope::visible_import_declarations_in_tree_with(
            rust.inner.adapter().lexical_caches(),
            self.root,
            self.source,
            node.start_byte(),
            root,
        );
        let explicit = matches!(imports.as_slice(), [import] if import.path.as_ref().is_some_and(|path| {
            path.kind == Some(brokk_bifrost_core::analyzer::model::StructuredImportPathKind::ExternCrate)
                && path.segments == [root]
        }));
        if !imports.is_empty() && !explicit {
            return None;
        }
        let routes = rust.file_routes(self.file, None).ok()?;
        if !routes.is_complete() {
            return None;
        }
        if routes.type_root_identity(self.file, root).is_some() {
            return None;
        }
        let implicit = match root {
            "std" => self.prelude_contains_type("String"),
            "core" => self.prelude_contains_type("Option"),
            _ => false,
        };
        (implicit || explicit).then_some(name)
    }

    fn standard_nominal_name(&self, node: Node<'tree>) -> Option<&'static str> {
        let base = if node.kind() == "generic_type" {
            node.child_by_field_name("type")?
        } else {
            node
        };
        let segments = brokk_bifrost_rust::graph_support::rust_path_segments(base)?;
        let parts = segments
            .iter()
            .map(|segment| rust_node_text(*segment, self.source))
            .collect::<Vec<_>>();
        if parts.len() > 1 {
            return self.standard_type_for_path(base, &parts);
        }
        let name = *parts.first()?;
        let canonical = match name {
            "String" => "String",
            "Vec" => "Vec",
            "Box" => "Box",
            "Option" => "Option",
            "Result" => "Result",
            _ => return None,
        };
        if self.name_has_lexical_competitor(base, name) {
            return None;
        }
        let rust = resolve_analyzer::<RustAnalyzer>(self.analyzer)?;
        let imports = brokk_bifrost_rust::lexical_scope::visible_import_declarations_in_tree_with(
            rust.inner.adapter().lexical_caches(),
            self.root,
            self.source,
            base.start_byte(),
            name,
        );
        if let [import] = imports.as_slice() {
            let path = import.path.as_ref()?;
            return self.standard_type_for_path(
                base,
                &path.segments.iter().map(String::as_str).collect::<Vec<_>>(),
            );
        }
        (imports.is_empty() && self.prelude_contains_type(name)).then_some(canonical)
    }

    fn names_unshadowed_prelude_type(&self, node: Node<'tree>) -> bool {
        self.standard_nominal_name(node).is_some()
    }

    fn nominal_type(&self, node: Node<'tree>) -> Result<RustConversionType, ConversionUnknown> {
        if let Some(name) = self.standard_nominal_name(node) {
            // Capturing the snapshot records Models even when activation is absent.
            let snapshot = self
                .analyzer
                .active_semantic_model_snapshot()
                .ok_or(ConversionUnknown::UnresolvedTargetType)?;
            let overlay = snapshot
                .semantic_model_overlay()
                .ok_or(ConversionUnknown::UnresolvedTargetType)?;
            let symbol = super::crate_identity::RustOverlayCrates::new(Some(overlay))
                .referenceable_symbol(match name {
                    "String" => "std.string.String",
                    "Result" => "std.result.Result",
                    "Option" => "std.option.Option",
                    "Vec" => "std.vec.Vec",
                    "Box" => "std.boxed.Box",
                    _ => return Err(ConversionUnknown::UnresolvedTargetType),
                })
                .ok_or(ConversionUnknown::UnresolvedTargetType)?;
            return Ok(RustConversionType::Model {
                model_set: snapshot.active_models().active_model_set_hash().to_owned(),
                symbol: symbol.id.clone(),
                arguments: Vec::new(),
            });
        }
        let name_node = node.child_by_field_name("name").unwrap_or(node);
        let resolved = self.resolve_declaration(name_node)?;
        // A type name may resolve to a trait, alias, or generic declaration.
        // None of those establishes a concrete nominal type without additional
        // obligations. Inspect the exact declaration, not its rendered name.
        let declaration = resolved.node()?;
        RustTypeContext {
            analyzer: self.analyzer,
            sources: self.sources,
            file: resolved.unit.source(),
            source: &resolved.source,
            root: resolved.tree.root_node(),
        }
        .supported_type_context(declaration)?;
        if declaration.has_error()
            || !matches!(
                declaration.kind(),
                "struct_item" | "enum_item" | "union_item"
            )
        {
            return Err(ConversionUnknown::UnsupportedConversion);
        }
        CALL_ARGUMENT_CONVERSION_PROVER.validate_owner(declaration)?;
        Ok(RustConversionType::Declaration(resolved.unit))
    }

    /// Whether the type name at `node` resolves to one struct, enum or union,
    /// generic or not. Such a type is never a reference.
    fn names_value_type_declaration(&self, node: Node<'tree>) -> bool {
        if self.names_unshadowed_prelude_type(node) {
            return true;
        }
        let name_node = node.child_by_field_name("name").unwrap_or(node);
        self.resolve_declaration(name_node).is_ok_and(|resolved| {
            resolved.node().is_ok_and(|declaration| {
                !declaration.has_error()
                    && matches!(
                        declaration.kind(),
                        "struct_item" | "enum_item" | "union_item"
                    )
            })
        })
    }

    /// Prove a result from the nested call's own complete selection.
    /// Bind a simple generic impl target from the exact receiver application.
    /// Bounds and non-parameter target arguments require applicability evidence.
    fn impl_result_bindings(
        &self,
        declaration: Node<'tree>,
        receiver: &RustConversionType,
    ) -> Result<
        std::collections::HashMap<String, crate::analyzer::semantic_model::TypeRef>,
        ConversionUnknown,
    > {
        use crate::analyzer::semantic_model::TypeRef;
        let mut bindings = std::collections::HashMap::new();
        for (name, actual) in self.impl_parameter_arguments(declaration, receiver)? {
            let value = match actual {
                RustConversionType::Primitive(primitive) => TypeRef::Named {
                    name: format!(
                        "core.primitive.{}",
                        match primitive {
                            RustPrimitive::Bool => "bool",
                            RustPrimitive::Char => "char",
                            RustPrimitive::Str => "str",
                            RustPrimitive::U8 => "u8",
                            RustPrimitive::U16 => "u16",
                            RustPrimitive::U32 => "u32",
                            RustPrimitive::U64 => "u64",
                            RustPrimitive::U128 => "u128",
                            RustPrimitive::Usize => "usize",
                            RustPrimitive::I8 => "i8",
                            RustPrimitive::I16 => "i16",
                            RustPrimitive::I32 => "i32",
                            RustPrimitive::I64 => "i64",
                            RustPrimitive::I128 => "i128",
                            RustPrimitive::Isize => "isize",
                            RustPrimitive::F32 => "f32",
                            RustPrimitive::F64 => "f64",
                        }
                    ),
                    arguments: vec![],
                    nullable: false,
                },
                RustConversionType::Model {
                    symbol, arguments, ..
                } if arguments.is_empty() => TypeRef::Declared {
                    id: symbol.clone(),
                    arguments: vec![],
                    nullable: false,
                },
                _ => return Err(ConversionUnknown::GenericSubstitution),
            };
            bindings.insert(name, value);
        }
        Ok(bindings)
    }

    fn impl_parameter_arguments<'argument, C: SelectedTypeCarrier>(
        &self,
        declaration: Node<'tree>,
        receiver: &'argument C,
    ) -> Result<Vec<(String, &'argument C)>, ConversionUnknown> {
        let owner = declaration
            .parent()
            .and_then(|list| list.parent())
            .filter(|owner| owner.kind() == "impl_item")
            .ok_or(ConversionUnknown::GenericSubstitution)?;
        if has_type_where_predicates(owner) || has_non_lifetime_parameters(declaration) {
            return Err(ConversionUnknown::GenericSubstitution);
        }
        let target = owner
            .child_by_field_name("type")
            .filter(|target| target.kind() == "generic_type")
            .ok_or(ConversionUnknown::GenericSubstitution)?;
        let base = target
            .child_by_field_name("type")
            .ok_or(ConversionUnknown::GenericSubstitution)?;
        let resolved = self.resolve_declaration(base)?;
        let (actual, arguments) = receiver
            .applied_parts()
            .ok_or(ConversionUnknown::GenericSubstitution)?;
        if actual.declaration_id() != resolved.unit.declaration_id() {
            return Err(ConversionUnknown::GenericSubstitution);
        }
        let parameters = owner
            .child_by_field_name("type_parameters")
            .ok_or(ConversionUnknown::GenericSubstitution)?;
        let mut names = Vec::new();
        for parameter in parameters.named_children(&mut parameters.walk()) {
            if parameter.kind() == "lifetime_parameter" {
                continue;
            }
            if parameter.kind() != "type_parameter"
                || parameter.child_by_field_name("bounds").is_some()
            {
                return Err(ConversionUnknown::GenericSubstitution);
            }
            names.push(rust_node_text(
                parameter
                    .child_by_field_name("name")
                    .ok_or(ConversionUnknown::GenericSubstitution)?,
                self.source,
            ));
        }
        let application = target
            .child_by_field_name("type_arguments")
            .ok_or(ConversionUnknown::GenericSubstitution)?;
        let written = application
            .named_children(&mut application.walk())
            .filter(|arg| arg.kind() != "lifetime")
            .collect::<Vec<_>>();
        if names.len() != arguments.len() || written.len() != names.len() {
            return Err(ConversionUnknown::GenericSubstitution);
        }
        let mut bindings = Vec::new();
        for (written, actual) in written.into_iter().zip(arguments) {
            let name = rust_node_text(written, self.source);
            if written.kind() != "type_identifier"
                || !names.contains(&name)
                || bindings.iter().any(|(bound, _)| bound == name)
            {
                return Err(ConversionUnknown::GenericSubstitution);
            }
            bindings.push((name.to_owned(), actual));
        }
        Ok(bindings)
    }

    fn collect_operator_candidates(
        &self,
        trait_name: &str,
    ) -> Result<Vec<(ProjectFile, std::ops::Range<usize>)>, ConversionUnknown> {
        use brokk_bifrost_rust::graph_support::RustFactSource;
        let unknown = ConversionUnknown::UnsupportedExpression;
        let rust = resolve_analyzer::<RustAnalyzer>(self.analyzer).ok_or(unknown)?;
        let spellings =
            super::trait_applicability::workspace_trait_spellings(self.analyzer, rust, trait_name)
                .ok_or(unknown)?;
        let mut files = std::collections::HashSet::new();
        let live = rust.live_blobs();
        for spelling in &spellings {
            if super::trait_applicability::macro_may_name_trait(rust, spelling).ok_or(unknown)? {
                return Err(unknown);
            }
            for row in rust
                .rust_unresolved_trait_impl_files(spelling)
                .map_err(|_| unknown)?
            {
                files.extend(live.paths_for_oid(row.impl_blob));
            }
        }
        let mut headers = Vec::new();
        for file in files {
            let parsed = self.sources.source(self.analyzer, &file).ok_or(unknown)?;
            let context = RustTypeContext {
                analyzer: self.analyzer,
                sources: self.sources,
                file: &file,
                source: &parsed.source,
                root: parsed.tree.root_node(),
            };
            let mut pending = vec![parsed.tree.root_node()];
            while let Some(node) = pending.pop() {
                if node.kind() != "impl_item" {
                    pending.extend(node.named_children(&mut node.walk()));
                    continue;
                }
                let Some(trait_node) = node.child_by_field_name("trait") else {
                    continue;
                };
                let head = if trait_node.kind() == "generic_type" {
                    trait_node.child_by_field_name("type").ok_or(unknown)?
                } else {
                    trait_node
                };
                // Operators dispatch through core::ops, never a workspace trait
                // that happens to have the same identifier.
                if context.resolve_declaration(head).is_ok() {
                    continue;
                }
                let segments =
                    brokk_bifrost_rust::graph_support::rust_path_segments(head).ok_or(unknown)?;
                let parts = segments
                    .iter()
                    .map(|n| rust_node_text(*n, &parsed.source))
                    .collect::<Vec<_>>();
                if !parts.last().is_some_and(|name| spellings.contains(*name)) {
                    continue;
                }
                let identity = if parts.len() > 1 {
                    context.standard_type_for_path(head, &parts)
                } else {
                    let imports =
                        brokk_bifrost_rust::lexical_scope::visible_import_declarations_in_tree_with(
                            rust.inner.adapter().lexical_caches(),
                            context.root,
                            context.source,
                            head.start_byte(),
                            parts[0],
                        );
                    if let [import] = imports.as_slice() {
                        import.path.as_ref().and_then(|path| {
                            context.standard_type_for_path(
                                head,
                                &path.segments.iter().map(String::as_str).collect::<Vec<_>>(),
                            )
                        })
                    } else {
                        None
                    }
                };
                if identity != Some(trait_name) {
                    return Err(unknown);
                }
                headers.push((file.clone(), node.byte_range()));
            }
        }
        Ok(headers)
    }

    /// Whether an impl target's written shape can denote `actual`, decided
    /// structurally before any generic argument is resolved, so an unrelated
    /// impl such as `impl<T> Add for &Vector<T>` is skipped rather than
    /// aborting the search. False only when the shapes provably differ; an
    /// undecidable shape (an unresolved name, possibly a type parameter) stays
    /// a candidate and its later resolution fails closed.
    fn impl_target_may_denote(&self, target: Node<'tree>, actual: &RustConversionType) -> bool {
        let nominal = |name: Node<'tree>, actual: &RustConversionType| {
            let Ok(resolved) = self.resolve_declaration(name) else {
                return true;
            };
            match actual {
                RustConversionType::Declaration(unit)
                | RustConversionType::AppliedDeclaration {
                    declaration: unit, ..
                } => unit.declaration_id() == resolved.unit.declaration_id(),
                _ => false,
            }
        };
        let (mut target, mut actual) = (target, actual);
        loop {
            match (target.kind(), actual) {
                ("reference_type", RustConversionType::Reference { mutable, referent }) => {
                    if rust_reference_is_mutable(target) != *mutable {
                        return false;
                    }
                    let Some(next) = rust_reference_type_referent(target) else {
                        return true;
                    };
                    (target, actual) = (next, referent.as_ref());
                }
                ("reference_type", _) => return false,
                ("generic_type", _) => {
                    return target
                        .child_by_field_name("type")
                        .is_none_or(|base| nominal(base, actual));
                }
                ("type_identifier" | "scoped_type_identifier", _) => {
                    return nominal(target, actual);
                }
                ("tuple_type", RustConversionType::Tuple(_))
                | (
                    "array_type",
                    RustConversionType::Array { .. } | RustConversionType::Slice { .. },
                )
                | ("unit_type", RustConversionType::Unit) => return true,
                ("tuple_type" | "array_type" | "unit_type", _) => return false,
                _ => return true,
            }
        }
    }

    fn workspace_operator_output(
        &self,
        left: &RustConversionType,
        right: &RustConversionType,
        trait_name: &str,
        depth: usize,
    ) -> Result<RustConversionType, ConversionUnknown> {
        use brokk_bifrost_analysis::analyzer::usages::common::{
            capture_memo_reads, replay_memo_reads,
        };
        let unknown = ConversionUnknown::UnsupportedExpression;
        let rust = resolve_analyzer::<RustAnalyzer>(self.analyzer).ok_or(unknown)?;
        let memo = rust
            .inner
            .active_query_request_memo::<OperatorCandidatesMemo>();
        let cached = memo.as_ref().and_then(|memo| {
            memo.entries
                .lock()
                .expect("operator memo poisoned")
                .get(trait_name)
                .cloned()
        });
        let candidates = cached.unwrap_or_else(|| {
            let (headers, reads) = capture_memo_reads(self.analyzer, || {
                self.collect_operator_candidates(trait_name)
            });
            let value = std::sync::Arc::new(OperatorCandidates { headers, reads });
            if let Some(memo) = &memo {
                memo.entries
                    .lock()
                    .expect("operator memo poisoned")
                    .entry(trait_name.to_owned())
                    .or_insert_with(|| value.clone())
                    .clone()
            } else {
                value
            }
        });
        replay_memo_reads(&candidates.reads, self.analyzer);
        let mut selected = None;
        for (file, range) in candidates.headers.as_ref().map_err(|error| *error)? {
            let parsed = self.sources.source(self.analyzer, file).ok_or(unknown)?;
            let context = RustTypeContext {
                analyzer: self.analyzer,
                sources: self.sources,
                file,
                source: &parsed.source,
                root: parsed.tree.root_node(),
            };
            let node = context
                .root
                .descendant_for_byte_range(range.start, range.end)
                .ok_or(unknown)?;
            let trait_node = node.child_by_field_name("trait").ok_or(unknown)?;
            let target = node.child_by_field_name("type").ok_or(unknown)?;
            // Decide whether the impl's target can be the left operand before
            // reading anything else from it, so an unrelated impl (an unbound
            // generic, a macro-built or cfg-split Output) is skipped rather
            // than aborting the search.
            if !context.impl_target_may_denote(target, left) {
                continue;
            }
            let generic_target = target.kind() == "generic_type";
            if generic_target {
                let base = target.child_by_field_name("type").ok_or(unknown)?;
                let resolved = context.resolve_declaration(base)?;
                let actual = match left {
                    RustConversionType::Declaration(unit) => unit,
                    RustConversionType::AppliedDeclaration { declaration, .. } => declaration,
                    _ => return Err(unknown),
                };
                if actual.declaration_id() != resolved.unit.declaration_id() {
                    continue;
                }
            } else {
                let owner = context.type_from_node(target, depth + 1)?;
                if !same_type(&owner, left) {
                    continue;
                }
                CALL_ARGUMENT_CONVERSION_PROVER.validate_owner(node)?;
            }
            let body = node.child_by_field_name("body").ok_or(unknown)?;
            let outputs = body
                .named_children(&mut body.walk())
                .filter(|n| {
                    n.kind() == "type_item"
                        && n.child_by_field_name("name")
                            .is_some_and(|name| rust_node_text(name, &parsed.source) == "Output")
                })
                .collect::<Vec<_>>();
            let [output] = outputs.as_slice() else {
                return Err(unknown);
            };
            let bindings = if generic_target {
                context.impl_result_bindings(*output, left)?
            } else {
                std::collections::HashMap::new()
            };
            let owner = left.clone();
            let rhs = if let Some(arguments) = trait_node.child_by_field_name("type_arguments") {
                let args = arguments
                    .named_children(&mut arguments.walk())
                    .filter(|n| n.kind() != "lifetime")
                    .collect::<Vec<_>>();
                let [arg] = args.as_slice() else {
                    return Err(unknown);
                };
                if let Some(bound) = bindings.get(rust_node_text(*arg, &parsed.source)) {
                    self.modeled_return_conversion(bound, depth + 1)?
                } else {
                    context.type_from_node(*arg, depth + 1)?
                }
            } else {
                owner.clone()
            };
            if !same_type(&rhs, right) {
                continue;
            }
            if selected.is_some() {
                return Err(ConversionUnknown::AmbiguousBinding);
            }
            let ty = output.child_by_field_name("type").ok_or(unknown)?;
            selected = Some(
                if let Some(bound) = bindings.get(rust_node_text(ty, &parsed.source)) {
                    self.modeled_return_conversion(bound, depth + 1)?
                } else if ty.kind() == "type_identifier"
                    && rust_node_text(ty, &parsed.source) == "Self"
                {
                    owner
                } else {
                    context.type_from_node(ty, depth + 1)?
                },
            );
        }
        selected.ok_or(unknown)
    }

    fn modeled_return_conversion(
        &self,
        returned: &crate::analyzer::semantic_model::TypeRef,
        depth: usize,
    ) -> Result<RustConversionType, ConversionUnknown> {
        self.modeled_return_conversion_carrier::<RustConversionType>(returned, depth, &mut ())
    }

    fn modeled_return_conversion_carrier<C: SelectedTypeCarrier>(
        &self,
        returned: &crate::analyzer::semantic_model::TypeRef,
        depth: usize,
        proofs: &mut C::Proofs,
    ) -> Result<C, ConversionUnknown> {
        let mut work = SelectedTypeWork::new(MAX_SELECTED_TYPE_WORK);
        self.modeled_return_conversion_with_bindings_carrier(
            returned,
            depth,
            &std::collections::HashMap::new(),
            &mut work,
            proofs,
        )
    }

    #[cfg(test)]
    fn modeled_return_conversion_with_bindings(
        &self,
        returned: &crate::analyzer::semantic_model::TypeRef,
        depth: usize,
        bindings: &std::collections::HashMap<String, RustConversionType>,
        work: &mut SelectedTypeWork,
    ) -> Result<RustConversionType, ConversionUnknown> {
        self.modeled_return_conversion_with_bindings_carrier::<RustConversionType>(
            returned,
            depth,
            bindings,
            work,
            &mut (),
        )
    }

    fn modeled_return_conversion_with_bindings_carrier<C: SelectedTypeCarrier>(
        &self,
        returned: &crate::analyzer::semantic_model::TypeRef,
        depth: usize,
        bindings: &std::collections::HashMap<String, C>,
        work: &mut SelectedTypeWork,
        proofs: &mut C::Proofs,
    ) -> Result<C, ConversionUnknown> {
        use crate::analyzer::semantic_model::TypeRef;
        self.charge_selected_type(depth, work)?;
        match returned {
            TypeRef::TypeParameter { name, .. } => {
                let value = bindings
                    .get(name)
                    .ok_or(ConversionUnknown::GenericSubstitution)?;
                C::binding(proofs, name);
                self.charge_selected_binding(value, depth, work)?;
                Ok(value.clone())
            }
            TypeRef::Named {
                name,
                arguments,
                nullable: false,
            } => {
                if arguments.is_empty()
                    && let Some(primitive) = modeled_primitive(name)
                {
                    return Ok(C::primitive(primitive));
                }
                let snapshot = self
                    .analyzer
                    .active_semantic_model_snapshot()
                    .ok_or(ConversionUnknown::GenericSubstitution)?;
                let overlay = snapshot
                    .semantic_model_overlay()
                    .ok_or(ConversionUnknown::GenericSubstitution)?;
                let symbol = overlay
                    .symbols_named_in_family(name, "rust")
                    .unique()
                    .ok_or(ConversionUnknown::GenericSubstitution)?;
                self.charge_selected_type(depth + 1, work)?;
                self.modeled_type_application_carrier(
                    &symbol.id,
                    arguments,
                    depth + 1,
                    bindings,
                    work,
                    proofs,
                )
            }
            TypeRef::Declared {
                id,
                arguments,
                nullable: false,
            } => {
                self.modeled_type_application_carrier(id, arguments, depth, bindings, work, proofs)
            }
            // A modeled by-reference type does not record Rust mutability,
            // so `&T` and `&mut T` are indistinguishable here: reading it as
            // a shared reference would report an identity where the real
            // conversion is a reborrow. Unknown until the model carries it.
            _ => Err(ConversionUnknown::GenericSubstitution),
        }
    }

    /// Both Named and Declared applications interpret the same borrowed
    /// arguments; cloning an unchecked model subtree would bypass the budget.
    fn modeled_type_application_carrier<C: SelectedTypeCarrier>(
        &self,
        id: &str,
        arguments: &[crate::analyzer::semantic_model::TypeRef],
        depth: usize,
        bindings: &std::collections::HashMap<String, C>,
        work: &mut SelectedTypeWork,
        proofs: &mut C::Proofs,
    ) -> Result<C, ConversionUnknown> {
        let arguments = arguments
            .iter()
            .enumerate()
            .map(|(index, argument)| {
                C::child(self.analyzer, proofs, index, |proofs| {
                    self.modeled_return_conversion_with_bindings_carrier(
                        argument,
                        depth + 1,
                        bindings,
                        work,
                        proofs,
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.complete_selected_model_type_carrier(id, arguments, depth, work, proofs)
    }

    fn call_result_proof(
        &self,
        call: Node<'tree>,
        depth: usize,
    ) -> Result<RustResultProof, ConversionUnknown> {
        if let Some(function) = call
            .child_by_field_name("function")
            .filter(|function| function.kind() == "field_expression")
            && let Some(receiver) = function.child_by_field_name("value")
            && let Ok(exact @ RustConversionType::Model { .. }) =
                self.expression_type(receiver, depth + 1)
        {
            let member = function
                .child_by_field_name("field")
                .ok_or(ConversionUnknown::UnsupportedExpression)?;
            let member = rust_node_text(member, self.source);
            let modeled = self.sources.rust_modeled_result(
                self.analyzer,
                self.file,
                call.byte_range(),
                &exact,
                member,
                depth,
                || {
                    self.analyzer
                        .active_semantic_model_snapshot()
                        .ok_or(ConversionUnknown::UnsupportedExpression)?;
                    let proof = super::std_types::RustTypeProof::new(self.analyzer)
                        .ok_or(ConversionUnknown::UnsupportedExpression)?;
                    let returned = if member == "clone" {
                        proof.modeled_clone_result(self.file, call.byte_range(), depth + 1)
                    } else {
                        proof.modeled_result(self.file, call.byte_range(), depth + 1)
                    }
                    .ok_or(ConversionUnknown::UnsupportedExpression)?;
                    self.modeled_return_conversion(&returned, depth + 1)
                },
            )?;
            return Ok(RustResultProof {
                shape: DerefShape::from_exact(&modeled),
                exact: Ok(modeled),
            });
        }
        let resolved = self.result_function(call, depth + 1)?;
        let declaration = resolved.node().map_err(source_type_error)?;
        let Some(return_type) = declaration.child_by_field_name("return_type") else {
            return Ok(RustResultProof {
                exact: CALL_ARGUMENT_CONVERSION_PROVER
                    .validate_owner(declaration)
                    .map(|()| RustConversionType::Unit),
                shape: DerefShape {
                    reference: false,
                    innermost: Innermost::Builtin,
                },
            });
        };
        let declaration_context = RustTypeContext {
            analyzer: self.analyzer,
            sources: self.sources,
            file: resolved.unit.source(),
            source: &resolved.source,
            root: resolved.tree.root_node(),
        };
        declaration_context.supported_macro_context(return_type)?;
        // result_function proved the receiver equals the written impl owner.
        // Peel only built-in references: following a user Deref here would
        // silently turn an unknown conversion into an exact answer.
        let mut returned = return_type;
        let mut references = Vec::new();
        while returned.kind() == "reference_type" {
            references.push(rust_reference_is_mutable(returned));
            returned = rust_reference_type_referent(returned)
                .ok_or(ConversionUnknown::UnsupportedConversion)?;
        }
        if returned.kind() == "type_identifier"
            && rust_node_text(returned, &resolved.source) != "Self"
            && let Some(receiver) = call
                .child_by_field_name("function")
                .filter(|function| function.kind() == "field_expression")
                .and_then(|function| function.child_by_field_name("value"))
            && let Ok(mut actual) = self.expression_type(receiver, depth + 1)
        {
            while let RustConversionType::Reference { referent, .. } = actual {
                actual = *referent;
            }
            if let Ok(bindings) = declaration_context.impl_result_bindings(declaration, &actual) {
                use crate::analyzer::semantic_model::TypeRef;
                let returned = TypeRef::TypeParameter {
                    name: rust_node_text(returned, &resolved.source).to_owned(),
                };
                if let Some(TypeRef::Named {
                    name,
                    arguments,
                    nullable: false,
                }) = super::trait_applicability::substitute(&returned, &bindings, 16)
                    && arguments.is_empty()
                    && let Some(primitive) = modeled_primitive(&name)
                {
                    let mut exact = RustConversionType::Primitive(primitive);
                    for mutable in references.into_iter().rev() {
                        exact = RustConversionType::Reference {
                            mutable,
                            referent: Box::new(exact),
                        };
                    }
                    return Ok(RustResultProof {
                        shape: DerefShape::from_exact(&exact),
                        exact: Ok(exact),
                    });
                }
            }
        }
        if returned.kind() == "type_identifier"
            && rust_node_text(returned, &resolved.source) == "Self"
        {
            let receiver = call
                .child_by_field_name("function")
                .filter(|function| function.kind() == "field_expression")
                .and_then(|function| function.child_by_field_name("value"))
                .ok_or(ConversionUnknown::UnsupportedExpression)?;
            let mut exact = self.expression_type(receiver, depth + 1)?;
            while let RustConversionType::Reference { referent, .. } = exact {
                exact = *referent;
            }
            for mutable in references.into_iter().rev() {
                exact = RustConversionType::Reference {
                    mutable,
                    referent: Box::new(exact),
                };
            }
            return Ok(RustResultProof {
                shape: DerefShape::from_exact(&exact),
                exact: Ok(exact),
            });
        }
        Ok(RustResultProof {
            exact: declaration_context
                .supported_type_context(return_type)
                .and_then(|()| declaration_context.type_from_node(return_type, depth + 1))
                .map_err(source_type_error),
            shape: declaration_context.type_shape(return_type),
        })
    }

    /// The `let` or parameter declaration that binds the identifier `node`,
    /// when its pattern is a plain identifier.
    fn binding_declaration(&self, node: Node<'tree>) -> Result<Node<'tree>, ConversionUnknown> {
        let name = rust_node_text(node, self.source).trim();
        let binding = self
            .sources
            .lexical_binding(self.analyzer, self.file, node, self.source, name)
            .ok_or(ConversionUnknown::UnresolvedSourceType)?;
        let definition = match binding {
            LexicalBindingResolution::Parameter(definition)
            | LexicalBindingResolution::OtherLocal(definition) => definition,
        };
        let declaration = self
            .root
            .named_descendant_for_byte_range(
                definition.declaration_range.start_byte,
                definition.declaration_range.end_byte,
            )
            .filter(|candidate| {
                candidate.start_byte() == definition.declaration_range.start_byte
                    && candidate.end_byte() == definition.declaration_range.end_byte
            })
            .ok_or(ConversionUnknown::UnresolvedSourceType)?;
        let pattern = declaration
            .child_by_field_name("pattern")
            .ok_or(ConversionUnknown::UnresolvedSourceType)?;
        if pattern.kind() != "identifier" {
            return Err(ConversionUnknown::UnsupportedExpression);
        }
        Ok(declaration)
    }

    fn declared_value_item(
        &self,
        node: Node<'tree>,
    ) -> Result<ResolvedDeclaration, ConversionUnknown> {
        let resolved =
            self.resolve_declaration(node.child_by_field_name("name").unwrap_or(node))?;
        if !matches!(resolved.node()?.kind(), "static_item" | "const_item") {
            return Err(ConversionUnknown::UnresolvedSourceType);
        }
        Ok(resolved)
    }

    /// The one free, non-async function the identifier or plain qualified
    /// callee (`m::f`, `crate::m::f`) of `call` names.
    /// Methods and associated functions are refused, because their return
    /// type may name `Self`.
    fn formal_is_inferred_from_actual(
        &self,
        formal: Node<'tree>,
        actual: ConversionSyntax<'_>,
        actual_context: &RustTypeContext<'_, '_>,
    ) -> bool {
        let Some(mut ty) = formal.child_by_field_name("type") else {
            return false;
        };
        if ty.kind() == "reference_type" {
            let Some(referent) = rust_reference_type_referent(ty) else {
                return false;
            };
            ty = referent;
        }
        if ty.kind() != "type_identifier" {
            return false;
        }
        let name = rust_node_text(ty, self.source);
        let Some(parameters) = formal.parent().filter(|node| node.kind() == "parameters") else {
            return false;
        };
        let Some(owner) = parameters
            .parent()
            .filter(|node| node.kind() == "function_item")
        else {
            return false;
        };
        let Some(generics) = owner.child_by_field_name("type_parameters") else {
            return false;
        };
        if !generics
            .named_children(&mut generics.walk())
            .any(|parameter| {
                parameter.kind() == "type_parameter"
                    && parameter
                        .child_by_field_name("name")
                        .is_some_and(|node| rust_node_text(node, self.source) == name)
            })
        {
            return false;
        }
        if self.supported_macro_context(formal).is_err()
            || actual_context.supported_macro_context(actual.node).is_err()
        {
            return false;
        }
        let mentions = |root: Node<'_>| {
            let mut pending = vec![root];
            while let Some(node) = pending.pop() {
                if matches!(node.kind(), "type_identifier" | "identifier")
                    && rust_node_text(node, self.source) == name
                {
                    return true;
                }
                pending.extend(node.named_children(&mut node.walk()));
            }
            false
        };
        if owner
            .child_by_field_name("return_type")
            .is_some_and(mentions)
            || parameters
                .named_children(&mut parameters.walk())
                .take_while(|node| node.start_byte() < formal.start_byte())
                .filter_map(|node| node.child_by_field_name("type"))
                .any(mentions)
        {
            return false;
        }
        let mut ancestor = actual.node.parent();
        let call = loop {
            let Some(node) = ancestor else {
                return false;
            };
            if node.kind() == "call_expression" {
                break node;
            }
            ancestor = node.parent();
        };
        let Some(function) = call.child_by_field_name("function") else {
            return false;
        };
        let mut pending = vec![function];
        while let Some(node) = pending.pop() {
            if matches!(node.kind(), "generic_function" | "generic_type") {
                return false;
            }
            pending.extend(node.named_children(&mut node.walk()));
        }
        // A direct free-function reference retains the generic binder. A
        // function pointer may already have fixed it at an earlier assignment.
        actual_context.free_function(call).is_ok_and(|resolved| {
            resolved.unit.source() == self.file
                && resolved
                    .node()
                    .is_ok_and(|node| node.byte_range() == owner.byte_range())
        })
    }

    fn expression_opaque_identity(
        &self,
        node: Node<'tree>,
        depth: usize,
    ) -> Option<OpaqueTypeIdentity> {
        if depth >= MAX_TYPE_DEPTH || node.has_error() {
            return None;
        }
        match node.kind() {
            "identifier" => {
                let declaration = self.binding_declaration(node).ok()?;
                if let Some(ty) = declaration.child_by_field_name("type") {
                    self.opaque_type_identity(ty, depth + 1)
                } else {
                    self.expression_opaque_identity(
                        declaration.child_by_field_name("value")?,
                        depth + 1,
                    )
                }
            }
            "reference_expression" => Some(OpaqueTypeIdentity::Reference(Box::new(
                self.expression_opaque_identity(rust_reference_expression_value(node)?, depth + 1)?,
            ))),
            "call_expression" => {
                let resolved = self.free_function(node).ok()?;
                let declaration = resolved.node().ok()?;
                let context = RustTypeContext {
                    analyzer: self.analyzer,
                    sources: self.sources,
                    file: resolved.unit.source(),
                    source: &resolved.source,
                    root: resolved.tree.root_node(),
                };
                context.opaque_type_identity(
                    declaration.child_by_field_name("return_type")?,
                    depth + 1,
                )
            }
            "parenthesized_expression" => {
                self.expression_opaque_identity(node.named_child(0)?, depth + 1)
            }
            _ => None,
        }
    }

    fn opaque_type_identity(&self, node: Node<'tree>, depth: usize) -> Option<OpaqueTypeIdentity> {
        if depth >= MAX_TYPE_DEPTH || node.has_error() || self.supported_type_context(node).is_err()
        {
            return None;
        }
        if let Ok(known) = self.type_from_node(node, depth) {
            return Some(OpaqueTypeIdentity::Known(known));
        }
        if node.kind() == "reference_type" {
            return Some(OpaqueTypeIdentity::Reference(Box::new(
                self.opaque_type_identity(rust_reference_type_referent(node)?, depth + 1)?,
            )));
        }
        let (base, arguments) = if node.kind() == "generic_type" {
            let args = node.child_by_field_name("type_arguments")?;
            let identities = args
                .named_children(&mut args.walk())
                .filter(|arg| arg.kind() != "lifetime")
                .map(|arg| self.opaque_type_identity(arg, depth + 1))
                .collect::<Option<Vec<_>>>()?;
            (node.child_by_field_name("type")?, identities)
        } else {
            (node, Vec::new())
        };
        if let Some(name) = self.standard_nominal_name(base) {
            return Some(OpaqueTypeIdentity::Path(
                OpaqueTypeRoot::Prelude,
                vec![name.to_owned()],
                arguments,
            ));
        }
        let segments = brokk_bifrost_rust::graph_support::rust_path_segments(base)?;
        let root = *segments.first()?;
        let name = rust_node_text(root, self.source);
        let rust = resolve_analyzer::<RustAnalyzer>(self.analyzer)?;
        if self.name_has_lexical_competitor(root, name) {
            return None;
        }
        let imports = brokk_bifrost_rust::lexical_scope::visible_import_declarations_in_tree_with(
            rust.inner.adapter().lexical_caches(),
            self.root,
            self.source,
            root.start_byte(),
            name,
        );
        let mut canonical_path = segments
            .iter()
            .map(|segment| rust_node_text(*segment, self.source).to_owned())
            .collect::<Vec<_>>();
        let binder = if let [import] = imports.as_slice() {
            let span = import.binder_span?;
            let same_binder =
                OpaqueTypeRoot::Import(self.file.clone(), span.start_byte, span.end_byte);
            let canonical = import.path.as_ref().and_then(|path| {
                let dependency = path.segments.first()?;
                let visible = brokk_bifrost_rust::lexical_scope::visible_import_binder_in_tree_with(
                    rust.inner.adapter().lexical_caches(),
                    self.root,
                    self.source,
                    root.start_byte(),
                );
                if visible.bindings.contains_key(dependency)
                    || self.name_has_lexical_competitor(root, dependency)
                {
                    return None;
                }
                let routes = rust.file_routes(self.file, None).ok()?;
                if !routes.is_complete() {
                    return None;
                }
                let (unit, edition) = routes.type_root_identity(self.file, dependency)?;
                (edition.parse::<u16>().ok()? >= 2018).then_some((unit, path))
            });
            if let Some((unit, path)) = canonical {
                canonical_path = path
                    .segments
                    .iter()
                    .cloned()
                    .chain(canonical_path.into_iter().skip(1))
                    .collect();
                OpaqueTypeRoot::Unit(unit)
            } else {
                same_binder
            }
        } else {
            if !imports.is_empty() || self.name_is_shadowed(root) {
                return None;
            }
            let routes = rust.file_routes(self.file, None).ok()?;
            if !routes.is_complete() {
                return None;
            }
            let (unit, edition) = routes.type_root_identity(self.file, name)?;
            if edition.parse::<u16>().ok()? < 2018 {
                return None;
            }
            OpaqueTypeRoot::Unit(unit)
        };
        Some(OpaqueTypeIdentity::Path(binder, canonical_path, arguments))
    }

    /// Resolve this nested call itself, rather than borrowing the outer
    /// callee's dispatch evidence. Definition selection alone does not prove
    /// receiver safety: require the written receiver to match the impl owner.
    fn result_function(
        &self,
        call: Node<'tree>,
        depth: usize,
    ) -> Result<ResolvedDeclaration, ConversionUnknown> {
        let function = call
            .child_by_field_name("function")
            .ok_or(ConversionUnknown::UnsupportedExpression)?;
        if function.kind() != "field_expression" {
            return self.free_function(call);
        }
        let method = function
            .child_by_field_name("field")
            .ok_or(ConversionUnknown::UnsupportedExpression)?;
        let receiver = function
            .child_by_field_name("value")
            .ok_or(ConversionUnknown::UnsupportedExpression)?;
        let receiver_type = self.expression_type(receiver, depth + 1)?;
        let mut scope = call;
        while !matches!(scope.kind(), "block" | "source_file") {
            scope = scope
                .parent()
                .ok_or(ConversionUnknown::UnsupportedExpression)?;
        }
        let arity = call
            .child_by_field_name("arguments")
            .ok_or(ConversionUnknown::UnsupportedExpression)?
            .named_children(&mut call.walk())
            .filter(|node| !node.is_extra())
            .count();
        let evidence = self.sources.rust_method_declaration(
            self.analyzer, self.file,
            brokk_bifrost_analysis::analyzer::usages::call_conversion::RustMethodConversionInput {
                receiver: &receiver_type, scope: scope.byte_range(),
                member: rust_node_text(method, self.source), arity, depth,
            }, || {
        let resolved = self
            .resolve_declaration(method)
            .map_err(source_type_error)?;
        let declaration = resolved.node().map_err(source_type_error)?;
        if declaration.kind() != "function_item"
            || declaration.has_error()
            || declaration
                .named_children(&mut declaration.walk())
                .filter(|child| child.kind() == "function_modifiers")
                .any(|modifiers| {
                    modifiers
                        .children(&mut modifiers.walk())
                        .any(|token| token.kind() == "async")
                })
        {
            return Err(ConversionUnknown::UnsupportedExpression);
        }
        if let Some(return_type) = declaration.child_by_field_name("return_type") {
            let mut pending = vec![return_type];
            while let Some(ty) = pending.pop() {
                if matches!(ty.kind(), "abstract_type" | "qualified_type")
                {
                    return Err(ConversionUnknown::GenericSubstitution);
                }
                pending.extend(ty.named_children(&mut ty.walk()));
            }
        }
        let implementation = declaration
            .parent()
            .and_then(|list| list.parent())
            .filter(|owner| owner.kind() == "impl_item");
        let owner = implementation
            .and_then(|owner| owner.child_by_field_name("type"))
            .ok_or(ConversionUnknown::UnsupportedExpression)?;
        let context = RustTypeContext {
            analyzer: self.analyzer,
            sources: self.sources,
            file: resolved.unit.source(),
            source: &resolved.source,
            root: resolved.tree.root_node(),
        };
        let owner_type = context.type_from_node(owner, depth + 1);
        let mut receiver_type = &receiver_type;
        while let RustConversionType::Reference { referent, .. } = receiver_type {
            receiver_type = referent;
        }
        // Only a non-lifetime impl parameter needs substitution. A lifetime-only
        // impl with concrete owner arguments (`impl<'a> Ref<'a, i32>`) keeps the
        // exact-owner validation above; routing it through the binder would lose
        // the proof.
        if implementation.is_some_and(has_non_lifetime_parameters)
            && owner.child_by_field_name("type_arguments").is_some_and(|arguments| {
                arguments
                    .named_children(&mut arguments.walk())
                    .any(|argument| argument.kind() != "lifetime")
            })
        {
            context.impl_result_bindings(declaration, receiver_type)?;
        } else {
            if !same_type(receiver_type, &owner_type?) {
                return Err(ConversionUnknown::UnsupportedExpression);
            }
            CALL_ARGUMENT_CONVERSION_PROVER.validate_owner(declaration)?;
        }
        Ok(brokk_bifrost_analysis::analyzer::usages::call_conversion::ConversionDeclaration {
            unit: resolved.unit, parsed: resolved.parsed, range: resolved.range,
        })
        })?;
        Ok(ResolvedDeclaration {
            unit: evidence.unit,
            parsed: evidence.parsed,
            range: evidence.range,
        })
    }

    fn free_function(&self, call: Node<'tree>) -> Result<ResolvedDeclaration, ConversionUnknown> {
        let function = call
            .child_by_field_name("function")
            .ok_or(ConversionUnknown::UnsupportedExpression)?;
        self.free_function_declaration(function)
    }

    fn free_function_declaration(
        &self,
        function: Node<'tree>,
    ) -> Result<ResolvedDeclaration, ConversionUnknown> {
        if function.kind() != "identifier"
            && !crate::analyzer::rust::semantic::rust_plain_scoped_callee(function)
        {
            return Err(ConversionUnknown::UnsupportedExpression);
        }
        let name_node = function.child_by_field_name("name").unwrap_or(function);
        let resolved = self
            .resolve_declaration(name_node)
            .map_err(source_type_error)?;
        let declaration = resolved.node().map_err(source_type_error)?;
        let is_async = declaration
            .named_children(&mut declaration.walk())
            .filter(|child| child.kind() == "function_modifiers")
            .any(|modifiers| {
                modifiers
                    .children(&mut modifiers.walk())
                    .any(|token| token.kind() == "async")
            });
        let in_impl_or_trait = declaration
            .parent()
            .and_then(|list| list.parent())
            .is_some_and(|owner| matches!(owner.kind(), "impl_item" | "trait_item"));
        if declaration.has_error()
            || declaration.kind() != "function_item"
            || is_async
            || in_impl_or_trait
        {
            return Err(ConversionUnknown::UnsupportedExpression);
        }
        Ok(resolved)
    }

    /// The deref-relevant shape of an expression's type, read from written
    /// type syntax. Lifetimes and lifetime parameters do not change it.
    fn expression_shape(&self, mut node: Node<'tree>, depth: usize) -> DerefShape {
        while node.kind() == "parenthesized_expression" {
            let Some(inner) = node.named_child(0) else {
                return DerefShape::UNKNOWN;
            };
            node = inner;
        }
        if depth >= MAX_TYPE_DEPTH || node.has_error() || node.is_missing() {
            return DerefShape::UNKNOWN;
        }
        match node.kind() {
            "block" => brokk_bifrost_rust::structural::rust_block_tail_expression(node)
                .map_or(DerefShape::UNKNOWN, |tail| {
                    self.expression_shape(tail, depth + 1)
                }),
            "array_expression" | "tuple_expression" => {
                let length = node.child_by_field_name("length");
                let all_builtin = node
                    .named_children(&mut node.walk())
                    .filter(|child| {
                        !child.is_extra() && length.is_none_or(|length| child.id() != length.id())
                    })
                    .all(|child| {
                        matches!(
                            self.expression_shape(child, depth + 1).innermost,
                            Innermost::Builtin
                        )
                    });
                if all_builtin {
                    DerefShape {
                        reference: false,
                        innermost: Innermost::Builtin,
                    }
                } else {
                    DerefShape::UNKNOWN
                }
            }
            "struct_expression" => DerefShape {
                reference: false,
                innermost: Innermost::Nominal,
            },
            "macro_invocation" if self.standard_statement_macro(node) => {
                let Some(path) = node.child_by_field_name("macro") else {
                    return DerefShape::UNKNOWN;
                };
                let Some(segments) = brokk_bifrost_rust::graph_support::rust_path_segments(path)
                else {
                    return DerefShape::UNKNOWN;
                };
                let Some(name) = segments.last() else {
                    return DerefShape::UNKNOWN;
                };
                match rust_node_text(*name, self.source) {
                    "format" | "vec" => DerefShape {
                        reference: false,
                        innermost: Innermost::Builtin,
                    },
                    "dbg" => DerefShape::UNKNOWN,
                    _ => DerefShape {
                        reference: false,
                        innermost: Innermost::Builtin,
                    },
                }
            }
            "integer_literal" | "float_literal" | "boolean_literal" | "char_literal" => {
                DerefShape {
                    reference: false,
                    innermost: Innermost::Builtin,
                }
            }
            "string_literal" | "raw_string_literal" => DerefShape {
                reference: true,
                innermost: Innermost::Builtin,
            },
            "identifier" | "scoped_identifier" => {
                let Ok(declaration) = self.binding_declaration(node) else {
                    let Ok(resolved) = self.declared_value_item(node) else {
                        return DerefShape::UNKNOWN;
                    };
                    let Some(type_node) = resolved
                        .node()
                        .ok()
                        .and_then(|item| item.child_by_field_name("type"))
                    else {
                        return DerefShape::UNKNOWN;
                    };
                    return RustTypeContext {
                        analyzer: self.analyzer,
                        sources: self.sources,
                        file: resolved.unit.source(),
                        source: &resolved.source,
                        root: resolved.tree.root_node(),
                    }
                    .type_shape(type_node);
                };
                if let Some(type_node) = declaration.child_by_field_name("type") {
                    return self.type_shape(type_node);
                }
                match declaration.child_by_field_name("value") {
                    Some(value) if declaration.kind() == "let_declaration" => {
                        self.expression_shape(value, depth + 1)
                    }
                    _ => DerefShape::UNKNOWN,
                }
            }
            "reference_expression" => match rust_reference_expression_value(node) {
                Some(value) => DerefShape {
                    reference: true,
                    innermost: self.expression_shape(value, depth + 1).innermost,
                },
                None => DerefShape::UNKNOWN,
            },
            "self" => self.self_shape(node),
            "field_expression" => self.field_shape(node, depth + 1),
            "call_expression" => self
                .call_result_proof(node, depth + 1)
                .map_or(DerefShape::UNKNOWN, |proof| proof.shape),
            "binary_expression" => {
                self.expression_type(node, depth + 1)
                    .map_or(DerefShape::UNKNOWN, |mut ty| {
                        let mut reference = false;
                        while let RustConversionType::Reference { referent, .. } = ty {
                            reference = true;
                            ty = *referent;
                        }
                        DerefShape {
                            reference,
                            innermost: match ty {
                                RustConversionType::Declaration(_)
                                | RustConversionType::AppliedDeclaration { .. }
                                | RustConversionType::Model { .. } => Innermost::Nominal,
                                _ => Innermost::Builtin,
                            },
                        }
                    })
            }
            _ => DerefShape::UNKNOWN,
        }
    }

    /// The shape of `self` in a method: a reference when the receiver is
    /// `&self` or `&mut self`, around the impl's own type.
    fn self_shape(&self, node: Node<'tree>) -> DerefShape {
        let mut function = None;
        let mut owner = None;
        let mut current = node.parent();
        while let Some(scope) = current {
            match scope.kind() {
                "function_item" if function.is_none() => function = Some(scope),
                "impl_item" => {
                    owner = Some(scope);
                    break;
                }
                _ => {}
            }
            current = scope.parent();
        }
        let (Some(function), Some(owner)) = (function, owner) else {
            return DerefShape::UNKNOWN;
        };
        let Some(receiver) = function
            .child_by_field_name("parameters")
            .and_then(|parameters| {
                brokk_bifrost_core::analyzer::tree_walk::first_named_child_of_kind(
                    parameters,
                    "self_parameter",
                )
            })
        else {
            return DerefShape::UNKNOWN;
        };
        let Some(owner_type) = owner.child_by_field_name("type") else {
            return DerefShape::UNKNOWN;
        };
        let reference = receiver
            .children(&mut receiver.walk())
            .any(|token| token.kind() == "&");
        DerefShape {
            reference,
            innermost: self.type_shape(owner_type).innermost,
        }
    }

    /// The shape of `base.field`: the declared type of the named field of the
    /// struct `base` is or refers to. Fields reached by auto-deref and unread
    /// bases stay unknown.
    fn field_shape(&self, node: Node<'tree>, depth: usize) -> DerefShape {
        let (Some(base), Some(field)) = (
            node.child_by_field_name("value"),
            node.child_by_field_name("field"),
        ) else {
            return DerefShape::UNKNOWN;
        };
        if !matches!(field.kind(), "field_identifier" | "integer_literal") {
            return DerefShape::UNKNOWN;
        }
        if field.kind() == "integer_literal"
            && let Ok(index) = rust_node_text(field, self.source).parse::<usize>()
            && base.kind() == "identifier"
            && let Ok(declaration) = self.binding_declaration(base)
            && declaration.child_by_field_name("type").is_none()
            && let Some(initializer) = declaration.child_by_field_name("value")
            && initializer.kind() == "tuple_expression"
            && let Some(element) = initializer
                .named_children(&mut initializer.walk())
                .filter(|child| !child.is_extra())
                .nth(index)
        {
            return self.expression_shape(element, depth + 1);
        }
        if field.kind() == "integer_literal"
            && let Ok(index) = rust_node_text(field, self.source).parse::<usize>()
            && let Ok(base_type) = self.expression_type(base, depth + 1)
        {
            let mut base_type = &base_type;
            while let RustConversionType::Reference { referent, .. } = base_type {
                base_type = referent;
            }
            if let RustConversionType::Tuple(elements) = base_type
                && let Some(mut element) = elements.get(index)
            {
                let mut reference = false;
                while let RustConversionType::Reference { referent, .. } = element {
                    reference = true;
                    element = referent;
                }
                return DerefShape {
                    reference,
                    innermost: match element {
                        RustConversionType::Declaration(_)
                        | RustConversionType::AppliedDeclaration { .. } => Innermost::Nominal,
                        _ => Innermost::Builtin,
                    },
                };
            }
        }
        let name = rust_node_text(field, self.source).trim();
        let Some(resolved) = self.expression_struct(base, depth) else {
            return DerefShape::UNKNOWN;
        };
        let Some(field_type) = declared_field_type(&resolved, name) else {
            return DerefShape::UNKNOWN;
        };
        RustTypeContext {
            analyzer: self.analyzer,
            sources: self.sources,
            file: resolved.unit.source(),
            source: &resolved.source,
            root: resolved.tree.root_node(),
        }
        .type_shape(field_type)
    }

    /// The one struct an expression's value is, or refers to through
    /// references, with its file parsed.
    fn expression_struct(
        &self,
        mut node: Node<'tree>,
        depth: usize,
    ) -> Option<ResolvedDeclaration> {
        while node.kind() == "parenthesized_expression" {
            node = node.named_child(0)?;
        }
        if depth >= MAX_TYPE_DEPTH || node.has_error() || node.is_missing() {
            return None;
        }
        match node.kind() {
            "struct_expression" => self.type_struct(node.child_by_field_name("name")?),
            "self" => {
                let mut current = node.parent();
                while let Some(scope) = current {
                    if scope.kind() == "impl_item" {
                        return self.type_struct(scope.child_by_field_name("type")?);
                    }
                    current = scope.parent();
                }
                None
            }
            "identifier" => {
                let declaration = self.binding_declaration(node).ok()?;
                match declaration.child_by_field_name("type") {
                    Some(type_node) => self.type_struct(type_node),
                    None if declaration.kind() == "let_declaration" => {
                        self.expression_struct(declaration.child_by_field_name("value")?, depth + 1)
                    }
                    None => None,
                }
            }
            "reference_expression" => {
                self.expression_struct(rust_reference_expression_value(node)?, depth + 1)
            }
            "call_expression" => {
                let resolved = self.free_function(node).ok()?;
                let return_type = resolved.node().ok()?.child_by_field_name("return_type")?;
                RustTypeContext {
                    analyzer: self.analyzer,
                    sources: self.sources,
                    file: resolved.unit.source(),
                    source: &resolved.source,
                    root: resolved.tree.root_node(),
                }
                .type_struct(return_type)
            }
            "field_expression" => {
                let base = node.child_by_field_name("value")?;
                let field = node.child_by_field_name("field")?;
                if !matches!(field.kind(), "field_identifier" | "integer_literal") {
                    return None;
                }
                let name = rust_node_text(field, self.source).trim();
                let resolved = self.expression_struct(base, depth + 1)?;
                let field_type = declared_field_type(&resolved, name)?;
                RustTypeContext {
                    analyzer: self.analyzer,
                    sources: self.sources,
                    file: resolved.unit.source(),
                    source: &resolved.source,
                    root: resolved.tree.root_node(),
                }
                .type_struct(field_type)
            }
            _ => None,
        }
    }

    /// The one struct a written type is, or refers to through references.
    fn type_struct(&self, mut node: Node<'tree>) -> Option<ResolvedDeclaration> {
        while node.kind() == "reference_type" {
            node = rust_reference_type_referent(node)?;
        }
        let name_node = match node.kind() {
            "generic_type" => node.child_by_field_name("type")?,
            "type_identifier" | "scoped_type_identifier" => node,
            _ => return None,
        };
        let name_node = name_node.child_by_field_name("name").unwrap_or(name_node);
        let resolved = self.resolve_declaration(name_node).ok()?;
        let declaration = resolved.node().ok()?;
        (!declaration.has_error() && declaration.kind() == "struct_item").then_some(resolved)
    }

    /// The deref-relevant shape of written type syntax: whether it is a
    /// reference, and what its innermost referent is.
    fn type_shape(&self, mut node: Node<'tree>) -> DerefShape {
        let mut reference = false;
        while node.kind() == "reference_type" {
            reference = true;
            let Some(referent) = rust_reference_type_referent(node) else {
                return DerefShape::UNKNOWN;
            };
            node = referent;
        }
        if matches!(self.standard_nominal_name(node), Some("String" | "Vec")) {
            return DerefShape {
                reference,
                innermost: Innermost::Builtin,
            };
        }
        let innermost = match node.kind() {
            _ if node.has_error() || node.is_missing() => Innermost::Unknown,
            "primitive_type" if self.primitive_type(node).is_ok() => Innermost::Builtin,
            "primitive_type" if self.names_value_type_declaration(node) => Innermost::Nominal,
            "array_type" | "tuple_type" | "unit_type" | "never_type" | "pointer_type"
            | "function_type" => Innermost::Builtin,
            "type_identifier" | "scoped_type_identifier"
                if self.names_value_type_declaration(node) =>
            {
                Innermost::Nominal
            }
            "generic_type"
                if node
                    .child_by_field_name("type")
                    .is_some_and(|base| self.names_value_type_declaration(base)) =>
            {
                Innermost::Nominal
            }
            _ => Innermost::Unknown,
        };
        DerefShape {
            reference,
            innermost,
        }
    }

    /// The one declaration the name at `name_node` resolves to, with its file
    /// parsed so the caller can inspect the exact declaration syntax.
    fn resolve_declaration(
        &self,
        name_node: Node<'tree>,
    ) -> Result<ResolvedDeclaration, ConversionUnknown> {
        let evidence = self.sources.declaration(
            self.analyzer,
            self.file,
            name_node.byte_range(),
            || {
        let name = rust_node_text(name_node, self.source).trim();
        if name.is_empty() {
            return Err(ConversionUnknown::UnresolvedTargetType);
        }
        let requesting = self
            .sources
            .source(self.analyzer, self.file)
            .ok_or(ConversionUnknown::UnresolvedTargetType)?;
        let mut outcomes = resolve_definition_batch_with_source_tree(
            self.analyzer,
            vec![DefinitionLookupRequest {
                file: self.file.clone(),
                line: None,
                column: None,
                start_byte: Some(name_node.start_byte()),
                end_byte: Some(name_node.end_byte()),
            }],
            self.file.clone(),
            std::sync::Arc::clone(&requesting.source),
            Some(requesting.tree.clone()),
        );
        let outcome = outcomes
            .pop()
            .expect("one native declaration request has one outcome");
        if outcome.status != DefinitionLookupStatus::Resolved || !outcome.diagnostics.is_empty() {
            return Err(ConversionUnknown::UnresolvedTargetType);
        }
        let mut candidates = outcome.definitions;
        candidates.sort_by_key(|unit| unit.declaration_id());
        candidates.dedup_by(|left, right| left.declaration_id() == right.declaration_id());
        let [unit] = candidates.as_slice() else {
            return Err(ConversionUnknown::AmbiguousBinding);
        };
        let parsed = self
            .sources
            .source(self.analyzer, unit.source())
            .ok_or(ConversionUnknown::UnresolvedTargetType)?;
        let ranges = self.analyzer.ranges_of(unit);
        let [range] = ranges.as_slice() else {
            return Err(ConversionUnknown::AmbiguousBinding);
        };
        Ok(brokk_bifrost_analysis::analyzer::usages::call_conversion::ConversionDeclaration {
            unit: unit.clone(),
            range: range.start_byte..range.end_byte,
            parsed,
        })
            },
        )?;
        Ok(ResolvedDeclaration {
            unit: evidence.unit,
            parsed: evidence.parsed,
            range: evidence.range,
        })
    }

    fn expression_type(
        &self,
        node: Node<'tree>,
        depth: usize,
    ) -> Result<RustConversionType, ConversionUnknown> {
        self.sources.rust_expression_type(
            self.analyzer,
            self.file,
            node.byte_range(),
            depth,
            || self.expression_type_uncached(node, depth),
        )
    }

    fn expression_type_uncached(
        &self,
        mut node: Node<'tree>,
        depth: usize,
    ) -> Result<RustConversionType, ConversionUnknown> {
        if depth >= MAX_TYPE_DEPTH {
            return Err(self.selected_type_stop(ConversionUnknown::BudgetExhausted));
        }
        if node.has_error() || node.is_missing() || rust_node_is_in_unsafe_context(node) {
            return Err(ConversionUnknown::UnsupportedExpression);
        }
        while node.kind() == "parenthesized_expression" {
            node = node
                .named_child(0)
                .ok_or(ConversionUnknown::UnsupportedExpression)?;
        }
        match node.kind() {
            "boolean_literal" | "char_literal" | "integer_literal" | "float_literal" => {
                match brokk_bifrost_rust::syntax::rust_literal_type(node, self.source) {
                    Some(brokk_bifrost_rust::syntax::RustLiteralType::Exact {
                        primitive,
                        reference_layers,
                    }) => {
                        assert_eq!(reference_layers, 0, "scalar literals are not references");
                        Ok(RustConversionType::Primitive(
                            primitive_for_spelling(primitive)
                                .expect("Rust literal primitive vocabulary"),
                        ))
                    }
                    _ => Err(ConversionUnknown::UnsupportedExpression),
                }
            }

            "struct_expression" => self.nominal_type(
                node.child_by_field_name("name")
                    .ok_or(ConversionUnknown::UnsupportedExpression)?,
            ),
            "identifier" | "scoped_identifier" => {
                let declaration = match self.binding_declaration(node) {
                    Ok(declaration) => declaration,
                    Err(_) => {
                        let resolved = self.declared_value_item(node)?;
                        let type_node = resolved
                            .node()?
                            .child_by_field_name("type")
                            .ok_or(ConversionUnknown::UnresolvedSourceType)?;
                        return RustTypeContext {
                            analyzer: self.analyzer,
                            sources: self.sources,
                            file: resolved.unit.source(),
                            source: &resolved.source,
                            root: resolved.tree.root_node(),
                        }
                        .type_from_node(type_node, depth + 1);
                    }
                };
                if let Some(type_node) = declaration.child_by_field_name("type") {
                    return self
                        .type_from_node(type_node, depth + 1)
                        .map_err(source_type_error);
                }
                // An immutable `let` with no written type has its
                // initializer's type: no coercion applies without an
                // expected type.
                match declaration.child_by_field_name("value") {
                    Some(value) if declaration.kind() == "let_declaration" => {
                        self.expression_type(value, depth + 1)
                    }
                    _ => Err(ConversionUnknown::UnresolvedSourceType),
                }
            }
            // A string literal is `&'static str`; a byte-string literal
            // (`b"..."`, `br"..."`) is a byte-array reference instead.
            "string_literal" | "raw_string_literal"
                if !rust_node_text(node, self.source).starts_with('b') =>
            {
                Ok(RustConversionType::Reference {
                    mutable: false,
                    referent: Box::new(RustConversionType::Primitive(RustPrimitive::Str)),
                })
            }
            "field_expression" => {
                let base = node
                    .child_by_field_name("value")
                    .ok_or(ConversionUnknown::UnsupportedExpression)?;
                let field = node
                    .child_by_field_name("field")
                    .ok_or(ConversionUnknown::UnsupportedExpression)?;
                let resolved = self
                    .expression_struct(base, depth + 1)
                    .ok_or(ConversionUnknown::UnresolvedSourceType)?;
                let field_type =
                    declared_field_type(&resolved, rust_node_text(field, self.source).trim())
                        .ok_or(ConversionUnknown::UnresolvedSourceType)?;
                RustTypeContext {
                    analyzer: self.analyzer,
                    sources: self.sources,
                    file: resolved.unit.source(),
                    source: &resolved.source,
                    root: resolved.tree.root_node(),
                }
                .type_from_node(field_type, depth + 1)
            }
            "binary_expression" => {
                let left = node
                    .child_by_field_name("left")
                    .ok_or(ConversionUnknown::UnsupportedExpression)?;
                let right = node
                    .child_by_field_name("right")
                    .ok_or(ConversionUnknown::UnsupportedExpression)?;
                let operator = node
                    .child_by_field_name("operator")
                    .ok_or(ConversionUnknown::UnsupportedExpression)?;
                let left = self.expression_type(left, depth + 1)?;
                let right = self.expression_type(right, depth + 1)?;
                let (RustConversionType::Primitive(left), RustConversionType::Primitive(right)) =
                    (&left, &right)
                else {
                    let trait_name = match operator.kind() {
                        "+" => "Add",
                        "-" => "Sub",
                        "*" => "Mul",
                        "/" => "Div",
                        "%" => "Rem",
                        "&" => "BitAnd",
                        "|" => "BitOr",
                        "^" => "BitXor",
                        "<<" => "Shl",
                        ">>" => "Shr",
                        _ => return Err(ConversionUnknown::UnsupportedExpression),
                    };
                    if !matches!(left, RustConversionType::Model { .. }) {
                        return self.workspace_operator_output(
                            &left,
                            &right,
                            trait_name,
                            depth + 1,
                        );
                    }
                    let returned = super::std_types::RustTypeProof::new(self.analyzer)
                        .and_then(|proof| proof.modeled_operator_result(&left, &right, trait_name))
                        .ok_or(ConversionUnknown::UnsupportedExpression)?;
                    return self.modeled_return_conversion(&returned, depth + 1);
                };
                let (left, right) = (*left, *right);
                use RustPrimitive::*;
                let integer = |ty| {
                    matches!(
                        ty,
                        U8 | U16 | U32 | U64 | U128 | Usize | I8 | I16 | I32 | I64 | I128 | Isize
                    )
                };
                let numeric = integer(left) || matches!(left, F32 | F64);
                let result = match operator.kind() {
                    "+" | "-" | "*" | "/" | "%" if left == right && numeric => left,
                    "<<" | ">>" if integer(left) && integer(right) => left,
                    "&" | "|" | "^" if left == right && (integer(left) || left == Bool) => left,
                    "&&" | "||" if left == Bool && right == Bool => Bool,
                    "==" | "!=" | "<" | "<=" | ">" | ">="
                        if left == right && (numeric || matches!(left, Bool | Char)) =>
                    {
                        Bool
                    }
                    _ => return Err(ConversionUnknown::UnsupportedExpression),
                };
                Ok(RustConversionType::Primitive(result))
            }
            "call_expression" => self.call_result_proof(node, depth + 1)?.exact,
            "reference_expression" => {
                let value = rust_reference_expression_value(node)
                    .ok_or(ConversionUnknown::UnsupportedExpression)?;
                let referent = self.expression_type(value, depth + 1)?;
                Ok(RustConversionType::Reference {
                    mutable: rust_reference_is_mutable(node),
                    referent: Box::new(referent),
                })
            }
            "unary_expression" => {
                let operand = rust_dereference_operand(node)
                    .ok_or(ConversionUnknown::UnsupportedExpression)?;
                match self.expression_type(operand, depth + 1)? {
                    RustConversionType::Reference { referent, .. } => Ok(*referent),
                    _ => Err(ConversionUnknown::UnsupportedExpression),
                }
            }
            _ => Err(ConversionUnknown::UnsupportedExpression),
        }
    }
}

fn conversion_kind(
    source: &RustConversionType,
    target: &RustConversionType,
) -> Option<ConversionKind> {
    if same_type(source, target) {
        return Some(ConversionKind::RustIdentity);
    }
    let (
        RustConversionType::Reference {
            mutable: source_mutable,
            referent: source_referent,
        },
        RustConversionType::Reference {
            mutable: target_mutable,
            referent: target_referent,
        },
    ) = (source, target)
    else {
        return None;
    };
    if *target_mutable && !*source_mutable {
        return None;
    }
    if *source_mutable && !*target_mutable && same_type(source_referent, target_referent) {
        return Some(ConversionKind::RustReborrow);
    }
    if let (
        RustConversionType::Array {
            element: source_element,
            ..
        },
        RustConversionType::Slice {
            element: target_element,
        },
    ) = (source_referent.as_ref(), target_referent.as_ref())
        && same_type(source_element, target_element)
    {
        return Some(ConversionKind::RustUnsizing);
    }
    // Only builtin reference dereferences participate. Mutable access must
    // survive every layer, including a shared reference to a mutable one.
    let mut current = source_referent.as_ref();
    while let RustConversionType::Reference { mutable, referent } = current {
        if *target_mutable && !*mutable {
            return None;
        }
        if same_type(referent, target_referent) {
            return Some(ConversionKind::RustDeref);
        }
        current = referent;
    }
    None
}

// Both inputs are producer-built under MAX_TYPE_DEPTH, so recursion is bounded.
fn same_type(left: &RustConversionType, right: &RustConversionType) -> bool {
    match (left, right) {
        (
            RustConversionType::Model {
                model_set: left_set,
                symbol: left_symbol,
                arguments: left_arguments,
            },
            RustConversionType::Model {
                model_set: right_set,
                symbol: right_symbol,
                arguments: right_arguments,
            },
        ) => {
            left_set == right_set
                && left_symbol == right_symbol
                && left_arguments.len() == right_arguments.len()
                && left_arguments
                    .iter()
                    .zip(right_arguments)
                    .all(|(left, right)| same_type(left, right))
        }
        (RustConversionType::Primitive(left), RustConversionType::Primitive(right)) => {
            left == right
        }
        (RustConversionType::Declaration(left), RustConversionType::Declaration(right)) => {
            left.declaration_id() == right.declaration_id()
        }
        (
            RustConversionType::AppliedDeclaration {
                declaration: left,
                arguments: left_arguments,
            },
            RustConversionType::AppliedDeclaration {
                declaration: right,
                arguments: right_arguments,
            },
        ) => {
            left.declaration_id() == right.declaration_id()
                && left_arguments.len() == right_arguments.len()
                && left_arguments
                    .iter()
                    .zip(right_arguments)
                    .all(|(left, right)| same_type(left, right))
        }
        (
            RustConversionType::Reference {
                mutable: left_mutable,
                referent: left_referent,
            },
            RustConversionType::Reference {
                mutable: right_mutable,
                referent: right_referent,
            },
        ) => left_mutable == right_mutable && same_type(left_referent, right_referent),
        (
            RustConversionType::Array {
                element: left_element,
                length: left_length,
            },
            RustConversionType::Array {
                element: right_element,
                length: right_length,
            },
        ) => left_length == right_length && same_type(left_element, right_element),
        (
            RustConversionType::Slice { element: left },
            RustConversionType::Slice { element: right },
        ) => same_type(left, right),
        (RustConversionType::Tuple(left), RustConversionType::Tuple(right)) => {
            left.len() == right.len() && left.iter().zip(right).all(|(l, r)| same_type(l, r))
        }
        (RustConversionType::Unit, RustConversionType::Unit) => true,
        _ => false,
    }
}

fn source_type_error(error: ConversionUnknown) -> ConversionUnknown {
    match error {
        ConversionUnknown::UnresolvedTargetType => ConversionUnknown::UnresolvedSourceType,
        other => other,
    }
}

/// Interpret the canonical identity of an already selected model type.
pub(crate) fn modeled_primitive(name: &str) -> Option<RustPrimitive> {
    name.strip_prefix("std.primitive.")
        .or_else(|| name.strip_prefix("core.primitive."))
        .and_then(primitive_for_spelling)
}

pub(super) fn primitive_for_spelling(spelling: &str) -> Option<RustPrimitive> {
    Some(match spelling {
        "bool" => RustPrimitive::Bool,
        "char" => RustPrimitive::Char,
        "str" => RustPrimitive::Str,
        "u8" => RustPrimitive::U8,
        "u16" => RustPrimitive::U16,
        "u32" => RustPrimitive::U32,
        "u64" => RustPrimitive::U64,
        "u128" => RustPrimitive::U128,
        "usize" => RustPrimitive::Usize,
        "i8" => RustPrimitive::I8,
        "i16" => RustPrimitive::I16,
        "i32" => RustPrimitive::I32,
        "i64" => RustPrimitive::I64,
        "i128" => RustPrimitive::I128,
        "isize" => RustPrimitive::Isize,
        "f32" => RustPrimitive::F32,
        "f64" => RustPrimitive::F64,
        _ => return None,
    })
}

fn has_type_where_predicates(node: Node<'_>) -> bool {
    if !matches!(
        node.kind(),
        "function_item"
            | "function_signature_item"
            | "impl_item"
            | "trait_item"
            | "struct_item"
            | "enum_item"
            | "union_item"
            | "type_item"
            | "associated_type"
    ) {
        return false;
    }
    node.named_children(&mut node.walk())
        .filter(|child| child.kind() == "where_clause")
        .any(|clause| {
            clause.named_children(&mut clause.walk()).any(|predicate| {
                predicate
                    .child_by_field_name("left")
                    .is_none_or(|left| left.kind() != "lifetime")
            })
        })
}

fn has_non_lifetime_parameters(node: Node<'_>) -> bool {
    node.child_by_field_name("type_parameters")
        .is_some_and(|parameters| {
            parameters
                .named_children(&mut parameters.walk())
                .any(|parameter| parameter.kind() != "lifetime_parameter")
        })
}

#[derive(PartialEq, Eq)]
enum OpaqueTypeRoot {
    Prelude,
    Import(ProjectFile, usize, usize),
    Unit([u8; 32]),
}

#[derive(PartialEq, Eq)]
enum OpaqueTypeIdentity {
    Known(RustConversionType),
    Reference(Box<OpaqueTypeIdentity>),
    Path(OpaqueTypeRoot, Vec<String>, Vec<OpaqueTypeIdentity>),
}

impl RustTypeContext<'_, '_> {
    fn supported_type_context(&self, node: Node<'_>) -> Result<(), ConversionUnknown> {
        let mut current = Some(node);
        while let Some(scope) = current {
            if has_non_lifetime_parameters(scope) || has_type_where_predicates(scope) {
                return Err(ConversionUnknown::GenericSubstitution);
            }
            current = scope.parent();
        }
        self.supported_macro_context(node)
    }

    fn supported_macro_context(&self, node: Node<'_>) -> Result<(), ConversionUnknown> {
        let mut current = Some(node);
        while let Some(scope) = current {
            if scope.kind() == "macro_definition"
                || (scope.kind() == "macro_invocation" && !self.standard_statement_macro(scope))
            {
                return Err(ConversionUnknown::UnsupportedExpression);
            }
            if matches!(scope.kind(), "block" | "source_file" | "declaration_list") {
                self.sources
                    .source_scope_support(self.analyzer, self.file, scope, || {
                        for child in scope.named_children(&mut scope.walk()) {
                            let invocation = if child.kind() == "macro_invocation" {
                                Some(child)
                            } else if child.kind() == "expression_statement" {
                                child
                                    .named_children(&mut child.walk())
                                    .find(|node| node.kind() == "macro_invocation")
                            } else {
                                None
                            };
                            if let Some(invocation) = invocation
                                && !self.resolved_standard_statement_macro(invocation)
                            {
                                return Err(ConversionUnknown::UnsupportedConversion);
                            }
                        }
                        Ok(())
                    })?;
            }
            if scope.kind() == "mod_item" {
                break;
            }
            current = scope.parent();
        }
        Ok(())
    }

    fn is_standard_noncoercing_macro_operand(&self, node: Node<'_>) -> bool {
        // Only a node strictly inside the macro is its operand. A macro
        // invocation used as the argument itself, such as `sink(dbg!(w))`,
        // passes its result, which coerces like any other value.
        let mut ancestor = node.parent();
        while let Some(invocation) = ancestor {
            // A nested call still performs its own argument conversions.
            if invocation.kind() == "call_expression" {
                return false;
            }
            if invocation.kind() == "macro_invocation" {
                if !self.standard_statement_macro(invocation) {
                    return false;
                }
                let Some(path) = invocation.child_by_field_name("macro") else {
                    return false;
                };
                let Some(segments) = brokk_bifrost_rust::graph_support::rust_path_segments(path)
                else {
                    return false;
                };
                let Some(name) = segments.last() else {
                    return false;
                };
                if brokk_bifrost_rust::format_args::rust_logging_macro(
                    "log",
                    rust_node_text(*name, self.source),
                )
                .is_some()
                {
                    let Ok(arguments) =
                        brokk_bifrost_rust::format_args::rust_format_macro_arguments(
                            invocation,
                            self.source,
                        )
                    else {
                        return false;
                    };
                    let Some(format) = brokk_bifrost_rust::format_args::rust_logging_format_operand(
                        invocation,
                        self.source,
                        &arguments,
                    ) else {
                        return false;
                    };
                    return arguments.iter().enumerate().any(|(index, argument)| {
                        index != format
                            && argument.value_range.start_byte <= node.start_byte()
                            && node.end_byte() <= argument.value_range.end_byte
                    });
                }
                return matches!(
                    rust_node_text(*name, self.source),
                    "println"
                        | "print"
                        | "eprintln"
                        | "eprint"
                        | "format"
                        | "format_args"
                        | "write"
                        | "writeln"
                        | "panic"
                        | "todo"
                        | "unimplemented"
                        | "unreachable"
                        | "assert"
                        | "assert_eq"
                        | "assert_ne"
                        | "debug_assert"
                        | "debug_assert_eq"
                        | "debug_assert_ne"
                        | "dbg"
                );
            }
            ancestor = invocation.parent();
        }
        false
    }

    fn standard_statement_macro(&self, invocation: Node<'_>) -> bool {
        self.sources
            .source_scope_support(self.analyzer, self.file, invocation, || {
                if self.resolved_standard_statement_macro(invocation) {
                    Ok(())
                } else {
                    Err(ConversionUnknown::UnsupportedExpression)
                }
            })
            .is_ok()
    }

    fn resolved_standard_statement_macro(&self, invocation: Node<'_>) -> bool {
        let Some(path) = invocation.child_by_field_name("macro") else {
            return false;
        };
        let Some(segments) = brokk_bifrost_rust::graph_support::rust_path_segments(path) else {
            return false;
        };
        let Some(terminal) = segments.last() else {
            return false;
        };
        let name = rust_node_text(*terminal, self.source);
        let logging_macro =
            brokk_bifrost_rust::format_args::rust_logging_macro("log", name).is_some();
        if !logging_macro
            && !matches!(
                name,
                "println"
                    | "print"
                    | "eprint"
                    | "format_args"
                    | "eprintln"
                    | "format"
                    | "write"
                    | "writeln"
                    | "assert"
                    | "assert_eq"
                    | "assert_ne"
                    | "debug_assert"
                    | "debug_assert_eq"
                    | "debug_assert_ne"
                    | "vec"
                    | "dbg"
                    | "panic"
                    | "todo"
                    | "unimplemented"
                    | "unreachable"
            )
        {
            return false;
        }
        let rust =
            resolve_analyzer::<RustAnalyzer>(self.analyzer).expect("Rust conversion analyzer");
        let imports = brokk_bifrost_rust::lexical_scope::visible_import_binder_in_tree_with(
            rust.inner.adapter().lexical_caches(),
            self.root,
            self.source,
            invocation.start_byte(),
        );
        if !logging_macro
            && (imports.bindings.contains_key(name)
                || imports
                    .bindings
                    .values()
                    .any(|binding| binding.kind == ImportKind::Glob))
        {
            return false;
        }
        let Some(parsed) = self.sources.source(self.analyzer, self.file) else {
            return false;
        };
        let scope = AnalyzerQueryScope::new(rust);
        let range = brokk_bifrost_core::analyzer::model::Range {
            start_byte: invocation.start_byte(),
            end_byte: invocation.end_byte(),
            start_line: invocation.start_position().row + 1,
            end_line: invocation.end_position().row + 1,
        };
        let Some(answer) = super::format_macro_dispatch::dispatch(
            brokk_bifrost_analysis::analyzer::usages::call_relations::CallDispatchLanguageRequest {
                analyzer: self.analyzer,
                token: scope.token(),
                file: self.file,
                source: self.source,
                tree: &parsed.tree,
                call_span: &range,
                member_selection: None,
                cancellation: None,
                work: Default::default(),
            },
        ) else {
            return false;
        };
        if logging_macro
            && brokk_bifrost_rust::format_args::rust_format_macro_arguments(invocation, self.source)
                .ok()
                .and_then(|arguments| {
                    brokk_bifrost_rust::format_args::rust_logging_format_operand(
                        invocation,
                        self.source,
                        &arguments,
                    )
                })
                .is_none()
        {
            return false;
        }
        answer.status == Some(DefinitionLookupStatus::Resolved)
            && matches!(answer.boundaries.as_slice(),
                [brokk_bifrost_analysis::analyzer::usages::call_relations::CallDispatchBoundaryKind::External {
                    external_callee_identity: Some(_), ..
                }])
    }
}

#[cfg(test)]
mod tests {

    use crate::analyzer::rust::call_conversion::*;

    fn selected_fixture_type(source: &str) -> Result<RustConversionType, ConversionUnknown> {
        let (_temp, analyzer) = super::super::test_support::project(&[("src/lib.rs", source)]);
        selected_fixture_type_with_analyzer(&analyzer, source)
    }

    fn selected_fixture_type_with_analyzer(
        analyzer: &RustAnalyzer,
        source: &str,
    ) -> Result<RustConversionType, ConversionUnknown> {
        selected_fixture_named_type(analyzer, source, "probe")
    }

    fn selected_fixture_named_type(
        analyzer: &RustAnalyzer,
        source: &str,
        function: &str,
    ) -> Result<RustConversionType, ConversionUnknown> {
        let file = super::super::test_support::analyzed_file(analyzer, "src/lib.rs");
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let mut pending = vec![tree.root_node()];
        let mut selected = None;
        while let Some(node) = pending.pop() {
            if node.kind() == "function_item"
                && node
                    .child_by_field_name("name")
                    .is_some_and(|name| rust_node_text(name, source) == function)
            {
                let parameters = node.child_by_field_name("parameters").unwrap();
                let parameter = parameters.named_child(0).unwrap();
                selected = parameter.child_by_field_name("type");
                break;
            }
            pending.extend(node.named_children(&mut node.walk()));
        }
        type_conversion_type(analyzer, &file, source, selected.unwrap())
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "f78115f8dd72: generic free calls were incorrectly treated as unknown qualifying types"
    )]
    fn qualifying_type_generic_free_functions_are_proven_unqualified() {
        for (source, spelling) in [
            (
                "fn helper<T>() {} fn run() { helper::<u8>(); }",
                "helper::<u8>()",
            ),
            (
                "mod helpers { pub fn helper<T>() {} } fn run() { helpers::helper::<u8>(); }",
                "helpers::helper::<u8>()",
            ),
        ] {
            let (_temp, analyzer) = super::super::test_support::project(&[("src/lib.rs", source)]);
            let file = super::super::test_support::analyzed_file(&analyzer, "src/lib.rs");
            let mut parser = tree_sitter::Parser::new();
            parser
                .set_language(&tree_sitter_rust::LANGUAGE.into())
                .unwrap();
            let tree = parser.parse(source, None).unwrap();
            let start = source.rfind(spelling).unwrap();
            let call = tree
                .root_node()
                .named_descendant_for_byte_range(start, start + spelling.len())
                .unwrap();
            assert_eq!(call.kind(), "call_expression");
            assert!(
                matches!(
                    call_qualifying_type(
                        &analyzer,
                        &CallConversionCache::default(),
                        &file,
                        source,
                        call
                    ),
                    Ok(None)
                ),
                "{source}"
            );
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "f78115f8dd72: valid generic source impl qualifiers were rejected by the conversion-owner guard"
    )]
    fn qualifying_type_generic_source_impls_keep_association_guards() {
        for (implementation, argument, complete) in [
            (
                "impl<T> Container<T> { fn new(value: T) -> Self { Self(value) } }",
                "u8",
                true,
            ),
            (
                "impl<T> Container<T> { fn new(value: T) -> Self { Self(value) } }",
                // Inference cannot prove which source impl supplies the method.
                "_",
                false,
            ),
            (
                "impl<T: Copy> Container<T> { fn new(value: T) -> Self { Self(value) } }",
                "u8",
                false,
            ),
            (
                "impl<T> Container<T> where T: Copy { fn new(value: T) -> Self { Self(value) } }",
                "u8",
                false,
            ),
            (
                "impl<T> Container<T> { fn new<U>(value: T) -> Self { Self(value) } }",
                "u8",
                false,
            ),
            (
                "impl Container<u8> { fn new(value: u8) -> Self { Self(value) } }",
                "u8",
                true,
            ),
            (
                "impl Container<u8> { fn new(value: u8) -> Self { Self(value) } }",
                "u16",
                false,
            ),
            (
                "impl<T> Container<T> { fn new(value: T) -> Self where T: Copy { Self(value) } }",
                "u8",
                false,
            ),
        ] {
            let spelling = format!("Container::<{argument}>::new(1)");
            let source =
                format!("struct Container<T>(T); {implementation} fn run() {{ {spelling}; }}");
            let (_temp, analyzer) = super::super::test_support::project(&[("src/lib.rs", &source)]);
            let file = super::super::test_support::analyzed_file(&analyzer, "src/lib.rs");
            let mut parser = tree_sitter::Parser::new();
            parser
                .set_language(&tree_sitter_rust::LANGUAGE.into())
                .unwrap();
            let tree = parser.parse(&source, None).unwrap();
            let start = source.rfind(&spelling).unwrap();
            let call = tree
                .root_node()
                .named_descendant_for_byte_range(start, start + spelling.len())
                .unwrap();
            assert_eq!(call.kind(), "call_expression");
            let result = call_qualifying_type(
                &analyzer,
                &CallConversionCache::default(),
                &file,
                &source,
                call,
            );
            if complete {
                assert!(
                    matches!(result, Ok(Some(_))),
                    "{source}: {:?}",
                    result.as_ref().err()
                );
            } else {
                assert!(
                    result.is_err(),
                    "unproved association must stay Partial, not a clean absence: {source}"
                );
            }
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#10770: repeated alias arguments could exceed the selected-type work bound"
    )]
    fn selected_alias_fanout_budget_is_deterministic_and_not_memoized() {
        let mut source = String::from("struct Leaf; struct Triple<T,U,V>(T,U,V); type A0 = Leaf;");
        for index in 1..=5 {
            source.push_str(&format!(
                "type A{index} = Triple<A{previous}, A{previous}, A{previous}>;",
                previous = index - 1
            ));
        }
        source.push_str("fn probe(_: A5) {} fn mixed(_: (A2, A2, A2, A2)) {} fn small(_: A2) {}");
        let (_temp, analyzer) =
            super::super::test_support::project(&[("src/lib.rs", source.as_str())]);
        let file = super::super::test_support::analyzed_file(&analyzer, "src/lib.rs");
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(&source, None).unwrap();
        let start = source.rfind("A5").unwrap();
        let node = tree
            .root_node()
            .named_descendant_for_byte_range(start, start + 2)
            .unwrap();
        let sources = CallConversionCache::default();
        let context = RustTypeContext {
            analyzer: &analyzer,
            sources: &CallConversionContext::reference(&sources),
            file: &file,
            source: &source,
            root: tree.root_node(),
        };
        let compute = |context: &RustTypeContext<'_, '_>, mut allowance: usize| {
            let expression = selected_type::alias_type_expr(
                node,
                context.file,
                &Arc::from(source.as_str()),
                &mut allowance,
            )
            .unwrap();
            let mut work = SelectedTypeWork::new(allowance);
            let answer = context.selected_type_expression(expression, 0, &mut work);
            (answer, work)
        };
        assert!(
            matches!(
                selected_fixture_named_type(&analyzer, &source, "mixed"),
                Err(ConversionUnknown::BudgetExhausted)
            ),
            "structural containers must share the same operation budget"
        );
        assert!(selected_fixture_named_type(&analyzer, &source, "small").is_ok());
        let builds = std::cell::Cell::new(0);
        for _ in 0..2 {
            let answer =
                sources.rust_expression_type(&analyzer, &file, node.byte_range(), 0, || {
                    builds.set(builds.get() + 1);
                    let (answer, work) = compute(&context, MAX_SELECTED_TYPE_WORK);
                    assert_eq!(work.remaining, 0);
                    answer
                });
            assert!(matches!(answer, Err(ConversionUnknown::BudgetExhausted)));
        }
        assert_eq!(
            builds.get(),
            2,
            "a stopped proof must be rebuilt even on warm source/declaration memos"
        );
        let (_cold_temp, cold_analyzer) =
            super::super::test_support::project(&[("src/lib.rs", source.as_str())]);
        let cold_file = super::super::test_support::analyzed_file(&cold_analyzer, "src/lib.rs");
        let cold_sources = CallConversionCache::default();
        let cold = RustTypeContext {
            analyzer: &cold_analyzer,
            sources: &CallConversionContext::reference(&cold_sources),
            file: &cold_file,
            source: &source,
            root: tree.root_node(),
        };
        let (answer, work) = compute(&cold, MAX_SELECTED_TYPE_WORK);
        assert!(matches!(answer, Err(ConversionUnknown::BudgetExhausted)));
        assert_eq!(
            work.remaining, 0,
            "cold and warm exhaust at the same canonical work point"
        );
        let complete = compute(&context, 4096)
            .0
            .expect("a new operation with enough work allowance completes the same input");
        let mut exact_nodes = SelectedTypeWork::new(364); // sum(3^0..3^5), independent of provider hits.
        context
            .charge_selected_binding(&complete, 0, &mut exact_nodes)
            .unwrap();
        assert_eq!(exact_nodes.remaining, 0);
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#10770: shallow modeled-result memo hits could bypass deeper proof limits"
    )]
    fn modeled_result_depth_budget_agrees_warm_and_cold() {
        use brokk_bifrost_analysis::analyzer::semantic_model::TypeRef;
        let source = "fn probe(_: u8) {}";
        let (_temp, analyzer) = super::super::test_support::project(&[("src/lib.rs", source)]);
        let file = super::super::test_support::analyzed_file(&analyzer, "src/lib.rs");
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let cache = CallConversionCache::default();
        let context = RustTypeContext {
            analyzer: &analyzer,
            sources: &CallConversionContext::reference(&cache),
            file: &file,
            source,
            root: tree.root_node(),
        };
        let receiver = RustConversionType::Model {
            model_set: "fixture".into(),
            symbol: "fixture.owner".into(),
            arguments: Vec::new(),
        };
        let returned = TypeRef::Named {
            name: "std.primitive.u8".into(),
            arguments: Vec::new(),
            nullable: false,
        };
        assert!(
            cache
                .rust_modeled_result(&analyzer, &file, 0..1, &receiver, "value", 0, || context
                    .modeled_return_conversion(&returned, 0))
                .is_ok()
        );
        let builds = std::cell::Cell::new(0);
        for _ in 0..2 {
            let warm = cache.rust_modeled_result(
                &analyzer,
                &file,
                0..1,
                &receiver,
                "value",
                MAX_TYPE_DEPTH,
                || {
                    builds.set(builds.get() + 1);
                    context.modeled_return_conversion(&returned, MAX_TYPE_DEPTH)
                },
            );
            assert!(matches!(warm, Err(ConversionUnknown::BudgetExhausted)));
        }
        assert_eq!(builds.get(), 2);
        let cold = CallConversionCache::default().rust_modeled_result(
            &analyzer,
            &file,
            0..1,
            &receiver,
            "value",
            MAX_TYPE_DEPTH,
            || context.modeled_return_conversion(&returned, MAX_TYPE_DEPTH),
        );
        assert!(matches!(cold, Err(ConversionUnknown::BudgetExhausted)));
        assert!(
            cache
                .rust_modeled_result(&analyzer, &file, 0..1, &receiver, "value", 0, || panic!(
                    "complete shallow proof should hit its own depth key"
                ))
                .is_ok()
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#10770: substituted model defaults cloned expanded bindings without charging work"
    )]
    fn model_default_parameter_clones_spend_the_shared_work_budget() {
        use brokk_bifrost_analysis::analyzer::semantic_model::TypeRef;
        let source = "fn probe(_: u8) {}";
        let (_temp, analyzer) = super::super::test_support::project(&[("src/lib.rs", source)]);
        let file = super::super::test_support::analyzed_file(&analyzer, "src/lib.rs");
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let sources = CallConversionCache::default();
        let context = RustTypeContext {
            analyzer: &analyzer,
            sources: &CallConversionContext::reference(&sources),
            file: &file,
            source,
            root: tree.root_node(),
        };
        let mut value = RustConversionType::Primitive(RustPrimitive::U8);
        for _ in 0..5 {
            value = RustConversionType::Tuple(vec![value.clone(), value.clone(), value]);
        }
        let bindings = std::collections::HashMap::from([("T".into(), value)]);
        let returned = TypeRef::TypeParameter { name: "T".into() };
        let mut work = SelectedTypeWork::new(MAX_SELECTED_TYPE_WORK);
        assert!(matches!(
            context.modeled_return_conversion_with_bindings(&returned, 0, &bindings, &mut work),
            Err(ConversionUnknown::BudgetExhausted)
        ));
        assert_eq!(work.remaining, 0);
        let mut work = SelectedTypeWork::new(1024);
        assert_eq!(
            context
                .modeled_return_conversion_with_bindings(&returned, 0, &bindings, &mut work)
                .unwrap(),
            bindings["T"]
        );
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#10770: written prelude types and modeled returns disagreed on default argument identity"
    )]
    fn selected_prelude_defaults_equal_canonical_model_returns() {
        use brokk_bifrost_analysis::analyzer::semantic_model::TypeRef;
        use serde_json::json;
        let source = "fn probe(_: Vec<u8>) {}";
        let (_temp, analyzer) = super::super::test_support::project(&[("src/lib.rs", source)]);
        let mut types = Vec::new();
        for (id, name, kind) in [
            ("std", "std", "module"),
            ("std.vec", "std.vec", "module"),
            ("std.alloc", "std.alloc", "module"),
            ("global", "std.alloc.Global", "struct"),
            ("vec", "std.vec.Vec", "struct"),
        ] {
            types.push(
                json!({ "id": id, "name": name, "type_kind": kind, "visibility": "public",
                "locator": { "kind": "artifact", "path": "fixture/std.rs", "symbol": name } }),
            );
        }
        types.last_mut().unwrap()["type_parameters"] = json!(["T", "A"]);
        types.last_mut().unwrap()["type_parameter_defaults"] = json!([null,
            { "kind": "type", "type": { "kind": "declared", "id": "global", "arguments": [], "nullable": false } }
        ]);
        let mut pack = json!({
            "schema_version": 30, "pack_id": "fixture.rust-selected-defaults", "version": "1.0.0",
            "producer": { "name": "test-only-selected-defaults", "version": "1.0.0" },
            "language": "rust", "ecosystem": "cargo", "compatibility": { "toolchains": [] },
            "provenance": { "source": "test-only canonical generic default declarations" },
            "license": "NOASSERTION", "completeness": "complete",
            "safety": { "generated_code_only": false, "review_required": false },
            "shards": [{ "id": "types", "activation": [{ "targets": [], "configurations": [] }],
                "payload": { "kind": "declaration_facts", "types": types } }]
        });
        brokk_bifrost_analysis::test_support::activate_rust_declaration_pack(
            &analyzer,
            "fixture.rust-selected-defaults",
            &pack,
        );
        let written = selected_fixture_type_with_analyzer(&analyzer, source).unwrap();
        let file = super::super::test_support::analyzed_file(&analyzer, "src/lib.rs");
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let sources = CallConversionCache::default();
        let context = RustTypeContext {
            analyzer: &analyzer,
            sources: &CallConversionContext::reference(&sources),
            file: &file,
            source,
            root: tree.root_node(),
        };
        let RustConversionType::Model {
            symbol: written_symbol,
            ..
        } = &written
        else {
            panic!("expected model type");
        };
        let snapshot = analyzer.active_semantic_model_snapshot().unwrap();
        let global = snapshot
            .semantic_model_overlay()
            .unwrap()
            .symbols_named_in_family("std.alloc.Global", "rust")
            .unique()
            .unwrap();
        let returned = context
            .modeled_return_conversion(
                &TypeRef::Declared {
                    id: written_symbol.clone(),
                    arguments: vec![TypeRef::Named {
                        name: "std.primitive.u8".into(),
                        arguments: Vec::new(),
                        nullable: false,
                    }],
                    nullable: false,
                },
                0,
            )
            .unwrap();
        let RustConversionType::Model { arguments, .. } = &written else {
            panic!("expected model type")
        };
        assert_eq!(arguments.len(), 2);
        assert!(
            matches!(&arguments[1], RustConversionType::Model { symbol, arguments, .. } if symbol == &global.id && arguments.is_empty())
        );
        assert_eq!(
            conversion_kind(&written, &returned),
            Some(ConversionKind::RustIdentity)
        );
        assert_eq!(
            conversion_kind(&returned, &written),
            Some(ConversionKind::RustIdentity)
        );
        // A declared default that names an external alias is not a
        // concrete nominal identity until the alias target is proved.
        for kind in ["type_alias", "module", "trait", "interface"] {
            pack["shards"][0]["payload"]["types"][3]["type_kind"] = json!(kind);
            brokk_bifrost_analysis::test_support::activate_rust_declaration_pack(
                &analyzer,
                "fixture.rust-selected-defaults",
                &pack,
            );
            assert!(
                matches!(
                    selected_fixture_type_with_analyzer(&analyzer, source),
                    Err(ConversionUnknown::GenericSubstitution)
                ),
                "{kind} cannot stand in for a proved nominal default"
            );
        }
        pack["shards"][0]["payload"]["types"][3]["type_kind"] = json!("struct");
        // Changing only model activation must move the canonical expansion,
        // and the retained analyzer must agree with a fresh activation.
        pack["shards"][0]["payload"]["types"][4]["type_parameter_defaults"][1] = json!({
            "kind": "type", "type": { "kind": "type_parameter", "name": "T" }
        });
        brokk_bifrost_analysis::test_support::activate_rust_declaration_pack(
            &analyzer,
            "fixture.rust-selected-defaults",
            &pack,
        );
        let warm = selected_fixture_type_with_analyzer(&analyzer, source).unwrap();
        assert_ne!(
            conversion_kind(&written, &warm),
            Some(ConversionKind::RustIdentity)
        );
        let (_cold_temp, cold) = super::super::test_support::project(&[("src/lib.rs", source)]);
        brokk_bifrost_analysis::test_support::activate_rust_declaration_pack(
            &cold,
            "fixture.rust-selected-defaults",
            &pack,
        );
        let fresh = selected_fixture_type_with_analyzer(&cold, source).unwrap();
        assert_eq!(
            conversion_kind(&warm, &fresh),
            Some(ConversionKind::RustIdentity)
        );
        let RustConversionType::Model { arguments, .. } = warm else {
            panic!("expected model")
        };
        assert!(matches!(
            arguments.as_slice(),
            [
                RustConversionType::Primitive(RustPrimitive::U8),
                RustConversionType::Primitive(RustPrimitive::U8)
            ]
        ));
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#10770: aliases and written nominal types disagreed on default argument identity"
    )]
    fn selected_alias_and_written_default_applications_have_identity_conversion() {
        for argument in [
            "u8",
            "&'static u8",
            "[u8; 4]",
            "&'static [u8]",
            "(u8, u16)",
            "()",
        ] {
            let source = format!(
                "struct Pair<T, U = T>(T, U); type Alias = Pair<{argument}>; fn probe(_: &Alias) {{}} fn written(_: &Pair<{argument}>) {{}}"
            );
            let (_temp, analyzer) =
                super::super::test_support::project(&[("src/lib.rs", source.as_str())]);
            let aliased = selected_fixture_named_type(&analyzer, &source, "probe").unwrap();
            let written = selected_fixture_named_type(&analyzer, &source, "written").unwrap();
            assert_eq!(
                conversion_kind(&aliased, &written),
                Some(ConversionKind::RustIdentity),
                "{argument}"
            );
            assert_eq!(
                conversion_kind(&written, &aliased),
                Some(ConversionKind::RustIdentity),
                "{argument}"
            );
        }
        let source = "struct Pair<T = u8, U = T>(T, U); type Alias = Pair; fn probe(_: Alias) {} fn written(_: Pair) {}";
        let (_temp, analyzer) = super::super::test_support::project(&[("src/lib.rs", source)]);
        let aliased = selected_fixture_named_type(&analyzer, source, "probe").unwrap();
        let written = selected_fixture_named_type(&analyzer, source, "written").unwrap();
        assert_eq!(
            conversion_kind(&aliased, &written),
            Some(ConversionKind::RustIdentity)
        );
    }

    #[test]
    fn selected_alias_reexports_and_repeated_instances_keep_distinct_arguments() {
        let source = "struct Pair<T, U>(T, U); struct Des; struct Aes; mod aliases { pub type Identity<T> = T; } use aliases::Identity as Renamed; type Alias = Pair<Renamed<Des>, Renamed<Aes>>; fn probe(_: Alias) {}";
        let answer = selected_fixture_type(source).unwrap();
        let RustConversionType::AppliedDeclaration { arguments, .. } = answer else {
            panic!("expected Pair")
        };
        let [
            RustConversionType::Declaration(first),
            RustConversionType::Declaration(second),
        ] = arguments.as_slice()
        else {
            panic!("expected distinct declarations")
        };
        assert_eq!(first.terminal_name(), "Des");
        assert_eq!(second.terminal_name(), "Aes");
        assert_ne!(first.declaration_id(), second.declaration_id());
    }

    #[test]
    fn selected_alias_defaults_use_declaration_scope_despite_caller_shadowing() {
        let source = "struct Des; mod aliases { pub struct Des; pub struct Pair<T, U>(T, U); pub type Chosen<T, U = Des> = Pair<T, U>; } type Alias = aliases::Chosen<Des>; fn probe(_: Alias) {}";
        let answer = selected_fixture_type(source).unwrap();
        let RustConversionType::AppliedDeclaration { arguments, .. } = answer else {
            panic!("expected Pair")
        };
        let [
            RustConversionType::Declaration(first),
            RustConversionType::Declaration(second),
        ] = arguments.as_slice()
        else {
            panic!("expected declarations")
        };
        assert!(!first.fq_name_str().contains("aliases"));
        assert!(second.fq_name_str().contains("aliases"));
    }

    #[test]
    fn selected_alias_long_chains_and_unknown_inner_types_stay_unknown() {
        let mut source = String::from("struct Des; type A0 = Des;");
        for index in 1..24 {
            source.push_str(&format!("type A{index} = A{};", index - 1));
        }
        source.push_str("fn probe(_: A23) {}");
        assert!(selected_fixture_type(&source).is_err());
        for source in [
            "struct Pair<T>(T); type A = Pair<Missing>; fn probe(_: A) {}",
            "type A = external::Unknown<Missing>; fn probe(_: A) {}",
            "trait Trait { type Output; } type A = <Missing as Trait>::Output; fn probe(_: A) {}",
        ] {
            assert!(selected_fixture_type(source).is_err(), "{source}");
        }
    }

    #[test]
    fn selected_alias_expansion_preserves_cancelled_and_stale_outcomes() {
        let source = "type Alias = u8; fn probe(_: Alias) {}";
        let (_temp, analyzer) = super::super::test_support::project(&[("src/lib.rs", source)]);
        let file = super::super::test_support::analyzed_file(&analyzer, "src/lib.rs");
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let start = source.rfind("Alias").unwrap();
        let node = tree
            .root_node()
            .named_descendant_for_byte_range(start, start + 5)
            .unwrap();
        let expression =
            selected_type::alias_type_expr(node, &file, &Arc::from(source), &mut 256).unwrap();
        let cancellation = brokk_bifrost_core::cancellation::CancellationToken::new();
        cancellation.cancel();
        assert!(matches!(
            selected_type::expand_alias_head(&analyzer, expression, &cancellation, 0, true),
            Err(selected_type::ExternalRoute::Unavailable)
        ));
        let stale = source.replace("= u8", "= u16");
        assert!(selected_fixture_type_with_analyzer(&analyzer, &stale).is_err());
    }

    #[test]
    fn selected_aliases_expand_generics_and_earlier_parameter_defaults() {
        let answer = selected_fixture_type("struct Des; struct Pair<T, U>(T, U); type Twice<T, U = T> = Pair<T, U>; type Renamed = Twice<Des>; fn probe(_: Renamed) {} ").unwrap();
        let RustConversionType::AppliedDeclaration {
            declaration,
            arguments,
        } = answer
        else {
            panic!("expected applied Pair")
        };
        assert_eq!(declaration.terminal_name(), "Pair");
        assert_eq!(arguments.len(), 2);
        for argument in arguments {
            let RustConversionType::Declaration(unit) = argument else {
                panic!("expected Des")
            };
            assert_eq!(unit.terminal_name(), "Des");
        }
    }

    #[test]
    fn selected_alias_arguments_keep_their_use_site_context() {
        let answer = selected_fixture_type("struct Des; mod inner { pub struct Des; pub type Identity<T> = T; } type Chosen = inner::Identity<Des>; fn probe(_: Chosen) {} ").unwrap();
        let RustConversionType::Declaration(unit) = answer else {
            panic!("expected declaration")
        };
        assert_eq!(unit.terminal_name(), "Des");
        assert!(!unit.fq_name_str().contains("inner"));
    }

    #[test]
    fn selected_alias_cycle_and_unresolved_targets_stay_unknown() {
        for source in [
            "type A = B; type B = A; fn probe(_: A) {}",
            "type A = Missing; fn probe(_: A) {}",
            "type A<const N: usize> = u8; fn probe(_: A<4>) {}",
            "struct Des; type A = *const Des; fn probe(_: A) {}",
        ] {
            assert!(selected_fixture_type(source).is_err(), "{source}");
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#10770: alias depth incorrectly consumed nested method conversion depth"
    )]
    fn selected_alias_depth_is_independent_of_method_conversion_depth() {
        let source = "struct W(i32); impl W { fn inner(&self) -> &i32 { &self.0 } fn wrapped(&self) -> &W { self } } fn take(_: &i32) {} fn run(w: &W) { take(w.wrapped().inner()); }";
        let (_temp, analyzer) = super::super::test_support::project(&[("src/lib.rs", source)]);
        let file = super::super::test_support::analyzed_file(&analyzer, "src/lib.rs");
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let start = source.rfind("w.wrapped().inner()").unwrap();
        let node = tree
            .root_node()
            .named_descendant_for_byte_range(start, start + "w.wrapped().inner()".len())
            .unwrap();
        let sources = CallConversionCache::default();
        let context = RustTypeContext {
            analyzer: &analyzer,
            sources: &CallConversionContext::reference(&sources),
            file: &file,
            source,
            root: tree.root_node(),
        };
        let actual = context.expression_type(node, 0).unwrap();
        assert_eq!(
            actual,
            RustConversionType::Reference {
                mutable: false,
                referent: Box::new(RustConversionType::Primitive(RustPrimitive::I32))
            }
        );
        for count in [8, 9] {
            let mut source = String::from("struct W; type A0 = W;");
            for index in 1..count {
                source.push_str(&format!("type A{index} = A{};", index - 1));
            }
            source.push_str(&format!("fn probe(_: A{}) {{}}", count - 1));
            let answer = selected_fixture_type(&source);
            if count == 8 {
                assert!(answer.is_ok(), "{answer:?}");
            } else {
                assert!(
                    matches!(answer, Err(ConversionUnknown::BudgetExhausted)),
                    "{answer:?}"
                );
            }
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#10770: alias reuse refusal leaked onto unrelated nominal types"
    )]
    fn selected_alias_reuse_refusal_is_specific_to_aliases() {
        use brokk_bifrost_analysis::analyzer::capture_query_reads;
        let source = "struct W; type Alias = W; type Generic<T> = T; fn plain(_: W) {} fn probe(_: Alias) {} fn generic(_: Generic<W>) {}";
        let (_temp, analyzer) = super::super::test_support::project(&[("src/lib.rs", source)]);
        for (name, refused) in [("plain", false), ("probe", true), ("generic", true)] {
            let (answer, reads) = capture_query_reads(&analyzer, || {
                selected_fixture_named_type(&analyzer, source, name)
            });
            assert!(answer.is_ok(), "{name}: {answer:?}");
            assert_eq!(
                reads.reuse_refused(),
                refused,
                "{name}: {:#?}",
                reads.keys()
            );
        }
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#10770: an absent alias or reexport must invalidate a retained nominal proof when added"
    )]
    fn selected_alias_absence_reads_cover_a_new_alias_and_reexport() {
        use brokk_bifrost_analysis::analyzer::read_ledger::IndexFamily;
        use brokk_bifrost_analysis::analyzer::{ReadKey, capture_query_reads};
        use serde_json::json;
        let source = "mod extra; use extra::*; pub struct Des; fn probe(_: String) {}";
        let pack = json!({
            "schema_version": 30, "pack_id": "fixture.alias-absence-std", "version": "1.0.0",
            "producer": {"name":"test-only", "version":"1.0.0"}, "language":"rust", "ecosystem":"cargo",
            "compatibility":{"toolchains":[]}, "provenance":{"source":"test-only alias absence"}, "license":"NOASSERTION", "completeness":"complete", "safety":{"generated_code_only":false,"review_required":false},
            "shards":[{"id":"types","activation":[{"targets":[],"configurations":[]}],"payload":{"kind":"declaration_facts","types":[
                {"id":"std","name":"std","type_kind":"module","visibility":"public","locator":{"kind":"artifact","path":"fixture/std.rs","symbol":"std"}},
                {"id":"string-module","name":"std.string","type_kind":"module","visibility":"public","locator":{"kind":"artifact","path":"fixture/std.rs","symbol":"std.string"}},
                {"id":"string","name":"std.string.String","type_kind":"struct","visibility":"public","locator":{"kind":"artifact","path":"fixture/std.rs","symbol":"std.string.String"}}
            ]}}]
        });
        for added in [
            "pub type String = crate::Des;",
            "pub use crate::Des as String;",
        ] {
            let (_temp, mut analyzer) = super::super::test_support::project(&[
                ("src/lib.rs", source),
                ("src/extra.rs", "// No aliases or reexports yet.\n"),
            ]);
            brokk_bifrost_analysis::test_support::activate_rust_declaration_pack(
                &analyzer,
                "fixture.alias-absence-std",
                &pack,
            );
            let (before, reads) = capture_query_reads(&analyzer, || {
                selected_fixture_type_with_analyzer(&analyzer, source)
            });
            assert!(
                matches!(before, Ok(RustConversionType::Model { .. })),
                "{before:?}"
            );
            assert!(
                !reads.reuse_refused(),
                "plain prelude resolution: {:#?}",
                reads.keys()
            );
            let keys = reads.keys();
            assert!(
                keys.contains(&ReadKey::index(IndexFamily::DefinitionIdentifier, "String")),
                "{keys:#?}"
            );
            assert!(keys.iter().any(|key| matches!(key, ReadKey::File { rel_path, .. } if rel_path.as_ref() == "src/extra.rs")), "the negative glob lookup must record the empty module: {keys:#?}");
            let extra = super::super::test_support::analyzed_file(&analyzer, "src/extra.rs");
            std::fs::write(extra.abs_path(), added).unwrap();
            analyzer =
                analyzer.update_with_listing(&std::collections::BTreeSet::from([extra]), None);
            let (warm, warm_reads) = capture_query_reads(&analyzer, || {
                selected_fixture_type_with_analyzer(&analyzer, source)
            });
            let (_cold_temp, cold) = super::super::test_support::project(&[
                ("src/lib.rs", source),
                ("src/extra.rs", added),
            ]);
            brokk_bifrost_analysis::test_support::activate_rust_declaration_pack(
                &cold,
                "fixture.alias-absence-std",
                &pack,
            );
            let fresh = selected_fixture_type_with_analyzer(&cold, source);
            let (
                Ok(RustConversionType::Declaration(warm)),
                Ok(RustConversionType::Declaration(fresh)),
            ) = (warm, fresh)
            else {
                panic!("added alias/reexport must resolve to Des")
            };
            assert_eq!(warm.terminal_name(), "Des");
            assert_eq!(warm.terminal_name(), fresh.terminal_name());
            if added.starts_with("pub type") {
                assert!(warm_reads.reuse_refused());
            }
        }
    }

    #[test]
    fn selected_alias_target_only_edits_equal_fresh_answers() {
        let source =
            "mod aliases; struct Des; struct Aes; use aliases::Chosen; fn probe(_: Chosen) {}";
        let (_temp, mut analyzer) = super::super::test_support::project(&[
            ("src/lib.rs", source),
            ("src/aliases.rs", "pub type Chosen = crate::Des;"),
        ]);
        let alias_file = super::super::test_support::analyzed_file(&analyzer, "src/aliases.rs");
        for target in ["Des", "Aes", "Des"] {
            let alias = format!("pub type Chosen = crate::{target};");
            std::fs::write(alias_file.abs_path(), &alias).unwrap();
            analyzer = analyzer.update_with_listing(
                &std::collections::BTreeSet::from([alias_file.clone()]),
                None,
            );
            let warm = selected_fixture_type_with_analyzer(&analyzer, source).unwrap();
            let (_cold_temp, cold_analyzer) = super::super::test_support::project(&[
                ("src/lib.rs", source),
                ("src/aliases.rs", alias.as_str()),
            ]);
            let cold = selected_fixture_type_with_analyzer(&cold_analyzer, source).unwrap();
            let (RustConversionType::Declaration(warm), RustConversionType::Declaration(cold)) =
                (warm, cold)
            else {
                panic!("expected complete declarations after {target} edit");
            };
            assert_eq!(warm.terminal_name(), target);
            assert_eq!(warm.terminal_name(), cold.terminal_name());
        }
    }

    #[test]
    fn builtin_deref_cannot_create_mutable_access_through_a_shared_reference() {
        let mutable = RustConversionType::Reference {
            mutable: true,
            referent: Box::new(RustConversionType::Primitive(RustPrimitive::U8)),
        };
        let shared = RustConversionType::Reference {
            mutable: false,
            referent: Box::new(RustConversionType::Primitive(RustPrimitive::U8)),
        };
        let shared_to_mutable = RustConversionType::Reference {
            mutable: false,
            referent: Box::new(mutable.clone()),
        };
        assert_eq!(conversion_kind(&shared_to_mutable, &mutable), None);
        assert_eq!(
            conversion_kind(&shared_to_mutable, &shared),
            Some(ConversionKind::RustDeref)
        );
    }
    fn named_model_regression_pack() -> serde_json::Value {
        use serde_json::json;
        let mut types = Vec::new();
        for (id, name, parameters) in [
            ("model", "model", vec![]),
            ("boxed", "model.Boxed", vec!["T"]),
            ("triple", "model.Triple", vec!["A", "B", "C"]),
            ("holder", "model.Holder", vec!["T", "U"]),
        ] {
            types.push(
                json!({"id":id,"name":name,"type_kind":if id=="model" {"module"} else {"struct"},
                "visibility":"public","type_parameters":parameters,
                "locator":{"kind":"artifact","path":"fixture/model.rs","symbol":name}}),
            );
        }
        types[3]["type_parameter_defaults"] = json!([null,{"kind":"type","type":{
            "kind":"named","name":"model.Boxed","arguments":[{"kind":"type_parameter","name":"T"}]
        }}]);
        json!({"schema_version":31,"pack_id":"fixture.named-model-regression","version":"1.0.0",
            "producer":{"name":"test-only","version":"1.0.0"},"language":"rust","ecosystem":"cargo",
            "compatibility":{"toolchains":[]},"provenance":{"source":"test-only Named substitution and work"},
            "license":"NOASSERTION","completeness":"complete","safety":{"generated_code_only":false,"review_required":false},
            "shards":[{"id":"types","activation":[{"targets":[],"configurations":[]}],"payload":{"kind":"declaration_facts","types":types}}]})
    }

    fn with_model_regression_context<R>(
        pack: &serde_json::Value,
        run: impl FnOnce(&RustTypeContext<'_, '_>) -> R,
    ) -> R {
        with_model_source_context(pack, "fn probe(_: u8) {}", run)
    }

    fn with_model_source_context<R>(
        pack: &serde_json::Value,
        source: &str,
        run: impl FnOnce(&RustTypeContext<'_, '_>) -> R,
    ) -> R {
        let (_temp, analyzer) = super::super::test_support::project(&[("src/lib.rs", source)]);
        brokk_bifrost_analysis::test_support::activate_rust_declaration_pack(
            &analyzer,
            pack["pack_id"].as_str().unwrap(),
            pack,
        );
        let file = super::super::test_support::analyzed_file(&analyzer, "src/lib.rs");
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let cache = CallConversionCache::default();
        let sources = CallConversionContext::reference(&cache);
        run(&RustTypeContext {
            analyzer: &analyzer,
            sources: &sources,
            file: &file,
            source,
            root: tree.root_node(),
        })
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11043: Named model defaults discarded earlier generic bindings"
    )]
    fn named_model_regression_keeps_generic_default_bindings() {
        use brokk_bifrost_analysis::analyzer::semantic_model::TypeRef;
        with_model_regression_context(&named_model_regression_pack(), |context| {
            let returned = TypeRef::Declared {
                id: "holder".into(),
                arguments: vec![TypeRef::named("std.primitive.u8")],
                nullable: false,
            };
            let strict = context.modeled_return_conversion(&returned, 0);
            let projected = context.modeled_return_conversion_carrier::<RustProjectedType>(
                &returned,
                0,
                &mut ProjectedTypeReads::default(),
            );
            let strict = strict.expect("Named default retains the earlier T binding");
            let projected = projected.unwrap();
            assert_eq!(projected.into_complete().unwrap(), strict);
            let RustConversionType::Model { arguments, .. } = &strict else {
                panic!("expected Holder")
            };
            assert!(matches!(
                &arguments[0],
                RustConversionType::Primitive(RustPrimitive::U8)
            ));
            assert!(
                matches!(&arguments[1], RustConversionType::Model { arguments, .. }
                if matches!(arguments.as_slice(), [RustConversionType::Primitive(RustPrimitive::U8)]))
            );
            println!("#11043 AFTER: generic Named default complete in both carriers: {strict:?}");
        });
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "#11043: Named nesting reset the shared work allowance and retained over-budget results"
    )]
    fn named_model_regression_spends_one_shared_budget() {
        use brokk_bifrost_analysis::analyzer::semantic_model::TypeRef;
        with_model_regression_context(&named_model_regression_pack(), |context| {
            let mut returned = TypeRef::named("std.primitive.u8");
            for _ in 0..5 {
                returned = TypeRef::Named {
                    name: "model.Triple".into(),
                    arguments: vec![returned.clone(), returned.clone(), returned],
                    nullable: false,
                };
            }
            let builds = std::cell::Cell::new(0);
            for _ in 0..2 {
                let answer = context.sources.rust_expression_type(
                    context.analyzer,
                    context.file,
                    0..1,
                    0,
                    || {
                        builds.set(builds.get() + 1);
                        context.modeled_return_conversion(&returned, 0)
                    },
                );
                assert!(
                    matches!(answer, Err(ConversionUnknown::BudgetExhausted)),
                    "{answer:?}"
                );
            }
            println!(
                "#11043 AFTER: wide Named tree Partial(BudgetExhausted); warm builds={}",
                builds.get()
            );
            assert_eq!(builds.get(), 2, "a stopped model expansion is not memoized");
            assert!(matches!(
                context.modeled_return_conversion_carrier::<RustProjectedType>(
                    &returned,
                    0,
                    &mut ProjectedTypeReads::default()
                ),
                Err(ConversionUnknown::BudgetExhausted)
            ));
            let mut work = SelectedTypeWork::new(MAX_SELECTED_TYPE_WORK);
            let answer = context.modeled_return_conversion_with_bindings(
                &returned,
                0,
                &std::collections::HashMap::new(),
                &mut work,
            );
            assert!(matches!(answer, Err(ConversionUnknown::BudgetExhausted)));
            assert_eq!(work.remaining, 0);
            assert!(work.aliases.is_empty());
            let mut generous = SelectedTypeWork::new(4096);
            assert!(
                context
                    .modeled_return_conversion_with_bindings(
                        &returned,
                        0,
                        &std::collections::HashMap::new(),
                        &mut generous
                    )
                    .is_ok()
            );
        });
    }
    fn add_model_alias(
        pack: &mut serde_json::Value,
        id: &str,
        name: &str,
        parameters: &[&str],
        target: Option<brokk_bifrost_analysis::analyzer::semantic_model::TypeRef>,
    ) {
        pack["schema_version"] = serde_json::json!(32);
        pack["shards"][0]["payload"]["types"].as_array_mut().unwrap().push(serde_json::json!({
            "id":id,"name":name,"type_kind":"type_alias","visibility":"public","type_parameters":parameters,
            "alias_target":target,"locator":{"kind":"artifact","path":"fixture/model.rs","symbol":name}
        }));
    }

    #[test]
    fn model_alias_targets_share_default_and_substitution_traversal() {
        use brokk_bifrost_analysis::analyzer::semantic_model::TypeRef;
        let mut pack = named_model_regression_pack();
        let parameter = |name: &str| TypeRef::TypeParameter { name: name.into() };
        let application = |name: &str, arguments| TypeRef::Named {
            name: name.into(),
            arguments,
            nullable: false,
        };
        add_model_alias(
            &mut pack,
            "identity",
            "model.Identity",
            &["T"],
            Some(parameter("T")),
        );
        add_model_alias(
            &mut pack,
            "wrapped",
            "model.Wrapped",
            &["T"],
            Some(application("model.Boxed", vec![parameter("T")])),
        );
        add_model_alias(
            &mut pack,
            "chained",
            "model.Chained",
            &["U"],
            Some(application("model.Wrapped", vec![parameter("U")])),
        );
        add_model_alias(
            &mut pack,
            "defaulted",
            "model.Defaulted",
            &["T", "U"],
            Some(application(
                "model.Holder",
                vec![parameter("T"), parameter("U")],
            )),
        );
        pack["shards"][0]["payload"]["types"]
            .as_array_mut()
            .unwrap()
            .last_mut()
            .unwrap()["type_parameter_defaults"] = serde_json::json!([null,{"kind":"type","type":{"kind":"named","name":"model.Boxed","arguments":[{"kind":"type_parameter","name":"T"}]}}]);
        with_model_regression_context(&pack, |context| {
            let byte = TypeRef::named("std.primitive.u8");
            for (alias, direct) in [
                (
                    application("model.Identity", vec![byte.clone()]),
                    byte.clone(),
                ),
                (
                    application("model.Wrapped", vec![byte.clone()]),
                    application("model.Boxed", vec![byte.clone()]),
                ),
                (
                    application("model.Chained", vec![byte.clone()]),
                    application("model.Boxed", vec![byte.clone()]),
                ),
                (
                    application("model.Defaulted", vec![byte.clone()]),
                    application(
                        "model.Holder",
                        vec![byte.clone(), application("model.Boxed", vec![byte.clone()])],
                    ),
                ),
                (
                    application(
                        "model.Identity",
                        vec![application("model.Identity", vec![byte.clone()])],
                    ),
                    byte.clone(),
                ),
            ] {
                let expected = context.modeled_return_conversion(&direct, 0).unwrap();
                assert_eq!(
                    context.modeled_return_conversion(&alias, 0).unwrap(),
                    expected
                );
                let projected = context
                    .modeled_return_conversion_carrier::<RustProjectedType>(
                        &alias,
                        0,
                        &mut ProjectedTypeReads::default(),
                    )
                    .unwrap();
                assert_eq!(projected.into_complete().unwrap(), expected);
            }
            // The alias's T is local: it must not capture an enclosing T.
            let mut work = SelectedTypeWork::new(MAX_SELECTED_TYPE_WORK);
            let bindings = std::collections::HashMap::from([(
                "T".into(),
                RustConversionType::Primitive(RustPrimitive::U16),
            )]);
            assert_eq!(
                context
                    .modeled_return_conversion_with_bindings(
                        &application("model.Identity", vec![byte]),
                        0,
                        &bindings,
                        &mut work
                    )
                    .unwrap(),
                RustConversionType::Primitive(RustPrimitive::U8)
            );
        });
    }

    #[test]
    fn model_alias_missing_and_incomplete_targets_remain_partial() {
        use brokk_bifrost_analysis::analyzer::semantic_model::TypeRef;
        let mut pack = named_model_regression_pack();
        add_model_alias(&mut pack, "missing", "model.Missing", &[], None);
        add_model_alias(
            &mut pack,
            "unknown",
            "model.Unknown",
            &[],
            Some(TypeRef::Unknown),
        );
        add_model_alias(
            &mut pack,
            "reference",
            "model.Reference",
            &[],
            Some(TypeRef::ByRef {
                element: Box::new(TypeRef::named("std.primitive.u8")),
                reference_kind: Default::default(),
            }),
        );
        add_model_alias(
            &mut pack,
            "wrapped",
            "model.Wrapped",
            &["T"],
            Some(TypeRef::Named {
                name: "model.Boxed".into(),
                arguments: vec![TypeRef::TypeParameter { name: "T".into() }],
                nullable: false,
            }),
        );
        with_model_regression_context(&pack, |context| {
            for returned in [
                TypeRef::named("model.Missing"),
                TypeRef::named("model.Unknown"),
                TypeRef::named("model.Reference"),
                TypeRef::Named {
                    name: "model.Wrapped".into(),
                    arguments: vec![],
                    nullable: false,
                },
                TypeRef::Named {
                    name: "model.Wrapped".into(),
                    arguments: vec![TypeRef::Unknown],
                    nullable: false,
                },
                TypeRef::Named {
                    name: "model.Wrapped".into(),
                    arguments: vec![TypeRef::Unknown, TypeRef::Unknown],
                    nullable: false,
                },
            ] {
                assert!(
                    context.modeled_return_conversion(&returned, 0).is_err(),
                    "{returned:?}"
                );
                let projected = context.modeled_return_conversion_carrier::<RustProjectedType>(
                    &returned,
                    0,
                    &mut ProjectedTypeReads::default(),
                );
                assert!(
                    projected
                        .and_then(RustProjectedType::into_complete)
                        .is_err(),
                    "{returned:?}"
                );
            }
        });
    }
    fn activate_model_packs(analyzer: &dyn IAnalyzer, packs: &[serde_json::Value]) {
        use brokk_bifrost_analysis::analyzer::semantic_model::*;
        let catalog = SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).unwrap();
        let mut controls = Vec::new();
        for wire in packs {
            let pack = compile_source(
                SourceFormat::Json,
                &serde_json::to_vec(wire).unwrap(),
                &CompilerOptions::default(),
            )
            .unwrap();
            catalog
                .register_session_pack(
                    &pack,
                    &SessionPackSource {
                        kind: SessionPackSourceKind::Embedded,
                        source_id: pack.manifest.pack_id.clone(),
                    },
                )
                .unwrap();
            controls.push(SemanticModelActivationControl {
                scope: SemanticModelControlScope::Workspace,
                action: SemanticModelControlAction::Enable,
                selector: SemanticModelPackSelector {
                    pack_id: pack.manifest.pack_id.clone(),
                    version: None,
                    manifest_digest: None,
                },
            });
        }
        let request = SemanticModelActivationRequest {
            approximate_standard_libraries: vec![],
            bifrost_version: env!("CARGO_PKG_VERSION").parse().unwrap(),
            evidence: vec![SemanticModelActivationEvidence {
                language: "rust".into(),
                ecosystem: "cargo".into(),
                package: Some(CatalogCoordinate {
                    name: "std".into(),
                    version: None,
                }),
                module: None,
                toolchain: None,
                target: None,
                configuration: None,
                artifact_sha256: None,
            }],
            controls,
            limits: SemanticModelRuntimeLimits::default(),
        };
        let outcome = acquire_active_semantic_models(
            analyzer,
            &catalog,
            None,
            &request,
            &brokk_bifrost_core::cancellation::CancellationToken::default(),
        );
        assert!(
            matches!(outcome, SemanticModelRuntimeOutcome::Ready { .. }),
            "{outcome:?}"
        );
    }

    #[test]
    fn model_alias_cycles_across_packs_are_partial_and_unwind_the_active_stack() {
        use brokk_bifrost_analysis::analyzer::semantic_model::TypeRef;
        let mut packs = Vec::new();
        for (side, other) in [("left", "right"), ("right", "left")] {
            let mut pack = named_model_regression_pack();
            pack["pack_id"] = serde_json::json!(format!("fixture.{side}"));
            let mut module = pack["shards"][0]["payload"]["types"][0].clone();
            module["id"] = serde_json::json!(format!("{side}-module"));
            module["name"] = serde_json::json!(side);
            let mut leaf = pack["shards"][0]["payload"]["types"][1].clone();
            leaf["id"] = serde_json::json!(format!("{side}-leaf"));
            leaf["name"] = serde_json::json!(format!("{side}.Leaf"));
            leaf["type_parameters"] = serde_json::json!([]);
            pack["shards"][0]["payload"]["types"] = serde_json::json!([module, leaf]);
            add_model_alias(
                &mut pack,
                &format!("{side}-alias"),
                &format!("{side}.Alias"),
                &[],
                Some(TypeRef::named(format!("{other}.Alias"))),
            );
            packs.push(pack);
        }
        with_model_regression_context(&packs[0], |context| {
            activate_model_packs(context.analyzer, &packs);
            for _ in 0..2 {
                let mut work = SelectedTypeWork::new(MAX_SELECTED_TYPE_WORK);
                let result = context.modeled_return_conversion_with_bindings(
                    &TypeRef::named("left.Alias"),
                    0,
                    &std::collections::HashMap::new(),
                    &mut work,
                );
                assert!(
                    matches!(result, Err(ConversionUnknown::GenericSubstitution)),
                    "{result:?}"
                );
                assert!(
                    work.remaining > 0,
                    "cycle detection precedes work exhaustion"
                );
                assert!(work.aliases.is_empty());
                assert!(
                    context
                        .modeled_return_conversion_with_bindings(
                            &TypeRef::named("right.Leaf"),
                            0,
                            &std::collections::HashMap::new(),
                            &mut work
                        )
                        .is_ok()
                );
                assert!(matches!(
                    context.modeled_return_conversion_carrier::<RustProjectedType>(
                        &TypeRef::named("left.Alias"),
                        0,
                        &mut ProjectedTypeReads::default()
                    ),
                    Err(ConversionUnknown::GenericSubstitution)
                ));
            }
        });
    }

    #[test]
    fn model_alias_depth_stops_are_deterministic_cold_and_warm() {
        use brokk_bifrost_analysis::analyzer::capture_query_reads;
        use brokk_bifrost_analysis::analyzer::semantic_model::TypeRef;
        let mut pack = named_model_regression_pack();
        for index in 0..=9 {
            let target = if index == 0 {
                TypeRef::named("std.primitive.u8")
            } else {
                TypeRef::named(format!("model.A{}", index - 1))
            };
            add_model_alias(
                &mut pack,
                &format!("a{index}"),
                &format!("model.A{index}"),
                &[],
                Some(target),
            );
        }
        for _ in 0..2 {
            with_model_regression_context(&pack, |context| {
                assert!(
                    context
                        .modeled_return_conversion(
                            &TypeRef::Declared {
                                id: "a7".into(),
                                arguments: vec![],
                                nullable: false
                            },
                            0
                        )
                        .is_ok()
                );
                for _ in 0..2 {
                    let (result, reads) = capture_query_reads(context.analyzer, || {
                        context.modeled_return_conversion(&TypeRef::named("model.A9"), 0)
                    });
                    assert!(
                        matches!(result, Err(ConversionUnknown::BudgetExhausted)),
                        "{result:?}"
                    );
                    assert!(reads.reuse_refused());
                }
            });
        }
    }

    #[test]
    fn model_alias_pack_only_change_invalidates_memo_and_projected_receipts() {
        use brokk_bifrost_analysis::analyzer::semantic_model::TypeRef;
        use brokk_bifrost_analysis::analyzer::{ReadKey, capture_query_reads};
        let mut pack = named_model_regression_pack();
        add_model_alias(
            &mut pack,
            "changing",
            "model.Changing",
            &[],
            Some(TypeRef::named("std.primitive.u8")),
        );
        with_model_regression_context(&pack, |context| {
            let alias = TypeRef::named("model.Changing");
            let builds = std::cell::Cell::new(0);
            let evaluate = || {
                context.sources.rust_expression_type(
                    context.analyzer,
                    context.file,
                    0..1,
                    0,
                    || {
                        builds.set(builds.get() + 1);
                        context.modeled_return_conversion(&alias, 0)
                    },
                )
            };
            let (before, before_reads) = capture_query_reads(context.analyzer, evaluate);
            assert_eq!(
                before.unwrap(),
                RustConversionType::Primitive(RustPrimitive::U8)
            );
            assert!(
                before_reads
                    .keys()
                    .iter()
                    .any(|key| matches!(key, ReadKey::Models(_)))
            );
            assert_eq!(
                evaluate().unwrap(),
                RustConversionType::Primitive(RustPrimitive::U8)
            );
            assert_eq!(builds.get(), 1);
            let projection = |context: &RustTypeContext<'_, '_>| {
                let nested = TypeRef::Named {
                    name: "model.Triple".into(),
                    arguments: vec![
                        alias.clone(),
                        TypeRef::named("std.primitive.u8"),
                        TypeRef::named("std.primitive.u8"),
                    ],
                    nullable: false,
                };
                let mut proofs = ProjectedTypeReads::default();
                let ty = context
                    .modeled_return_conversion_carrier::<RustProjectedType>(&nested, 0, &mut proofs)
                    .unwrap();
                let (_, replayed) = capture_query_reads(context.analyzer, || {
                    for (path, receipt) in &proofs.components {
                        if path == &[0] {
                            receipt.replay(context.analyzer);
                        }
                    }
                });
                let keys = replayed
                    .keys()
                    .into_iter()
                    .filter(|key| matches!(key, ReadKey::Models(_)))
                    .collect::<Vec<_>>();
                assert!(
                    !keys.is_empty(),
                    "the selected alias component carries its pack read"
                );
                (ty, keys)
            };
            let (before_projection, old_receipt_keys) = projection(context);
            let mut changed = pack.clone();
            changed["shards"][0]["payload"]["types"]
                .as_array_mut()
                .unwrap()
                .last_mut()
                .unwrap()["alias_target"] =
                serde_json::to_value(TypeRef::named("std.primitive.u16")).unwrap();
            brokk_bifrost_analysis::test_support::activate_rust_declaration_pack(
                context.analyzer,
                changed["pack_id"].as_str().unwrap(),
                &changed,
            );
            let (warm, warm_reads) = capture_query_reads(context.analyzer, evaluate);
            let warm = warm.unwrap();
            assert_eq!(warm, RustConversionType::Primitive(RustPrimitive::U16));
            assert_eq!(
                builds.get(),
                2,
                "a pack-only edit invalidates a retained source memo"
            );
            assert_ne!(before_reads.keys(), warm_reads.keys());
            assert_eq!(evaluate().unwrap(), warm);
            assert_eq!(builds.get(), 2);
            let (warm_projection, new_receipt_keys) = projection(context);
            assert_ne!(before_projection, warm_projection);
            assert_ne!(old_receipt_keys, new_receipt_keys);
            with_model_regression_context(&changed, |cold| {
                assert_eq!(cold.modeled_return_conversion(&alias, 0).unwrap(), warm);
                assert_eq!(projection(cold), (warm_projection, new_receipt_keys));
            });
        });
    }

    #[test]
    #[brokk_bifrost_test_macros::hardwon(
        "8f5ddde56c5f: alias input receipts survived at output paths after substitution"
    )]
    fn model_alias_receipts_follow_reordered_duplicated_and_erased_parameters() {
        use brokk_bifrost_analysis::analyzer::semantic_model::TypeRef;
        use brokk_bifrost_analysis::analyzer::{
            AnalyzerQueryScope, QueryReadIncomplete, ReadKey, capture_query_reads,
            i_analyzer::QueryReadReceipt, store::StoreError,
        };
        let mut pack = named_model_regression_pack();
        let parameter = |name: &str| TypeRef::TypeParameter { name: name.into() };
        let target = |arguments| TypeRef::Named {
            name: "model.Triple".into(),
            arguments,
            nullable: false,
        };
        add_model_alias(
            &mut pack,
            "swap",
            "model.Swap",
            &["A", "B"],
            Some(target(vec![parameter("B"), parameter("A"), parameter("B")])),
        );
        add_model_alias(
            &mut pack,
            "repeat",
            "model.Repeat",
            &["A", "B"],
            Some(target(vec![parameter("B"), parameter("B"), parameter("B")])),
        );
        add_model_alias(
            &mut pack,
            "drop",
            "model.Drop",
            &["A", "B"],
            Some(parameter("B")),
        );
        add_model_alias(
            &mut pack,
            "nested",
            "model.Nested",
            &["A", "B"],
            Some(TypeRef::Named {
                name: "model.Swap".into(),
                arguments: vec![parameter("A"), parameter("B")],
                nullable: false,
            }),
        );
        with_model_regression_context(&pack, |context| {
            let unused = ReadKey::Configuration(
                brokk_bifrost_analysis::analyzer::semantic::ids::StableDigest::sha256(
                    b"unused alias input",
                ),
            );
            let deciding = ReadKey::Configuration(
                brokk_bifrost_analysis::analyzer::semantic::ids::StableDigest::sha256(
                    b"deciding alias input",
                ),
            );
            let (_, bad) = QueryReadReceipt::capture_deferred(context.analyzer, || {
                context.analyzer.record_read(unused.clone());
                context.analyzer.record_query_incomplete(
                    QueryReadIncomplete::SemanticEvidenceUnavailable("unknown A".into()),
                );
                context
                    .analyzer
                    .record_query_incomplete(QueryReadIncomplete::StoreFailure(StoreError::new(
                        "unrelated A store failure",
                    )));
            });
            let (_, good) = QueryReadReceipt::capture_deferred(context.analyzer, || {
                context.analyzer.record_read(deciding.clone());
            });
            let bad = Arc::new(bad);
            let good = Arc::new(good);
            for alias in ["swap", "repeat", "drop", "nested"] {
                let mut proofs = ProjectedTypeReads {
                    components: vec![(vec![0], Arc::clone(&bad)), (vec![1], Arc::clone(&good))],
                    ..Default::default()
                };
                let result = context
                    .complete_selected_model_type_carrier::<RustProjectedType>(
                        alias,
                        vec![
                            RustProjectedType::Unknown(ConversionUnknown::UnresolvedTargetType),
                            RustProjectedType::Primitive(RustPrimitive::U16),
                        ],
                        0,
                        &mut SelectedTypeWork::new(MAX_SELECTED_TYPE_WORK),
                        &mut proofs,
                    )
                    .unwrap();
                let selected = if alias == "drop" { vec![] } else { vec![0] };
                let ((completion, failure), reads) = capture_query_reads(context.analyzer, || {
                    let scope = AnalyzerQueryScope::capturing_read_incompleteness(context.analyzer);
                    for (path, receipt) in &proofs.components {
                        if selected.starts_with(path) || path.starts_with(&selected) {
                            receipt.replay(context.analyzer);
                        }
                    }
                    (
                        scope.read_completion(),
                        scope.captured_read_incompleteness(),
                    )
                });
                assert_eq!(completion, Ok(()), "{alias}");
                assert!(failure.is_empty(), "{alias}");
                assert!(reads.keys().contains(&deciding), "{alias}");
                assert!(!reads.keys().contains(&unused), "{alias}");
                assert!(proofs.bindings.is_empty(), "binding scope must unwind");
                if alias == "drop" {
                    assert_eq!(result, RustProjectedType::Primitive(RustPrimitive::U16));
                } else {
                    assert!(matches!(&result,RustProjectedType::Model { arguments,.. }
                        if arguments[0]==RustProjectedType::Primitive(RustPrimitive::U16)));
                }
                if alias == "swap" || alias == "nested" {
                    let ((completion, failure), reads) =
                        capture_query_reads(context.analyzer, || {
                            let scope =
                                AnalyzerQueryScope::capturing_read_incompleteness(context.analyzer);
                            for (path, receipt) in &proofs.components {
                                if path == &[1] {
                                    receipt.replay(context.analyzer);
                                }
                            }
                            (
                                scope.read_completion(),
                                scope.captured_read_incompleteness(),
                            )
                        });
                    assert!(
                        completion.is_err(),
                        "selected A keeps its own incompleteness"
                    );
                    assert!(
                        failure
                            .iter()
                            .any(|reason| matches!(reason, QueryReadIncomplete::StoreFailure(_))),
                        "selected A keeps its own store failure"
                    );
                    assert!(reads.keys().contains(&unused));
                }
            }
        });
    }

    // The production cache is oracle-generation local. Deliberately retain it
    // across activation here to verify the model identity defense in depth.
    #[test]
    fn nominal_model_pack_only_change_separates_retained_memo_entries() {
        use brokk_bifrost_analysis::analyzer::semantic_model::TypeRef;
        let mut pack = named_model_regression_pack();
        pack["shards"][0]["payload"]["types"][3]["type_parameter_defaults"][1]["type"] =
            serde_json::to_value(TypeRef::named("std.primitive.u8")).unwrap();
        with_model_regression_context(&pack, |context| {
            let returned = TypeRef::Named {
                name: "model.Holder".into(),
                arguments: vec![TypeRef::named("std.primitive.u8")],
                nullable: false,
            };
            let builds = std::cell::Cell::new(0);
            let evaluate = || {
                context
                    .sources
                    .rust_expression_type(context.analyzer, context.file, 0..1, 0, || {
                        builds.set(builds.get() + 1);
                        context.modeled_return_conversion(&returned, 0)
                    })
                    .unwrap()
            };
            let before = evaluate();
            assert_eq!(evaluate(), before);
            assert_eq!(builds.get(), 1);
            let mut changed = pack.clone();
            changed["shards"][0]["payload"]["types"][3]["type_parameter_defaults"][1]["type"] =
                serde_json::to_value(TypeRef::named("std.primitive.u16")).unwrap();
            brokk_bifrost_analysis::test_support::activate_rust_declaration_pack(
                context.analyzer,
                changed["pack_id"].as_str().unwrap(),
                &changed,
            );
            let warm = evaluate();
            assert_ne!(before, warm);
            assert_eq!(builds.get(), 2);
            assert_eq!(
                warm,
                context.modeled_return_conversion(&returned, 0).unwrap()
            );
            with_model_regression_context(&changed, |cold| {
                assert_eq!(warm, cold.modeled_return_conversion(&returned, 0).unwrap());
            });
        });
    }

    fn external_nominal_pack() -> serde_json::Value {
        let mut pack = named_model_regression_pack();
        let types = pack["shards"][0]["payload"]["types"]
            .as_array_mut()
            .unwrap();
        for (id, name, kind, parameters) in [
            ("cbc", "cbc", "module", vec![]),
            ("des", "des", "module", vec![]),
            ("encryptor", "cbc.Encryptor", "struct", vec!["Cipher"]),
            ("des-type", "des.Des", "struct", vec![]),
        ] {
            types.push(serde_json::json!({"id":id,"name":name,"type_kind":kind,
                "visibility":"public","type_parameters":parameters,
                "locator":{"kind":"artifact","path":"fixture/external.rs","symbol":name}}));
        }
        pack
    }

    fn with_external_nominal_context<R>(
        packs: &[serde_json::Value],
        source: &str,
        dependencies: &str,
        run: impl FnOnce(&RustTypeContext<'_, '_>) -> R,
    ) -> R {
        let manifest = format!(
            "[package]\nname=\"fixture\"\nversion=\"0.1.0\"\nedition=\"2024\"\n[dependencies]\n{dependencies}"
        );
        let (_fixture, analyzer) = super::super::test_support::certified_project(&[
            ("Cargo.toml", manifest.as_str()),
            ("src/lib.rs", source),
        ]);
        activate_model_packs(&analyzer, packs);
        let file = super::super::test_support::analyzed_file(&analyzer, "src/lib.rs");
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let cache = CallConversionCache::default();
        let sources = CallConversionContext::reference(&cache);
        run(&RustTypeContext {
            analyzer: &analyzer,
            sources: &sources,
            file: &file,
            source,
            root: tree.root_node(),
        })
    }

    #[test]
    fn scope_proved_external_nominal_target_completes_source_alias() {
        use brokk_bifrost_analysis::analyzer::semantic_model::TypeRef;
        use brokk_bifrost_analysis::analyzer::{ReadKey, capture_query_reads};
        let pack = external_nominal_pack();
        let source =
            "type MyDesEncryptor = cbc::Encryptor<des::Des>; fn probe(_: MyDesEncryptor) {}";
        with_external_nominal_context(&[pack], source, "cbc=\"0.1\"\ndes=\"0.8\"\n", |context| {
            let start = source.rfind("MyDesEncryptor").unwrap();
            let node = context
                .root
                .named_descendant_for_byte_range(start, start + 14)
                .unwrap();
            let (strict, reads) =
                capture_query_reads(context.analyzer, || context.type_from_node(node, 0));
            assert_eq!(
                strict,
                context.modeled_return_conversion(
                    &TypeRef::Named {
                        name: "cbc.Encryptor".into(),
                        arguments: vec![TypeRef::named("des.Des")],
                        nullable: false,
                    },
                    0
                )
            );
            assert!(strict.is_ok(), "{strict:?}");
            assert!(
                reads
                    .keys()
                    .iter()
                    .any(|key| matches!(key, ReadKey::Models(_)))
            );
            let mut work = SelectedTypeWork::new(MAX_SELECTED_TYPE_WORK);
            let expression = selected_type::alias_type_expr(
                node,
                context.file,
                &Arc::from(source),
                &mut work.remaining,
            )
            .unwrap();
            let projected = context
                .selected_type_expression_carrier::<RustProjectedType>(
                    expression,
                    0,
                    &mut work,
                    &mut ProjectedTypeReads::default(),
                )
                .unwrap()
                .into_complete();
            assert_eq!(projected, strict);
        });
    }

    #[test]
    fn external_type_namespace_keeps_values_and_ambiguity_partial() {
        use brokk_bifrost_analysis::analyzer::semantic_model::overlay::RustReexportNamespace;
        let pack = external_nominal_pack();
        let source = "fn probe(_: cbc::Encryptor<des::Des>) {}";
        with_external_nominal_context(
            std::slice::from_ref(&pack),
            source,
            "cbc=\"0.1\"\ndes=\"0.8\"\n",
            |context| {
                let snapshot = context.analyzer.active_semantic_model_snapshot().unwrap();
                let overlay = snapshot.semantic_model_overlay().unwrap();
                let crates = super::super::crate_identity::RustOverlayCrates::new(Some(overlay));
                assert!(
                    crates
                        .referenceable_symbol_in_namespace(
                            "cbc.Encryptor",
                            RustReexportNamespace::TypeOrModule
                        )
                        .is_some()
                );
            },
        );
        let mut other = pack.clone();
        other["pack_id"] = serde_json::json!("fixture.ambiguous-external");
        other["shards"][0]["payload"]["types"][6]["id"] = serde_json::json!("encryptor-other");
        with_external_nominal_context(
            &[pack, other],
            source,
            "cbc=\"0.1\"\ndes=\"0.8\"\n",
            |context| {
                let start = source.find("cbc::").unwrap();
                let node = context
                    .root
                    .named_descendant_for_byte_range(start, source.find(">)").unwrap() + 1)
                    .unwrap();
                assert!(context.type_from_node(node, 0).is_err());
            },
        );
    }

    #[test]
    fn module_value_collision_obeys_type_namespace_only() {
        use brokk_bifrost_analysis::analyzer::semantic_model::overlay::RustReexportNamespace;
        let mut pack = external_nominal_pack();
        pack["shards"][0]["payload"]["types"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "id":"cbc-sub","name":"cbc.Sub","type_kind":"module","visibility":"public",
                "locator":{"kind":"artifact","path":"fixture/external.rs","symbol":"cbc.Sub"}
            }));
        pack["shards"][0]["payload"]["members"] = serde_json::json!([{
            "id":"cbc-sub-value","owner":"cbc","name":"Sub","member_kind":"constant","visibility":"public",
            "locator":{"kind":"artifact","path":"fixture/external.rs","symbol":"cbc.Sub"}
        }]);
        with_external_nominal_context(&[pack], "fn probe() {}", "cbc=\"0.1\"\n", |context| {
            let snapshot = context.analyzer.active_semantic_model_snapshot().unwrap();
            let overlay = snapshot.semantic_model_overlay().unwrap();
            let crates = super::super::crate_identity::RustOverlayCrates::new(Some(overlay));
            assert!(
                crates.referenceable_symbol("cbc.Sub").is_none(),
                "Unknown preserves the collision"
            );
            assert!(crates.is_module_surface(&["cbc".into(), "Sub".into()]));
            assert_eq!(
                crates
                    .referenceable_symbol_in_namespace("cbc.Sub", RustReexportNamespace::Value)
                    .unwrap()
                    .id,
                "cbc-sub-value"
            );
        });
    }

    #[test]
    fn external_nominal_value_only_and_unproved_routes_remain_partial() {
        use brokk_bifrost_analysis::analyzer::{ReadKey, capture_query_reads};
        let mut value_only = external_nominal_pack();
        value_only["shards"][0]["payload"]["types"]
            .as_array_mut()
            .unwrap()
            .retain(|ty| ty["id"] != "encryptor");
        value_only["shards"][0]["payload"]["members"] = serde_json::json!([{
            "id":"encryptor-value","owner":"cbc","name":"Encryptor","member_kind":"constant","visibility":"public",
            "locator":{"kind":"artifact","path":"fixture/external.rs","symbol":"cbc.Encryptor"}
        }]);
        // As for external calls, an activated published model root is enough
        // to admit that spelling (including std without a Cargo dependency).
        // A local shadow or a different, unselected root is not such proof.
        for (pack, source, deps) in [
            (
                value_only,
                "fn probe(_: cbc::Encryptor<des::Des>) {}",
                "cbc=\"0.1\"\ndes=\"0.8\"\n",
            ),
            (
                external_nominal_pack(),
                "mod cbc {} fn probe(_: cbc::Encryptor<des::Des>) {}",
                "cbc=\"0.1\"\ndes=\"0.8\"\n",
            ),
            (
                external_nominal_pack(),
                "fn probe(_: unproved::Encryptor<des::Des>) {}",
                "unproved=\"0.1\"\ndes=\"0.8\"\n",
            ),
        ] {
            with_external_nominal_context(&[pack], source, deps, |context| {
                let start = source
                    .find("cbc::")
                    .or_else(|| source.find("unproved::"))
                    .unwrap();
                let end = source.find(">)").unwrap() + 1;
                let node = context
                    .root
                    .named_descendant_for_byte_range(start, end)
                    .unwrap();
                let (answer, reads) =
                    capture_query_reads(context.analyzer, || context.type_from_node(node, 0));
                assert!(answer.is_err(), "{source}: {answer:?}");
                assert!(
                    reads
                        .keys()
                        .iter()
                        .any(|key| matches!(key, ReadKey::Models(_)))
                );
            });
        }
    }

    #[test]
    fn external_nominal_pack_only_change_matches_cold_and_keeps_ambiguity_partial() {
        use brokk_bifrost_analysis::analyzer::{ReadKey, capture_query_reads};
        let pack = external_nominal_pack();
        let source =
            "type MyDesEncryptor = cbc::Encryptor<des::Des>; fn probe(_: MyDesEncryptor) {}";
        let dependencies = "cbc=\"0.1\"\ndes=\"0.8\"\n";
        with_external_nominal_context(
            std::slice::from_ref(&pack),
            source,
            dependencies,
            |context| {
                let start = source.rfind("MyDesEncryptor").unwrap();
                let node = context
                    .root
                    .named_descendant_for_byte_range(start, start + 14)
                    .unwrap();
                let builds = std::cell::Cell::new(0);
                let evaluate = || {
                    context.sources.rust_expression_type(
                        context.analyzer,
                        context.file,
                        start..start + 14,
                        0,
                        || {
                            builds.set(builds.get() + 1);
                            context.type_from_node(node, 0)
                        },
                    )
                };
                let (before, old_reads) = capture_query_reads(context.analyzer, evaluate);
                assert!(before.is_ok(), "{before:?}");
                assert_eq!(evaluate(), before);
                assert_eq!(builds.get(), 1);
                let mut duplicate = pack.clone();
                duplicate["pack_id"] = serde_json::json!("fixture.external-second-candidate");
                duplicate["shards"][0]["payload"]["types"][6]["id"] =
                    serde_json::json!("encryptor-other");
                let changed = [pack.clone(), duplicate];
                activate_model_packs(context.analyzer, &changed);
                let (warm, new_reads) = capture_query_reads(context.analyzer, evaluate);
                assert!(warm.is_err(), "{warm:?}");
                assert_eq!(evaluate(), warm);
                assert_eq!(
                    builds.get(),
                    2,
                    "stable ambiguity may be memoized, but remains Partial on every hit"
                );
                let models = |reads: &brokk_bifrost_analysis::analyzer::read_ledger::ReadLedger| {
                    reads
                        .keys()
                        .into_iter()
                        .filter(|key| matches!(key, ReadKey::Models(_)))
                        .collect::<Vec<_>>()
                };
                assert!(!models(&old_reads).is_empty());
                assert!(!models(&new_reads).is_empty());
                assert_ne!(models(&old_reads), models(&new_reads));
                with_external_nominal_context(&changed, source, dependencies, |cold| {
                    let node = cold
                        .root
                        .named_descendant_for_byte_range(start, start + 14)
                        .unwrap();
                    let (answer, reads) =
                        capture_query_reads(cold.analyzer, || cold.type_from_node(node, 0));
                    assert_eq!(answer, warm);
                    assert_eq!(models(&reads), models(&new_reads));
                });
            },
        );
    }

    #[test]
    fn qualifying_model_alias_constructors_select_arity_and_keep_ambiguity_partial() {
        use brokk_bifrost_analysis::analyzer::semantic_model::TypeRef;
        let mut pack = named_model_regression_pack();
        for (id, name, kind, parameters) in [
            ("cipher", "cipher", "module", vec![]),
            ("rabbit", "rabbit", "module", vec![]),
            (
                "wrapper",
                "cipher.StreamCipherCoreWrapper",
                "struct",
                vec!["T"],
            ),
            ("rabbit-core", "rabbit.RabbitCore", "struct", vec![]),
            (
                "rabbit-key-only-core",
                "rabbit.RabbitKeyOnlyCore",
                "struct",
                vec![],
            ),
        ] {
            pack["shards"][0]["payload"]["types"].as_array_mut().unwrap().push(serde_json::json!({
                "id":id,"name":name,"type_kind":kind,"type_parameters":parameters,"visibility":"public",
                "locator":{"kind":"artifact","path":"fixture/cipher.rs","symbol":name}
            }));
        }
        for (id, name, core) in [
            ("rabbit-alias", "rabbit.Rabbit", "rabbit-core"),
            (
                "rabbit-key-only-alias",
                "rabbit.RabbitKeyOnly",
                "rabbit-key-only-core",
            ),
        ] {
            add_model_alias(
                &mut pack,
                id,
                name,
                &[],
                Some(TypeRef::Declared {
                    id: "wrapper".into(),
                    arguments: vec![TypeRef::Declared {
                        id: core.into(),
                        arguments: vec![],
                        nullable: false,
                    }],
                    nullable: false,
                }),
            );
        }
        pack["shards"][0]["payload"]["members"] = serde_json::Value::Array([1,2].into_iter().map(|arity| {
            let parameters=(0..arity).map(|index| serde_json::json!({"name":format!("input{index}"),"type":{"kind":"unknown"}})).collect::<Vec<_>>();
            serde_json::json!({"id":format!("wrapper.new.{arity}"),"owner":"wrapper","name":"new",
                "member_kind":"method","visibility":"public","is_static":true,"callable_family_complete":true,
                "signature":{"parameters":parameters,"returns":{"kind":"declared","id":"wrapper","arguments":[{"kind":"type_parameter","name":"T"}],"nullable":false}},
                "locator":{"kind":"artifact","path":"fixture/cipher.rs","symbol":"cipher.StreamCipherCoreWrapper.new"}})
        }).collect());
        let source = "fn run() { rabbit::Rabbit::new(0u8, 0u8); rabbit::RabbitKeyOnly::new(0u8); rabbit::Rabbit::new(); }";
        let evaluate = |pack: &serde_json::Value, spelling: &str| {
            with_external_nominal_context(
                std::slice::from_ref(pack),
                source,
                "rabbit=\"0.4\"\ncipher=\"0.4\"\n",
                |context| {
                    let start = source.find(spelling).unwrap();
                    let call = context
                        .root
                        .named_descendant_for_byte_range(start, start + spelling.len())
                        .unwrap();
                    assert_eq!(call.kind(), "call_expression");
                    call_qualifying_type(
                        context.analyzer,
                        context.sources,
                        context.file,
                        source,
                        call,
                    )
                    .map(|proof| proof.map(|proof| proof.ty))
                },
            )
        };
        for spelling in [
            "rabbit::Rabbit::new(0u8, 0u8)",
            "rabbit::RabbitKeyOnly::new(0u8)",
        ] {
            let proof = evaluate(&pack, spelling).unwrap().unwrap();
            assert!(matches!(proof,RustProjectedType::Model { symbol,.. } if symbol=="wrapper"));
        }
        assert!(
            evaluate(&pack, "rabbit::Rabbit::new()").is_err(),
            "absent arity is Partial, never nonmatch"
        );
        let mut same_arity = pack.clone();
        let mut duplicate = same_arity["shards"][0]["payload"]["members"][0].clone();
        duplicate["id"] = serde_json::json!("wrapper.new.1-second");
        same_arity["shards"][0]["payload"]["members"]
            .as_array_mut()
            .unwrap()
            .push(duplicate);
        assert!(
            evaluate(&same_arity, "rabbit::RabbitKeyOnly::new(0u8)").is_err(),
            "two same-arity candidates stay Partial"
        );
    }

    #[test]
    fn source_alias_to_model_alias_keeps_the_target_pack_scope() {
        use brokk_bifrost_analysis::analyzer::semantic_model::TypeRef;
        let mut pack = named_model_regression_pack();
        for (id, name) in [("std-module", "std"), ("string-module", "std.string")] {
            pack["shards"][0]["payload"]["types"]
                .as_array_mut()
                .unwrap()
                .push(serde_json::json!({
                    "id":id,"name":name,"type_kind":"module","visibility":"public",
                    "locator":{"kind":"artifact","path":"fixture/std.rs","symbol":name}
                }));
        }
        let target = TypeRef::Named {
            name: "model.Boxed".into(),
            arguments: vec![TypeRef::named("std.primitive.u8")],
            nullable: false,
        };
        add_model_alias(
            &mut pack,
            "string",
            "std.string.String",
            &[],
            Some(target.clone()),
        );
        let source = "mod model { pub struct Boxed; } type Chosen = String; fn probe(_: Chosen) {}";
        with_model_source_context(&pack, source, |context| {
            let start = source.rfind("Chosen").unwrap();
            let node = context
                .root
                .named_descendant_for_byte_range(start, start + 6)
                .unwrap();
            let strict = context.type_from_node(node, 0).unwrap();
            assert_eq!(
                strict,
                context.modeled_return_conversion(&target, 0).unwrap()
            );
            assert!(
                matches!(&strict, RustConversionType::Model { .. }),
                "the caller's model::Boxed must not capture a pack reference"
            );
            let mut work = SelectedTypeWork::new(MAX_SELECTED_TYPE_WORK);
            let expression = selected_type::alias_type_expr(
                node,
                context.file,
                &Arc::from(source),
                &mut work.remaining,
            )
            .unwrap();
            let projected = context
                .selected_type_expression_carrier::<RustProjectedType>(
                    expression,
                    0,
                    &mut work,
                    &mut ProjectedTypeReads::default(),
                )
                .unwrap();
            assert_eq!(projected.into_complete().unwrap(), strict);
        });
    }
}
