//! Contextual result-use proof for direct Java expression-lambda calls.

mod selected;

use crate::analyzer::usages::get_definition::java::*;
use brokk_bifrost_analysis::analyzer::AnalyzerQueryScope;
use brokk_bifrost_analysis::analyzer::CodeUnit;
use brokk_bifrost_analysis::analyzer::IAnalyzer;
use brokk_bifrost_analysis::analyzer::Language;
use brokk_bifrost_analysis::analyzer::ProjectFile;
use brokk_bifrost_analysis::analyzer::Range;
use brokk_bifrost_analysis::analyzer::resolve_analyzer;
use brokk_bifrost_analysis::cancellation::CancellationToken;
use brokk_bifrost_core::analyzer::query_token::QueryScope;
use brokk_bifrost_core::analyzer::usages::inverted_edges::first_precise;
use brokk_bifrost_core::analyzer::usages::resolution_session::BoundedResolution;
use std::sync::Arc;
use tree_sitter::Node;

use crate::analyzer::jvm::external::JvmExternalDeclarationSource;

use crate::analyzer::jvm::external::JvmExternalType;

use brokk_bifrost_analysis::analyzer::semantic_model::runtime::ActiveSemanticModelSnapshot;

use brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay;

use brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelSymbol;

use brokk_bifrost_analysis::analyzer::semantic_model::TypeRef;

use brokk_bifrost_analysis::analyzer::analyzer_definition_lookup::AnalyzerDefinitionLookup;

use brokk_bifrost_jvm::java::graph::return_type::java_type_name_from_node;
use brokk_bifrost_jvm::java::structural::JavaCallResultUse;

/// Classify a call which syntax alone cannot classify because it is the body
/// of an expression lambda. All source reads use the supplied source snapshot;
/// external declarations use the supplied activation snapshot. None is an
/// explicit missing proof, never a retained-result verdict.
#[allow(clippy::too_many_arguments)]
pub fn java_expression_lambda_result_use(
    analyzer: &dyn IAnalyzer,
    snapshot: Option<&ActiveSemanticModelSnapshot>,
    file: &ProjectFile,
    source: &str,
    range: Range,
    remaining_work: &mut usize,
    cancellation: &CancellationToken,
) -> Option<JavaCallResultUse> {
    if cancellation.is_cancelled() {
        return None;
    }
    // Parsing is transient and charged by input bytes. Only selected,
    // syntax-unclassified call sites reach this path; the caller memoizes the
    // result under the exact source identity and call span.
    let Some(after_parse) = remaining_work.checked_sub(source.len()) else {
        *remaining_work = 0;
        return None;
    };
    *remaining_work = after_parse;
    let tree = brokk_bifrost_jvm::java::declarations::parse_tree(source)?;
    let root = tree.root_node();
    if root.has_error() {
        return None;
    }
    let call = root.named_descendant_for_byte_range(range.start_byte, range.end_byte)?;
    if call.start_byte() != range.start_byte
        || call.end_byte() != range.end_byte
        || !matches!(
            call.kind(),
            "method_invocation" | "object_creation_expression"
        )
    {
        return None;
    }
    let mut expression = call;
    while expression
        .parent()
        .is_some_and(|parent| parent.kind() == "parenthesized_expression")
    {
        expression = expression.parent().expect("parent was checked");
    }
    let lambda = expression.parent()?;
    if lambda.kind() != "lambda_expression"
        || lambda.child_by_field_name("body") != Some(expression)
    {
        return None;
    }
    let parameters = lambda.child_by_field_name("parameters")?;
    let arity = if parameters.kind() == "identifier" {
        1
    } else {
        let mut cursor = parameters.walk();
        parameters
            .named_children(&mut cursor)
            .filter(|node| !node.is_extra())
            .count()
    };
    let java = resolve_analyzer::<JavaAnalyzer>(analyzer)?;
    let snapshot = snapshot?;
    let models = snapshot.semantic_model_overlay()?.clone();
    let selected = snapshot.jdk_artifact_for_home(java.selected_jdk_home_for_file(file).ok()?)?;
    let digest = selected.single_raw_sha256()?;
    let digest = digest.as_str();
    let support = AnalyzerDefinitionLookup::new(analyzer, Language::Java);
    let session = JavaResolutionSession::bounded(
        &support,
        ReceiverAnalysisBudget::default(),
        Some(cancellation),
    );
    let scope = AnalyzerQueryScope::new(analyzer);
    let token = scope.token();
    let file_for_lambda = file;
    let resolved = (|| {
        let resolve_type = |context_file: &ProjectFile, context_source: &str, mut ty: Node<'_>| {
            let file = context_file;
            let source = context_source;
            if java.selected_jdk_home_for_file(file).ok()?
                != java.selected_jdk_home_for_file(file_for_lambda).ok()?
            {
                return None;
            }
            while ty.kind() == "annotated_type" {
                let mut cursor = ty.walk();
                ty = ty.named_children(&mut cursor).find(|node| {
                    brokk_bifrost_jvm::java::graph::return_type::is_java_nominal_type_node(
                        node.kind(),
                    )
                })?;
            }
            if !matches!(
                ty.kind(),
                "type_identifier" | "scoped_type_identifier" | "generic_type"
            ) {
                return None;
            }
            let name = java_type_name_from_node(ty, source)?;
            if brokk_bifrost_jvm::java::graph_support::java_type_parameter_in_scope(
                ty, source, &name,
            )
            .is_some()
            {
                return None;
            }
            if let Some(unit) = java_type_text_with_context(
                analyzer, token, java, &session, file, source, &name, ty,
            ) {
                return Some(ResolvedFunctionalTarget::Source(unit));
            }
            let parsed_name = JavaTypeName::from_normalized_spelling(&name)?;
            let site = UseSite {
                token,
                source,
                node: ty,
            };
            let resolved = session.query_optional_row(|| {
                java.resolve_type_name_at(
                    token,
                    Some(Arc::clone(&models)),
                    file,
                    &parsed_name,
                    Some(digest),
                    Some(&site),
                )
            })?;
            match resolved {
                JavaTypeResolution::External(external) => {
                    selected_symbol(&models, &external).map(ResolvedFunctionalTarget::External)
                }
                JavaTypeResolution::Source(unit) => Some(ResolvedFunctionalTarget::Source(unit)),
            }
        };
        let owner = match contextual_type(analyzer, token, &session, file, source, root, lambda)? {
            LambdaTarget::Type(ty) => resolve_type(file, source, ty)?,
            LambdaTarget::ExternalArgument(invocation) => {
                // Other arguments and varargs need their own applicability proof.
                if argument_list_arity(invocation) != 1 {
                    return None;
                }
                let receiver = invocation.child_by_field_name("object")?;
                let ty = java_receiver_type_node(&session, file, source, root, receiver)?;
                let ResolvedFunctionalTarget::External(receiver) = resolve_type(file, source, ty)?
                else {
                    return None;
                };
                let name = java_node_text(invocation.child_by_field_name("name")?, source);
                let method = models.java_single_instance_method(
                    &receiver,
                    name,
                    remaining_work,
                    cancellation,
                )?;
                let signature = method.structured_signature()?;
                let [formal] = signature.parameters.as_slice() else {
                    return None;
                };
                if formal.variadic {
                    return None;
                }
                if formal.r#type.contains_unknown() {
                    return None;
                }
                let candidates = match &formal.r#type {
                    TypeRef::Named { name, .. } => models.symbols_named(name),
                    TypeRef::Declared { id, .. } => models.symbols_with_id(id),
                    _ => return None,
                };
                if matches!(candidates.disposition, brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelOverlayDisposition::Open(_)) { return None; }
                let [target] = candidates.records.as_slice() else {
                    return None;
                };
                if target.provenance.ambiguous
                    || target.provenance.pack_id != receiver.provenance.pack_id
                {
                    return None;
                }
                ResolvedFunctionalTarget::External(target.clone())
            }
            LambdaTarget::Parameter(method, ordinal) => {
                let ranges = session.ranges(analyzer, &method);
                let [range] = ranges.as_slice() else {
                    return None;
                };
                let method_file = method.source();
                if method_file == file {
                    let ty = formal_type(&session, root, source, range, ordinal)?;
                    resolve_type(file, source, ty)?
                } else {
                    // Read the indexed snapshot, never a newer on-disk declaration.
                    let method_source =
                        session.query_optional_row(|| analyzer.indexed_source(method_file))?;
                    let Some(remaining) = remaining_work.checked_sub(method_source.len()) else {
                        *remaining_work = 0;
                        return None;
                    };
                    *remaining_work = remaining;
                    let tree = session
                        .structured_query(|| {
                            parse_tree_for_language(method_file, Language::Java, &method_source)
                        })
                        .flatten()?;
                    let ty =
                        formal_type(&session, tree.root_node(), &method_source, range, ordinal)?;
                    resolve_type(method_file, &method_source, ty)?
                }
            }
        };
        let object = session.query_optional_row(|| {
            java.resolve_type_name_with_selected_jdk(
                token,
                Some(Arc::clone(&models)),
                file,
                "java.lang.Object",
                Some(digest),
            )
        })?;
        let JavaTypeResolution::External(object) = object else {
            return None;
        };
        let object = selected_symbol(&models, &object)?;
        if object
            .provenance
            .activation
            .matched_evidence
            .artifact_sha256
            .as_deref()
            != Some(digest)
        {
            return None;
        }
        match owner {
            ResolvedFunctionalTarget::External(owner) => {
                let method =
                    models.java_functional_method(&owner, &object, remaining_work, cancellation)?;
                let signature = method.structured_signature()?;
                if signature.parameters.len() != arity {
                    return None;
                }
                Some(if signature.returns.is_some() {
                    JavaCallResultUse::OtherContext
                } else {
                    JavaCallResultUse::Discarded
                })
            }
            ResolvedFunctionalTarget::Source(unit) => {
                let load = |unit: &CodeUnit, remaining: &mut usize| {
                    if !session.charge_scope_step() {
                        return None;
                    }
                    let target_file = unit.source();
                    if java.selected_jdk_home_for_file(target_file).ok()?
                        != java.selected_jdk_home_for_file(file).ok()?
                    {
                        return None;
                    }
                    let ranges = session.ranges(analyzer, unit);
                    let [range] = ranges.as_slice() else {
                        return None;
                    };
                    let prove = |root, source: &str| {
                        source_interface_inventory(
                            analyzer,
                            token,
                            java,
                            &session,
                            &models,
                            digest,
                            target_file,
                            source,
                            root,
                            range,
                        )
                    };
                    if target_file == file {
                        prove(root, source)
                    } else {
                        let target_source =
                            session.query_optional_row(|| analyzer.indexed_source(target_file))?;
                        spend(remaining, cancellation, target_source.len())?;
                        let tree = session
                            .structured_query(|| {
                                parse_tree_for_language(target_file, Language::Java, &target_source)
                            })
                            .flatten()?;
                        prove(tree.root_node(), &target_source)
                    }
                };
                use crate::analyzer::jvm::selected_operation::{
                    SelectedJvmOperationOutcome, SelectedJvmRecipe,
                };
                use brokk_bifrost_analysis::analyzer::resolution::{
                    SelectedFactOperationBlueprintConstruction,
                    SelectedResolutionContextValidationOutcome,
                };
                use brokk_bifrost_analysis::analyzer::store::resolution_operation::jvm_demand::JvmForwardOperationContext;
                use brokk_bifrost_analysis::analyzer::store::resolution_operation::{
                    SelectedResolutionContextMetrics, jvm_context,
                };
                let result = (|| -> brokk_bifrost_analysis::analyzer::store::Result<Option<JavaCallResultUse>> {
                    let recipe = SelectedJvmRecipe::new(java.inner())?;
                    let SelectedJvmOperationOutcome::Ready(operation) = recipe.open(cancellation)? else { return Ok(None); };
                    let caller_path = brokk_bifrost_core::path_utils::rel_path_string(file);
                    let jvm_context::JvmImportContext::Ready { context, scoped_gaps, .. } = operation.jvm_import_context(Language::Java, &caller_path, cancellation)? else { return Ok(None); };
                    let SelectedResolutionContextValidationOutcome::Ready(context) = operation.prepare_context(*context, cancellation, &SelectedResolutionContextMetrics)? else { return Ok(None); };
                    let SelectedFactOperationBlueprintConstruction::Ready(blueprint) = operation.ready().collect_blueprint(context, cancellation)? else { return Ok(None); };
                    let lexical = operation.ready().lexical_source();
                    let typed = operation.ready().typed_source();
                    let export_root_reads = || brokk_bifrost_analysis::analyzer::root_presence::record_consumed_root_presence(java.inner(), &operation);
                    operation.with_jvm_hierarchy_query_receipts(
                        JvmForwardOperationContext {
                            storage_language: "java", blueprint: &blueprint,
                            caller_path: &caller_path, import_gaps: &scoped_gaps,
                            lexical: &lexical, typed: &typed, cancellation,
                            session: &session.resolution,
                        },
                        &mut crate::analyzer::jvm::selected_operation::HierarchyReadCapture(java.inner(), &export_root_reads),
                        |query| {
                            let mut selected_hierarchy = selected::SelectedSourceHierarchy::new(&operation, query, &typed, &models, digest, &session, cancellation);
                            let hierarchy = |owner: &FunctionalOwner, parameters: Option<&[SourceVariable]>, content: Option<git2::Oid>, remaining: &mut usize| {
                                spend(remaining, cancellation, 1)?;
                                match selected_hierarchy.edges(owner, parameters, content) {
                                    Ok(edges) => edges,
                                    Err(error) => {
                                        eprintln!("selected Java SAM hierarchy unavailable for {file:?}: {error}");
                                        None
                                    }
                                }
                            };
                            let mut inventory = SourceFunctionalInventory {
                                load, hierarchy, models: &models, object: &object,
                                remaining_work, cancellation, methods: Vec::new(),
                                source_members: Default::default(), parameters: Default::default(), edges: Default::default(),
                            };
                            Ok((|| {
                                let selected = functional_method(&mut inventory, FunctionalOwner::Source(unit))?;
                                if inventory.name_and_arity(&selected.method)?.1 != arity { return None; }
                                // JLS 9.9: substitution preserves arity and cannot turn void
                                // into a value. Result-use proof also accepts a non-ground SAM.
                                match selected.method {
                                    FunctionalMember::Source(index) => inventory.methods[index].result_use,
                                    FunctionalMember::External(id) => {
                                        let method = inventory.external(&id)?;
                                        Some(if method.structured_signature()?.returns.is_some() { JavaCallResultUse::OtherContext } else { JavaCallResultUse::Discarded })
                                    }
                                }
                            })())
                        },
                    )
                })();
                match result {
                    Ok(value) => value,
                    Err(error) => {
                        eprintln!("selected Java SAM operation unavailable for {file:?}: {error}");
                        None
                    }
                }
            }
        }
    })();
    match session.finish(resolved) {
        BoundedResolution::Complete { value, work } => {
            // Resolution rounds are iterations, not lambda lookup expansion, and
            // visiting syntax never counts against an allowance (#13216).
            let spent = work
                .setup_nodes
                .saturating_add(work.summary_expansions)
                .saturating_add(work.hierarchy_order_steps);
            let Some(remaining) = remaining_work.checked_sub(spent) else {
                *remaining_work = 0;
                return None;
            };
            *remaining_work = remaining;
            value
        }
        BoundedResolution::Exceeded { .. }
        | BoundedResolution::Unavailable { .. }
        | BoundedResolution::Cancelled { .. } => {
            *remaining_work = 0;
            None
        }
    }
}

enum ResolvedFunctionalTarget {
    External(Arc<SemanticModelSymbol>),
    Source(CodeUnit),
}

fn selected_symbol(
    models: &SemanticModelOverlay,
    ty: &JvmExternalType,
) -> Option<Arc<SemanticModelSymbol>> {
    let JvmExternalDeclarationSource::SemanticPack {
        pack_id,
        declaration_id,
        ..
    } = ty.source()
    else {
        return None;
    };
    let found = models.symbols_with_id(declaration_id);
    if matches!(
        found.disposition,
        brokk_bifrost_analysis::analyzer::semantic_model::SemanticModelOverlayDisposition::Open(_)
    ) {
        return None;
    }
    let [symbol] = found.records.as_slice() else {
        return None;
    };
    (!symbol.provenance.ambiguous
        && symbol.provenance.pack_id == *pack_id
        && symbol.qualified_name == ty.fqn())
    .then_some(symbol.clone())
}

enum LambdaTarget<'a> {
    Type(Node<'a>),
    Parameter(CodeUnit, usize),
    ExternalArgument(Node<'a>),
}

#[allow(clippy::too_many_arguments)]
fn contextual_type<'a>(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    session: &JavaResolutionSession<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'a>,
    lambda: Node<'a>,
) -> Option<LambdaTarget<'a>> {
    let mut expression = lambda;
    loop {
        if !session.charge_scope_step() {
            return None;
        }
        let parent = expression.parent()?;
        match parent.kind() {
            "parenthesized_expression" => expression = parent,
            "variable_declarator" if parent.child_by_field_name("value") == Some(expression) => {
                return parent
                    .parent()?
                    .child_by_field_name("type")
                    .map(LambdaTarget::Type);
            }
            "cast_expression" => {
                let mut cursor = parent.walk();
                if parent
                    .named_children(&mut cursor)
                    .filter(|node| !node.is_extra())
                    .count()
                    != 2
                {
                    return None;
                }
                return parent.child_by_field_name("type").map(LambdaTarget::Type);
            }
            "assignment_expression" if parent.child_by_field_name("right") == Some(expression) => {
                let left = parent.child_by_field_name("left")?;
                if left.kind() != "identifier" {
                    return None;
                }
                let bindings =
                    java_bindings_before_scoped(session, file, source, root, left.start_byte());
                let JavaLocalType::Declared(declared) =
                    first_precise(&bindings, java_node_text(left, source))?
                else {
                    return None;
                };
                if &declared.file != file {
                    return None;
                }
                return session
                    .smallest_named_node_covering(root, declared.start_byte, declared.end_byte)
                    .map(LambdaTarget::Type);
            }
            "argument_list" => {
                let invocation = parent.parent()?;
                if invocation.kind() != "method_invocation" {
                    return None;
                }
                let mut ordinal = None;
                let mut cursor = parent.walk();
                for (index, argument) in parent
                    .named_children(&mut cursor)
                    .filter(|node| !node.is_extra())
                    .enumerate()
                {
                    if !session.charge_scope_step() {
                        return None;
                    }
                    if argument == expression {
                        ordinal = Some(index);
                        break;
                    }
                }
                let binding = java_method_invocation_binding(
                    analyzer, token, session, file, source, root, invocation,
                );
                if session.is_stopped() {
                    return None;
                }
                if matches!(
                    binding.outcome.status,
                    DefinitionLookupStatus::UnresolvableImportBoundary
                        | DefinitionLookupStatus::NoDefinition
                ) && binding.outcome.definitions.is_empty()
                {
                    return Some(LambdaTarget::ExternalArgument(invocation));
                }
                if binding.outcome.status != DefinitionLookupStatus::Resolved {
                    return None;
                }
                let [method] = binding.outcome.definitions.as_slice() else {
                    return None;
                };
                return Some(LambdaTarget::Parameter(method.clone(), ordinal?));
            }
            "return_statement" => {
                let mut container = parent.parent()?;
                loop {
                    if !session.charge_scope_step() {
                        return None;
                    }
                    match container.kind() {
                        "method_declaration" => {
                            return container
                                .child_by_field_name("type")
                                .map(LambdaTarget::Type);
                        }
                        "lambda_expression" | "constructor_declaration" | "class_body" => {
                            return None;
                        }
                        _ => container = container.parent()?,
                    }
                }
            }
            _ => return None,
        }
    }
}

// The resolver selected this declaration before its formal can supply a target.
// Explicit receivers do not occupy argument slots; varargs need array-element
// adaptation and remain unknown here.
fn formal_type<'a>(
    session: &JavaResolutionSession<'_>,
    root: Node<'a>,
    source: &str,
    range: &Range,
    ordinal: usize,
) -> Option<Node<'a>> {
    if root.has_error() {
        return None;
    }
    let mut owner = session.smallest_named_node_covering(root, range.start_byte, range.end_byte)?;
    while owner.kind() != "method_declaration" {
        if !session.charge_scope_step() {
            return None;
        }
        owner = owner.parent()?;
    }
    let slots = brokk_bifrost_analysis::analyzer::lexical_definitions::formal_parameter_slots_for_owner_with_nodes(
        Language::Java,
        owner,
        source,
    )?;
    let (slot, parameter) = slots
        .into_iter()
        .filter(|(slot, _)| !slot.receiver)
        .nth(ordinal)?;
    if slot.variadic.is_some() {
        return None;
    }
    let ty = crate::analyzer::java::declared_type_node(parameter)?;
    if crate::analyzer::java::declaration_declares_array(parameter, ty) {
        return None;
    }
    Some(ty)
}

#[derive(Clone, PartialEq, Eq, Hash)]
enum FunctionalOwner {
    Source(CodeUnit),
    External(String),
}
#[derive(Clone, PartialEq, Eq)]
enum FunctionalMember {
    Source(usize),
    External(String),
}
#[derive(Clone, PartialEq, Eq)]
enum SourceReference {
    Source(CodeUnit, usize),
    Model(ErasedReference<String>),
}
#[derive(Clone, PartialEq, Eq)]
enum SourceVariable {
    Source(
        ProjectFile,
        std::ops::Range<usize>,
        usize,
        Option<usize>,
        Option<SourceReference>,
        Option<(String, usize)>,
    ),
    Model((String, String, usize)),
}
#[derive(Clone)]
struct SourceMethod {
    name: String,
    parameters: Vec<FunctionalType<SourceReference, SourceVariable>>,
    returns: Option<FunctionalType<SourceReference, SourceVariable>>,
    is_abstract: bool,
    has_type_parameters: bool,
    method_bounds: Option<Vec<Vec<FunctionalType<SourceReference, SourceVariable>>>>,
    ground: bool,
    parameterized: bool,
    nested_variables: bool,
    result_use: Option<JavaCallResultUse>,
}
struct SourceInterface {
    content_oid: git2::Oid,
    parameters: Vec<SourceVariable>,
    methods: Vec<SourceMethod>,
    sealed: bool,
}
struct SourceFunctionalInventory<'a, F, H> {
    load: F,
    hierarchy: H,
    models: &'a SemanticModelOverlay,
    object: &'a SemanticModelSymbol,
    remaining_work: &'a mut usize,
    cancellation: &'a CancellationToken,
    methods: Vec<SourceMethod>,
    source_members: brokk_bifrost_analysis::hash::HashMap<CodeUnit, Vec<FunctionalMember>>,
    parameters: std::collections::HashMap<FunctionalOwner, Option<Vec<SourceVariable>>>,
    edges: std::collections::HashMap<
        (FunctionalOwner, FunctionalOwner),
        Option<Vec<JavaArgument<SourceClosedArgument>>>,
    >,
}
#[derive(Clone, PartialEq, Eq)]
struct SourceClosedArgument {
    ty: FunctionalType<SourceReference, SourceVariable>,
    shape: Vec<SourceClosedToken>,
    parameterized: bool,
}
#[derive(Clone, PartialEq, Eq)]
enum SourceClosedToken {
    Reference(SourceReference),
    Primitive(brokk_bifrost_jvm::java::primitives::JavaPrimitive),
    Array,
    Applied(usize),
}
type SourceEdges = Vec<(
    FunctionalOwner,
    Option<Vec<JavaArgument<SourceClosedArgument>>>,
)>;
use brokk_bifrost_jvm::java::type_projection::JavaArgument;

use brokk_bifrost_analysis::analyzer::semantic_model::{
    SemanticModelOverlayDisposition, SemanticModelSymbolKind, Visibility,
};
use brokk_bifrost_jvm::java::functional::{
    CallableInventory, CallableType, ErasedElement, ErasedReference, FunctionalInventory,
    FunctionalMethod, FunctionalType, functional_method,
};
use brokk_bifrost_semantic::analyzer::semantic_model::overlay::java_functional::{
    ground_types, spend,
};
impl<F, H> SourceFunctionalInventory<'_, F, H> {
    fn external(&self, id: &str) -> Option<Arc<SemanticModelSymbol>> {
        let found = self.models.symbols_with_id(id);
        let [symbol] = found.records.as_slice() else {
            return None;
        };
        (!symbol.provenance.ambiguous).then(|| Arc::clone(symbol))
    }
}
impl<F, H> CallableInventory for SourceFunctionalInventory<'_, F, H>
where
    F: FnMut(&CodeUnit, &mut usize) -> Option<SourceInterface>,
    H: FnMut(
        &FunctionalOwner,
        Option<&[SourceVariable]>,
        Option<git2::Oid>,
        &mut usize,
    ) -> Option<SourceEdges>,
{
    type Type = FunctionalOwner;
    fn spend(&mut self) -> Option<()> {
        spend(self.remaining_work, self.cancellation, 1)
    }
    fn callable_type(&mut self, owner: &FunctionalOwner) -> Option<CallableType<FunctionalOwner>> {
        let (parameters, is_interface, sealed, content_oid) = match owner {
            FunctionalOwner::Source(unit) => {
                let interface = (self.load)(unit, self.remaining_work)?;
                let start = self.methods.len();
                let end = start + interface.methods.len();
                self.methods.extend(interface.methods);
                self.source_members.insert(
                    unit.clone(),
                    (start..end).map(FunctionalMember::Source).collect(),
                );
                (
                    Some(interface.parameters),
                    true,
                    interface.sealed,
                    Some(interface.content_oid),
                )
            }
            FunctionalOwner::External(id) => {
                let facts = self.models.java_callable_type_inventory(
                    id,
                    self.remaining_work,
                    self.cancellation,
                )?;
                let parameters = self.models.java_declared_type_parameters(id).map(|names| {
                    names
                        .into_iter()
                        .map(|name| SourceVariable::Model((id.clone(), name, 0)))
                        .collect()
                });
                (parameters, facts.is_interface, facts.sealed, None)
            }
        };
        let edges = (self.hierarchy)(
            owner,
            parameters.as_deref(),
            content_oid,
            self.remaining_work,
        )?;
        let parents = edges.iter().map(|(parent, _)| parent.clone()).collect();
        self.parameters.insert(owner.clone(), parameters);
        for (parent, arguments) in edges {
            // JLS 9.1.3 requires distinct direct superinterfaces. Indirect
            // paths are compared by the shared substitution walk instead.
            if self
                .edges
                .insert((owner.clone(), parent), arguments)
                .is_some()
            {
                return None;
            }
        }
        Some(CallableType {
            is_interface,
            sealed,
            parents,
        })
    }
}
impl<F, H> FunctionalInventory for SourceFunctionalInventory<'_, F, H>
where
    F: FnMut(&CodeUnit, &mut usize) -> Option<SourceInterface>,
    H: FnMut(
        &FunctionalOwner,
        Option<&[SourceVariable]>,
        Option<git2::Oid>,
        &mut usize,
    ) -> Option<SourceEdges>,
{
    type Method = FunctionalMember;
    type Reference = SourceReference;
    type Variable = SourceVariable;
    type ClosedArgument = SourceClosedArgument;
    fn type_parameters(&mut self, owner: &FunctionalOwner) -> Option<Vec<SourceVariable>> {
        self.parameters.get(owner)?.clone()
    }
    fn edge_arguments(
        &mut self,
        owner: &FunctionalOwner,
        parent: &FunctionalOwner,
    ) -> Option<Vec<JavaArgument<SourceClosedArgument>>> {
        self.edges.get(&(owner.clone(), parent.clone()))?.clone()
    }
    fn project_method(
        &mut self,
        method: &FunctionalMember,
        parameters: Option<&[SourceVariable]>,
        arguments: Option<&[JavaArgument<SourceClosedArgument>]>,
        target_parameters: Option<&[SourceVariable]>,
    ) -> Option<FunctionalMember> {
        let mut projected = match method {
            FunctionalMember::Source(index) => self.methods[*index].clone(),
            FunctionalMember::External(id) => {
                let member = self.external(id)?;
                let signature = member.structured_signature()?;
                SourceMethod {
                    name: member.name.clone(),
                    parameters: (0..signature.parameters.len())
                        .map(|ordinal| self.parameter_type(method, ordinal))
                        .collect::<Option<Vec<_>>>()?,
                    returns: self.return_type(method)?,
                    is_abstract: member.declaration_is_abstract,
                    has_type_parameters: !signature.type_parameters.is_empty(),
                    method_bounds: signature.type_parameters.is_empty().then(Vec::new),
                    ground: self.ground(method)?,
                    parameterized: signature
                        .parameters
                        .iter()
                        .any(|parameter| model_type_has_arguments(&parameter.r#type))
                        || signature
                            .returns
                            .as_ref()
                            .is_some_and(model_type_has_arguments),
                    nested_variables: model_nested_owner_variables(
                        signature,
                        self.remaining_work,
                        self.cancellation,
                    )?,
                    result_use: Some(if signature.returns.is_some() {
                        JavaCallResultUse::OtherContext
                    } else {
                        JavaCallResultUse::Discarded
                    }),
                }
            }
        };
        projected.ground = !projected.nested_variables;
        {
            // Bounds participate in signature agreement too. Project their bare
            // interface variables before using a method variable's erasure.
            let mut project_type = |ty: &mut FunctionalType<SourceReference, SourceVariable>| {
                self.spend()?;
                let FunctionalType::TypeVariable(variable) = ty else {
                    return Some((true, false));
                };
                if self.method_variable_position(variable).is_some() {
                    return Some((true, false));
                }
                let position = parameters.and_then(|parameters| {
                    parameters
                        .iter()
                        .position(|parameter| same_source_variable(parameter, variable))
                });
                match position.and_then(|position| arguments?.get(position)) {
                    Some(JavaArgument::Position(position)) => {
                        let mut replacement = target_parameters?.get(*position)?.clone();
                        add_variable_dimensions(
                            &mut replacement,
                            source_variable_dimensions(variable),
                        );
                        *ty = FunctionalType::TypeVariable(replacement);
                        Some((true, false))
                    }
                    Some(JavaArgument::Closed(argument)) => {
                        let mut replacement = argument.ty.clone();
                        add_type_dimensions(
                            &mut replacement,
                            source_variable_dimensions(variable),
                        )?;
                        *ty = replacement;
                        Some((true, argument.parameterized))
                    }
                    Some(JavaArgument::Open) | None => Some((false, false)),
                }
            };
            let mut bounds_known = projected.method_bounds.is_some();
            if let Some(bounds) = &mut projected.method_bounds {
                for ty in bounds.iter_mut().flatten() {
                    let (ground, parameterized) = project_type(ty)?;
                    bounds_known &= ground && !parameterized;
                }
            }
            if !bounds_known {
                projected.method_bounds = None;
            }
            for ty in projected
                .parameters
                .iter_mut()
                .chain(projected.returns.iter_mut())
            {
                let (ground, parameterized) = project_type(ty)?;
                projected.ground &= ground;
                projected.parameterized |= parameterized;
            }
        }
        let bounds = projected.method_bounds.clone();
        for ty in projected
            .parameters
            .iter_mut()
            .chain(projected.returns.iter_mut())
            .chain(
                projected
                    .method_bounds
                    .iter_mut()
                    .flat_map(|bounds| bounds.iter_mut().flatten()),
            )
        {
            let FunctionalType::TypeVariable(variable) = ty else {
                continue;
            };
            let Some((mut position, mut rank)) = self.method_variable_position(variable) else {
                continue;
            };
            let mut seen = std::collections::HashSet::new();
            let (erasure, name) = loop {
                self.spend()?;
                if !seen.insert(position) {
                    break (None, None);
                }
                let Some(bound) = bounds
                    .as_ref()
                    .and_then(|bounds| bounds.get(position))
                    .and_then(|bounds| bounds.first())
                else {
                    break (None, None);
                };
                match bound {
                    FunctionalType::Reference(reference) => {
                        let mut reference = reference.clone();
                        add_reference_dimensions(&mut reference, rank);
                        let name = self.reference_name(&reference);
                        break (Some(reference), name);
                    }
                    FunctionalType::TypeVariable(bound) => {
                        if let Some((next, dimensions)) = self.method_variable_position(bound) {
                            position = next;
                            rank += dimensions;
                            continue;
                        }
                        let mut reference = self.variable_erasure(bound);
                        if let Some(reference) = &mut reference {
                            add_reference_dimensions(reference, rank);
                        }
                        let name = self
                            .variable_erasure_name(bound)
                            .map(|(name, dimensions)| (name, dimensions + rank));
                        break (reference, name);
                    }
                    FunctionalType::NonPrimitive {
                        simple_name,
                        dimensions,
                    } => {
                        break (
                            None,
                            simple_name.clone().map(|name| (name, dimensions + rank)),
                        );
                    }
                    _ => break (None, None),
                }
            };
            if let SourceVariable::Source(_, _, _, _, variable_erasure, variable_name) = variable {
                *variable_erasure = erasure;
                *variable_name = name;
            }
        }
        let index = self.methods.len();
        self.methods.push(projected);
        Some(FunctionalMember::Source(index))
    }
    fn methods(&mut self, owner: &FunctionalOwner) -> Option<Vec<FunctionalMember>> {
        match owner {
            FunctionalOwner::Source(unit) => self.source_members.get(unit).cloned(),
            FunctionalOwner::External(id) => Some(
                self.models
                    .java_functional_members(id, self.remaining_work, self.cancellation)?
                    .into_iter()
                    .map(FunctionalMember::External)
                    .collect(),
            ),
        }
    }
    fn object_methods(&mut self) -> Option<Vec<FunctionalMember>> {
        if self.object.kind != SemanticModelSymbolKind::Class
            || self.object.language != "java"
            || self.object.qualified_name != "java.lang.Object"
            || self.object.provenance.ambiguous
            || !self.object.callable_surface_complete()
        {
            return None;
        }
        let members = self.models.members_of(&self.object.id);
        if matches!(
            members.disposition,
            SemanticModelOverlayDisposition::Open(_)
        ) {
            return None;
        }
        // This is a collection lookup: several Object members are expected.
        // Ambiguous declarations are rejected individually below.
        let mut methods = Vec::new();
        for member in members.records {
            self.spend()?;
            if member.kind == SemanticModelSymbolKind::Method
                && !member.is_static
                && member.visibility == Visibility::Public
            {
                if member.provenance.ambiguous {
                    return None;
                }
                member.structured_signature()?;
                methods.push(FunctionalMember::External(member.id.clone()));
            }
        }
        Some(methods)
    }
    fn method(&mut self, method: &FunctionalMember) -> Option<FunctionalMethod> {
        match method {
            FunctionalMember::Source(index) => {
                let member = &self.methods[*index];
                Some(FunctionalMethod {
                    is_abstract: member.is_abstract,
                    has_type_parameters: member.has_type_parameters,
                })
            }
            FunctionalMember::External(id) => {
                let member = self.external(id)?;
                let signature = member.structured_signature()?;
                if signature.contains_unknown_types() {
                    return None;
                }
                Some(FunctionalMethod {
                    is_abstract: member.declaration_is_abstract,
                    has_type_parameters: !signature.type_parameters.is_empty(),
                })
            }
        }
    }
    fn name_and_arity(&mut self, method: &FunctionalMember) -> Option<(String, usize)> {
        match method {
            FunctionalMember::Source(index) => {
                let method = &self.methods[*index];
                Some((method.name.clone(), method.parameters.len()))
            }
            FunctionalMember::External(id) => {
                let method = self.external(id)?;
                Some((
                    method.name.clone(),
                    method.structured_signature()?.parameters.len(),
                ))
            }
        }
    }
    fn parameter_type(
        &mut self,
        method: &FunctionalMember,
        ordinal: usize,
    ) -> Option<FunctionalType<SourceReference, SourceVariable>> {
        match method {
            FunctionalMember::Source(index) => {
                self.methods[*index].parameters.get(ordinal).cloned()
            }
            FunctionalMember::External(id) => {
                let method = self.external(id)?;
                let ty = &method
                    .structured_signature()?
                    .parameters
                    .get(ordinal)?
                    .r#type;
                Some(source_model_functional_type(
                    self.models.java_functional_type(ty, &method),
                ))
            }
        }
    }
    fn return_type(
        &mut self,
        method: &FunctionalMember,
    ) -> Option<Option<FunctionalType<SourceReference, SourceVariable>>> {
        match method {
            FunctionalMember::Source(index) => Some(self.methods[*index].returns.clone()),
            FunctionalMember::External(id) => {
                let method = self.external(id)?;
                Some(method.structured_signature()?.returns.as_ref().map(|ty| {
                    source_model_functional_type(self.models.java_functional_type(ty, &method))
                }))
            }
        }
    }
    fn parameter_agreement(
        &mut self,
        left: &FunctionalMember,
        right: &FunctionalMember,
        ordinal: usize,
    ) -> Option<bool> {
        if let (FunctionalMember::External(left), FunctionalMember::External(right)) = (left, right)
        {
            let left = self.external(left)?;
            let right = self.external(right)?;
            let left = left.structured_signature()?.parameters.get(ordinal)?;
            let right = right.structured_signature()?.parameters.get(ordinal)?;
            if !ground_types(
                [&left.r#type, &right.r#type],
                self.remaining_work,
                self.cancellation,
            )? {
                return None;
            }
            return Some(left.r#type == right.r#type && left.variadic == right.variadic);
        }
        for member in [left, right] {
            let parameterized = match member {
                FunctionalMember::Source(index) => self.methods[*index].parameterized,
                FunctionalMember::External(id) => model_type_has_arguments(
                    &self
                        .external(id)?
                        .structured_signature()?
                        .parameters
                        .get(ordinal)?
                        .r#type,
                ),
            };
            if parameterized {
                return None;
            }
        }
        Some(true)
    }
    fn return_agreement(
        &mut self,
        left: &FunctionalMember,
        right: &FunctionalMember,
    ) -> Option<bool> {
        if let (FunctionalMember::External(left), FunctionalMember::External(right)) = (left, right)
        {
            let left = self.external(left)?;
            let right = self.external(right)?;
            let left = &left.structured_signature()?.returns;
            let right = &right.structured_signature()?.returns;
            if !ground_types(
                left.iter().chain(right.iter()),
                self.remaining_work,
                self.cancellation,
            )? {
                return None;
            }
            return Some(left == right);
        }
        for member in [left, right] {
            let parameterized = match member {
                FunctionalMember::Source(index) => self.methods[*index].parameterized,
                FunctionalMember::External(id) => self
                    .external(id)?
                    .structured_signature()?
                    .returns
                    .as_ref()
                    .is_some_and(model_type_has_arguments),
            };
            if parameterized {
                return None;
            }
        }
        Some(true)
    }
    fn reference_name(&mut self, reference: &SourceReference) -> Option<(String, usize)> {
        match reference {
            SourceReference::Source(unit, rank) => Some((unit.terminal_name().to_owned(), *rank)),
            SourceReference::Model(ErasedReference {
                element: ErasedElement::Declared(id),
                dimensions,
            }) => Some((self.external(id)?.name.clone(), *dimensions)),
            _ => None,
        }
    }
    fn method_variable_position(&mut self, variable: &SourceVariable) -> Option<(usize, usize)> {
        match variable {
            SourceVariable::Source(_, _, rank, position, _, _) => {
                position.map(|position| (position, *rank))
            }
            SourceVariable::Model((scope, name, rank)) => self
                .external(scope)?
                .structured_signature()?
                .type_parameters
                .iter()
                .position(|parameter| parameter == name)
                .map(|position| (position, *rank)),
        }
    }
    fn variable_erasure(&mut self, variable: &SourceVariable) -> Option<SourceReference> {
        match variable {
            SourceVariable::Source(_, _, _, _, erasure, _) => erasure.clone(),
            SourceVariable::Model(_) => None,
        }
    }
    fn variable_erasure_name(&mut self, variable: &SourceVariable) -> Option<(String, usize)> {
        match variable {
            SourceVariable::Source(_, _, _, _, _, name) => name.clone(),
            SourceVariable::Model(_) => None,
        }
    }
    fn method_parameters_agree(
        &mut self,
        left: &FunctionalMember,
        right: &FunctionalMember,
    ) -> Option<bool> {
        match (left, right) {
            (FunctionalMember::Source(left), FunctionalMember::Source(right)) => {
                let left = self.methods[*left].method_bounds.clone()?;
                let right = self.methods[*right].method_bounds.clone()?;
                if left.len() != right.len() {
                    return None;
                }
                for (left, right) in left.into_iter().zip(right) {
                    if left.len() != right.len() {
                        return None;
                    }
                    for (left, right) in left.into_iter().zip(right) {
                        self.spend()?;
                        if brokk_bifrost_jvm::java::functional::same_type(
                            self, left, true, right, true,
                        ) != Some(true)
                        {
                            return None;
                        }
                    }
                }
                Some(true)
            }
            _ => {
                if self.method(left)?.has_type_parameters || self.method(right)?.has_type_parameters
                {
                    None
                } else {
                    Some(true)
                }
            }
        }
    }
    fn ground(&mut self, method: &FunctionalMember) -> Option<bool> {
        match method {
            FunctionalMember::Source(index) => Some(self.methods[*index].ground),
            FunctionalMember::External(id) => {
                let member = self.external(id)?;
                let signature = member.structured_signature()?;
                brokk_bifrost_semantic::analyzer::semantic_model::overlay::java_functional::ground_types_with_variables(
                    signature.parameters.iter().map(|parameter| &parameter.r#type).chain(signature.returns.iter()),
                    self.remaining_work, self.cancellation,
                    |name| signature.type_parameters.iter().any(|parameter| parameter == name),
                )
            }
        }
    }
}

fn same_source_variable(left: &SourceVariable, right: &SourceVariable) -> bool {
    match (left, right) {
        (
            SourceVariable::Source(lf, lp, _, _, _, _),
            SourceVariable::Source(rf, rp, _, _, _, _),
        ) => lf == rf && lp == rp,
        (SourceVariable::Model((lo, ln, _)), SourceVariable::Model((ro, rn, _))) => {
            lo == ro && ln == rn
        }
        _ => false,
    }
}
fn source_variable_dimensions(variable: &SourceVariable) -> usize {
    match variable {
        SourceVariable::Source(_, _, rank, _, _, _) | SourceVariable::Model((_, _, rank)) => *rank,
    }
}
fn add_variable_dimensions(variable: &mut SourceVariable, added: usize) {
    match variable {
        SourceVariable::Source(_, _, rank, _, erasure, name) => {
            *rank += added;
            if let Some(erasure) = erasure {
                add_reference_dimensions(erasure, added);
            }
            if let Some((_, rank)) = name {
                *rank += added;
            }
        }
        SourceVariable::Model((_, _, rank)) => *rank += added,
    }
}
fn add_reference_dimensions(reference: &mut SourceReference, added: usize) {
    match reference {
        SourceReference::Source(_, rank) => *rank += added,
        SourceReference::Model(reference) => reference.dimensions += added,
    }
}
fn add_type_dimensions(
    ty: &mut FunctionalType<SourceReference, SourceVariable>,
    added: usize,
) -> Option<()> {
    match ty {
        FunctionalType::Reference(reference) => add_reference_dimensions(reference, added),
        FunctionalType::TypeVariable(variable) => add_variable_dimensions(variable, added),
        FunctionalType::Primitive(kind) if added > 0 => {
            *ty = FunctionalType::Reference(SourceReference::Model(ErasedReference {
                element: ErasedElement::Primitive(*kind),
                dimensions: added,
            }))
        }
        FunctionalType::Primitive(_) if added == 0 => {}
        FunctionalType::NonPrimitive { dimensions, .. } => *dimensions += added,
        _ => return None,
    }
    Some(())
}

fn model_nested_owner_variables(
    signature: &brokk_bifrost_analysis::analyzer::semantic_model::Signature,
    remaining: &mut usize,
    cancellation: &CancellationToken,
) -> Option<bool> {
    let mut pending = signature
        .parameters
        .iter()
        .map(|parameter| (&parameter.r#type, false))
        .chain(signature.returns.iter().map(|ty| (ty, false)))
        .collect::<Vec<_>>();
    while let Some((ty, nested)) = pending.pop() {
        spend(remaining, cancellation, 1)?;
        match ty {
            TypeRef::TypeParameter { name }
                if nested && !signature.type_parameters.contains(name) =>
            {
                return Some(true);
            }
            TypeRef::Named { arguments, .. } | TypeRef::Declared { arguments, .. } => {
                pending.extend(arguments.iter().map(|ty| (ty, true)))
            }
            TypeRef::Array { element } => pending.push((element, nested)),
            TypeRef::Wildcard { bound, .. } => {
                pending.extend(bound.iter().map(|ty| (ty.as_ref(), true)))
            }
            _ => {}
        }
    }
    Some(false)
}

fn model_type_has_arguments(mut ty: &TypeRef) -> bool {
    while let TypeRef::Array { element } = ty {
        ty = element;
    }
    matches!(ty, TypeRef::Named { arguments, .. } | TypeRef::Declared { arguments, .. } if !arguments.is_empty())
}

fn source_model_functional_type(
    ty: FunctionalType<ErasedReference<String>, (String, String, usize)>,
) -> FunctionalType<SourceReference, SourceVariable> {
    match ty {
        FunctionalType::Primitive(kind) => FunctionalType::Primitive(kind),
        FunctionalType::TypeVariable(identity) => {
            FunctionalType::TypeVariable(SourceVariable::Model(identity))
        }
        FunctionalType::Unknown => FunctionalType::Unknown,
        FunctionalType::NonPrimitive {
            simple_name,
            dimensions,
        } => FunctionalType::NonPrimitive {
            simple_name,
            dimensions,
        },
        FunctionalType::Reference(identity) => {
            FunctionalType::Reference(SourceReference::Model(identity))
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn source_signature_type(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    java: &JavaAnalyzer,
    session: &JavaResolutionSession<'_>,
    models: &Arc<SemanticModelOverlay>,
    digest: &str,
    file: &ProjectFile,
    source: &str,
    declaration: Node<'_>,
    ty: Node<'_>,
) -> FunctionalType<SourceReference, SourceVariable> {
    let shape = if declaration.kind() == "spread_parameter" {
        crate::analyzer::java::java_type_node_shape(ty)
            .ok()
            .map(|(node, rank)| (node, rank + 1))
    } else {
        crate::analyzer::java::declared_java_type_shape(declaration, ty).ok()
    };
    let classify = || {
        if !session.charge_scope_step() {
            return None;
        }
        let (ty, dimensions) = shape?;
        if matches!(
            ty.kind(),
            "integral_type" | "floating_point_type" | "boolean_type"
        ) {
            let kind = brokk_bifrost_jvm::java::primitives::primitive_for_name(java_node_text(
                ty, source,
            ))?;
            return Some(if dimensions == 0 {
                FunctionalType::Primitive(kind)
            } else {
                FunctionalType::Reference(SourceReference::Model(ErasedReference {
                    element: ErasedElement::Primitive(kind),
                    dimensions,
                }))
            });
        }
        let name = java_type_name_from_node(ty, source)?;
        if let Some(parameter) =
            brokk_bifrost_jvm::java::graph_support::java_type_parameter_in_scope(ty, source, &name)
        {
            use brokk_bifrost_jvm::java::graph_support::{
                java_declared_type_parameters, java_type_parameter_bounds,
            };
            let scope = parameter.parent().and_then(|list| list.parent())?;
            let position = if scope.kind() == "method_declaration" {
                java_declared_type_parameters(scope)
                    .iter()
                    .position(|node| *node == parameter)
            } else {
                None
            };
            // Erasure follows only the leftmost bound. Walk variable-bound
            // chains iteratively; a cycle or unavailable identity stays unknown.
            let mut current = parameter;
            let mut seen = std::collections::HashSet::new();
            let mut erasure_name = None;
            let erasure = loop {
                if !session.charge_scope_step() || !seen.insert(current.start_byte()) {
                    break None;
                }
                let bounds = java_type_parameter_bounds(current);
                let bound_name = if let Some(bound) = bounds.first() {
                    let Some(name) = java_type_name_from_node(*bound, source) else {
                        break None;
                    };
                    if let Some(next) =
                        brokk_bifrost_jvm::java::graph_support::java_type_parameter_in_scope(
                            *bound, source, &name,
                        )
                    {
                        current = next;
                        continue;
                    }
                    erasure_name =
                        brokk_bifrost_jvm::java::graph::return_type::java_type_name_components(
                            *bound, source,
                        )
                        .and_then(|names| names.last().cloned())
                        .map(|name| (name, dimensions));
                    name
                } else {
                    erasure_name = Some(("Object".to_owned(), dimensions));
                    "java.lang.Object".to_owned()
                };
                let resolved = session.query_optional_row(|| {
                    java.resolve_type_name_with_selected_jdk(
                        token,
                        Some(Arc::clone(models)),
                        file,
                        &bound_name,
                        Some(digest),
                    )
                });
                break match resolved {
                    Some(JavaTypeResolution::Source(unit)) => {
                        Some(SourceReference::Source(unit, dimensions))
                    }
                    Some(JavaTypeResolution::External(external)) => {
                        selected_symbol(models, &external).map(|symbol| {
                            SourceReference::Model(ErasedReference {
                                element: ErasedElement::Declared(symbol.id.clone()),
                                dimensions,
                            })
                        })
                    }
                    None => None,
                };
            };
            return Some(FunctionalType::TypeVariable(SourceVariable::Source(
                file.clone(),
                brokk_bifrost_jvm::java::graph_support::java_type_parameter_name_node(parameter)?
                    .byte_range(),
                dimensions,
                position,
                erasure,
                erasure_name,
            )));
        }
        if let Some(unit) =
            java_type_text_with_context(analyzer, token, java, session, file, source, &name, ty)
        {
            return Some(FunctionalType::Reference(SourceReference::Source(
                unit, dimensions,
            )));
        }
        let identity = match session.query_optional_row(|| {
            java.resolve_type_name_with_selected_jdk(
                token,
                Some(Arc::clone(models)),
                file,
                &name,
                Some(digest),
            )
        })? {
            JavaTypeResolution::Source(unit) => SourceReference::Source(unit, dimensions),
            JavaTypeResolution::External(external) => SourceReference::Model(ErasedReference {
                element: ErasedElement::Declared(selected_symbol(models, &external)?.id.clone()),
                dimensions,
            }),
        };
        Some(FunctionalType::Reference(identity))
    };
    classify().unwrap_or_else(|| {
        if let Some((node, dimensions)) = shape
            && !matches!(
                node.kind(),
                "integral_type" | "floating_point_type" | "boolean_type"
            )
        {
            FunctionalType::NonPrimitive {
                simple_name:
                    brokk_bifrost_jvm::java::graph::return_type::java_type_name_components(
                        node, source,
                    )
                    .filter(|names| {
                        brokk_bifrost_jvm::java::graph_support::java_type_parameter_in_scope(
                            node,
                            source,
                            &names.join("."),
                        )
                        .is_none()
                    })
                    .and_then(|names| names.last().cloned()),
                dimensions,
            }
        } else {
            FunctionalType::Unknown
        }
    })
}

#[allow(clippy::too_many_arguments)]
fn source_interface_inventory(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    java: &JavaAnalyzer,
    session: &JavaResolutionSession<'_>,
    models: &Arc<SemanticModelOverlay>,
    digest: &str,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    range: &Range,
) -> Option<SourceInterface> {
    use brokk_bifrost_analysis::analyzer::lexical_definitions::formal_parameter_slots_for_owner_with_nodes;
    use brokk_bifrost_jvm::java::declarations::java_modifier_keywords;
    if root.has_error() {
        return None;
    }
    let mut owner = session.smallest_named_node_covering(root, range.start_byte, range.end_byte)?;
    while owner.kind() != "interface_declaration" {
        if !session.charge_scope_step()
            || matches!(
                owner.kind(),
                "class_declaration" | "enum_declaration" | "record_declaration" | "program"
            )
        {
            return None;
        }
        owner = owner.parent()?;
    }
    let sealed = java_modifier_keywords(owner).any(|modifier| modifier == "sealed");
    let parameters = brokk_bifrost_jvm::java::graph_support::java_declared_type_parameters(owner)
        .into_iter()
        .map(|parameter| {
            let name =
                brokk_bifrost_jvm::java::graph_support::java_type_parameter_name_node(parameter)?;
            match source_signature_type(
                analyzer, token, java, session, models, digest, file, source, parameter, name,
            ) {
                FunctionalType::TypeVariable(variable) => Some(variable),
                _ => None,
            }
        })
        .collect::<Option<Vec<_>>>()?;
    let body = owner.child_by_field_name("body")?;
    let mut methods = Vec::new();
    let mut cursor = body.walk();
    for member in body
        .named_children(&mut cursor)
        .filter(|node| !node.is_extra())
    {
        if !session.charge_scope_step() {
            return None;
        }
        match member.kind() {
            "method_declaration" => {}
            "constant_declaration"
            | "class_declaration"
            | "interface_declaration"
            | "enum_declaration"
            | "record_declaration"
            | "annotation_type_declaration" => continue,
            _ => return None,
        }
        if java_modifier_keywords(member).any(|modifier| matches!(modifier, "static" | "private")) {
            continue;
        }
        let is_abstract = !java_modifier_keywords(member).any(|modifier| modifier == "default");
        if is_abstract && member.child_by_field_name("body").is_some() {
            return None;
        }
        let parameters =
            formal_parameter_slots_for_owner_with_nodes(Language::Java, member, source)?;
        let parameters = parameters
            .iter()
            .filter(|(slot, _)| !slot.receiver)
            .map(|(_, declaration)| {
                let Some(ty) = crate::analyzer::java::declared_type_node(*declaration) else {
                    return FunctionalType::Unknown;
                };
                source_signature_type(
                    analyzer,
                    token,
                    java,
                    session,
                    models,
                    digest,
                    file,
                    source,
                    *declaration,
                    ty,
                )
            })
            .collect();
        let returned = member.child_by_field_name("type")?;
        let mut ground = true;
        let mut parameterized = false;
        let mut nested_variables = false;
        let mut pending = vec![returned];
        if let Some(parameters) = member.child_by_field_name("parameters") {
            pending.push(parameters);
        }
        while let Some(node) = pending.pop() {
            if !session.charge_scope_step() {
                return None;
            }
            parameterized |= node.kind() == "generic_type";
            if node.kind() == "type_identifier"
                && node
                    .parent()
                    .is_none_or(|parent| parent.kind() != "scoped_type_identifier")
                && brokk_bifrost_jvm::java::graph_support::java_type_parameter_in_scope(
                    node,
                    source,
                    java_node_text(node, source),
                )
                .is_some_and(|parameter| {
                    parameter
                        .parent()
                        .and_then(|list| list.parent())
                        .is_none_or(|scope| scope.kind() != "method_declaration")
                })
            {
                ground = false;
                let mut parent = node.parent();
                while let Some(ancestor) = parent {
                    if !session.charge_scope_step() {
                        return None;
                    }
                    if ancestor == member {
                        break;
                    }
                    if ancestor.kind() == "generic_type" {
                        nested_variables = true;
                        break;
                    }
                    parent = ancestor.parent();
                }
            }
            let mut cursor = node.walk();
            pending.extend(node.named_children(&mut cursor));
        }
        let method_bounds =
            brokk_bifrost_jvm::java::graph_support::java_declared_type_parameters(member)
                .into_iter()
                .map(|parameter| {
                    let bounds = brokk_bifrost_jvm::java::graph_support::java_type_parameter_bounds(
                        parameter,
                    );
                    if bounds.is_empty() {
                        let name =
                            brokk_bifrost_jvm::java::graph_support::java_type_parameter_name_node(
                                parameter,
                            )?;
                        let variable = source_signature_type(
                            analyzer, token, java, session, models, digest, file, source,
                            parameter, name,
                        );
                        let FunctionalType::TypeVariable(SourceVariable::Source(
                            _,
                            _,
                            _,
                            _,
                            Some(erasure),
                            _,
                        )) = variable
                        else {
                            return None;
                        };
                        return Some(vec![FunctionalType::Reference(erasure)]);
                    }
                    bounds
                        .into_iter()
                        .map(|bound| {
                            // Nested generic bounds need structural agreement; erasure
                            // alone cannot certify them until that fact is available.
                            if bound.kind() == "generic_type" {
                                return None;
                            }
                            Some(source_signature_type(
                                analyzer, token, java, session, models, digest, file, source,
                                parameter, bound,
                            ))
                        })
                        .collect::<Option<Vec<_>>>()
                })
                .collect::<Option<Vec<_>>>();
        let result_use = if is_abstract {
            source_method_result_use(
                analyzer, token, java, session, models, digest, file, source, returned,
            )
        } else {
            None
        };
        methods.push(SourceMethod {
            name: java_node_text(member.child_by_field_name("name")?, source).to_owned(),
            parameters,
            returns: (returned.kind() != "void_type").then(|| {
                source_signature_type(
                    analyzer, token, java, session, models, digest, file, source, member, returned,
                )
            }),
            is_abstract,
            has_type_parameters: member.child_by_field_name("type_parameters").is_some(),
            method_bounds,
            ground,
            parameterized,
            nested_variables,
            result_use,
        });
    }
    Some(SourceInterface {
        content_oid: git2::Oid::hash_object(git2::ObjectType::Blob, source.as_bytes())
            .expect("source bytes have a Git blob identity"),
        parameters,
        methods,
        sealed,
    })
}

#[allow(clippy::too_many_arguments)]
fn source_method_result_use(
    analyzer: &dyn IAnalyzer,
    token: QueryToken<'_>,
    java: &JavaAnalyzer,
    session: &JavaResolutionSession<'_>,
    models: &Arc<SemanticModelOverlay>,
    digest: &str,
    file: &ProjectFile,
    source: &str,
    mut returned: Node<'_>,
) -> Option<JavaCallResultUse> {
    if returned.kind() == "void_type" {
        return Some(JavaCallResultUse::Discarded);
    }
    loop {
        if !session.charge_scope_step() {
            return None;
        }
        match returned.kind() {
            "array_type" => {
                returned = returned
                    .child_by_field_name("element")
                    .or_else(|| returned.child_by_field_name("type"))?
            }
            "annotated_type" => {
                let mut cursor = returned.walk();
                returned = returned.named_children(&mut cursor).find(|node| {
                    brokk_bifrost_jvm::java::graph::return_type::is_java_nominal_type_node(
                        node.kind(),
                    )
                })?;
            }
            "integral_type" | "floating_point_type" | "boolean_type" => {
                return Some(JavaCallResultUse::OtherContext);
            }
            _ => break,
        }
    }
    let name = java_type_name_from_node(returned, source)?;
    let parsed_returned = JavaTypeName::from_normalized_spelling(&name);
    let returned_site = UseSite {
        token,
        source,
        node: returned,
    };
    if brokk_bifrost_jvm::java::graph_support::java_type_parameter_in_scope(returned, source, &name)
        .is_some()
        || java_type_text_with_context(
            analyzer, token, java, session, file, source, &name, returned,
        )
        .is_some()
        || parsed_returned.as_ref().is_some_and(|parsed| {
            session
                .query_optional_row(|| {
                    java.resolve_type_name_at(
                        token,
                        Some(Arc::clone(models)),
                        file,
                        parsed,
                        Some(digest),
                        Some(&returned_site),
                    )
                })
                .is_some()
        })
    {
        Some(JavaCallResultUse::OtherContext)
    } else {
        None
    }
}
