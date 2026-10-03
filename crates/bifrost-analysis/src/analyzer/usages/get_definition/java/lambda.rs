//! Contextual result-use proof for direct Java expression-lambda calls.

use super::*;
use crate::analyzer::jvm::external::{JvmExternalDeclarationSource, JvmExternalType};
use crate::analyzer::semantic_model::{
    ActiveSemanticModelSnapshot, SemanticModelOverlay, SemanticModelSymbol, TypeRef,
};
use crate::analyzer::{AnalyzerDefinitionLookup, JavaCallResultUse};
use brokk_bifrost_jvm::java::graph::return_type::java_type_name_from_node;

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
    let digest = selected.artifact_sha256.as_deref()?;
    let support = AnalyzerDefinitionLookup::new(analyzer, Language::Java);
    let session = JavaResolutionSession::bounded(
        &support,
        ReceiverAnalysisBudget {
            max_scope_nodes: *remaining_work,
            ..ReceiverAnalysisBudget::default()
        },
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
                analyzer,
                token,
                java,
                &session,
                file,
                &name,
                ty.start_byte(),
            ) {
                return Some(ResolvedFunctionalTarget::Source(unit));
            }
            let resolved = session.query_optional_row(|| {
                java.resolve_type_name_with_selected_jdk(
                    token,
                    Some(Arc::clone(&models)),
                    file,
                    &name,
                    Some(digest),
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
                    receiver,
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
                let candidates = match &formal.r#type {
                    TypeRef::Named { name, .. } => models.symbols_named(name),
                    TypeRef::Declared { id, .. } => models.symbols_with_id(id),
                    _ => return None,
                };
                let [target] = candidates.records.as_slice() else {
                    return None;
                };
                if target.provenance.ambiguous
                    || target.provenance.pack_id != receiver.provenance.pack_id
                {
                    return None;
                }
                ResolvedFunctionalTarget::External(target)
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
        let mut target = owner;
        let mut seen = HashSet::default();
        loop {
            if !session.charge_scope_step() {
                return None;
            }
            match target {
                ResolvedFunctionalTarget::External(owner) => {
                    let method = models.java_functional_method(
                        owner,
                        object,
                        remaining_work,
                        cancellation,
                    )?;
                    let signature = method.structured_signature()?;
                    if signature.parameters.len() != arity {
                        return None;
                    }
                    return Some(if signature.returns.is_some() {
                        JavaCallResultUse::OtherContext
                    } else {
                        JavaCallResultUse::Discarded
                    });
                }
                ResolvedFunctionalTarget::Source(unit) => {
                    if !seen.insert(unit.clone()) {
                        return None;
                    }
                    let target_file = unit.source();
                    if java.selected_jdk_home_for_file(target_file).ok()?
                        != java.selected_jdk_home_for_file(file).ok()?
                    {
                        return None;
                    }
                    let ranges = session.ranges(analyzer, &unit);
                    let [range] = ranges.as_slice() else {
                        return None;
                    };
                    let prove = |root, source: &str| {
                        source_functional_result_use(
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
                            object,
                            arity,
                        )
                    };
                    let result = if target_file == file {
                        prove(root, source)
                    } else {
                        let target_source =
                            session.query_optional_row(|| analyzer.indexed_source(target_file))?;
                        let Some(remaining) = remaining_work.checked_sub(target_source.len())
                        else {
                            *remaining_work = 0;
                            return None;
                        };
                        *remaining_work = remaining;
                        let tree = session
                            .structured_query(|| {
                                parse_tree_for_language(target_file, Language::Java, &target_source)
                            })
                            .flatten()?;
                        prove(tree.root_node(), &target_source)
                    }?;
                    match result {
                        SourceFunctionalResult::Use(result) => return Some(result),
                        SourceFunctionalResult::Parent(JavaTypeResolution::Source(unit)) => {
                            target = ResolvedFunctionalTarget::Source(unit)
                        }
                        SourceFunctionalResult::Parent(JavaTypeResolution::External(external)) => {
                            target = ResolvedFunctionalTarget::External(selected_symbol(
                                &models, &external,
                            )?)
                        }
                    }
                }
            }
        }
    })();
    match session.finish(resolved) {
        BoundedResolution::Complete { value, work } => {
            let spent = work
                .setup_nodes
                .saturating_add(work.scope_nodes)
                .saturating_add(work.summary_expansions);
            let Some(remaining) = remaining_work.checked_sub(spent) else {
                *remaining_work = 0;
                return None;
            };
            *remaining_work = remaining;
            value
        }
        BoundedResolution::Exceeded { .. } | BoundedResolution::Cancelled { .. } => {
            *remaining_work = 0;
            None
        }
    }
}

enum ResolvedFunctionalTarget<'a> {
    External(&'a SemanticModelSymbol),
    Source(CodeUnit),
}

fn selected_symbol<'a>(
    models: &'a SemanticModelOverlay,
    ty: &JvmExternalType,
) -> Option<&'a SemanticModelSymbol> {
    let JvmExternalDeclarationSource::SemanticPack {
        pack_id,
        declaration_id,
    } = ty.source()
    else {
        return None;
    };
    let found = models.symbols_with_id(declaration_id);
    let [symbol] = found.records.as_slice() else {
        return None;
    };
    (!symbol.provenance.ambiguous
        && symbol.provenance.pack_id == *pack_id
        && symbol.qualified_name == ty.fqn())
    .then_some(*symbol)
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
    let slots = crate::analyzer::lexical_definitions::formal_parameter_slots_for_owner_with_nodes(
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

enum SourceFunctionalResult {
    Use(JavaCallResultUse),
    Parent(JavaTypeResolution),
}

/// Prove a directly declared workspace interface without importing an external
/// declaration for a same-spelled type. A single inherited contract can be
/// forwarded when no instance method changes it. Signature merges and potential
/// Object overrides remain unknown until source signatures prove equivalence.
#[allow(clippy::too_many_arguments)]
fn source_functional_result_use(
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
    object: &SemanticModelSymbol,
    arity: usize,
) -> Option<SourceFunctionalResult> {
    use crate::analyzer::lexical_definitions::formal_parameter_slots_for_owner_with_nodes;
    use crate::analyzer::semantic_model::{SemanticModelSymbolKind, Visibility};
    use brokk_bifrost_jvm::java::declarations::java_modifier_keywords;

    if root.has_error()
        || object.kind != SemanticModelSymbolKind::Class
        || object.provenance.ambiguous
        || !object.callable_surface_complete()
    {
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
    if java_modifier_keywords(owner).any(|modifier| modifier == "sealed") {
        return None;
    }
    let mut cursor = owner.walk();
    let inherited = owner
        .named_children(&mut cursor)
        .find(|child| child.kind() == "extends_interfaces");
    let body = owner.child_by_field_name("body")?;
    let object_members = models.members_of(&object.id);
    let mut selected = None;
    let mut has_instance_method = false;
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
        has_instance_method = true;
        if java_modifier_keywords(member).any(|modifier| modifier == "default") {
            continue;
        }
        if member.child_by_field_name("body").is_some()
            || member.child_by_field_name("type_parameters").is_some()
        {
            return None;
        }
        let parameters =
            formal_parameter_slots_for_owner_with_nodes(Language::Java, member, source)?;
        let count = parameters.iter().filter(|(slot, _)| !slot.receiver).count();
        let name = java_node_text(member.child_by_field_name("name")?, source);
        for candidate in &object_members.records {
            if !session.charge_scope_step() {
                return None;
            }
            if candidate.kind != SemanticModelSymbolKind::Method
                || candidate.is_static
                || candidate.visibility != Visibility::Public
            {
                continue;
            }
            if candidate.provenance.ambiguous {
                return None;
            }
            let signature = candidate.structured_signature()?;
            if candidate.name == name && signature.parameters.len() == count {
                return None;
            }
        }
        if selected.is_some() || count != arity {
            return None;
        }
        selected = member.child_by_field_name("type");
    }
    if let Some(inherited) = inherited {
        if has_instance_method {
            return None;
        }
        let types = crate::analyzer::jvm::java_artifact::hierarchy_type_nodes(inherited)?;
        let [ty] = types.as_slice() else {
            return None;
        };
        let name = java_type_name_from_node(*ty, source)?;
        let parent = if let Some(unit) = java_type_text_with_context(
            analyzer,
            token,
            java,
            session,
            file,
            &name,
            ty.start_byte(),
        ) {
            JavaTypeResolution::Source(unit)
        } else {
            session.query_optional_row(|| {
                java.resolve_type_name_with_selected_jdk(
                    token,
                    Some(Arc::clone(models)),
                    file,
                    &name,
                    Some(digest),
                )
            })?
        };
        return Some(SourceFunctionalResult::Parent(parent));
    }
    let mut returned = selected?;
    if returned.kind() == "void_type" {
        return Some(SourceFunctionalResult::Use(JavaCallResultUse::Discarded));
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
                return Some(SourceFunctionalResult::Use(JavaCallResultUse::OtherContext));
            }
            _ => break,
        }
    }
    let name = java_type_name_from_node(returned, source)?;
    if brokk_bifrost_jvm::java::graph_support::java_type_parameter_in_scope(returned, source, &name)
        .is_some()
        || java_type_text_with_context(
            analyzer,
            token,
            java,
            session,
            file,
            &name,
            returned.start_byte(),
        )
        .is_some()
        || session
            .query_optional_row(|| {
                java.resolve_type_name_with_selected_jdk(
                    token,
                    Some(Arc::clone(models)),
                    file,
                    &name,
                    Some(digest),
                )
            })
            .is_some()
    {
        Some(SourceFunctionalResult::Use(JavaCallResultUse::OtherContext))
    } else {
        None
    }
}
