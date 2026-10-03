use crate::analyzer::java::JavaAnalyzer;
use crate::analyzer::java::imports::JavaTypeResolution;
use crate::analyzer::jvm::external::{
    JvmExternalDeclarationSource, JvmExternalType, JvmExternalTypeKind,
};
use crate::analyzer::lexical_definitions::{
    LexicalBindingResolution, formal_parameter_slots_for_owner_with_nodes,
    parameter_owner_for_range, resolve_lexical_binding,
};
use crate::analyzer::multi_analyzer::resolve_analyzer;
use crate::analyzer::semantic::StableDigest;
use crate::analyzer::semantic_model::TypeRef;
use crate::analyzer::usages::call_conversion::{
    ArgumentTypeConversion, CallArgumentConversionProver, ConversionKind, ConversionUnknown,
    ExternalConversionIdentity, ExternalConversionProvenance, JavaPrimitive,
    ResolvedConversionType,
};
use crate::analyzer::usages::get_definition::java::{
    JavaResolutionSession, JavaSourceInvocationReturn, java_external_constructor,
    java_external_invocation_return_type, java_source_invocation_return_declaration,
    java_type_from_node_with_context,
};
use crate::analyzer::usages::get_definition::{BoundedResolution, parse_tree_for_language};
use crate::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;
use crate::analyzer::{
    AnalyzerDefinitionLookup, AnalyzerQueryScope, CodeUnit, CodeUnitIndex, IAnalyzer, Language,
    ProjectFile, QueryScope,
};
use brokk_bifrost_jvm::java::declarations::node_text;
use brokk_bifrost_jvm::java::graph::return_type::java_type_name_components;
use brokk_bifrost_jvm::java::graph_support::java_type_parameter_in_scope;
use tree_sitter::Node;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TypeResolutionFailure {
    Unresolved,
    AmbiguousBinding,
    GenericSubstitution,
    UnsupportedConversion,
    BudgetExhausted,
    Cancelled,
}

impl TypeResolutionFailure {
    fn source(self) -> ConversionUnknown {
        match self {
            Self::Unresolved => ConversionUnknown::UnresolvedSourceType,
            Self::AmbiguousBinding => ConversionUnknown::AmbiguousBinding,
            Self::GenericSubstitution => ConversionUnknown::GenericSubstitution,
            Self::UnsupportedConversion => ConversionUnknown::UnsupportedConversion,
            Self::BudgetExhausted => ConversionUnknown::BudgetExhausted,
            Self::Cancelled => ConversionUnknown::Cancelled,
        }
    }

    fn target(self) -> ConversionUnknown {
        match self {
            Self::Unresolved => ConversionUnknown::UnresolvedTargetType,
            Self::AmbiguousBinding => ConversionUnknown::AmbiguousBinding,
            Self::GenericSubstitution => ConversionUnknown::GenericSubstitution,
            Self::UnsupportedConversion => ConversionUnknown::UnsupportedConversion,
            Self::BudgetExhausted => ConversionUnknown::BudgetExhausted,
            Self::Cancelled => ConversionUnknown::Cancelled,
        }
    }
}

/// The Java view of one conversion side. Arrays are modeled structurally from
/// tree-sitter declaration shapes and model `TypeRef` terms. The shared
/// conversion fact records the element pair with its proven kind; this layer
/// owns array identity so a lexical `String[]` actual applies only to an
/// `Array(String)` model formal.
#[derive(Debug, Clone, PartialEq, Eq)]
enum JavaConversionType {
    Value(ResolvedConversionType),
    Array(Box<JavaConversionType>),
}

/// Prove the conversion for one Java actual/formal pair.
///
/// The caller supplies the exact expression and formal declaration nodes from
/// their parser snapshots. This adapter deliberately has no fallback based on
/// rendered signatures or source spelling: a type is accepted only when the
/// workspace declaration index or the activated external declaration surface
/// proves it.
pub(super) fn prove_argument(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    actual: Node<'_>,
    source: &str,
    formal_file: &ProjectFile,
    formal: Node<'_>,
    formal_source: &str,
) -> Result<ArgumentTypeConversion, ConversionUnknown> {
    if file.language() != Language::Java || formal_file.language() != Language::Java {
        return Err(ConversionUnknown::UnsupportedLanguage);
    }

    let java =
        resolve_analyzer::<JavaAnalyzer>(analyzer).ok_or(ConversionUnknown::UnsupportedLanguage)?;
    let scope = AnalyzerQueryScope::new(java);
    let token = scope.token();
    let packs = analyzer.semantic_model_overlay();

    let target = resolve_formal_type(
        java,
        token,
        packs.clone(),
        formal_file,
        formal,
        formal_source,
    )?;
    let source_type = resolve_actual_type(java, token, packs.clone(), file, actual, source)?;

    classify_java_conversion_with_hierarchy(
        java,
        packs.as_deref(),
        source_type,
        JavaConversionType::Value(target),
    )
}

/// Resolver-backed conversion for one exact local binding write.
/// This is assignment typing, not proof of allocation, non-nullness or dispatch.
#[derive(Debug, Clone)]
pub struct JavaLocalAssignmentEvidence {
    pub assignment: crate::analyzer::Range,
    pub target_binding: crate::analyzer::Range,
    pub source_range: crate::analyzer::Range,
    pub source_digest: StableDigest,
    pub conversion: ArgumentTypeConversion,
}

impl JavaLocalAssignmentEvidence {
    pub fn preserves_reference_identity(&self) -> bool {
        matches!(
            self.conversion.kind,
            ConversionKind::JavaIdentity | ConversionKind::JavaReferenceWidening
        ) && matches!(
            self.conversion.source,
            ResolvedConversionType::Declaration(_) | ResolvedConversionType::External { .. }
        ) && matches!(
            self.conversion.target,
            ResolvedConversionType::Declaration(_) | ResolvedConversionType::External { .. }
        )
    }

    pub fn source_reference_type_id(&self) -> Option<String> {
        assignment_reference_type_id(&self.conversion.source)
    }

    pub fn target_reference_type_id(&self) -> Option<String> {
        assignment_reference_type_id(&self.conversion.target)
    }
}

fn assignment_reference_type_id(resolved: &ResolvedConversionType) -> Option<String> {
    match resolved {
        ResolvedConversionType::Declaration(declaration) => {
            Some(declaration.declaration_id().as_str().to_owned())
        }
        ResolvedConversionType::External { identity } => Some(identity.digest().to_string()),
        _ => None,
    }
}

/// One query-owned parser snapshot used to prove local assignment conversions.
/// The caller binds this source to its immutable semantic artifact and charges
/// source retention and conversion work before requesting proofs.
pub struct JavaLocalAssignmentConversionProver<'a> {
    analyzer: &'a dyn IAnalyzer,
    file: ProjectFile,
    source: String,
    tree: tree_sitter::Tree,
    source_digest: StableDigest,
}

impl<'a> JavaLocalAssignmentConversionProver<'a> {
    pub fn new(
        analyzer: &'a dyn IAnalyzer,
        file: &ProjectFile,
        source: &str,
    ) -> Result<Self, ConversionUnknown> {
        if file.language() != Language::Java {
            return Err(ConversionUnknown::UnsupportedLanguage);
        }
        if !analyzer.indexed_source_matches(file, source) {
            return Err(ConversionUnknown::UnresolvedSourceType);
        }
        let tree = parse_tree_for_language(file, Language::Java, source)
            .ok_or(ConversionUnknown::UnsupportedExpression)?;
        Ok(Self {
            analyzer,
            file: file.clone(),
            source: source.to_owned(),
            tree,
            source_digest: StableDigest::sha256(source.as_bytes()),
        })
    }

    pub fn prove(
        &self,
        assignment: crate::analyzer::Range,
        target_binding: crate::analyzer::Range,
    ) -> Result<JavaLocalAssignmentEvidence, ConversionUnknown> {
        let root = self.tree.root_node();
        let mut node = root
            .named_descendant_for_byte_range(assignment.start_byte, assignment.end_byte)
            .ok_or(ConversionUnknown::UnsupportedExpression)?;
        if node.start_byte() != assignment.start_byte || node.end_byte() != assignment.end_byte {
            return Err(ConversionUnknown::UnsupportedExpression);
        }
        // An event can be anchored on the initializer or its containing write.
        // Ascend only through transparent syntax, never a call or another write.
        while !matches!(node.kind(), "variable_declarator" | "assignment_expression") {
            let parent = node
                .parent()
                .ok_or(ConversionUnknown::UnsupportedExpression)?;
            if parent.child_by_field_name("value") != Some(node)
                && parent.child_by_field_name("right") != Some(node)
                && parent.kind() != "parenthesized_expression"
            {
                return Err(ConversionUnknown::UnsupportedExpression);
            }
            node = parent;
        }
        if node.has_error() || node.is_missing() {
            return Err(ConversionUnknown::UnsupportedExpression);
        }
        let (name, actual, declaration) = if node.kind() == "variable_declarator" {
            if node
                .parent()
                .is_none_or(|parent| parent.kind() != "local_variable_declaration")
            {
                return Err(ConversionUnknown::UnsupportedExpression);
            }
            (
                node.child_by_field_name("name")
                    .ok_or(ConversionUnknown::UnresolvedTargetType)?,
                node.child_by_field_name("value")
                    .ok_or(ConversionUnknown::UnresolvedSourceType)?,
                node,
            )
        } else {
            let operator = node
                .child_by_field_name("operator")
                .ok_or(ConversionUnknown::UnsupportedExpression)?;
            if operator.kind() != "=" {
                return Err(ConversionUnknown::UnsupportedConversion);
            }
            let name = node
                .child_by_field_name("left")
                .ok_or(ConversionUnknown::UnresolvedTargetType)?;
            if name.kind() != "identifier" {
                return Err(ConversionUnknown::UnsupportedExpression);
            }
            let binding = resolve_lexical_binding(
                Language::Java,
                root,
                &self.source,
                name.start_byte(),
                name.end_byte(),
                node_text(name, &self.source),
            )
            .ok_or(ConversionUnknown::UnresolvedTargetType)?;
            let LexicalBindingResolution::OtherLocal(binding) = binding else {
                return Err(ConversionUnknown::UnsupportedExpression);
            };
            if binding.name_range.start_byte >= name.start_byte() {
                return Err(ConversionUnknown::AmbiguousBinding);
            }
            let declaration = root
                .named_descendant_for_byte_range(
                    binding.declaration_range.start_byte,
                    binding.declaration_range.end_byte,
                )
                .ok_or(ConversionUnknown::UnresolvedTargetType)?;
            (
                name,
                node.child_by_field_name("right")
                    .ok_or(ConversionUnknown::UnresolvedSourceType)?,
                declaration,
            )
        };
        if name.kind() != "identifier"
            || declaration.kind() != "variable_declarator"
            || declaration
                .parent()
                .is_none_or(|parent| parent.kind() != "local_variable_declaration")
        {
            return Err(ConversionUnknown::UnsupportedExpression);
        }
        let declared_name = declaration
            .child_by_field_name("name")
            .ok_or(ConversionUnknown::UnresolvedTargetType)?;
        let target_matches = [declared_name, declaration].into_iter().any(|candidate| {
            candidate.start_byte() == target_binding.start_byte
                && candidate.end_byte() == target_binding.end_byte
        });
        if !target_matches {
            return Err(ConversionUnknown::AmbiguousBinding);
        }
        // Cross-lambda/class copies require capture semantics, not lexical name lookup.
        fn owner(mut node: Node<'_>) -> Option<usize> {
            loop {
                if matches!(
                    node.kind(),
                    "method_declaration"
                        | "constructor_declaration"
                        | "lambda_expression"
                        | "static_initializer"
                ) {
                    return Some(node.id());
                }
                node = node.parent()?;
            }
        }
        if owner(node).is_none() || owner(node) != owner(declaration) {
            return Err(ConversionUnknown::UnsupportedExpression);
        }
        let mut source_node = actual;
        while source_node.kind() == "parenthesized_expression" {
            source_node = source_node
                .named_child(0)
                .ok_or(ConversionUnknown::UnsupportedExpression)?;
        }
        if source_node.kind() == "identifier" {
            let binding = resolve_lexical_binding(
                Language::Java,
                root,
                &self.source,
                source_node.start_byte(),
                source_node.end_byte(),
                node_text(source_node, &self.source),
            )
            .ok_or(ConversionUnknown::UnresolvedSourceType)?;
            let (LexicalBindingResolution::Parameter(binding)
            | LexicalBindingResolution::OtherLocal(binding)) = binding;
            if binding.name_range.start_byte >= source_node.start_byte() {
                return Err(ConversionUnknown::AmbiguousBinding);
            }
            let source_declaration = root
                .named_descendant_for_byte_range(
                    binding.declaration_range.start_byte,
                    binding.declaration_range.end_byte,
                )
                .ok_or(ConversionUnknown::UnresolvedSourceType)?;
            if owner(source_declaration) != owner(node) {
                return Err(ConversionUnknown::UnsupportedExpression);
            }
        }
        let java = resolve_analyzer::<JavaAnalyzer>(self.analyzer)
            .ok_or(ConversionUnknown::UnsupportedLanguage)?;
        if java
            .active_query_cancellation()
            .is_some_and(|token| token.is_cancelled())
        {
            return Err(ConversionUnknown::Cancelled);
        }
        let scope = AnalyzerQueryScope::new(java);
        let token = scope.token();
        let packs = self.analyzer.semantic_model_overlay();
        let type_node =
            declared_type_node(declaration).ok_or(ConversionUnknown::UnresolvedTargetType)?;
        if declaration_declares_array(declaration, type_node) {
            return Err(ConversionUnknown::UnsupportedConversion);
        }
        let target = resolve_type_node(
            java,
            token,
            packs.clone(),
            &self.file,
            type_node,
            &self.source,
        )
        .map_err(TypeResolutionFailure::target)?;
        let source = resolve_local_assignment_source_type(
            java,
            token,
            packs.clone(),
            &self.file,
            actual,
            &self.source,
        )?;
        if matches!(source, JavaConversionType::Array(_)) {
            return Err(ConversionUnknown::UnsupportedConversion);
        }
        let conversion = classify_java_conversion_with_hierarchy(
            java,
            packs.as_deref(),
            source,
            JavaConversionType::Value(target),
        )?;
        if java
            .active_query_cancellation()
            .is_some_and(|token| token.is_cancelled())
        {
            return Err(ConversionUnknown::Cancelled);
        }
        if let Some(hierarchy) = &conversion.hierarchy
            && let Some(reason) = hierarchy.incomplete.first()
        {
            use crate::analyzer::semantic_model::JavaHierarchyIncomplete;
            return Err(match reason {
                JavaHierarchyIncomplete::Cancelled => ConversionUnknown::Cancelled,
                JavaHierarchyIncomplete::BudgetExhausted => ConversionUnknown::BudgetExhausted,
                JavaHierarchyIncomplete::Ambiguous => ConversionUnknown::AmbiguousBinding,
                JavaHierarchyIncomplete::GenericSubstitution => {
                    ConversionUnknown::GenericSubstitution
                }
                JavaHierarchyIncomplete::MissingHierarchy => ConversionUnknown::IncompleteHierarchy,
            });
        }
        Ok(JavaLocalAssignmentEvidence {
            assignment,
            target_binding,
            source_range: crate::analyzer::Range {
                start_byte: actual.start_byte(),
                end_byte: actual.end_byte(),
                start_line: actual.start_position().row + 1,
                end_line: actual.end_position().row + 1,
            },
            source_digest: self.source_digest,
            conversion,
        })
    }
}

fn resolve_local_assignment_source_type(
    java: &JavaAnalyzer,
    token: crate::analyzer::QueryToken<'_>,
    packs: Option<std::sync::Arc<crate::analyzer::semantic_model::SemanticModelOverlay>>,
    file: &ProjectFile,
    actual: Node<'_>,
    source: &str,
) -> Result<JavaConversionType, ConversionUnknown> {
    let mut expression = actual;
    while expression.kind() == "parenthesized_expression" {
        expression = expression
            .named_child(0)
            .ok_or(ConversionUnknown::UnsupportedExpression)?;
    }
    if expression.kind() == "method_invocation" {
        let _model_scope = AnalyzerQueryScope::with_semantic_model_overlay(java, packs.clone());
        let definitions = AnalyzerDefinitionLookup::new(java, Language::Java);
        let cancellation = java.active_query_cancellation();
        let session = JavaResolutionSession::bounded(
            &definitions,
            ReceiverAnalysisBudget::default(),
            cancellation.as_ref(),
        );
        let selected = java_source_invocation_return_declaration(
            java, token, &session, file, source, expression,
        );
        match session.finish(selected) {
            BoundedResolution::Complete {
                value: JavaSourceInvocationReturn::Source { declaration, range },
                ..
            } => {
                // Preserve source identity and inspect the selected declaration's
                // type node; no displayed return signature participates.
                let declaration_file = declaration.source();
                let other_source;
                let other_tree;
                let (declaration_source, declaration_root) = if declaration_file == file {
                    (source, root_of(expression))
                } else {
                    other_source = java
                        .indexed_source(declaration_file)
                        .ok_or(ConversionUnknown::UnresolvedSourceType)?;
                    other_tree =
                        parse_tree_for_language(declaration_file, Language::Java, &other_source)
                            .ok_or(ConversionUnknown::UnresolvedSourceType)?;
                    (other_source.as_str(), other_tree.root_node())
                };
                let method = parameter_owner_for_range(Language::Java, declaration_root, &range)
                    .ok_or(ConversionUnknown::UnresolvedSourceType)?;
                if method.kind() != "method_declaration"
                    || method.has_error()
                    || method.child_by_field_name("type_parameters").is_some()
                {
                    return Err(ConversionUnknown::GenericSubstitution);
                }
                let result_type = method
                    .child_by_field_name("type")
                    .ok_or(ConversionUnknown::UnresolvedSourceType)?;
                if declaration_declares_array(method, result_type) {
                    return Err(ConversionUnknown::UnsupportedConversion);
                }
                return resolve_type_node(
                    java,
                    token,
                    packs,
                    declaration_file,
                    result_type,
                    declaration_source,
                )
                .map(JavaConversionType::Value)
                .map_err(TypeResolutionFailure::source);
            }
            BoundedResolution::Complete {
                value: JavaSourceInvocationReturn::NoSourceDeclaration,
                ..
            } => {}
            BoundedResolution::Complete {
                value: JavaSourceInvocationReturn::Ambiguous,
                ..
            } => return Err(ConversionUnknown::AmbiguousBinding),
            BoundedResolution::Complete {
                value: JavaSourceInvocationReturn::UnprovenApplicability,
                ..
            } => return Err(ConversionUnknown::UnsupportedConversion),
            BoundedResolution::Complete {
                value: JavaSourceInvocationReturn::Incomplete,
                ..
            } => return Err(ConversionUnknown::UnresolvedSourceType),
            BoundedResolution::Exceeded { .. } => return Err(ConversionUnknown::BudgetExhausted),
            BoundedResolution::Cancelled { .. } => return Err(ConversionUnknown::Cancelled),
        }
    }
    resolve_actual_type(java, token, packs, file, actual, source)
}

/// Read the static primitive type of one exact call argument for Java overload
/// selection. Overload selection needs only the argument's type (JLS 15.12.2),
/// so a numeric literal's type and a primitive cast's target type count here.
/// The conversion prover deliberately does not accept them as a bounded
/// source-type proof for value transfer. Other expression kinds remain
/// undecided rather than being treated as an incompatible argument.
pub(crate) fn primitive_actual_type(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    actual: Node<'_>,
    source: &str,
) -> Option<JavaPrimitive> {
    let mut expression = actual;
    while expression.kind() == "parenthesized_expression" {
        expression = expression.named_child(0)?;
    }
    if let Some(primitive) = numeric_literal_type(expression, source) {
        return Some(primitive);
    }
    if expression.kind() == "cast_expression" {
        let target = expression.child_by_field_name("type")?;
        expression.child_by_field_name("value")?;
        return matches!(
            target.kind(),
            "integral_type" | "floating_point_type" | "boolean_type"
        )
        .then(|| primitive_type(target))
        .flatten();
    }
    let java = resolve_analyzer::<JavaAnalyzer>(analyzer)?;
    let scope = AnalyzerQueryScope::new(java);
    let resolved = resolve_actual_type(
        java,
        scope.token(),
        analyzer.semantic_model_overlay(),
        file,
        actual,
        source,
    )
    .ok()?;
    match resolved {
        JavaConversionType::Value(ResolvedConversionType::JavaPrimitive(primitive)) => {
            Some(primitive)
        }
        _ => None,
    }
}

/// How one declared Java formal takes a primitive actual during strict
/// invocation (JLS 15.12.2.2). A primitive actual reaches a reference formal,
/// including an array, a varargs slot or a type variable, only by boxing,
/// which strict invocation does not allow. A reference formal therefore needs
/// no type resolution to be excluded from the strict phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JavaFormalShape {
    Primitive(JavaPrimitive),
    Reference,
}

/// Parse one Java declaring file for [`formal_shapes`]. Callers parse each
/// file once and read every candidate it declares from the same tree.
pub(crate) fn parse_declaring_file(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
) -> Option<(String, tree_sitter::Tree)> {
    if file.language() != Language::Java {
        return None;
    }
    let source = analyzer.indexed_source(file)?;
    let tree = parse_tree_for_language(file, Language::Java, &source)?;
    Some((source, tree))
}

/// Read one indexed method's ordinary formals as strict-invocation shapes from
/// its declaring file's tree. Recovered syntax and a type spelled in a form
/// this reader does not classify leave the whole list undecided.
pub(crate) fn formal_shapes(
    analyzer: &dyn IAnalyzer,
    target: &CodeUnit,
    root: Node<'_>,
    source: &str,
) -> Option<Vec<JavaFormalShape>> {
    let ranges = analyzer.ranges_of(target);
    let [range] = ranges.as_slice() else {
        return None;
    };
    let owner = parameter_owner_for_range(Language::Java, root, range)?;
    if owner.has_error() || owner.is_missing() {
        return None;
    }
    let slots = formal_parameter_slots_for_owner_with_nodes(Language::Java, owner, source)?;
    slots
        .into_iter()
        .filter(|(slot, _)| !slot.receiver)
        .map(|(slot, formal)| {
            if slot.variadic.is_some() {
                return Some(JavaFormalShape::Reference);
            }
            let type_node = declared_type_node(formal)?;
            if declaration_declares_array(formal, type_node) {
                return Some(JavaFormalShape::Reference);
            }
            match type_node.kind() {
                "integral_type" | "floating_point_type" | "boolean_type" => {
                    primitive_type(type_node).map(JavaFormalShape::Primitive)
                }
                "type_identifier" | "scoped_type_identifier" | "generic_type" => {
                    Some(JavaFormalShape::Reference)
                }
                _ => None,
            }
        })
        .collect()
}

pub(crate) fn primitive_converts(source: JavaPrimitive, target: JavaPrimitive) -> bool {
    source == target || primitive_widens(source, target)
}

pub(crate) static CALL_ARGUMENT_CONVERSION_PROVER: JavaCallArgumentConversionProver =
    JavaCallArgumentConversionProver;

pub(crate) struct JavaCallArgumentConversionProver;

impl CallArgumentConversionProver for JavaCallArgumentConversionProver {
    fn prove_argument(
        &self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        actual: Node<'_>,
        source: &str,
        formal_file: &ProjectFile,
        formal: Node<'_>,
        formal_source: &str,
    ) -> Result<ArgumentTypeConversion, ConversionUnknown> {
        prove_argument(
            analyzer,
            file,
            actual,
            source,
            formal_file,
            formal,
            formal_source,
        )
    }

    fn prove_model_argument(
        &self,
        analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        actual: Node<'_>,
        source: &str,
        formal_type: &TypeRef,
    ) -> Result<ArgumentTypeConversion, ConversionUnknown> {
        if file.language() != Language::Java {
            return Err(ConversionUnknown::UnsupportedLanguage);
        }
        let java = resolve_analyzer::<JavaAnalyzer>(analyzer)
            .ok_or(ConversionUnknown::UnsupportedLanguage)?;
        let scope = AnalyzerQueryScope::new(java);
        let token = scope.token();
        let packs = analyzer.semantic_model_overlay();
        let source_type = resolve_actual_type(java, token, packs.clone(), file, actual, source)?;
        let target = resolve_model_type_ref(java, token, packs.clone(), file, formal_type)?;
        classify_java_conversion_with_hierarchy(java, packs.as_deref(), source_type, target)
    }
}

fn resolve_formal_type(
    java: &JavaAnalyzer,
    token: crate::analyzer::QueryToken<'_>,
    packs: Option<std::sync::Arc<crate::analyzer::semantic_model::SemanticModelOverlay>>,
    file: &ProjectFile,
    formal: Node<'_>,
    source: &str,
) -> Result<ResolvedConversionType, ConversionUnknown> {
    if !matches!(
        formal.kind(),
        "formal_parameter" | "receiver_parameter" | "catch_formal_parameter"
    ) {
        return Err(ConversionUnknown::UnresolvedSignature);
    }
    let type_node = declared_type_node(formal).ok_or(ConversionUnknown::UnresolvedSignature)?;
    if declaration_declares_array(formal, type_node) {
        return Err(ConversionUnknown::UnsupportedConversion);
    }
    resolve_type_node(java, token, packs, file, type_node, source)
        .map_err(TypeResolutionFailure::target)
}

fn resolve_actual_type(
    java: &JavaAnalyzer,
    token: crate::analyzer::QueryToken<'_>,
    packs: Option<std::sync::Arc<crate::analyzer::semantic_model::SemanticModelOverlay>>,
    file: &ProjectFile,
    actual: Node<'_>,
    source: &str,
) -> Result<JavaConversionType, ConversionUnknown> {
    resolve_actual_type_bounded(java, token, packs, file, actual, source, 8)
}

// Constructor nesting spends this bound before descending. Unlike an
// unrestricted AST walk, this recursion has a fixed maximum depth of eight.
fn resolve_actual_type_bounded(
    java: &JavaAnalyzer,
    token: crate::analyzer::QueryToken<'_>,
    packs: Option<std::sync::Arc<crate::analyzer::semantic_model::SemanticModelOverlay>>,
    file: &ProjectFile,
    actual: Node<'_>,
    source: &str,
    remaining: usize,
) -> Result<JavaConversionType, ConversionUnknown> {
    let mut expression = actual;
    while expression.kind() == "parenthesized_expression" {
        expression = expression
            .named_child(0)
            .ok_or(ConversionUnknown::UnsupportedExpression)?;
    }

    if let Some(primitive) = primitive_literal(expression) {
        return Ok(JavaConversionType::Value(
            ResolvedConversionType::JavaPrimitive(primitive),
        ));
    }

    match expression.kind() {
        "identifier" => resolve_lexical_actual_type(java, token, packs, file, expression, source),
        "method_invocation" => {
            // The caller may be a multi-language analyzer whose query owns
            // the activated overlay. Freeze it on the Java delegate too.
            let _model_scope = AnalyzerQueryScope::with_semantic_model_overlay(java, packs.clone());
            let definitions = AnalyzerDefinitionLookup::new(java, Language::Java);
            let cancellation = java.active_query_cancellation();
            let session = JavaResolutionSession::bounded(
                &definitions,
                ReceiverAnalysisBudget::default(),
                cancellation.as_ref(),
            );
            let returned = java_external_invocation_return_type(
                java, token, &session, file, source, expression,
            );
            match session.finish(returned) {
                BoundedResolution::Complete {
                    value: Some(returned),
                    ..
                } => {
                    resolve_model_type_ref(java, token, packs, file, &returned).map_err(|reason| {
                        match reason {
                            ConversionUnknown::UnresolvedTargetType => {
                                ConversionUnknown::UnresolvedSourceType
                            }
                            other => other,
                        }
                    })
                }
                BoundedResolution::Exceeded { .. } => Err(ConversionUnknown::BudgetExhausted),
                BoundedResolution::Cancelled { .. } => Err(ConversionUnknown::Cancelled),
                BoundedResolution::Complete { value: None, .. } => {
                    Err(ConversionUnknown::UnresolvedSourceType)
                }
            }
        }
        "object_creation_expression" => {
            use crate::analyzer::semantic_model::SemanticModelCallableKey;
            let remaining = remaining
                .checked_sub(1)
                .ok_or(ConversionUnknown::UnsupportedExpression)?;
            let overlay = packs
                .clone()
                .ok_or(ConversionUnknown::UnresolvedSourceType)?;
            let _model_scope = AnalyzerQueryScope::with_semantic_model_overlay(java, packs.clone());
            let definitions = AnalyzerDefinitionLookup::new(java, Language::Java);
            let cancellation = java.active_query_cancellation();
            let session = JavaResolutionSession::bounded(
                &definitions,
                ReceiverAnalysisBudget::default(),
                cancellation.as_ref(),
            );
            let selected =
                java_external_constructor(java, token, java, &session, file, source, expression);
            let (owner, member, arity) = match session.finish(selected) {
                BoundedResolution::Complete {
                    value: Some(selected),
                    ..
                } => selected,
                BoundedResolution::Complete { value: None, .. } => {
                    return Err(ConversionUnknown::UnresolvedSourceType);
                }
                BoundedResolution::Exceeded { .. } => {
                    return Err(ConversionUnknown::BudgetExhausted);
                }
                BoundedResolution::Cancelled { .. } => return Err(ConversionUnknown::Cancelled),
            };
            let matched = overlay.callable_for_target(SemanticModelCallableKey::new(
                "java", &owner, &member, false, arity,
            ));
            let [symbol] = matched.records.as_slice() else {
                return Err(ConversionUnknown::AmbiguousBinding);
            };
            let signature = symbol
                .structured_signature
                .as_ref()
                .ok_or(ConversionUnknown::UnresolvedSignature)?;
            let arguments = expression
                .child_by_field_name("arguments")
                .ok_or(ConversionUnknown::UnsupportedExpression)?;
            let mut cursor = arguments.walk();
            let actuals = arguments.named_children(&mut cursor).collect::<Vec<_>>();
            if actuals.len() != signature.parameters.len() {
                return Err(ConversionUnknown::SignatureApplicability);
            }
            for (actual, formal) in actuals.into_iter().zip(&signature.parameters) {
                let source_type = resolve_actual_type_bounded(
                    java,
                    token,
                    packs.clone(),
                    file,
                    actual,
                    source,
                    remaining,
                )?;
                let target_type =
                    resolve_model_type_ref(java, token, packs.clone(), file, &formal.r#type)?;
                classify_java_conversion_with_hierarchy(
                    java,
                    packs.as_deref(),
                    source_type,
                    target_type,
                )?;
            }
            resolve_external_spelling(
                java,
                packs,
                file,
                &owner,
                ConversionUnknown::UnresolvedSourceType,
            )
            .map(JavaConversionType::Value)
        }
        "string_literal" => resolve_external_spelling(
            java,
            packs,
            file,
            "java.lang.String",
            ConversionUnknown::UnresolvedSourceType,
        )
        .map(JavaConversionType::Value),
        _ => Err(ConversionUnknown::UnsupportedExpression),
    }
}

fn resolve_lexical_actual_type(
    java: &JavaAnalyzer,
    token: crate::analyzer::QueryToken<'_>,
    packs: Option<std::sync::Arc<crate::analyzer::semantic_model::SemanticModelOverlay>>,
    file: &ProjectFile,
    actual: Node<'_>,
    source: &str,
) -> Result<JavaConversionType, ConversionUnknown> {
    let identifier = node_text(actual, source);
    if identifier.is_empty() {
        return Err(ConversionUnknown::UnresolvedSourceType);
    }
    let root = root_of(actual);
    let binding = resolve_lexical_binding(
        Language::Java,
        root,
        source,
        actual.start_byte(),
        actual.end_byte(),
        identifier,
    )
    .ok_or(ConversionUnknown::UnresolvedSourceType)?;
    let declaration_range = match binding {
        LexicalBindingResolution::Parameter(definition)
        | LexicalBindingResolution::OtherLocal(definition) => definition.declaration_range,
    };
    let declaration = root
        .descendant_for_byte_range(declaration_range.start_byte, declaration_range.end_byte)
        .or_else(|| {
            root.named_descendant_for_byte_range(
                declaration_range.start_byte,
                declaration_range.end_byte,
            )
        })
        .ok_or(ConversionUnknown::UnresolvedSourceType)?;
    let type_node =
        declared_type_node(declaration).ok_or(ConversionUnknown::UnresolvedSourceType)?;
    let (element_type_node, array_dimensions) = declared_java_type_shape(declaration, type_node)?;
    let element = resolve_type_node(java, token, packs, file, element_type_node, source)
        .map_err(TypeResolutionFailure::source)?;
    Ok(array_java_type(element, array_dimensions))
}

/// The declared element type and array dimension count, read structurally
/// from tree-sitter `array_type` element/dimensions fields and declarator
/// dimension fields. No rendered-spelling parsing.
fn declared_java_type_shape<'a>(
    declaration: Node<'a>,
    type_node: Node<'a>,
) -> Result<(Node<'a>, usize), ConversionUnknown> {
    if declaration.kind() == "spread_parameter" {
        return Err(ConversionUnknown::UnsupportedConversion);
    }
    let mut element = type_node;
    let mut dimensions = 0usize;
    while element.kind() == "array_type" {
        dimensions += dimension_count(element.child_by_field_name("dimensions"));
        element = element
            .child_by_field_name("element")
            .ok_or(ConversionUnknown::UnresolvedSourceType)?;
    }
    dimensions += dimension_count(declaration.child_by_field_name("dimensions"));
    Ok((element, dimensions))
}

fn dimension_count(dimensions: Option<Node<'_>>) -> usize {
    // Each `[]` axis contributes two anonymous child tokens to a
    // `dimensions` node, so the axis count is half the child count.
    dimensions.map_or(0, |dimensions| dimensions.child_count() / 2)
}

fn array_java_type(element: ResolvedConversionType, dimensions: usize) -> JavaConversionType {
    let mut java_type = JavaConversionType::Value(element);
    for _ in 0..dimensions {
        java_type = JavaConversionType::Array(Box::new(java_type));
    }
    java_type
}

fn resolve_type_node(
    java: &JavaAnalyzer,
    token: crate::analyzer::QueryToken<'_>,
    packs: Option<std::sync::Arc<crate::analyzer::semantic_model::SemanticModelOverlay>>,
    file: &ProjectFile,
    type_node: Node<'_>,
    source: &str,
) -> Result<ResolvedConversionType, TypeResolutionFailure> {
    if has_generic_shape(type_node) {
        return Err(TypeResolutionFailure::GenericSubstitution);
    }

    if let Some(primitive) = primitive_type(type_node) {
        return Ok(ResolvedConversionType::JavaPrimitive(primitive));
    }
    if matches!(
        type_node.kind(),
        "array_type" | "annotated_type" | "void_type"
    ) {
        return Err(TypeResolutionFailure::UnsupportedConversion);
    }

    let components =
        java_type_name_components(type_node, source).ok_or(TypeResolutionFailure::Unresolved)?;
    let raw_name = components.join(".");
    if components.len() == 1
        && java_type_parameter_in_scope(type_node, source, &components[0]).is_some()
    {
        return Err(TypeResolutionFailure::GenericSubstitution);
    }

    // Reuse the resolver's lexical/local/member type scope. File-level imports
    // alone cannot resolve a member type such as App.Payload from App.take.
    let definitions = AnalyzerDefinitionLookup::new(java, Language::Java);
    let cancellation = java.active_query_cancellation();
    let session = JavaResolutionSession::bounded(
        &definitions,
        ReceiverAnalysisBudget::default(),
        cancellation.as_ref(),
    );
    let resolved =
        java_type_from_node_with_context(java, token, java, &session, file, source, type_node);
    match session.finish(resolved) {
        BoundedResolution::Complete {
            value: Some(unit), ..
        } => return workspace_type_identity(java, unit),
        BoundedResolution::Complete { value: None, .. } => {}
        BoundedResolution::Exceeded { .. } => return Err(TypeResolutionFailure::BudgetExhausted),
        BoundedResolution::Cancelled { .. } => return Err(TypeResolutionFailure::Cancelled),
    }

    if java
        .resolve_type_name_candidates_in_file(token, file, &raw_name)
        .len()
        > 1
    {
        return Err(TypeResolutionFailure::AmbiguousBinding);
    }

    match java.resolve_type_name_with_external(token, packs.clone(), file, &raw_name) {
        Some(JavaTypeResolution::Source(unit)) => workspace_type_identity(java, unit),
        Some(JavaTypeResolution::External(external)) => {
            let identity = external_identity(java, packs.as_deref(), &external)
                .ok_or(TypeResolutionFailure::Unresolved)?;
            Ok(ResolvedConversionType::External { identity })
        }
        None => Err(TypeResolutionFailure::Unresolved),
    }
}

fn resolve_external_spelling(
    java: &JavaAnalyzer,
    packs: Option<std::sync::Arc<crate::analyzer::semantic_model::SemanticModelOverlay>>,
    file: &ProjectFile,
    spelling: &str,
    unknown: ConversionUnknown,
) -> Result<ResolvedConversionType, ConversionUnknown> {
    let access_package = java.package_name_of(file).unwrap_or_default();
    let external = java
        .external_declarations(packs.clone())
        .resolve_qualified_name(spelling, &access_package)
        .and_then(|external| external_identity(java, packs.as_deref(), &external));
    external
        .map(|identity| ResolvedConversionType::External { identity })
        .ok_or(unknown)
}

pub(crate) fn primitive_for_name(name: &str) -> Option<JavaPrimitive> {
    match name {
        "boolean" => Some(JavaPrimitive::Boolean),
        "byte" => Some(JavaPrimitive::Byte),
        "short" => Some(JavaPrimitive::Short),
        "char" => Some(JavaPrimitive::Char),
        "int" => Some(JavaPrimitive::Int),
        "long" => Some(JavaPrimitive::Long),
        "float" => Some(JavaPrimitive::Float),
        "double" => Some(JavaPrimitive::Double),
        _ => None,
    }
}

/// Resolve the model's structured type term through the same declaration
/// surface used for source formals. The field is a structured `TypeRef`, not
/// a rendered signature; generic terms remain explicitly unresolved and
/// arrays are walked structurally to their element terms.
fn resolve_model_type_ref(
    java: &JavaAnalyzer,
    token: crate::analyzer::QueryToken<'_>,
    packs: Option<std::sync::Arc<crate::analyzer::semantic_model::SemanticModelOverlay>>,
    file: &ProjectFile,
    type_ref: &TypeRef,
) -> Result<JavaConversionType, ConversionUnknown> {
    let mut element = type_ref;
    let mut dimensions = 0;
    while let TypeRef::Array { element: inner } = element {
        dimensions += 1;
        element = inner;
    }
    let TypeRef::Named {
        name, arguments, ..
    } = element
    else {
        return Err(ConversionUnknown::UnsupportedConversion);
    };
    let mut resolved = resolve_model_named_type(java, token, packs, file, name, arguments)?;
    for _ in 0..dimensions {
        resolved = JavaConversionType::Array(Box::new(resolved));
    }
    Ok(resolved)
}

fn resolve_model_named_type(
    java: &JavaAnalyzer,
    token: crate::analyzer::QueryToken<'_>,
    packs: Option<std::sync::Arc<crate::analyzer::semantic_model::SemanticModelOverlay>>,
    file: &ProjectFile,
    name: &str,
    arguments: &[TypeRef],
) -> Result<JavaConversionType, ConversionUnknown> {
    if !arguments.is_empty() {
        return Err(ConversionUnknown::GenericSubstitution);
    }
    if let Some(primitive) = primitive_for_name(name) {
        return Ok(JavaConversionType::Value(
            ResolvedConversionType::JavaPrimitive(primitive),
        ));
    }

    if java
        .resolve_type_name_candidates_in_file(token, file, name)
        .len()
        > 1
    {
        return Err(ConversionUnknown::AmbiguousBinding);
    }
    match java.resolve_type_name_with_external(token, packs.clone(), file, name) {
        Some(JavaTypeResolution::Source(unit)) => Ok(JavaConversionType::Value(
            workspace_type_identity(java, unit).map_err(TypeResolutionFailure::target)?,
        )),
        Some(JavaTypeResolution::External(external)) => {
            let identity = external_identity(java, packs.as_deref(), &external)
                .ok_or(ConversionUnknown::UnresolvedTargetType)?;
            Ok(JavaConversionType::Value(
                ResolvedConversionType::External { identity },
            ))
        }
        None => Err(ConversionUnknown::UnresolvedTargetType),
    }
}

/// Classify one conversion between structured Java types. Identical array
/// shapes recurse to their element pair, so the recorded fact carries the
/// element identities with the proven kind; a shape mismatch stays a typed
/// rejection and never falls back to element compatibility.
fn classify_java_conversion_with_hierarchy(
    java: &JavaAnalyzer,
    overlay: Option<&crate::analyzer::semantic_model::SemanticModelOverlay>,
    source: JavaConversionType,
    target: JavaConversionType,
) -> Result<ArgumentTypeConversion, ConversionUnknown> {
    let result = classify_java_conversion(source.clone(), target.clone());
    if !matches!(result, Err(ConversionUnknown::UnsupportedConversion)) {
        return result;
    }
    let (
        JavaConversionType::Value(ResolvedConversionType::External {
            identity: source_identity,
        }),
        JavaConversionType::Value(ResolvedConversionType::External {
            identity: target_identity,
        }),
    ) = (&source, &target)
    else {
        return result;
    };
    let overlay = overlay.ok_or(ConversionUnknown::IncompleteHierarchy)?;
    let source_symbol = source_identity
        .model_declaration(overlay)
        .ok_or(ConversionUnknown::IncompleteHierarchy)?;
    let target_symbol = target_identity
        .model_declaration(overlay)
        .ok_or(ConversionUnknown::IncompleteHierarchy)?;
    let cancellation = java.active_query_cancellation();
    let hierarchy =
        overlay.java_reference_widening(source_symbol, target_symbol, 256, cancellation.as_ref());
    if hierarchy.witness.is_some() {
        let JavaConversionType::Value(source) = source else {
            unreachable!()
        };
        let JavaConversionType::Value(target) = target else {
            unreachable!()
        };
        return Ok(ArgumentTypeConversion {
            source,
            target,
            kind: ConversionKind::JavaReferenceWidening,
            hierarchy: Some(hierarchy),
        });
    }
    use crate::analyzer::semantic_model::JavaHierarchyIncomplete;
    let terminal = [
        JavaHierarchyIncomplete::Cancelled,
        JavaHierarchyIncomplete::BudgetExhausted,
    ]
    .into_iter()
    .find(|reason| hierarchy.incomplete.contains(reason));
    let reason = terminal
        .as_ref()
        .or(hierarchy.incomplete.first())
        .map(|reason| match reason {
            JavaHierarchyIncomplete::MissingHierarchy => ConversionUnknown::IncompleteHierarchy,
            JavaHierarchyIncomplete::Ambiguous => ConversionUnknown::AmbiguousBinding,
            JavaHierarchyIncomplete::GenericSubstitution => ConversionUnknown::GenericSubstitution,
            JavaHierarchyIncomplete::BudgetExhausted => ConversionUnknown::BudgetExhausted,
            JavaHierarchyIncomplete::Cancelled => ConversionUnknown::Cancelled,
        })
        .unwrap_or(ConversionUnknown::UnsupportedConversion);
    Err(reason)
}

fn classify_java_conversion(
    source: JavaConversionType,
    target: JavaConversionType,
) -> Result<ArgumentTypeConversion, ConversionUnknown> {
    match (source, target) {
        (JavaConversionType::Array(source_element), JavaConversionType::Array(target_element))
            if source_element == target_element =>
        {
            classify_java_conversion(*source_element, *target_element)
        }
        (JavaConversionType::Value(source), JavaConversionType::Value(target)) => {
            classify_conversion(source, target)
        }
        _ => Err(ConversionUnknown::UnsupportedConversion),
    }
}

fn classify_conversion(
    source: ResolvedConversionType,
    target: ResolvedConversionType,
) -> Result<ArgumentTypeConversion, ConversionUnknown> {
    let kind = match (&source, &target) {
        (
            ResolvedConversionType::JavaPrimitive(source),
            ResolvedConversionType::JavaPrimitive(target),
        ) if source == target => ConversionKind::JavaIdentity,
        (
            ResolvedConversionType::JavaPrimitive(source),
            ResolvedConversionType::JavaPrimitive(target),
        ) if primitive_widens(*source, *target) => ConversionKind::JavaPrimitiveWidening,
        (
            ResolvedConversionType::JavaPrimitive(source),
            ResolvedConversionType::External { identity },
        ) if java_wrapper_for(identity) == Some(*source) => ConversionKind::JavaBoxing,
        (
            ResolvedConversionType::External { identity },
            ResolvedConversionType::JavaPrimitive(target),
        ) if java_wrapper_for(identity) == Some(*target) => ConversionKind::JavaUnboxing,
        (
            ResolvedConversionType::Declaration(source),
            ResolvedConversionType::Declaration(target),
        ) if source == target => ConversionKind::JavaIdentity,
        (
            ResolvedConversionType::External { identity: source },
            ResolvedConversionType::External { identity: target },
        ) if source == target => ConversionKind::JavaIdentity,
        _ => return Err(ConversionUnknown::UnsupportedConversion),
    };
    Ok(ArgumentTypeConversion {
        hierarchy: None,
        source,
        target,
        kind,
    })
}

fn external_identity(
    java: &JavaAnalyzer,
    packs: Option<&crate::analyzer::semantic_model::SemanticModelOverlay>,
    external: &JvmExternalType,
) -> Option<ExternalConversionIdentity> {
    let external_surface_identity = java
        .external_declaration_index()
        .dispatch_behavior_identity();
    let active_model_set_identity =
        packs.map(|overlay| StableDigest::sha256(overlay.active_model_set_hash().as_bytes()));
    let provenance = match external.source() {
        JvmExternalDeclarationSource::SourceJar {
            artifact_path,
            source_path,
        } => ExternalConversionProvenance::SourceJar {
            artifact_path: artifact_path.clone(),
            source_path: source_path.clone(),
        },
        JvmExternalDeclarationSource::ClassFile {
            artifact_path,
            class_entry,
        } => ExternalConversionProvenance::ClassFile {
            artifact_path: artifact_path.clone(),
            class_entry: class_entry.clone(),
        },
        JvmExternalDeclarationSource::SemanticPack {
            pack_id,
            declaration_id,
        } => ExternalConversionProvenance::SemanticPack {
            pack_id: pack_id.clone(),
            declaration_id: declaration_id.clone(),
        },
    };
    ExternalConversionIdentity::from_provenance(
        external.fqn(),
        provenance,
        external.kind() == JvmExternalTypeKind::Class,
        external_surface_identity,
        active_model_set_identity,
    )
}

fn workspace_declaration_is_generic(java: &JavaAnalyzer, unit: &CodeUnit) -> bool {
    let mut owner = Some(unit.clone());
    while let Some(unit) = owner {
        if java.signature_metadata(&unit).iter().any(|metadata| {
            metadata.type_parameters_recorded() && !metadata.type_parameters().is_empty()
        }) {
            return true;
        }
        owner = java.parent_of(&unit);
    }
    false
}

fn workspace_type_identity(
    java: &JavaAnalyzer,
    unit: CodeUnit,
) -> Result<ResolvedConversionType, TypeResolutionFailure> {
    // The receiver resolver can return one nested declaration from a
    // best-effort lookup. Conversion proof requires a unique declaration,
    // including when duplicate declarations share one indexed identity.
    let candidates: Vec<_> = java
        .get_definitions(&unit.fq_name())
        .into_iter()
        .filter(|candidate| candidate.is_class() && candidate.fq_name() == unit.fq_name())
        .collect();
    if candidates.as_slice() != std::slice::from_ref(&unit) || java.ranges_of(&unit).len() != 1 {
        return Err(TypeResolutionFailure::AmbiguousBinding);
    }
    if workspace_declaration_is_generic(java, &unit) {
        return Err(TypeResolutionFailure::GenericSubstitution);
    }
    Ok(ResolvedConversionType::Declaration(unit))
}

pub(crate) fn declaration_declares_array(declaration: Node<'_>, type_node: Node<'_>) -> bool {
    if declaration.kind() == "spread_parameter" {
        return true;
    }
    let mut type_stack = vec![type_node];
    while let Some(node) = type_stack.pop() {
        if matches!(node.kind(), "array_type" | "dimensions") {
            return true;
        }
        let mut cursor = node.walk();
        type_stack.extend(node.named_children(&mut cursor));
    }

    let mut current = Some(declaration);
    while let Some(node) = current {
        if node.child_by_field_name("dimensions").is_some() {
            return true;
        }
        if matches!(
            node.kind(),
            "local_variable_declaration"
                | "field_declaration"
                | "constant_declaration"
                | "formal_parameter"
                | "receiver_parameter"
                | "catch_formal_parameter"
                | "resource"
                | "enhanced_for_statement"
                | "type_pattern"
        ) {
            break;
        }
        current = node.parent();
    }
    false
}

fn primitive_widens(source: JavaPrimitive, target: JavaPrimitive) -> bool {
    match source {
        JavaPrimitive::Byte => matches!(
            target,
            JavaPrimitive::Short
                | JavaPrimitive::Int
                | JavaPrimitive::Long
                | JavaPrimitive::Float
                | JavaPrimitive::Double
        ),
        JavaPrimitive::Short => matches!(
            target,
            JavaPrimitive::Int | JavaPrimitive::Long | JavaPrimitive::Float | JavaPrimitive::Double
        ),
        JavaPrimitive::Char => matches!(
            target,
            JavaPrimitive::Int | JavaPrimitive::Long | JavaPrimitive::Float | JavaPrimitive::Double
        ),
        JavaPrimitive::Int => matches!(
            target,
            JavaPrimitive::Long | JavaPrimitive::Float | JavaPrimitive::Double
        ),
        JavaPrimitive::Long => matches!(target, JavaPrimitive::Float | JavaPrimitive::Double),
        JavaPrimitive::Float => target == JavaPrimitive::Double,
        JavaPrimitive::Boolean | JavaPrimitive::Double => false,
    }
}

fn wrapper_for(identity: &str) -> Option<JavaPrimitive> {
    match identity {
        "java.lang.Boolean" => Some(JavaPrimitive::Boolean),
        "java.lang.Byte" => Some(JavaPrimitive::Byte),
        "java.lang.Short" => Some(JavaPrimitive::Short),
        "java.lang.Character" => Some(JavaPrimitive::Char),
        "java.lang.Integer" => Some(JavaPrimitive::Int),
        "java.lang.Long" => Some(JavaPrimitive::Long),
        "java.lang.Float" => Some(JavaPrimitive::Float),
        "java.lang.Double" => Some(JavaPrimitive::Double),
        _ => None,
    }
}

fn java_wrapper_for(identity: &ExternalConversionIdentity) -> Option<JavaPrimitive> {
    identity
        .declaration_is_class()
        .then(|| wrapper_for(identity.fqn()))
        .flatten()
}

fn primitive_literal(node: Node<'_>) -> Option<JavaPrimitive> {
    match node.kind() {
        "true" | "false" | "boolean_literal" => Some(JavaPrimitive::Boolean),
        "character_literal" => Some(JavaPrimitive::Char),
        _ => None,
    }
}

/// The static type of one numeric literal token (JLS 3.10.1, 3.10.2), fixed by
/// its kind and the type suffix that is part of the token.
fn numeric_literal_type(node: Node<'_>, source: &str) -> Option<JavaPrimitive> {
    let suffix = || source.get(node.byte_range())?.chars().next_back();
    match node.kind() {
        "decimal_integer_literal"
        | "hex_integer_literal"
        | "octal_integer_literal"
        | "binary_integer_literal" => Some(if matches!(suffix()?, 'l' | 'L') {
            JavaPrimitive::Long
        } else {
            JavaPrimitive::Int
        }),
        "decimal_floating_point_literal" | "hex_floating_point_literal" => {
            Some(if matches!(suffix()?, 'f' | 'F') {
                JavaPrimitive::Float
            } else {
                JavaPrimitive::Double
            })
        }
        _ => None,
    }
}

fn primitive_type(node: Node<'_>) -> Option<JavaPrimitive> {
    let direct = match node.kind() {
        "boolean" | "boolean_type" => Some(JavaPrimitive::Boolean),
        "byte" | "byte_type" => Some(JavaPrimitive::Byte),
        "short" | "short_type" => Some(JavaPrimitive::Short),
        "char" | "char_type" => Some(JavaPrimitive::Char),
        "int" | "int_type" => Some(JavaPrimitive::Int),
        "long" | "long_type" => Some(JavaPrimitive::Long),
        "float" | "float_type" => Some(JavaPrimitive::Float),
        "double" | "double_type" => Some(JavaPrimitive::Double),
        _ => None,
    };
    if direct.is_some() {
        return direct;
    }

    let mut cursor = node.walk();
    node.children(&mut cursor)
        .find_map(|child| match child.kind() {
            "boolean" => Some(JavaPrimitive::Boolean),
            "byte" => Some(JavaPrimitive::Byte),
            "short" => Some(JavaPrimitive::Short),
            "char" => Some(JavaPrimitive::Char),
            "int" => Some(JavaPrimitive::Int),
            "long" => Some(JavaPrimitive::Long),
            "float" => Some(JavaPrimitive::Float),
            "double" => Some(JavaPrimitive::Double),
            _ => None,
        })
}

fn has_generic_shape(node: Node<'_>) -> bool {
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        if matches!(
            current.kind(),
            "generic_type" | "type_arguments" | "wildcard" | "type_parameter"
        ) {
            return true;
        }
        let mut cursor = current.walk();
        stack.extend(current.named_children(&mut cursor));
    }
    false
}

pub(crate) fn declared_type_node(node: Node<'_>) -> Option<Node<'_>> {
    let mut current = node;
    loop {
        if let Some(type_node) = current.child_by_field_name("type") {
            return Some(type_node);
        }
        let parent = current.parent()?;
        if !matches!(
            parent.kind(),
            "local_variable_declaration"
                | "field_declaration"
                | "constant_declaration"
                | "formal_parameter"
                | "receiver_parameter"
                | "catch_formal_parameter"
                | "resource"
                | "enhanced_for_statement"
                | "type_pattern"
        ) {
            return None;
        }
        current = parent;
    }
}

fn root_of(node: Node<'_>) -> Node<'_> {
    let mut root = node;
    while let Some(parent) = root.parent() {
        root = parent;
    }
    root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_assignment_identity_requires_exact_reference_types_and_binding() {
        let source = "class App { void run(App input) { App value = input; App alias = value; alias = value; } }";
        let project = crate::inline_project::InlineTestProject::with_language(Language::Java)
            .file("App.java", source)
            .build();
        let analyzer = JavaAnalyzer::from_project(project.project().clone());
        let prover =
            JavaLocalAssignmentConversionProver::new(&analyzer, &project.file("App.java"), source)
                .unwrap();
        let range = |text: &str| {
            let start = source.find(text).unwrap();
            crate::analyzer::Range {
                start_byte: start,
                end_byte: start + text.len(),
                start_line: 1,
                end_line: 1,
            }
        };
        let declaration = range("alias = value");
        let target = crate::analyzer::Range {
            end_byte: declaration.start_byte + "alias".len(),
            ..declaration
        };
        let proof = prover.prove(declaration, target).expect("exact local copy");
        assert!(proof.preserves_reference_identity(), "{proof:?}");
        let start = source.rfind("alias = value").unwrap();
        let reassignment = crate::analyzer::Range {
            start_byte: start,
            end_byte: start + "alias = value".len(),
            start_line: 1,
            end_line: 1,
        };
        assert!(
            prover
                .prove(reassignment, target)
                .expect("same local target")
                .preserves_reference_identity()
        );
        let wrong = range("value = input");
        assert!(matches!(
            prover.prove(declaration, wrong),
            Err(ConversionUnknown::AmbiguousBinding)
        ));
    }

    #[test]
    fn local_assignment_primitive_identity_is_not_reference_identity() {
        let source = "class App { void run(int input) { int value = input; int alias = value; } }";
        let project = crate::inline_project::InlineTestProject::with_language(Language::Java)
            .file("App.java", source)
            .build();
        let analyzer = JavaAnalyzer::from_project(project.project().clone());
        let prover =
            JavaLocalAssignmentConversionProver::new(&analyzer, &project.file("App.java"), source)
                .unwrap();
        let start = source.find("alias = value").unwrap();
        let write = crate::analyzer::Range {
            start_byte: start,
            end_byte: start + "alias = value".len(),
            start_line: 1,
            end_line: 1,
        };
        let target = crate::analyzer::Range {
            end_byte: start + "alias".len(),
            ..write
        };
        let proof = prover
            .prove(write, target)
            .expect("primitive conversion is classified");
        assert_eq!(proof.conversion.kind, ConversionKind::JavaIdentity);
        assert!(!proof.preserves_reference_identity(), "{proof:?}");
    }

    #[test]
    fn local_assignment_unknown_cast_generic_and_field_write_remain_open() {
        for (source, written) in [
            (
                "class App { void run(App input) { App value = (App) input; } }",
                "value = (App) input",
            ),
            (
                "class App<T> { void run(T input) { T value = input; } }",
                "value = input",
            ),
            (
                "class App { App field; void run(App input) { field = input; } }",
                "field = input",
            ),
        ] {
            let project = crate::inline_project::InlineTestProject::with_language(Language::Java)
                .file("App.java", source)
                .build();
            let analyzer = JavaAnalyzer::from_project(project.project().clone());
            let prover = JavaLocalAssignmentConversionProver::new(
                &analyzer,
                &project.file("App.java"),
                source,
            )
            .unwrap();
            let start = source.find(written).unwrap();
            let write = crate::analyzer::Range {
                start_byte: start,
                end_byte: start + written.len(),
                start_line: 1,
                end_line: 1,
            };
            let name_len = 5;
            let target = crate::analyzer::Range {
                end_byte: start + name_len,
                ..write
            };
            assert!(
                prover.prove(write, target).is_err(),
                "unsupported shape: {source}"
            );
        }
    }

    #[test]
    fn local_assignment_rejects_a_stale_source_snapshot() {
        let source = "class App { void run(App input) { App value = input; } }";
        let project = crate::inline_project::InlineTestProject::with_language(Language::Java)
            .file("App.java", source)
            .build();
        let analyzer = JavaAnalyzer::from_project(project.project().clone());
        let changed = source.replace("App value", "Object value");
        assert!(matches!(
            JavaLocalAssignmentConversionProver::new(
                &analyzer,
                &project.file("App.java"),
                &changed
            ),
            Err(ConversionUnknown::UnresolvedSourceType)
        ));
    }

    #[test]
    fn local_assignment_call_result_retains_selected_declared_type() {
        let source =
            "class App { static native App acquire(); void run() { App value = acquire(); } }";
        let project = crate::inline_project::InlineTestProject::with_language(Language::Java)
            .file("App.java", source)
            .build();
        let analyzer = JavaAnalyzer::from_project(project.project().clone());
        let prover =
            JavaLocalAssignmentConversionProver::new(&analyzer, &project.file("App.java"), source)
                .unwrap();
        let start = source.find("value = acquire()").unwrap();
        let write = crate::analyzer::Range {
            start_byte: start,
            end_byte: start + "value = acquire()".len(),
            start_line: 1,
            end_line: 1,
        };
        let target = crate::analyzer::Range {
            end_byte: start + "value".len(),
            ..write
        };
        assert!(
            prover
                .prove(write, target)
                .expect("selected static return type")
                .preserves_reference_identity()
        );
    }

    #[test]
    fn local_assignment_source_call_with_unproven_arguments_stays_unknown() {
        let source = "class App { static native App acquire(App input); void run(App input) { App value = acquire(input); } }";
        let project = crate::inline_project::InlineTestProject::with_language(Language::Java)
            .file("App.java", source)
            .build();
        let analyzer = JavaAnalyzer::from_project(project.project().clone());
        let prover =
            JavaLocalAssignmentConversionProver::new(&analyzer, &project.file("App.java"), source)
                .unwrap();
        let start = source.find("value = acquire(input)").unwrap();
        let write = crate::analyzer::Range {
            start_byte: start,
            end_byte: start + "value = acquire(input)".len(),
            start_line: 1,
            end_line: 1,
        };
        let target = crate::analyzer::Range {
            end_byte: start + "value".len(),
            ..write
        };
        assert!(
            prover.prove(write, target).is_err(),
            "a selected return declaration alone does not prove argument applicability"
        );
    }

    #[test]
    fn local_assignment_boxing_certificate_never_claims_reference_identity() {
        let primitive = ResolvedConversionType::JavaPrimitive(JavaPrimitive::Int);
        let wrapper = ResolvedConversionType::External {
            identity: external("java.lang.Integer", true),
        };
        for (source, target, expected) in [
            (
                primitive.clone(),
                wrapper.clone(),
                ConversionKind::JavaBoxing,
            ),
            (wrapper, primitive, ConversionKind::JavaUnboxing),
        ] {
            let conversion = classify_conversion(source, target).expect("exact wrapper conversion");
            assert_eq!(conversion.kind, expected);
            let range = crate::analyzer::Range {
                start_byte: 0,
                end_byte: 1,
                start_line: 1,
                end_line: 1,
            };
            let certificate = JavaLocalAssignmentEvidence {
                assignment: range,
                target_binding: range,
                source_range: range,
                source_digest: StableDigest::sha256(b"test"),
                conversion,
            };
            assert!(
                !certificate.preserves_reference_identity(),
                "{certificate:?}"
            );
        }
    }

    #[test]
    fn local_assignment_captured_target_is_not_procedure_local() {
        let source = "class App { void run(App input) { App value = input; Runnable later = () -> { value = input; }; } }";
        let project = crate::inline_project::InlineTestProject::with_language(Language::Java)
            .file("App.java", source)
            .build();
        let analyzer = JavaAnalyzer::from_project(project.project().clone());
        let prover =
            JavaLocalAssignmentConversionProver::new(&analyzer, &project.file("App.java"), source)
                .unwrap();
        let first = source.find("value = input").unwrap();
        let last = source.rfind("value = input").unwrap();
        let write = crate::analyzer::Range {
            start_byte: last,
            end_byte: last + "value = input".len(),
            start_line: 1,
            end_line: 1,
        };
        let target = crate::analyzer::Range {
            start_byte: first,
            end_byte: first + "value".len(),
            start_line: 1,
            end_line: 1,
        };
        assert!(matches!(
            prover.prove(write, target),
            Err(ConversionUnknown::UnsupportedExpression)
        ));
    }

    #[test]
    fn local_assignment_captured_source_needs_capture_evidence() {
        let source =
            "class App { void run(App input) { Runnable later = () -> { App value = input; }; } }";
        let project = crate::inline_project::InlineTestProject::with_language(Language::Java)
            .file("App.java", source)
            .build();
        let analyzer = JavaAnalyzer::from_project(project.project().clone());
        let prover =
            JavaLocalAssignmentConversionProver::new(&analyzer, &project.file("App.java"), source)
                .unwrap();
        let start = source.find("value = input").unwrap();
        let write = crate::analyzer::Range {
            start_byte: start,
            end_byte: start + "value = input".len(),
            start_line: 1,
            end_line: 1,
        };
        let target = crate::analyzer::Range {
            end_byte: start + "value".len(),
            ..write
        };
        assert!(matches!(
            prover.prove(write, target),
            Err(ConversionUnknown::UnsupportedExpression)
        ));
    }

    fn parse_java(source: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_java::LANGUAGE.into())
            .expect("java grammar loads");
        parser.parse(source, None).expect("java source parses")
    }

    fn first_kind<'tree>(root: tree_sitter::Node<'tree>, kind: &str) -> tree_sitter::Node<'tree> {
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            if node.kind() == kind {
                return node;
            }
            let mut cursor = node.walk();
            stack.extend(node.named_children(&mut cursor));
        }
        panic!("no {kind} node in test source");
    }

    fn external(fqn: &str, declaration_is_class: bool) -> ExternalConversionIdentity {
        ExternalConversionIdentity::from_provenance(
            fqn,
            ExternalConversionProvenance::SemanticPack {
                pack_id: "test-pack".to_owned(),
                declaration_id: fqn.to_owned(),
            },
            declaration_is_class,
            StableDigest::sha256(b"test-surface"),
            Some(StableDigest::sha256(b"test-models")),
        )
        .expect("semantic-pack identities require active model evidence")
    }

    #[test]
    fn wrapper_interpretation_requires_resolver_class_evidence() {
        assert_eq!(
            java_wrapper_for(&external("java.lang.Integer", true)),
            Some(JavaPrimitive::Int)
        );
        assert_eq!(
            java_wrapper_for(&external("java.lang.Integer", false)),
            None,
            "a matching name without class evidence is not a wrapper"
        );
        assert_eq!(
            java_wrapper_for(&external("example.Integer", true)),
            None,
            "a user type with a similar short name is not a wrapper"
        );
    }

    #[test]
    fn semantic_pack_identity_requires_active_model_set() {
        assert!(
            ExternalConversionIdentity::from_provenance(
                "java.lang.Integer",
                ExternalConversionProvenance::SemanticPack {
                    pack_id: "test-pack".to_owned(),
                    declaration_id: "integer".to_owned(),
                },
                true,
                StableDigest::sha256(b"test-surface"),
                None,
            )
            .is_none()
        );
    }

    #[test]
    fn lexical_array_shapes_are_read_structurally() {
        let tree = parse_java("class A { void f(String[] args) {} }");
        let root = tree.root_node();
        let formal = first_kind(root, "formal_parameter");
        let type_node = declared_type_node(formal).expect("formal declares a type");
        let (element, dimensions) =
            declared_java_type_shape(formal, type_node).expect("array shape resolves");
        assert_eq!(element.kind(), "type_identifier");
        assert_eq!(dimensions, 1);
    }

    #[test]
    fn c_style_declarator_dimensions_are_structural() {
        let tree = parse_java("class A { void f(String args[]) {} }");
        let root = tree.root_node();
        let formal = first_kind(root, "formal_parameter");
        let type_node = declared_type_node(formal).expect("formal declares a type");
        let (element, dimensions) =
            declared_java_type_shape(formal, type_node).expect("array shape resolves");
        assert_eq!(element.kind(), "type_identifier");
        assert_eq!(dimensions, 1);
    }

    #[test]
    fn nested_array_dimensions_count_each_axis() {
        let tree = parse_java("class A { void m() { String[][] grid = null; } }");
        let root = tree.root_node();
        let declarator = first_kind(root, "variable_declarator");
        let type_node = declared_type_node(declarator).expect("declarator declares a type");
        let (element, dimensions) =
            declared_java_type_shape(declarator, type_node).expect("array shape resolves");
        assert_eq!(element.kind(), "type_identifier");
        assert_eq!(dimensions, 2);
    }

    #[test]
    fn non_array_declarations_have_zero_dimensions() {
        let tree = parse_java("class A { void f(String command) {} }");
        let root = tree.root_node();
        let formal = first_kind(root, "formal_parameter");
        let type_node = declared_type_node(formal).expect("formal declares a type");
        let (element, dimensions) =
            declared_java_type_shape(formal, type_node).expect("shape resolves");
        assert_eq!(element.kind(), "type_identifier");
        assert_eq!(dimensions, 0);
    }

    #[test]
    fn spread_parameters_stay_typed_unsupported() {
        let tree = parse_java("class A { void f(String... args) {} }");
        let root = tree.root_node();
        let spread = first_kind(root, "spread_parameter");
        // A spread_parameter carries no `type` field; its first named child
        // is the element type.
        let type_node = spread.named_child(0).expect("spread declares a type");
        let error = declared_java_type_shape(spread, type_node)
            .expect_err("spread parameters stay unsupported");
        assert_eq!(error, ConversionUnknown::UnsupportedConversion);
    }

    #[test]
    fn array_java_type_wraps_one_layer_per_dimension() {
        let element = ResolvedConversionType::External {
            identity: external("java.lang.String", true),
        };
        let shape = array_java_type(element.clone(), 2);
        assert_eq!(
            shape,
            JavaConversionType::Array(Box::new(JavaConversionType::Array(Box::new(
                JavaConversionType::Value(element.clone())
            ))))
        );
        assert_eq!(
            array_java_type(element.clone(), 0),
            JavaConversionType::Value(element)
        );
    }

    #[test]
    fn identical_array_shapes_prove_element_identity() {
        let string = ResolvedConversionType::External {
            identity: external("java.lang.String", true),
        };
        let array = JavaConversionType::Array(Box::new(JavaConversionType::Value(string.clone())));
        let conversion =
            classify_java_conversion(array.clone(), array).expect("identical arrays convert");
        assert_eq!(conversion.kind, ConversionKind::JavaIdentity);
        assert_eq!(conversion.source, string);
        assert_eq!(conversion.target, string);
    }

    #[test]
    fn array_actual_rejects_non_array_model_formal() {
        let string = ResolvedConversionType::External {
            identity: external("java.lang.String", true),
        };
        let array = JavaConversionType::Array(Box::new(JavaConversionType::Value(string.clone())));
        let value = JavaConversionType::Value(string);
        let error = classify_java_conversion(array, value)
            .expect_err("an array actual never applies to a non-array formal");
        assert_eq!(error, ConversionUnknown::UnsupportedConversion);
    }

    #[test]
    fn array_shape_mismatch_is_typed_unsupported() {
        let string = ResolvedConversionType::External {
            identity: external("java.lang.String", true),
        };
        let one_dimension =
            JavaConversionType::Array(Box::new(JavaConversionType::Value(string.clone())));
        let two_dimensions = JavaConversionType::Array(Box::new(one_dimension.clone()));
        let error = classify_java_conversion(two_dimensions, one_dimension)
            .expect_err("shape mismatches never fall back to element compatibility");
        assert_eq!(error, ConversionUnknown::UnsupportedConversion);
    }

    #[test]
    fn value_widening_survives_the_java_type_layer() {
        let conversion = classify_java_conversion(
            JavaConversionType::Value(ResolvedConversionType::JavaPrimitive(JavaPrimitive::Int)),
            JavaConversionType::Value(ResolvedConversionType::JavaPrimitive(JavaPrimitive::Long)),
        )
        .expect("int to long widens");
        assert_eq!(conversion.kind, ConversionKind::JavaPrimitiveWidening);
    }

    #[test]
    fn array_elements_do_not_borrow_scalar_primitive_widening() {
        let int_array =
            array_java_type(ResolvedConversionType::JavaPrimitive(JavaPrimitive::Int), 1);
        let long_array = array_java_type(
            ResolvedConversionType::JavaPrimitive(JavaPrimitive::Long),
            1,
        );
        assert_eq!(
            classify_java_conversion(int_array, long_array),
            Err(ConversionUnknown::UnsupportedConversion)
        );
    }
}
