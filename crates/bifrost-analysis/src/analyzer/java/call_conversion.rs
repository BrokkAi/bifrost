use crate::analyzer::java::JavaAnalyzer;
use crate::analyzer::java::imports::JavaTypeResolution;
use crate::analyzer::jvm::external::{
    JvmExternalDeclarationSource, JvmExternalType, JvmExternalTypeKind,
};
use crate::analyzer::lexical_definitions::{LexicalBindingResolution, resolve_lexical_binding};
use crate::analyzer::multi_analyzer::resolve_analyzer;
use crate::analyzer::semantic::StableDigest;
use crate::analyzer::semantic_model::TypeRef;
use crate::analyzer::usages::call_conversion::{
    ArgumentTypeConversion, CallArgumentConversionProver, ConversionKind, ConversionUnknown,
    ExternalConversionIdentity, ExternalConversionProvenance, JavaPrimitive,
    ResolvedConversionType,
};
use crate::analyzer::usages::get_definition::BoundedResolution;
use crate::analyzer::usages::get_definition::java::{
    JavaResolutionSession, java_type_from_node_with_context,
};
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
}

impl TypeResolutionFailure {
    fn source(self) -> ConversionUnknown {
        match self {
            Self::Unresolved => ConversionUnknown::UnresolvedSourceType,
            Self::AmbiguousBinding => ConversionUnknown::AmbiguousBinding,
            Self::GenericSubstitution => ConversionUnknown::GenericSubstitution,
            Self::UnsupportedConversion => ConversionUnknown::UnsupportedConversion,
        }
    }

    fn target(self) -> ConversionUnknown {
        match self {
            Self::Unresolved => ConversionUnknown::UnresolvedTargetType,
            Self::AmbiguousBinding => ConversionUnknown::AmbiguousBinding,
            Self::GenericSubstitution => ConversionUnknown::GenericSubstitution,
            Self::UnsupportedConversion => ConversionUnknown::UnsupportedConversion,
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
    let source_type = resolve_actual_type(java, token, packs, file, actual, source)?;

    classify_java_conversion(source_type, JavaConversionType::Value(target))
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
        let target = resolve_model_type_ref(java, token, packs, file, formal_type)?;
        classify_java_conversion(source_type, target)
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
        // A constructor expression also requires proving the selected
        // constructor is applicable. The initial bounded adapter does not
        // attempt that proof from the type node alone.
        "object_creation_expression" => Err(ConversionUnknown::UnsupportedExpression),
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
    let session =
        JavaResolutionSession::bounded(&definitions, ReceiverAnalysisBudget::default(), None);
    let resolved =
        java_type_from_node_with_context(java, token, java, &session, file, source, type_node);
    match session.finish(resolved) {
        BoundedResolution::Complete {
            value: Some(unit), ..
        } => return workspace_type_identity(java, unit),
        BoundedResolution::Complete { value: None, .. } => {}
        _ => return Err(TypeResolutionFailure::Unresolved),
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

fn model_primitive_type(name: &str) -> Option<JavaPrimitive> {
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
/// arrays recurse structurally to their element terms.
fn resolve_model_type_ref(
    java: &JavaAnalyzer,
    token: crate::analyzer::QueryToken<'_>,
    packs: Option<std::sync::Arc<crate::analyzer::semantic_model::SemanticModelOverlay>>,
    file: &ProjectFile,
    type_ref: &TypeRef,
) -> Result<JavaConversionType, ConversionUnknown> {
    match type_ref {
        TypeRef::Array { element } => Ok(JavaConversionType::Array(Box::new(
            resolve_model_type_ref(java, token, packs, file, element)?,
        ))),
        TypeRef::Named {
            name,
            arguments,
            nullable: _,
        } => resolve_model_named_type(java, token, packs, file, name, arguments),
        // Declared, type-parameter, reference, slice, fixed-length, map,
        // channel and wildcard terms stay typed unsupported for this Java
        // adapter rather than falling back to any element interpretation.
        _ => Err(ConversionUnknown::UnsupportedConversion),
    }
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
    if let Some(primitive) = model_primitive_type(name) {
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
fn classify_java_conversion(
    source: JavaConversionType,
    target: JavaConversionType,
) -> Result<ArgumentTypeConversion, ConversionUnknown> {
    match (source, target) {
        (JavaConversionType::Array(source_element), JavaConversionType::Array(target_element)) => {
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

fn declaration_declares_array(declaration: Node<'_>, type_node: Node<'_>) -> bool {
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

fn declared_type_node(node: Node<'_>) -> Option<Node<'_>> {
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
}
