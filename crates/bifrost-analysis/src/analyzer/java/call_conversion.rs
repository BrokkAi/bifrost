use crate::analyzer::java::JavaAnalyzer;
use crate::analyzer::java::imports::JavaTypeResolution;
use crate::analyzer::jvm::external::{
    JvmExternalDeclarationSource, JvmExternalType, JvmExternalTypeKind,
};
use crate::analyzer::lexical_definitions::{LexicalBindingResolution, resolve_lexical_binding};
use crate::analyzer::multi_analyzer::resolve_analyzer;
use crate::analyzer::semantic::StableDigest;
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
    let packs = analyzer
        .active_query_semantic_model_overlay()
        .and_then(|overlay| overlay);

    let target = resolve_formal_type(
        java,
        token,
        packs.clone(),
        formal_file,
        formal,
        formal_source,
    )?;
    let source_type = resolve_actual_type(java, token, packs, file, actual, source)?;

    classify_conversion(source_type, target)
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
) -> Result<ResolvedConversionType, ConversionUnknown> {
    let mut expression = actual;
    while expression.kind() == "parenthesized_expression" {
        expression = expression
            .named_child(0)
            .ok_or(ConversionUnknown::UnsupportedExpression)?;
    }

    if let Some(primitive) = primitive_literal(expression) {
        return Ok(ResolvedConversionType::JavaPrimitive(primitive));
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
        ),
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
) -> Result<ResolvedConversionType, ConversionUnknown> {
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
    if declaration_declares_array(declaration, type_node) {
        return Err(ConversionUnknown::UnsupportedConversion);
    }
    resolve_type_node(java, token, packs, file, type_node, source)
        .map_err(TypeResolutionFailure::source)
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
}
