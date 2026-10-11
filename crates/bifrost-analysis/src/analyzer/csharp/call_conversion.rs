use crate::analyzer::lexical_definitions::formal_parameter_slots_for_owner_with_nodes;
use crate::analyzer::semantic_model::TypeRef;
use crate::analyzer::usages::call_conversion::{
    ArgumentTypeConversion, CSharpPrimitive, CallArgumentConversionProver, ConversionKind,
    ConversionUnknown, ResolvedConversionType,
};
use crate::analyzer::{IAnalyzer, Language, ProjectFile};
use tree_sitter::Node;

pub(crate) static CALL_ARGUMENT_CONVERSION_PROVER: CSharpCallArgumentConversionProver =
    CSharpCallArgumentConversionProver;

pub(crate) struct CSharpCallArgumentConversionProver;

impl CallArgumentConversionProver for CSharpCallArgumentConversionProver {
    fn prove_argument(
        &self,
        _analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        actual: Node<'_>,
        source: &str,
        formal_file: &ProjectFile,
        formal: Node<'_>,
        formal_source: &str,
    ) -> Result<ArgumentTypeConversion, ConversionUnknown> {
        if file.language() != Language::CSharp || formal_file.language() != Language::CSharp {
            return Err(ConversionUnknown::UnsupportedLanguage);
        }
        let source_type = actual_type(actual, source)?;
        let formal_type = formal
            .child_by_field_name("type")
            .ok_or(ConversionUnknown::UnresolvedSignature)
            .and_then(|node| type_node(node, formal_source))?;
        classify(source_type, formal_type)
    }

    fn prove_model_argument(
        &self,
        _analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        actual: Node<'_>,
        source: &str,
        formal_type: &TypeRef,
    ) -> Result<ArgumentTypeConversion, ConversionUnknown> {
        if file.language() != Language::CSharp {
            return Err(ConversionUnknown::UnsupportedLanguage);
        }
        let source_type = actual_type(actual, source)?;
        let formal_type = model_type(formal_type)?;
        classify(source_type, formal_type)
    }
}

fn classify(
    source: CSharpPrimitive,
    target: CSharpPrimitive,
) -> Result<ArgumentTypeConversion, ConversionUnknown> {
    let kind = if source == target {
        ConversionKind::CSharpIdentity
    } else if source == CSharpPrimitive::Char && target == CSharpPrimitive::Int32 {
        ConversionKind::CSharpImplicitNumeric
    } else {
        return Err(ConversionUnknown::UnsupportedConversion);
    };
    Ok(ArgumentTypeConversion {
        source: ResolvedConversionType::CSharpPrimitive(source),
        target: ResolvedConversionType::CSharpPrimitive(target),
        kind,
        hierarchy: None,
    })
}

fn model_type(reference: &TypeRef) -> Result<CSharpPrimitive, ConversionUnknown> {
    let TypeRef::Named {
        name,
        arguments,
        nullable,
    } = reference
    else {
        return Err(ConversionUnknown::UnsupportedConversion);
    };
    if *nullable || !arguments.is_empty() {
        return Err(ConversionUnknown::UnsupportedConversion);
    }
    primitive_name(name).ok_or(ConversionUnknown::UnsupportedConversion)
}

fn type_node(node: Node<'_>, source: &str) -> Result<CSharpPrimitive, ConversionUnknown> {
    let spelling = source
        .get(node.byte_range())
        .ok_or(ConversionUnknown::UnresolvedTargetType)?;
    primitive_name(spelling).ok_or(ConversionUnknown::UnsupportedConversion)
}

fn primitive_name(name: &str) -> Option<CSharpPrimitive> {
    Some(match name {
        "char" | "System.Char" => CSharpPrimitive::Char,
        "int" | "System.Int32" => CSharpPrimitive::Int32,
        "string" | "System.String" => CSharpPrimitive::String,
        _ => return None,
    })
}

fn actual_type(node: Node<'_>, source: &str) -> Result<CSharpPrimitive, ConversionUnknown> {
    match node.kind() {
        "character_literal" => Ok(CSharpPrimitive::Char),
        "integer_literal" => Ok(CSharpPrimitive::Int32),
        "string_literal"
        | "verbatim_string_literal"
        | "raw_string_literal"
        | "interpolated_string_expression" => Ok(CSharpPrimitive::String),
        "identifier" => parameter_type(node, source),
        _ => Err(ConversionUnknown::UnsupportedExpression),
    }
}

fn parameter_type(node: Node<'_>, source: &str) -> Result<CSharpPrimitive, ConversionUnknown> {
    let name = source
        .get(node.byte_range())
        .ok_or(ConversionUnknown::UnresolvedSourceType)?;
    let mut owner = node.parent();
    while let Some(candidate) = owner {
        if let Some(parameters) =
            formal_parameter_slots_for_owner_with_nodes(Language::CSharp, candidate, source)
        {
            for (slot, declaration) in parameters {
                if slot.names.iter().any(|parameter| parameter == name) {
                    let declared_type = declaration
                        .child_by_field_name("type")
                        .ok_or(ConversionUnknown::UnresolvedSourceType)?;
                    return type_node(declared_type, source);
                }
            }
        }
        owner = candidate.parent();
    }
    Err(ConversionUnknown::UnresolvedSourceType)
}
