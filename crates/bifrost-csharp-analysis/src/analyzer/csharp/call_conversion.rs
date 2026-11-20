use brokk_bifrost_analysis::analyzer::lexical_definitions::formal_parameter_slots_for_owner_with_nodes;
use brokk_bifrost_analysis::analyzer::semantic_model::TypeRef;

use brokk_bifrost_analysis::analyzer::usages::call_conversion::ArgumentTypeConversion;

use brokk_bifrost_analysis::analyzer::usages::call_conversion::CSharpConversionType;

use brokk_bifrost_analysis::analyzer::usages::call_conversion::CSharpPrimitive;

use brokk_bifrost_analysis::analyzer::usages::call_conversion::CallArgumentConversionProver;

use brokk_bifrost_analysis::analyzer::usages::call_conversion::ConversionKind;

use brokk_bifrost_analysis::analyzer::usages::call_conversion::ConversionUnknown;

use brokk_bifrost_analysis::analyzer::usages::call_conversion::ModelArgumentApplicability;

use brokk_bifrost_analysis::analyzer::usages::call_conversion::ResolvedConversionType;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use brokk_bifrost_core::analyzer::model::Language;

use brokk_bifrost_core::analyzer::model::ProjectFile;
use tree_sitter::Node;

use crate::analyzer::usages::get_definition::csharp::{
    canonical_csharp_predefined_type, csharp_using_alias_definition,
};

pub(crate) static CALL_ARGUMENT_CONVERSION_PROVER: CSharpCallArgumentConversionProver =
    CSharpCallArgumentConversionProver;

pub(crate) struct CSharpCallArgumentConversionProver;

impl CallArgumentConversionProver for CSharpCallArgumentConversionProver {
    fn validate_owner(&self, owner: Node<'_>) -> Result<(), ConversionUnknown> {
        if let Some(parameters) =
            brokk_bifrost_csharp::declarations::csharp_parameter_list_node(owner)
                .filter(|parameters| parameters.kind() == "parameter_list")
        {
            let formals = brokk_bifrost_csharp::declarations::csharp_parameter_syntax(
                parameters,
                &mut || true,
            )
            .ok_or(ConversionUnknown::UnresolvedSignature)?;
            if formals.iter().any(|formal| {
                formal.params && formal.type_node.is_none_or(|ty| ty.kind() != "array_type")
            }) {
                // Collection params still have Rest input ports, but array
                // invocation/conversion proofs do not describe their construction.
                return Err(ConversionUnknown::UnsupportedConversion);
            }
        }
        Ok(())
    }

    fn prove_argument(
        &self,
        _analyzer: &dyn IAnalyzer,
        _sources: &brokk_bifrost_analysis::analyzer::usages::call_conversion::CallConversionContext<
            '_,
        >,
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
        let formal_type = brokk_bifrost_csharp::declarations::csharp_parameter_type_node(formal)
            .ok_or(ConversionUnknown::UnresolvedSignature)
            .and_then(|node| written_type(node, formal_source))?;
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

    fn model_argument_applicability(
        &self,
        _analyzer: &dyn IAnalyzer,
        file: &ProjectFile,
        actual: Node<'_>,
        source: &str,
        formal_type: &TypeRef,
    ) -> ModelArgumentApplicability {
        if file.language() != Language::CSharp {
            return ModelArgumentApplicability::Unknown(ConversionUnknown::UnsupportedLanguage);
        }
        // An anonymous function converts only to a delegate or expression-tree
        // type, or through its natural type to `System.Delegate` and its bases.
        // A built-in or array formal is none of those (#9981).
        let is_anonymous_function = matches!(
            actual.kind(),
            "lambda_expression" | "anonymous_method_expression"
        );
        if is_anonymous_function && is_builtin_or_array_formal(formal_type) {
            return ModelArgumentApplicability::Inapplicable;
        }
        let source_type = actual_type(actual, source);
        // Arrays declare no user-defined conversions and the three built-in
        // types declare none to or from an array, so a built-in actual never
        // reaches an array formal (#9981), nor an array actual a built-in
        // formal (#8296).
        match (&source_type, formal_type) {
            (Ok(CSharpConversionType::Primitive(_)), TypeRef::Array { .. }) => {
                return ModelArgumentApplicability::Inapplicable;
            }
            (Ok(CSharpConversionType::Array(_)), _)
                if matches!(
                    model_type(formal_type),
                    Ok(CSharpConversionType::Primitive(_))
                ) =>
            {
                return ModelArgumentApplicability::Inapplicable;
            }
            _ => {}
        }
        let source_type = match source_type {
            Ok(source_type) => source_type,
            Err(reason) => return ModelArgumentApplicability::Unknown(reason),
        };
        let formal_type = match model_type(formal_type) {
            Ok(formal_type) => formal_type,
            Err(reason) => return ModelArgumentApplicability::Unknown(reason),
        };
        // These three built-in types have identity conversion and only char ->
        // int numeric widening. Int constants do not implicitly convert to char;
        // user-defined conversions cannot connect two built-in types (#3811).
        if let (CSharpConversionType::Primitive(source), CSharpConversionType::Primitive(target)) =
            (&source_type, &formal_type)
            && builtin_conversion_kind(*source, *target).is_none()
        {
            return ModelArgumentApplicability::Inapplicable;
        }
        match classify(source_type, formal_type) {
            Ok(proof) => ModelArgumentApplicability::Applicable(Box::new(proof)),
            Err(reason) => ModelArgumentApplicability::Unknown(reason),
        }
    }

    fn select_model_invocation(
        &self,
        _analyzer: &dyn IAnalyzer,
        _file: &ProjectFile,
        actuals: &[Node<'_>],
        source: &str,
        signatures: &[brokk_bifrost_analysis::analyzer::semantic_model::Signature],
    ) -> Option<
        Result<
            brokk_bifrost_analysis::analyzer::usages::call_conversion::ModelInvocationSelection,
            ConversionUnknown,
        >,
    > {
        // C# chooses normal/expanded form per member, not by Java's whole-set
        // phases. This bounded hook certifies only a complete singleton family;
        // the shared selector retains ambiguous/expanded/unknown candidates.
        let [signature] = signatures else {
            return None;
        };
        let last = signature
            .parameters
            .last()
            .filter(|formal| formal.variadic)?;
        if !signature.type_parameters.is_empty()
            || signature
                .parameters
                .iter()
                .any(|formal| !formal.passing_mode.accepts_positional())
            || signature.parameters[..signature.parameters.len() - 1]
                .iter()
                .any(|formal| formal.variadic)
        {
            return None;
        }
        if !matches!(last.r#type, TypeRef::Array { .. }) {
            return None;
        }
        if signature.parameters.len() != actuals.len() {
            return None;
        }
        let types = signature
            .parameters
            .iter()
            .map(|formal| model_type(&formal.r#type))
            .collect::<Result<Vec<_>, _>>();
        let normal = types.and_then(|types| prove_normal_array(actuals, source, &types));
        match normal {
            Ok(()) => Some(Ok((
                0,
                signature
                    .parameters
                    .iter()
                    .map(|formal| formal.r#type.clone())
                    .collect(),
                Some(
                    brokk_bifrost_analysis::analyzer::semantic::call_binding::FixedArrayInvocation,
                ),
            ))),
            Err(_) => None,
        }
    }

    fn exact_match_is_best_member(&self) -> bool {
        true
    }
}

/// Identity for any two equal types and char -> int widening. Every other
/// pair, such as a reference conversion or a user-defined one, is unknown.
fn classify(
    source: CSharpConversionType,
    target: CSharpConversionType,
) -> Result<ArgumentTypeConversion, ConversionUnknown> {
    let kind = match (&source, &target) {
        _ if source == target => ConversionKind::CSharpIdentity,
        (CSharpConversionType::Primitive(source), CSharpConversionType::Primitive(target)) => {
            builtin_conversion_kind(*source, *target)
                .ok_or(ConversionUnknown::UnsupportedConversion)?
        }
        _ => return Err(ConversionUnknown::UnsupportedConversion),
    };
    Ok(ArgumentTypeConversion {
        source: resolved(source),
        target: resolved(target),
        kind,
        hierarchy: None,
    })
}

fn resolved(ty: CSharpConversionType) -> ResolvedConversionType {
    match ty {
        CSharpConversionType::Primitive(primitive) => {
            ResolvedConversionType::CSharpPrimitive(primitive)
        }
        other => ResolvedConversionType::CSharp(other),
    }
}

fn builtin_conversion_kind(
    source: CSharpPrimitive,
    target: CSharpPrimitive,
) -> Option<ConversionKind> {
    if source == target {
        Some(ConversionKind::CSharpIdentity)
    } else if source == CSharpPrimitive::Char && target == CSharpPrimitive::Int32 {
        Some(ConversionKind::CSharpImplicitNumeric)
    } else {
        None
    }
}

fn model_type(reference: &TypeRef) -> Result<CSharpConversionType, ConversionUnknown> {
    match reference {
        TypeRef::Named {
            name,
            arguments,
            nullable: false,
        } if arguments.is_empty() => Ok(named_type(name)),
        TypeRef::Array { element } if !matches!(element.as_ref(), TypeRef::Array { .. }) => {
            Ok(CSharpConversionType::Array(Box::new(model_type(element)?)))
        }
        _ => Err(ConversionUnknown::UnsupportedConversion),
    }
}

fn is_builtin_or_array_formal(reference: &TypeRef) -> bool {
    matches!(reference, TypeRef::Array { .. })
        || matches!(
            model_type(reference),
            Ok(CSharpConversionType::Primitive(_))
        )
}

/// The identity a predefined-type keyword or a qualified metadata name
/// spells.
fn named_type(name: &str) -> CSharpConversionType {
    let name = canonical_csharp_predefined_type(name).unwrap_or(name);
    match name {
        "System.Char" => CSharpConversionType::Primitive(CSharpPrimitive::Char),
        "System.Int32" => CSharpConversionType::Primitive(CSharpPrimitive::Int32),
        "System.String" => CSharpConversionType::Primitive(CSharpPrimitive::String),
        other => CSharpConversionType::Nominal(other.into()),
    }
}

/// The type a written type node denotes when its spelling alone fixes it: a
/// predefined-type keyword, a qualified name whose leftmost segment is not a
/// using alias, a `global::` name, or a single-dimensional array of one of
/// those. A simple name needs scope and using lookup, so it stays unknown.
/// A qualified name is read as fully qualified, as the external type ladder
/// reads it.
fn written_type(node: Node<'_>, source: &str) -> Result<CSharpConversionType, ConversionUnknown> {
    let text = |node: Node<'_>| {
        source
            .get(node.byte_range())
            .ok_or(ConversionUnknown::UnresolvedTargetType)
    };
    match node.kind() {
        "predefined_type" => canonical_csharp_predefined_type(text(node)?)
            .map(named_type)
            .ok_or(ConversionUnknown::UnsupportedConversion),
        "qualified_name" | "alias_qualified_name" => {
            let mut segments = Vec::new();
            let mut current = node;
            loop {
                let name = current
                    .child_by_field_name("name")
                    .filter(|name| name.kind() == "identifier")
                    .ok_or(ConversionUnknown::UnsupportedConversion)?;
                segments.push(text(name)?);
                match current.kind() {
                    "alias_qualified_name" => {
                        let alias = current
                            .child_by_field_name("alias")
                            .ok_or(ConversionUnknown::UnsupportedConversion)?;
                        if text(alias)? != "global" {
                            return Err(ConversionUnknown::UnsupportedConversion);
                        }
                        break;
                    }
                    _ => {
                        let qualifier = current
                            .child_by_field_name("qualifier")
                            .ok_or(ConversionUnknown::UnsupportedConversion)?;
                        match qualifier.kind() {
                            "qualified_name" | "alias_qualified_name" => current = qualifier,
                            "identifier" => {
                                let leftmost = text(qualifier)?;
                                let mut root = qualifier;
                                while let Some(parent) = root.parent() {
                                    root = parent;
                                }
                                if csharp_using_alias_definition(root, source, leftmost).is_some() {
                                    return Err(ConversionUnknown::UnsupportedConversion);
                                }
                                segments.push(leftmost);
                                break;
                            }
                            _ => return Err(ConversionUnknown::UnsupportedConversion),
                        }
                    }
                }
            }
            segments.reverse();
            Ok(named_type(&segments.join(".")))
        }
        "array_type" => {
            let rank = node
                .child_by_field_name("rank")
                .ok_or(ConversionUnknown::UnsupportedConversion)?;
            let mut cursor = rank.walk();
            let multidimensional = rank.children(&mut cursor).any(|child| child.kind() == ",");
            let element = node
                .child_by_field_name("type")
                .ok_or(ConversionUnknown::UnsupportedConversion)?;
            if multidimensional || element.kind() == "array_type" {
                return Err(ConversionUnknown::UnsupportedConversion);
            }
            Ok(CSharpConversionType::Array(Box::new(written_type(
                element, source,
            )?)))
        }
        _ => Err(ConversionUnknown::UnsupportedConversion),
    }
}

fn actual_type(node: Node<'_>, source: &str) -> Result<CSharpConversionType, ConversionUnknown> {
    if node.has_error() || node.is_missing() {
        return Err(ConversionUnknown::UnsupportedExpression);
    }
    match node.kind() {
        "character_literal" => Ok(CSharpConversionType::Primitive(CSharpPrimitive::Char)),
        "integer_literal" => integer_literal_type(
            node.utf8_text(source.as_bytes())
                .map_err(|_| ConversionUnknown::UnsupportedExpression)?,
        ),
        "string_literal"
        | "verbatim_string_literal"
        | "raw_string_literal"
        | "interpolated_string_expression" => {
            Ok(CSharpConversionType::Primitive(CSharpPrimitive::String))
        }
        "identifier" => parameter_type(node, source),
        _ => Err(ConversionUnknown::UnsupportedExpression),
    }
}

// The AST has already selected the literal. Classify its value and suffix,
// without interpreting surrounding source syntax (C# 6.4.5.3).
fn integer_literal_type(text: &str) -> Result<CSharpConversionType, ConversionUnknown> {
    let lower = text.to_ascii_lowercase();
    let digits_end = lower.trim_end_matches(['u', 'l']).len();
    let (digits, suffix) = lower.split_at(digits_end);
    let digits = digits.replace('_', "");
    let (digits, radix) = if let Some(value) = digits.strip_prefix("0x") {
        (value, 16)
    } else if let Some(value) = digits.strip_prefix("0b") {
        (value, 2)
    } else {
        (digits.as_str(), 10)
    };
    let value =
        u64::from_str_radix(digits, radix).map_err(|_| ConversionUnknown::UnsupportedExpression)?;
    let name = match suffix {
        "" if value <= i32::MAX as u64 => "int",
        "" | "u" if value <= u32::MAX as u64 => "uint",
        "" | "l" if value <= i64::MAX as u64 => "long",
        "" | "u" | "l" | "ul" | "lu" => "ulong",
        _ => return Err(ConversionUnknown::UnsupportedExpression),
    };
    Ok(named_type(name))
}

fn parameter_type(node: Node<'_>, source: &str) -> Result<CSharpConversionType, ConversionUnknown> {
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
                    let declared_type =
                        brokk_bifrost_csharp::declarations::csharp_parameter_type_node(declaration)
                            .ok_or(ConversionUnknown::UnresolvedSourceType)?;
                    return written_type(declared_type, source);
                }
            }
        }
        owner = candidate.parent();
    }
    Err(ConversionUnknown::UnresolvedSourceType)
}

/// Normal-form proof is intentionally narrower than C# applicability: every
/// conversion must be supported, including identity of the final array value.
fn prove_normal_array(
    actuals: &[Node<'_>],
    source: &str,
    types: &[CSharpConversionType],
) -> Result<(), ConversionUnknown> {
    if actuals.len() != types.len() {
        return Err(ConversionUnknown::SignatureApplicability);
    }
    let Some(CSharpConversionType::Array(_)) = types.last() else {
        return Err(ConversionUnknown::UnsupportedConversion);
    };
    for (actual, target) in actuals.iter().zip(types) {
        classify(actual_type(*actual, source)?, target.clone())?;
    }
    Ok(())
}

pub(crate) fn source_normal_array_invocation(
    call: Node<'_>,
    source: &str,
    declaration: Node<'_>,
    formal_source: &str,
) -> Option<brokk_bifrost_analysis::analyzer::semantic::call_binding::FixedArrayInvocation> {
    let parameters = brokk_bifrost_csharp::declarations::csharp_parameter_list_node(declaration)?;
    let formals =
        brokk_bifrost_csharp::declarations::csharp_parameter_syntax(parameters, &mut || true)?;
    if !formals.last()?.params {
        return None;
    }
    // Generic substitution and ref/out/in passing are outside this proof.
    let mut owner = Some(declaration);
    while let Some(node) = owner {
        if node.child_by_field_name("type_parameters").is_some() {
            return None;
        }
        owner = node.parent();
    }
    let arguments = call.child_by_field_name("arguments")?;
    let mut actuals = Vec::new();
    for argument in arguments.named_children(&mut arguments.walk()) {
        if argument.kind() == "comment" {
            continue;
        }
        if argument.kind() != "argument"
            || argument.has_error()
            || argument.is_missing()
            || argument.child_by_field_name("name").is_some()
            || argument
                .children(&mut argument.walk())
                .any(|child| matches!(child.kind(), "ref" | "out" | "in"))
        {
            return None;
        }
        let expressions = argument
            .named_children(&mut argument.walk())
            .filter(|node| node.kind() != "comment")
            .collect::<Vec<_>>();
        let [expression] = expressions.as_slice() else {
            return None;
        };
        actuals.push(*expression);
    }
    let types = formals
        .iter()
        .map(|formal| {
            if formal
                .anchor
                .children(&mut formal.anchor.walk())
                .any(|node| matches!(node.kind(), "ref" | "out" | "in"))
            {
                return Err(ConversionUnknown::UnsupportedConversion);
            }
            written_type(
                formal
                    .type_node
                    .ok_or(ConversionUnknown::UnresolvedSignature)?,
                formal_source,
            )
        })
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    prove_normal_array(&actuals, source, &types).ok()?;
    Some(brokk_bifrost_analysis::analyzer::semantic::call_binding::FixedArrayInvocation)
}
