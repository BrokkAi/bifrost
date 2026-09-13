//! Resolver-backed Scala call-argument conversion facts (#2852 / #2724).

use tree_sitter::Node;

use crate::analyzer::semantic::{children_by_field_name, node_text};
use crate::analyzer::tree_walk::named_children;
use crate::analyzer::usages::call_conversion::{
    ArgumentTypeConversion, CallArgumentConversionProver, ConversionKind, ConversionUnknown,
    ResolvedConversionType, ScalaConversionType,
};
use crate::analyzer::{CodeUnit, IAnalyzer, Language, ProjectFile};
use crate::hash::HashMap;

use super::scala_type_lookup_segments;
use super::semantic_adaptation::{
    AdaptationFailure, ScalaAdaptationCatalog, ScalaTypeBinding, SelectedAdaptationKind,
    scala_nominal_types_match,
};

pub(crate) static CALL_ARGUMENT_CONVERSION_PROVER: ScalaCallArgumentConversionProver =
    ScalaCallArgumentConversionProver;

pub(crate) struct ScalaCallArgumentConversionProver;

impl CallArgumentConversionProver for ScalaCallArgumentConversionProver {
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
        if file.language() != Language::Scala || formal_file.language() != Language::Scala {
            return Err(ConversionUnknown::UnsupportedLanguage);
        }
        let target = formal_type_identity(formal, formal_source)
            .ok_or(ConversionUnknown::UnresolvedTargetType)?;
        let source_type = expression_nominal_type(actual, source)
            .ok_or(ConversionUnknown::UnresolvedSourceType)?;
        classify_scala_conversion(analyzer, file, actual, source, &source_type, &target)
    }
}

fn classify_scala_conversion(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    actual: Node<'_>,
    source: &str,
    source_type: &[String],
    target_type: &[String],
) -> Result<ArgumentTypeConversion, ConversionUnknown> {
    let Some(root) = compilation_unit(actual) else {
        return Err(ConversionUnknown::UnsupportedConversion);
    };
    let catalog = ScalaAdaptationCatalog::collect(source, root, &HashMap::default());
    let source_id = resolved_conversion_type(
        analyzer,
        file,
        &catalog,
        source,
        actual,
        source_type,
        ConversionUnknown::UnresolvedSourceType,
    )?;
    let target_id = resolved_conversion_type(
        analyzer,
        file,
        &catalog,
        source,
        actual,
        target_type,
        ConversionUnknown::UnresolvedTargetType,
    )?;
    if conversion_types_match(&source_id, &target_id) {
        return Ok(ArgumentTypeConversion {
            source: source_id,
            target: target_id,
            kind: ConversionKind::ScalaIdentity,
        });
    }
    match catalog.select(source, actual, source_type, target_type) {
        Ok(selected) => {
            let kind = match selected.kind {
                SelectedAdaptationKind::ImplicitCall { .. } => {
                    ConversionKind::ScalaImplicitConversion
                }
                SelectedAdaptationKind::OpaqueWrap | SelectedAdaptationKind::OpaqueUnwrap => {
                    ConversionKind::ScalaOpaqueAdaptation
                }
            };
            Ok(ArgumentTypeConversion {
                source: source_id,
                target: target_id,
                kind,
            })
        }
        Err(super::semantic_adaptation::AdaptationFailure::Ambiguous) => {
            Err(ConversionUnknown::AmbiguousBinding)
        }
        Err(super::semantic_adaptation::AdaptationFailure::Unresolved) => {
            if catalog.value_class_boxes(source, actual, source_type, target_type) {
                return Ok(ArgumentTypeConversion {
                    source: source_id,
                    target: target_id,
                    kind: ConversionKind::ScalaValueClassBoxing,
                });
            }
            if catalog.value_class_unboxes(source, actual, source_type, target_type) {
                return Ok(ArgumentTypeConversion {
                    source: source_id,
                    target: target_id,
                    kind: ConversionKind::ScalaValueClassUnboxing,
                });
            }
            Err(ConversionUnknown::UnsupportedConversion)
        }
    }
}

fn resolved_conversion_type(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    catalog: &ScalaAdaptationCatalog<'_>,
    source: &str,
    use_site: Node<'_>,
    segments: &[String],
    unresolved: ConversionUnknown,
) -> Result<ResolvedConversionType, ConversionUnknown> {
    match catalog.bind_nominal_type(source, segments, use_site) {
        Ok(ScalaTypeBinding::Declaration(declaration)) => {
            let unit = declaration_code_unit(analyzer, file, declaration).ok_or(unresolved)?;
            Ok(ResolvedConversionType::Scala(
                ScalaConversionType::Declaration(unit),
            ))
        }
        Ok(ScalaTypeBinding::Prelude) => Ok(resolved_nominal(segments)),
        Ok(ScalaTypeBinding::TypeParameter) => Err(ConversionUnknown::GenericSubstitution),
        Err(AdaptationFailure::Ambiguous) => Err(ConversionUnknown::AmbiguousBinding),
        Err(AdaptationFailure::Unresolved) => Err(unresolved),
    }
}

fn declaration_code_unit(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    node: Node<'_>,
) -> Option<CodeUnit> {
    let index = analyzer.class_range_index(file);
    if let Some(unit) = index.unit_for_exact_span(node.start_byte(), node.end_byte()) {
        return Some(unit.clone());
    }
    let mut matches = analyzer
        .get_declarations(file)
        .into_iter()
        .filter(|unit| {
            analyzer.ranges(unit).iter().any(|range| {
                range.start_byte == node.start_byte() && range.end_byte == node.end_byte()
            })
        })
        .collect::<Vec<_>>();
    match matches.len() {
        1 => matches.pop(),
        _ => None,
    }
}

fn conversion_types_match(left: &ResolvedConversionType, right: &ResolvedConversionType) -> bool {
    match (left, right) {
        (
            ResolvedConversionType::Scala(ScalaConversionType::Declaration(left)),
            ResolvedConversionType::Scala(ScalaConversionType::Declaration(right)),
        ) => left == right,
        (
            ResolvedConversionType::Scala(ScalaConversionType::Nominal(left)),
            ResolvedConversionType::Scala(ScalaConversionType::Nominal(right)),
        ) => {
            let left = left
                .iter()
                .map(|segment| segment.to_string())
                .collect::<Vec<_>>();
            let right = right
                .iter()
                .map(|segment| segment.to_string())
                .collect::<Vec<_>>();
            scala_nominal_types_match(&left, &right)
        }
        _ => false,
    }
}

fn resolved_nominal(segments: &[String]) -> ResolvedConversionType {
    ResolvedConversionType::Scala(ScalaConversionType::Nominal(
        segments
            .iter()
            .map(|segment| Box::<str>::from(segment.as_str()))
            .collect::<Vec<_>>()
            .into_boxed_slice(),
    ))
}

fn formal_type_identity(formal: Node<'_>, source: &str) -> Option<Vec<String>> {
    let declared = formal.child_by_field_name("type").or_else(|| {
        named_children(formal)
            .into_iter()
            .find(|child| child.kind() == "parameter")
            .and_then(|parameter| parameter.child_by_field_name("type"))
    })?;
    if subtree_has_kind(declared, "lazy_parameter_type")
        || subtree_has_kind(formal, "lazy_parameter_type")
    {
        return None;
    }
    let segments = scala_type_lookup_segments(declared, source);
    (!segments.is_empty()).then_some(segments)
}

fn expression_nominal_type(mut node: Node<'_>, source: &str) -> Option<Vec<String>> {
    for _ in 0..32 {
        match node.kind() {
            "parenthesized_expression" => node = named_children(node).into_iter().next()?,
            "identifier" => {
                let name = node_text(source, node).filter(|name| !name.is_empty())?;
                return lexical_type(node, name, source);
            }
            "integer_literal" => return Some(vec!["Int".to_owned()]),
            "floating_point_literal" => return Some(vec!["Double".to_owned()]),
            "boolean_literal" => return Some(vec!["Boolean".to_owned()]),
            "character_literal" => return Some(vec!["Char".to_owned()]),
            "string" | "string_literal" => return Some(vec!["String".to_owned()]),
            "instance_expression" => {
                let constructed = node.child_by_field_name("type")?;
                let segments = scala_type_lookup_segments(constructed, source);
                return (!segments.is_empty()).then_some(segments);
            }
            _ => {
                if let Some(name) = literal_type_name(node) {
                    return Some(vec![name.to_owned()]);
                }
                return None;
            }
        }
    }
    None
}

fn literal_type_name(node: Node<'_>) -> Option<&'static str> {
    match node.kind() {
        "integer_literal" => Some("Int"),
        "floating_point_literal" => Some("Double"),
        "boolean_literal" => Some("Boolean"),
        "character_literal" => Some("Char"),
        "string" | "string_literal" => Some("String"),
        "unit" => Some("Unit"),
        _ => None,
    }
}

fn lexical_type(node: Node<'_>, name: &str, source: &str) -> Option<Vec<String>> {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if matches!(
            parent.kind(),
            "function_definition"
                | "function_declaration"
                | "lambda_expression"
                | "given_definition"
        ) {
            for list in children_by_field_name(parent, "parameters") {
                for parameter in named_children(list) {
                    if parameter.kind() == "parameter"
                        && parameter
                            .child_by_field_name("name")
                            .and_then(|declared| node_text(source, declared))
                            == Some(name)
                    {
                        let declared = parameter.child_by_field_name("type")?;
                        let segments = scala_type_lookup_segments(declared, source);
                        return (!segments.is_empty()).then_some(segments);
                    }
                }
            }
        }
        if matches!(parent.kind(), "val_definition" | "var_definition")
            && parent
                .child_by_field_name("pattern")
                .and_then(|pattern| node_text(source, pattern))
                == Some(name)
            && let Some(declared) = parent.child_by_field_name("type")
        {
            let segments = scala_type_lookup_segments(declared, source);
            if !segments.is_empty() {
                return Some(segments);
            }
        }
        current = parent;
    }
    None
}

fn compilation_unit(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        if node.kind() == "compilation_unit" {
            return Some(node);
        }
        node = node.parent()?;
    }
}

fn subtree_has_kind(node: Node<'_>, kind: &str) -> bool {
    let mut stack = vec![node];
    let mut examined = 0_usize;
    while let Some(current) = stack.pop() {
        examined += 1;
        if examined > 64 {
            return false;
        }
        if current.kind() == kind {
            return true;
        }
        stack.extend(named_children(current));
    }
    false
}
