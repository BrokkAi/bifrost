//! Bounded Rust actual-to-formal conversion proofs.
//!
//! This module intentionally covers only conversions whose evidence is local to
//! Rust's syntax and resolver: exact type identity, builtin reference deref and
//! reborrow, and array-reference unsizing.  It does not model borrow checking,
//! lifetimes, user `Deref` implementations, generic substitution, or inferred
//! local types.

use crate::analyzer::lexical_definitions::{LexicalBindingResolution, resolve_lexical_binding};
use crate::analyzer::usages::ImportKind;
use crate::analyzer::usages::call_conversion::{
    ArgumentTypeConversion, CallArgumentConversionProver, ConversionKind, ConversionUnknown,
    ResolvedConversionType, RustConversionType, RustPrimitive,
};
use crate::analyzer::usages::get_definition::parse_tree_for_language;
use crate::analyzer::usages::get_definition::{
    AnalyzerRustDefinitionProvider, rust_is_type_definition, rust_resolve_type_node_fqn,
};
use crate::analyzer::usages::rust_graph::RustDefinitionProvider;
use crate::analyzer::{
    AnalyzerQueryScope, IAnalyzer, Language, ProjectFile, QueryScope, RustAnalyzer,
    resolve_analyzer,
};
use brokk_bifrost_rust::declarations::rust_node_text;
use brokk_bifrost_rust::graph::ast::type_parameter_trait_bounds;
use brokk_bifrost_rust::lexical_scope::{rust_lexical_scope_index, visible_import_binder_in_tree};
use brokk_bifrost_rust::ownership::{
    rust_dereference_operand, rust_node_is_in_unsafe_context, rust_reference_expression_value,
    rust_reference_is_mutable, rust_reference_type_referent,
};
use tree_sitter::Node;

const MAX_TYPE_DEPTH: usize = 16;

pub(crate) static CALL_ARGUMENT_CONVERSION_PROVER: RustCallArgumentConversionProver =
    RustCallArgumentConversionProver;

pub(crate) struct RustCallArgumentConversionProver;

impl CallArgumentConversionProver for RustCallArgumentConversionProver {
    fn validate_owner(&self, owner: Node<'_>) -> Result<(), ConversionUnknown> {
        let mut current = Some(owner);
        while let Some(node) = current {
            if node.child_by_field_name("type_parameters").is_some()
                || has_named_child_kind(node, "where_clause")
            {
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
        file: &ProjectFile,
        actual: Node<'_>,
        source: &str,
        formal_file: &ProjectFile,
        formal: Node<'_>,
        formal_source: &str,
    ) -> Result<ArgumentTypeConversion, ConversionUnknown> {
        supported_type_context(actual)?;
        supported_type_context(formal)?;
        let rust = resolve_analyzer::<RustAnalyzer>(analyzer)
            .ok_or(ConversionUnknown::UnsupportedLanguage)?;
        let scope = AnalyzerQueryScope::new(rust);
        let token = scope.token();
        let support = AnalyzerRustDefinitionProvider::new(rust, true);

        let actual_context = RustTypeContext {
            analyzer,
            file,
            source,
            root: node_root(actual),
        };
        let formal_context = RustTypeContext {
            analyzer,
            file: formal_file,
            source: formal_source,
            root: node_root(formal),
        };

        let source_type = actual_context.expression_type(actual, &support, token, 0)?;
        let target_node = formal
            .child_by_field_name("type")
            .ok_or(ConversionUnknown::UnresolvedTargetType)?;
        let target_type = formal_context.type_from_node(target_node, &support, token, 0)?;
        let kind = conversion_kind(&source_type, &target_type)
            .ok_or(ConversionUnknown::UnsupportedConversion)?;

        Ok(ArgumentTypeConversion {
            source: ResolvedConversionType::Rust(source_type),
            target: ResolvedConversionType::Rust(target_type),
            kind,
        })
    }
}

struct RustTypeContext<'a, 'tree> {
    analyzer: &'a dyn IAnalyzer,
    file: &'a ProjectFile,
    source: &'a str,
    root: Node<'tree>,
}

impl<'a, 'tree> RustTypeContext<'a, 'tree> {
    fn type_from_node(
        &self,
        node: Node<'tree>,
        support: &AnalyzerRustDefinitionProvider<'_>,
        token: crate::analyzer::QueryToken<'_>,
        depth: usize,
    ) -> Result<RustConversionType, ConversionUnknown> {
        if depth >= MAX_TYPE_DEPTH || node.has_error() || node.is_missing() {
            return Err(ConversionUnknown::UnsupportedConversion);
        }
        match node.kind() {
            "primitive_type" => self.primitive_type(node),
            "unit_type" => Ok(RustConversionType::Unit),
            "reference_type" => {
                if has_named_child_kind(node, "lifetime") {
                    return Err(ConversionUnknown::UnsupportedConversion);
                }
                let referent = rust_reference_type_referent(node)
                    .ok_or(ConversionUnknown::UnresolvedTargetType)?;
                Ok(RustConversionType::Reference {
                    mutable: rust_reference_is_mutable(node),
                    referent: Box::new(self.type_from_node(referent, support, token, depth + 1)?),
                })
            }
            "array_type" => {
                let element = node
                    .child_by_field_name("element")
                    .ok_or(ConversionUnknown::UnresolvedTargetType)?;
                let element = self.type_from_node(element, support, token, depth + 1)?;
                match node.child_by_field_name("length") {
                    Some(length_node) => {
                        let (length, suffix) =
                            super::semantic::rust_integer_literal_parts(self.source, length_node)
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
                    elements.push(self.type_from_node(child, support, token, depth + 1)?);
                }
                Ok(RustConversionType::Tuple(elements))
            }
            "generic_type"
            | "generic_function"
            | "qualified_type"
            | "higher_ranked_trait_bound" => Err(ConversionUnknown::GenericSubstitution),
            "type_identifier"
            | "identifier"
            | "scoped_type_identifier"
            | "scoped_identifier"
            | "self"
            | "crate"
            | "super" => self.nominal_type(node, support, token),
            _ => Err(ConversionUnknown::UnsupportedConversion),
        }
    }

    fn primitive_type(&self, node: Node<'tree>) -> Result<RustConversionType, ConversionUnknown> {
        let spelling = rust_node_text(node, self.source).trim();
        let primitive =
            primitive_for_spelling(spelling).ok_or(ConversionUnknown::UnsupportedConversion)?;
        let scope = rust_lexical_scope_index(self.root, self.source);
        let imports = visible_import_binder_in_tree(self.root, self.source, node.start_byte());
        if scope.item_bound_at(spelling, node.start_byte())
            || imports.bindings.contains_key(spelling)
            || imports
                .bindings
                .values()
                .any(|binding| binding.kind == ImportKind::Glob)
            || type_parameter_trait_bounds(node, spelling, self.source).is_some()
        {
            return Err(ConversionUnknown::UnsupportedConversion);
        }
        Ok(RustConversionType::Primitive(primitive))
    }

    fn nominal_type(
        &self,
        node: Node<'tree>,
        support: &AnalyzerRustDefinitionProvider<'_>,
        token: crate::analyzer::QueryToken<'_>,
    ) -> Result<RustConversionType, ConversionUnknown> {
        let name_node = node.child_by_field_name("name").unwrap_or(node);
        let name = rust_node_text(name_node, self.source).trim();
        if name.is_empty() {
            return Err(ConversionUnknown::UnresolvedTargetType);
        }
        if type_parameter_trait_bounds(node, name, self.source).is_some() {
            return Err(ConversionUnknown::GenericSubstitution);
        }
        let fqn = rust_resolve_type_node_fqn(
            self.analyzer,
            token,
            support,
            self.file,
            self.source,
            node,
            Some(node.start_byte()),
        )
        .ok_or(ConversionUnknown::UnresolvedTargetType)?;
        let mut candidates = support
            .fqn(&fqn)
            .into_iter()
            .filter(|unit| rust_is_type_definition(self.analyzer, unit))
            .collect::<Vec<_>>();
        candidates.sort_by_key(|unit| unit.declaration_id());
        candidates.dedup_by(|left, right| left.declaration_id() == right.declaration_id());
        let [unit] = candidates.as_slice() else {
            return Err(ConversionUnknown::AmbiguousBinding);
        };
        // A type name may resolve to a trait, alias, or generic declaration.
        // None of those establishes a concrete nominal type without additional
        // obligations. Inspect the exact declaration, not its rendered name.
        let declaration_source = self
            .analyzer
            .indexed_source(unit.source())
            .ok_or(ConversionUnknown::UnresolvedTargetType)?;
        let tree = parse_tree_for_language(unit.source(), Language::Rust, &declaration_source)
            .ok_or(ConversionUnknown::UnresolvedTargetType)?;
        let ranges = self.analyzer.ranges_of(unit);
        let [range] = ranges.as_slice() else {
            return Err(ConversionUnknown::AmbiguousBinding);
        };
        let declaration = tree
            .root_node()
            .named_descendant_for_byte_range(range.start_byte, range.end_byte)
            .filter(|node| node.byte_range() == (range.start_byte..range.end_byte))
            .ok_or(ConversionUnknown::UnresolvedTargetType)?;
        supported_type_context(declaration)?;
        if declaration.has_error()
            || !matches!(
                declaration.kind(),
                "struct_item" | "enum_item" | "union_item"
            )
        {
            return Err(ConversionUnknown::UnsupportedConversion);
        }
        CALL_ARGUMENT_CONVERSION_PROVER.validate_owner(declaration)?;
        Ok(RustConversionType::Declaration(unit.clone()))
    }

    fn expression_type(
        &self,
        mut node: Node<'tree>,
        support: &AnalyzerRustDefinitionProvider<'_>,
        token: crate::analyzer::QueryToken<'_>,
        depth: usize,
    ) -> Result<RustConversionType, ConversionUnknown> {
        if depth >= MAX_TYPE_DEPTH
            || node.has_error()
            || node.is_missing()
            || rust_node_is_in_unsafe_context(node)
        {
            return Err(ConversionUnknown::UnsupportedExpression);
        }
        while node.kind() == "parenthesized_expression" {
            node = node
                .named_child(0)
                .ok_or(ConversionUnknown::UnsupportedExpression)?;
        }
        match node.kind() {
            "identifier" => {
                let name = rust_node_text(node, self.source).trim();
                let binding = resolve_lexical_binding(
                    Language::Rust,
                    self.root,
                    self.source,
                    node.start_byte(),
                    node.end_byte(),
                    name,
                )
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
                let type_node = declaration
                    .child_by_field_name("type")
                    .ok_or(ConversionUnknown::UnresolvedSourceType)?;
                self.type_from_node(type_node, support, token, depth + 1)
                    .map_err(source_type_error)
            }
            "reference_expression" => {
                let value = rust_reference_expression_value(node)
                    .ok_or(ConversionUnknown::UnsupportedExpression)?;
                let referent = self.expression_type(value, support, token, depth + 1)?;
                Ok(RustConversionType::Reference {
                    mutable: rust_reference_is_mutable(node),
                    referent: Box::new(referent),
                })
            }
            "unary_expression" => {
                let operand = rust_dereference_operand(node)
                    .ok_or(ConversionUnknown::UnsupportedExpression)?;
                match self.expression_type(operand, support, token, depth + 1)? {
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
        (RustConversionType::Primitive(left), RustConversionType::Primitive(right)) => {
            left == right
        }
        (RustConversionType::Declaration(left), RustConversionType::Declaration(right)) => {
            left.declaration_id() == right.declaration_id()
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

fn primitive_for_spelling(spelling: &str) -> Option<RustPrimitive> {
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

fn has_named_child_kind(node: Node<'_>, kind: &str) -> bool {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .any(|child| child.kind() == kind)
}

fn supported_type_context(node: Node<'_>) -> Result<(), ConversionUnknown> {
    let mut current = Some(node);
    while let Some(scope) = current {
        if matches!(scope.kind(), "macro_invocation" | "macro_definition") {
            return Err(ConversionUnknown::UnsupportedExpression);
        }
        if matches!(scope.kind(), "block" | "source_file" | "declaration_list") {
            // A statement/item macro may introduce a type or import that shadows
            // an apparent builtin or nominal. Unexpanded syntax cannot prove
            // the absence of that binding. Sibling bodies are separate scopes.
            let mut cursor = scope.walk();
            if scope.named_children(&mut cursor).any(|child| {
                child.kind() == "macro_invocation"
                    || (child.kind() == "expression_statement"
                        && has_named_child_kind(child, "macro_invocation"))
            }) {
                return Err(ConversionUnknown::UnsupportedConversion);
            }
        }
        if scope.kind() == "mod_item" {
            break;
        }
        current = scope.parent();
    }
    Ok(())
}

fn node_root<'tree>(mut node: Node<'tree>) -> Node<'tree> {
    while let Some(parent) = node.parent() {
        node = parent;
    }
    node
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
