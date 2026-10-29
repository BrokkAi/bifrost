//! Analyzer-independent language rules.

use brokk_bifrost_core::analyzer::Language;
use brokk_bifrost_core::analyzer::fq_name::FqName;
use brokk_bifrost_core::analyzer::fq_name::SegmentKind;
use brokk_bifrost_core::analyzer::fq_name::segment_interner;
use brokk_bifrost_core::analyzer::language_knowledge::BuiltinSupertypes;
use brokk_bifrost_core::analyzer::language_knowledge::GuardConditionSyntax;
use brokk_bifrost_core::analyzer::language_knowledge::LanguageKnowledge;
use brokk_bifrost_core::analyzer::language_knowledge::ParserFlavor;
use brokk_bifrost_core::analyzer::resolution_facts::IntrinsicTypeKind;
use brokk_bifrost_core::analyzer::structural::spec::StructuralSpec;

/// Java syntax and static language rules.
pub struct JavaKnowledge;

impl LanguageKnowledge for JavaKnowledge {
    fn semantic_string_constant_value(&self, payload: &str) -> Option<String> {
        Some(payload.to_owned())
    }

    fn declared_type_is_referent_immutable(&self, canonical_type: &str) -> bool {
        matches!(
            canonical_type,
            "java.lang.String"
                | "java.lang.Boolean"
                | "java.lang.Byte"
                | "java.lang.Short"
                | "java.lang.Character"
                | "java.lang.Integer"
                | "java.lang.Long"
                | "java.lang.Float"
                | "java.lang.Double"
                | "java.io.File"
                | "java.nio.file.Path"
                | "java.net.URI"
                | "boolean"
                | "byte"
                | "short"
                | "char"
                | "int"
                | "long"
                | "float"
                | "double"
        )
    }

    fn guard_condition_syntax(&self) -> Option<&'static GuardConditionSyntax> {
        Some(&GuardConditionSyntax {
            call_kinds: &["method_invocation"],
            parenthesis_kinds: &["parenthesized_expression"],
            parenthesis_field: None,
            negation_kinds: &["unary_expression"],
            operator_field: "operator",
            negation_operator: "!",
            operand_field: "operand",
        })
    }

    fn field_initializer<'t>(
        &self,
        node: tree_sitter::Node<'t>,
    ) -> Option<(tree_sitter::Node<'t>, tree_sitter::Node<'t>)> {
        if node.kind() != "variable_declarator" {
            return None;
        }
        Some((
            node.child_by_field_name("name")?,
            node.child_by_field_name("value")?,
        ))
    }

    fn factory_name_node<'t>(&self, call: tree_sitter::Node<'t>) -> Option<tree_sitter::Node<'t>> {
        if call.kind() != "method_invocation" {
            return None;
        }
        call.child_by_field_name("name")
    }

    fn numeric_promotion(
        &self,
        operands: &[Option<&str>],
    ) -> Option<(IntrinsicTypeKind, &'static str)> {
        // JLS 5.6.1/5.6.2: unbox, then promote byte/short/char to int;
        // otherwise double, float and long dominate in that order.
        // JLS 15.22.2 also admits the all-boolean bitwise case.
        let mut rank = 0;
        let mut booleans = 0;
        for operand in operands {
            let next = match (*operand)? {
                "byte"
                | "short"
                | "char"
                | "int"
                | "java.lang.Byte"
                | "java.lang.Short"
                | "java.lang.Character"
                | "java.lang.Integer" => 1,
                "long" | "java.lang.Long" => 2,
                "float" | "java.lang.Float" => 3,
                "double" | "java.lang.Double" => 4,
                "boolean" | "java.lang.Boolean" => {
                    booleans += 1;
                    continue;
                }
                _ => return None,
            };
            rank = rank.max(next);
        }
        if booleans != 0 {
            return (booleans == operands.len())
                .then_some((IntrinsicTypeKind::Primitive, "boolean"));
        }
        let name = match rank {
            1 => "int",
            2 => "long",
            3 => "float",
            4 => "double",
            _ => return None,
        };
        Some((IntrinsicTypeKind::Primitive, name))
    }

    fn string_concatenation_operand(&self, operands: &[Option<&str>]) -> Option<usize> {
        operands
            .iter()
            .position(|operand| *operand == Some("java.lang.String"))
    }

    fn language(&self) -> Language {
        Language::Java
    }

    fn parser_language(&self, _flavor: ParserFlavor) -> tree_sitter::Language {
        tree_sitter_java::LANGUAGE.into()
    }

    fn structural_spec(&self) -> &'static dyn StructuralSpec {
        &crate::java::structural::JAVA_STRUCTURAL_SPEC
    }

    fn highlight_query(&self) -> Option<&'static str> {
        Some(tree_sitter_java::HIGHLIGHTS_QUERY)
    }
}

/// Kotlin syntax and static language rules.
pub struct KotlinKnowledge;

impl LanguageKnowledge for KotlinKnowledge {
    fn declared_type_is_referent_immutable(&self, _canonical_type: &str) -> bool {
        false
    }

    fn field_initializer<'t>(
        &self,
        node: tree_sitter::Node<'t>,
    ) -> Option<(tree_sitter::Node<'t>, tree_sitter::Node<'t>)> {
        if node.kind() != "property_declaration" {
            return None;
        }
        let mut cursor = node.walk();
        let binding = node.named_children(&mut cursor).find(|child| {
            matches!(
                child.kind(),
                "variable_declaration" | "multi_variable_declaration"
            )
        })?;
        Some((
            binding,
            crate::kotlin::structural::property_value_node(node)?,
        ))
    }

    fn language(&self) -> Language {
        Language::Kotlin
    }

    fn numeric_promotion(
        &self,
        operands: &[Option<&str>],
    ) -> Option<(IntrinsicTypeKind, &'static str)> {
        // The built-in `plus`, `minus`, `times`, `div` and `rem` operators of
        // kotlin.Byte, Short, Int, Long, Float and Double return the widest
        // operand type, with Byte and Short widened to Int. Char, Boolean,
        // unsigned and user types have other or no operator members, so they
        // leave the result open.
        let mut rank = 0;
        for operand in operands {
            let next = match (*operand)? {
                "kotlin.Byte" | "kotlin.Short" | "kotlin.Int" => 1,
                "kotlin.Long" => 2,
                "kotlin.Float" => 3,
                "kotlin.Double" => 4,
                _ => return None,
            };
            rank = rank.max(next);
        }
        let name = match rank {
            1 => "kotlin.Int",
            2 => "kotlin.Long",
            3 => "kotlin.Float",
            4 => "kotlin.Double",
            _ => return None,
        };
        Some((IntrinsicTypeKind::LanguageBuiltin, name))
    }

    // The kotlin.* builtin class headers, plus java.io.Serializable, which the
    // JVM builtins add to primitives and String. A mapped Java spelling names
    // the same type, and scala.Any and scala.AnyRef name java.lang.Object.
    // Platform boxes and Comparable's type argument stay open. Nothing and
    // FunctionN follow other rules and have no answer.
    //
    // A Scala or Java formal names a Kotlin builtin in its own vocabulary:
    // Scala `Int` is scala.Int and Java `int` is the primitive, both the JVM
    // int that Kotlin calls kotlin.Int. Kotlin has no implicit widening, so
    // only the same type is an alias. A Scala `Unit` parameter erases to
    // scala.runtime.BoxedUnit rather than kotlin.Unit, so it stays open.
    fn builtin_supertypes(&self, spelling: &str) -> Option<BuiltinSupertypes> {
        const ANY: &[&str] = &[
            "kotlin.Any",
            "java.lang.Object",
            "scala.Any",
            "scala.AnyRef",
        ];
        const SCALAR: &[&str] = &[
            "java.io.Serializable",
            "kotlin.Any",
            "java.lang.Object",
            "scala.Any",
            "scala.AnyRef",
        ];
        const NUMBER: &[&str] = &[
            "kotlin.Number",
            "java.lang.Number",
            "java.io.Serializable",
            "kotlin.Any",
            "java.lang.Object",
            "scala.Any",
            "scala.AnyRef",
        ];
        const STRING: &[&str] = &[
            "kotlin.String",
            "java.lang.String",
            "kotlin.CharSequence",
            "java.lang.CharSequence",
            "java.io.Serializable",
            "kotlin.Any",
            "java.lang.Object",
            "scala.Any",
            "scala.AnyRef",
        ];
        const COMPARABLE: &[&str] = &["kotlin.Comparable", "java.lang.Comparable"];
        const BOXED: &[&str] = &[
            "kotlin.Comparable",
            "java.lang.Comparable",
            "java.lang.Boolean",
            "java.lang.Byte",
            "java.lang.Character",
            "java.lang.Double",
            "java.lang.Float",
            "java.lang.Integer",
            "java.lang.Long",
            "java.lang.Short",
        ];
        let (aliases, nominal, open): (&[&str], _, _) = match spelling {
            "kotlin.Any" | "java.lang.Object" => (&[], ANY, &[][..]),
            "kotlin.Unit" => (&[], ANY, &["scala.Unit"][..]),
            "kotlin.Byte" => (&["scala.Byte", "byte"], NUMBER, BOXED),
            "kotlin.Short" => (&["scala.Short", "short"], NUMBER, BOXED),
            "kotlin.Int" => (&["scala.Int", "int"], NUMBER, BOXED),
            "kotlin.Long" => (&["scala.Long", "long"], NUMBER, BOXED),
            "kotlin.Float" => (&["scala.Float", "float"], NUMBER, BOXED),
            "kotlin.Double" => (&["scala.Double", "double"], NUMBER, BOXED),
            "kotlin.Char" => (&["scala.Char", "char"], SCALAR, BOXED),
            "kotlin.Boolean" => (&["scala.Boolean", "boolean"], SCALAR, BOXED),
            "kotlin.String" | "java.lang.String" => (&["scala.Predef.String"], STRING, COMPARABLE),
            _ => return None,
        };
        Some(BuiltinSupertypes {
            aliases,
            nominal,
            open,
        })
    }

    fn call_may_apply_value(&self) -> bool {
        true
    }

    // Kotlin spec, local property declarations: a `val` or `var` without a
    // written type takes its initializer's type; assignments must conform.
    fn inferred_local_type_is_initializer_type(&self) -> bool {
        true
    }

    // Invocation validity cannot change a candidate's written result type.
    // Shared projection keeps the union of those types and other uncertainty.
    fn callable_result_is_applicability_independent(&self) -> bool {
        true
    }

    /// Kotlin's grammar names neither the callee of a call nor the member of a
    /// navigation, so both are read through the positional readers the Kotlin adapters
    /// already use.
    fn call_callee_node<'t>(&self, call: tree_sitter::Node<'t>) -> Option<tree_sitter::Node<'t>> {
        crate::kotlin::syntax::kotlin_callee(call)
    }

    /// No Kotlin declaration names its identifier with a field either, so the header
    /// token is read positionally. Without this, name selection falls through to a text
    /// search over the whole declaration and can answer with a same-named occurrence in
    /// the body, such as `this.offset` inside `fun offset` (#2712).
    fn declaration_name_node<'t>(
        &self,
        declaration: tree_sitter::Node<'t>,
    ) -> Option<tree_sitter::Node<'t>> {
        crate::kotlin::syntax::kotlin_declaration_name(declaration)
    }

    /// The argument list is `value_arguments`, which an ordinary call nests one level
    /// down inside `call_suffix`.
    fn call_argument_nodes<'t>(
        &self,
        call: tree_sitter::Node<'t>,
    ) -> Option<Vec<tree_sitter::Node<'t>>> {
        Some(
            crate::kotlin::syntax::kotlin_value_arguments(call)
                .into_iter()
                .collect(),
        )
    }

    fn factory_name_node<'t>(&self, call: tree_sitter::Node<'t>) -> Option<tree_sitter::Node<'t>> {
        if call.kind() != "call_expression" {
            return None;
        }
        let callee = crate::kotlin::syntax::kotlin_callee(call)?;
        match callee.kind() {
            "navigation_expression" => crate::kotlin::syntax::kotlin_navigation_member(callee),
            "simple_identifier" => Some(callee),
            _ => None,
        }
    }

    fn positional_parameter_default<'t>(
        &self,
        parameter: tree_sitter::Node<'t>,
    ) -> Option<tree_sitter::Node<'t>> {
        crate::kotlin::syntax::kotlin_parameter_default(parameter)
    }

    fn parser_language(&self, _flavor: ParserFlavor) -> tree_sitter::Language {
        crate::kotlin::language::LANGUAGE.into()
    }

    fn structural_spec(&self) -> &'static dyn StructuralSpec {
        &crate::kotlin::structural::KOTLIN_STRUCTURAL_SPEC
    }

    fn highlight_query(&self) -> Option<&'static str> {
        Some(crate::queries::KOTLIN_HIGHLIGHTS_QUERY)
    }
}

/// Scala syntax and static language rules.
pub struct ScalaKnowledge;

impl LanguageKnowledge for ScalaKnowledge {
    fn declared_type_is_referent_immutable(&self, _canonical_type: &str) -> bool {
        false
    }

    fn field_initializer<'t>(
        &self,
        node: tree_sitter::Node<'t>,
    ) -> Option<(tree_sitter::Node<'t>, tree_sitter::Node<'t>)> {
        if !matches!(node.kind(), "val_definition" | "var_definition") {
            return None;
        }
        Some((
            node.child_by_field_name("pattern")?,
            node.child_by_field_name("value")?,
        ))
    }

    fn language(&self) -> Language {
        Language::Scala
    }

    fn call_may_apply_value(&self) -> bool {
        true
    }

    fn native_local_binding_diagnostic(&self) -> bool {
        true
    }

    fn call_target_lookup_routes(
        &self,
    ) -> Option<
        &'static [(
            u32,
            brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace,
        )],
    > {
        use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;
        Some(&[
            (0, ResolutionNamespace::Callable),
            (0, ResolutionNamespace::Value),
            (1, ResolutionNamespace::Type),
        ])
    }

    /// The trailing `$` marks a companion object in the indexed name and is not part of
    /// how anyone writes or reads the type.
    ///
    /// This is the string-only reading, for callers that hold a spelling rather than a
    /// declaration: it accepts a name a reader plausibly typed. Anything that *prints* a
    /// name holds the declaration and must go through [`Self::undecorated_fq_name`],
    /// whose structured answer keeps a `$` the source itself wrote (#3505).
    fn display_symbol_name(&self, symbol: &str) -> String {
        symbol
            .split('.')
            .map(|segment| segment.trim_end_matches('$'))
            .collect::<Vec<_>>()
            .join(".")
    }

    /// Scala's only `$` decoration is the suffix [`FqName::render_native`] appends to a
    /// [`SegmentKind::Companion`] segment, so demoting that kind to `Type` removes
    /// exactly one `$` per object segment and nothing else. `object ConstellationNode$`
    /// renders `org.constellation.ConstellationNode$$` and undecorates to
    /// `org.constellation.ConstellationNode$`, the spelling its source writes and the
    /// index answers.
    fn undecorated_fq_name(&self, fq: &FqName) -> Option<FqName> {
        let interner = segment_interner();
        fq.segments()
            .iter()
            .any(|&id| interner.resolve(id).1 == SegmentKind::Companion)
            .then(|| crate::scala::scala_normalize_fq_name(fq))
    }

    /// The same decoration, read off a single identifier: an object is indexed
    /// as `Name$` but declared as `Name`. Without this override the
    /// seek-then-verify lookup of a source-spelled object name fails
    /// verification against the persisted identifier (#2419).
    fn source_identifier<'s>(&self, identifier: &'s str) -> &'s str {
        identifier.strip_suffix('$').unwrap_or(identifier)
    }

    fn parser_language(&self, _flavor: ParserFlavor) -> tree_sitter::Language {
        crate::scala::language::LANGUAGE.into()
    }

    fn structural_spec(&self) -> &'static dyn StructuralSpec {
        &crate::scala::structural::SCALA_STRUCTURAL_SPEC
    }

    fn highlight_query(&self) -> Option<&'static str> {
        Some(crate::queries::SCALA_HIGHLIGHTS_QUERY)
    }
}
