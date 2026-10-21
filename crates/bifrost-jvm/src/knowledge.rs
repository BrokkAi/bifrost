//! Analyzer-independent language rules.

use brokk_bifrost_core::analyzer::Language;
use brokk_bifrost_core::analyzer::fq_name::FqName;
use brokk_bifrost_core::analyzer::fq_name::SegmentKind;
use brokk_bifrost_core::analyzer::fq_name::segment_interner;
use brokk_bifrost_core::analyzer::language_knowledge::LanguageKnowledge;
use brokk_bifrost_core::analyzer::language_knowledge::ParserFlavor;
use brokk_bifrost_core::analyzer::structural::spec::StructuralSpec;

/// Java syntax and static language rules.
pub struct JavaKnowledge;

impl LanguageKnowledge for JavaKnowledge {
    fn numeric_promotion(&self, operands: &[Option<&str>]) -> Option<&'static str> {
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
            return (booleans == operands.len()).then_some("boolean");
        }
        match rank {
            1 => Some("int"),
            2 => Some("long"),
            3 => Some("float"),
            4 => Some("double"),
            _ => None,
        }
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
    fn language(&self) -> Language {
        Language::Kotlin
    }

    fn call_may_apply_value(&self) -> bool {
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
