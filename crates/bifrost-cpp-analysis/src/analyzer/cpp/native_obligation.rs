//! Query-time C and C++ `[[nodiscard]]` and `warn_unused_result` facts.
//!
//! The declaration attributes are read from the canonical prepared tree for a
//! resolved workspace target. Nothing is inferred from a rendered signature or
//! from the spelling of a call. The proof is deliberately query-scoped: the
//! source tree, visibility index, and candidate rows are released with the
//! surrounding analyzer query.

use brokk_bifrost_core::analyzer::CodeUnitIndex;
use brokk_bifrost_core::analyzer::model::StructuredTypeNodeView;
use brokk_bifrost_core::analyzer::structural::native_obligation::{
    NativeResultObligation, NativeResultObligationBasis,
};
use brokk_bifrost_core::analyzer::{CodeUnit, Language, Range};
use brokk_bifrost_core::hash::HashSet;
use brokk_bifrost_cpp::declarations::{
    cpp_callable_declaration_return_type_identity, cpp_callable_declaration_return_type_node,
    cpp_declaration_has_native_must_use_attribute,
};
use brokk_bifrost_cpp::graph::CppGraphSource;
use brokk_bifrost_cpp::graph::extractor::{
    initialized_ordinary_type_imports, resolve_type_node_lexically,
};
use brokk_bifrost_cpp::graph::resolver::{LexicalTypeResolution, VisibilityIndex};
use brokk_bifrost_cpp::graph_support::CppSource;
use tree_sitter::Node;

use crate::analyzer::cpp::CppAnalyzer;

use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;

use brokk_bifrost_analysis::analyzer::i_analyzer::IAnalyzer;

use brokk_bifrost_core::analyzer::query_token::QueryScope;

use brokk_bifrost_core::analyzer::query_token::QueryToken;

use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;

/// The native C/C++ obligation proof for one resolved callable and result
/// port. `Open` is retained by the query surface so missing declaration or
/// return-type evidence cannot become a clean absence claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CppNativeObligationProof {
    Obligation(NativeResultObligation),
    /// A nodiscard base declaration supplies the virtual-family contract. The
    /// RQL dispatcher may still leave a virtual site open because it cannot
    /// name every override; the base contract is enough for that family.
    BaseContract(NativeResultObligation),
    NoObligation,
    Open(&'static str),
}

struct CppNativeProof<'a> {
    cpp: &'a CppAnalyzer,
    token: QueryToken<'a>,
}

impl<'a> CppNativeProof<'a> {
    fn new(cpp: &'a CppAnalyzer, token: QueryToken<'a>) -> Self {
        Self { cpp, token }
    }

    fn target_obligation(
        &self,
        target: &CodeUnit,
        result_ordinal: u32,
    ) -> CppNativeObligationProof {
        if target.source().declaration_language() != Language::Cpp {
            return CppNativeObligationProof::Open("native_target_language");
        }
        if result_ordinal != 0 {
            return CppNativeObligationProof::NoObligation;
        }
        if !target.is_function() {
            return CppNativeObligationProof::Open("native_target_not_callable");
        }

        let Some(occurrences) = self.cpp.declaration_source_occurrences(self.token, target) else {
            return CppNativeObligationProof::Open("native_target_declaration");
        };
        if occurrences.is_empty() {
            return CppNativeObligationProof::Open("native_target_declaration");
        }
        let Some(prepared) = self.cpp.prepared_syntax(self.token, target.source()) else {
            return CppNativeObligationProof::Open("native_target_source");
        };
        let ancestry =
            brokk_bifrost_core::analyzer::tree_walk::ParentIndex::new(prepared.tree().root_node());

        let mut callable_attribute = false;
        let mut return_type = None;
        let mut constructor = false;
        for occurrence in occurrences {
            let Some(declaration) = exact_node(prepared.tree().root_node(), occurrence.range)
            else {
                return CppNativeObligationProof::Open("native_target_declaration");
            };
            if has_recovery_ancestor(declaration) {
                return CppNativeObligationProof::Open("native_target_recovered");
            }
            callable_attribute |=
                cpp_declaration_has_native_must_use_attribute(declaration, prepared.source());
            constructor |= occurrence.fact.callable_is_constructor;
            if return_type.is_none() {
                return_type = cpp_callable_declaration_return_type_node(
                    declaration,
                    prepared.source(),
                    &ancestry,
                );
            }
        }

        // C++ [dcl.attr.nodiscard] describes the diagnostic in terms of a
        // call to a function "declared with the nodiscard attribute". For a
        // virtual family, the base declaration is the static declaration that
        // supplies that contract; every resolved override still has to pass
        // this same proof before the dispatcher can publish a finding. The
        // base declaration is also sufficient when the dispatcher cannot name
        // every override, because the static call contract is unchanged.
        let base_attribute = match self.callable_or_base_attribute(target, callable_attribute) {
            Ok(value) => value,
            Err(reason) => return CppNativeObligationProof::Open(reason),
        };
        if callable_attribute {
            return CppNativeObligationProof::Obligation(NativeResultObligation::must_use_value(
                0,
                NativeResultObligationBasis::StaticSignature,
            ));
        }
        if base_attribute {
            return CppNativeObligationProof::BaseContract(NativeResultObligation::must_use_value(
                0,
                NativeResultObligationBasis::StaticSignature,
            ));
        }

        let Some(return_type) = return_type else {
            return if constructor {
                CppNativeObligationProof::NoObligation
            } else {
                CppNativeObligationProof::Open("native_return_type_unknown")
            };
        };
        let Some(identity) = self.return_type_identity(target) else {
            return if constructor {
                CppNativeObligationProof::NoObligation
            } else {
                CppNativeObligationProof::Open("native_return_type_unknown")
            };
        };
        let Some(root) = identity.view(identity.root_id()) else {
            return CppNativeObligationProof::Open("native_return_type_unknown");
        };
        if !matches!(
            root,
            StructuredTypeNodeView::Named(_) | StructuredTypeNodeView::Generic { .. }
        ) {
            return CppNativeObligationProof::NoObligation;
        }
        if is_primitive_return_type(return_type) {
            return CppNativeObligationProof::NoObligation;
        }
        if matches!(
            return_type.kind(),
            "class_specifier" | "struct_specifier" | "union_specifier" | "enum_specifier"
        ) {
            return if cpp_declaration_has_native_must_use_attribute(
                return_type,
                self.cpp
                    .prepared_syntax(self.token, target.source())
                    .expect("prepared target source remains available")
                    .source(),
            ) {
                CppNativeObligationProof::Obligation(NativeResultObligation::must_use_value(
                    0,
                    NativeResultObligationBasis::StaticSignature,
                ))
            } else {
                CppNativeObligationProof::NoObligation
            };
        }

        match self.return_type_declaration(target, return_type) {
            Ok(Some(type_unit)) => match self.type_has_native_attribute(&type_unit) {
                Ok(true) => {
                    CppNativeObligationProof::Obligation(NativeResultObligation::must_use_value(
                        0,
                        NativeResultObligationBasis::StaticSignature,
                    ))
                }
                Ok(false) => CppNativeObligationProof::NoObligation,
                Err(reason) => CppNativeObligationProof::Open(reason),
            },
            Ok(None) => CppNativeObligationProof::Open("native_return_type_unresolved"),
            Err(reason) => CppNativeObligationProof::Open(reason),
        }
    }

    fn return_type_identity(
        &self,
        target: &CodeUnit,
    ) -> Option<brokk_bifrost_core::analyzer::model::StructuredTypeIdentity> {
        let prepared = self.cpp.prepared_syntax(self.token, target.source())?;
        let declaration = exact_node(
            prepared.tree().root_node(),
            self.cpp
                .declaration_source_occurrences(self.token, target)?
                .first()?
                .range,
        )?;
        let ancestry =
            brokk_bifrost_core::analyzer::tree_walk::ParentIndex::new(prepared.tree().root_node());
        cpp_callable_declaration_return_type_identity(declaration, prepared.source(), &ancestry)
    }

    fn return_type_declaration(
        &self,
        target: &CodeUnit,
        return_type: Node<'_>,
    ) -> Result<Option<CodeUnit>, &'static str> {
        let prepared = self
            .cpp
            .prepared_syntax(self.token, target.source())
            .ok_or("native_target_source")?;
        let type_node = unwrap_type_descriptor(return_type);
        let roots = HashSet::from_iter([target.source().clone()]);
        let graph = CppGraphSource::from_source(self.cpp, self.token);
        let visibility = VisibilityIndex::build(
            self.cpp.read_capability(),
            self.cpp,
            self.token,
            &graph,
            &roots,
        );
        let imports = initialized_ordinary_type_imports(
            prepared.tree().root_node(),
            &graph,
            &visibility,
            target.source(),
            prepared.source(),
        );
        match resolve_type_node_lexically(
            type_node,
            &graph,
            &visibility,
            &imports,
            target.source(),
            prepared.source(),
        ) {
            LexicalTypeResolution::Resolved { unit, .. } if unit.is_class() => {
                if self
                    .cpp
                    .declaration_source_properties(self.token, &unit)
                    .is_some_and(|facts| facts.iter().any(|fact| fact.alias_target.is_some()))
                {
                    Err("native_return_type_alias")
                } else {
                    Ok(Some(unit))
                }
            }
            LexicalTypeResolution::Resolved { .. } => Ok(None),
            LexicalTypeResolution::Ambiguous => Err("native_return_type_ambiguous"),
            LexicalTypeResolution::Missing => Ok(None),
        }
    }

    fn type_has_native_attribute(&self, type_unit: &CodeUnit) -> Result<bool, &'static str> {
        let Some(occurrences) = self
            .cpp
            .declaration_source_occurrences(self.token, type_unit)
        else {
            return Err("native_return_type_declaration");
        };
        if occurrences.is_empty() {
            return Err("native_return_type_declaration");
        }
        let mut found = false;
        for occurrence in occurrences {
            let Some(prepared) = self.cpp.prepared_syntax(self.token, type_unit.source()) else {
                return Err("native_return_type_source");
            };
            let Some(declaration) = exact_node(prepared.tree().root_node(), occurrence.range)
            else {
                return Err("native_return_type_declaration");
            };
            if has_recovery_ancestor(declaration) {
                return Err("native_return_type_recovered");
            }
            found |= cpp_declaration_has_native_must_use_attribute(declaration, prepared.source());
        }
        Ok(found)
    }

    fn callable_or_base_attribute(
        &self,
        target: &CodeUnit,
        own_attribute: bool,
    ) -> Result<bool, &'static str> {
        if own_attribute || !target.owner_is_type_scope() {
            return Ok(false);
        }
        let Some(owner) = self.cpp.parent_of(target) else {
            return Err("native_virtual_owner");
        };
        let Some(hierarchy) = self.cpp.type_hierarchy_provider() else {
            return Err("native_virtual_hierarchy");
        };
        for ancestor in hierarchy.get_ancestors(&owner) {
            for candidate in self.cpp.get_direct_children(&ancestor) {
                if !candidate.is_function()
                    || candidate.identifier() != target.identifier()
                    || !callable_shapes_agree(self.cpp, self.token, target, &candidate)
                {
                    continue;
                }
                let Some(occurrences) = self
                    .cpp
                    .declaration_source_occurrences(self.token, &candidate)
                else {
                    return Err("native_virtual_declaration");
                };
                for occurrence in occurrences {
                    let Some(prepared) = self.cpp.prepared_syntax(self.token, candidate.source())
                    else {
                        return Err("native_virtual_source");
                    };
                    let Some(declaration) =
                        exact_node(prepared.tree().root_node(), occurrence.range)
                    else {
                        return Err("native_virtual_declaration");
                    };
                    if cpp_declaration_has_native_must_use_attribute(declaration, prepared.source())
                    {
                        return Ok(true);
                    }
                }
            }
        }
        Ok(false)
    }
}

/// Prove the native B4 obligation for one resolved C or C++ callable.
pub fn cpp_native_result_obligation(
    analyzer: &dyn IAnalyzer,
    target: &CodeUnit,
    result_ordinal: u32,
) -> CppNativeObligationProof {
    let Some(cpp) = resolve_analyzer::<CppAnalyzer>(analyzer) else {
        return CppNativeObligationProof::Open("native_cpp_analyzer");
    };
    let scope = AnalyzerQueryScope::new(analyzer);
    let proof = CppNativeProof::new(cpp, scope.token());
    proof.target_obligation(target, result_ordinal)
}

fn exact_node<'tree>(root: Node<'tree>, range: Range) -> Option<Node<'tree>> {
    let node = root.named_descendant_for_byte_range(range.start_byte, range.end_byte)?;
    (node.start_byte() == range.start_byte && node.end_byte() == range.end_byte).then_some(node)
}

fn has_recovery_ancestor(mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent() {
        if parent.is_error() || parent.is_missing() {
            return true;
        }
        node = parent;
    }
    false
}

fn unwrap_type_descriptor(mut node: Node<'_>) -> Node<'_> {
    while node.kind() == "type_descriptor" {
        let Some(inner) = node
            .child_by_field_name("type")
            .or_else(|| node.named_child(0))
        else {
            break;
        };
        node = inner;
    }
    node
}

fn is_primitive_return_type(node: Node<'_>) -> bool {
    let node = unwrap_type_descriptor(node);
    node.kind() == "primitive_type"
}

fn callable_shapes_agree(
    cpp: &CppAnalyzer,
    token: QueryToken<'_>,
    left: &CodeUnit,
    right: &CodeUnit,
) -> bool {
    let Some(left_facts) = cpp.declaration_source_properties(token, left) else {
        return false;
    };
    let Some(right_facts) = cpp.declaration_source_properties(token, right) else {
        return false;
    };
    left_facts.iter().any(|left| {
        right_facts.iter().any(|right| {
            left.callable_identity_suffix == right.callable_identity_suffix
                && left.callable_comparable_shapes == right.callable_comparable_shapes
                && left.callable_is_template == right.callable_is_template
                && left.callable_comparable_shapes.is_some()
        })
    })
}
