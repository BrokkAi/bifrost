//! Analyzer-independent language rules.

use brokk_bifrost_core::analyzer::Language;
use brokk_bifrost_core::analyzer::language_knowledge::LanguageKnowledge;
use brokk_bifrost_core::analyzer::language_knowledge::ParserFlavor;
use brokk_bifrost_core::analyzer::language_knowledge::ScalarObjectFieldKind;
use brokk_bifrost_core::analyzer::structural::spec::StructuralSpec;

/// Rust syntax and static language rules.
pub struct RustKnowledge;

impl LanguageKnowledge for RustKnowledge {
    fn unmarked_member_stores(
        &self,
    ) -> brokk_bifrost_core::analyzer::language_knowledge::UnmarkedMemberStores {
        brokk_bifrost_core::analyzer::language_knowledge::UnmarkedMemberStores::Followable
    }

    fn scalar_object_field_is_copy(&self, kind: ScalarObjectFieldKind) -> bool {
        matches!(
            kind,
            ScalarObjectFieldKind::Boolean | ScalarObjectFieldKind::Number
        )
    }
    fn models_compose_from_catalog_rows(&self) -> bool {
        true
    }

    fn declared_type_is_referent_immutable(&self, canonical_type: &str) -> bool {
        matches!(
            canonical_type,
            "bool"
                | "char"
                | "u8"
                | "u16"
                | "u32"
                | "u64"
                | "u128"
                | "usize"
                | "i8"
                | "i16"
                | "i32"
                | "i64"
                | "i128"
                | "isize"
                | "f32"
                | "f64"
                | "&str"
        )
    }

    fn unbound_call_passes_receiver_as_argument(&self) -> bool {
        true
    }

    fn generated_items_cannot_shadow_bindings(&self) -> bool {
        true
    }

    fn aggregate_member_initializer<'t>(
        &self,
        node: tree_sitter::Node<'t>,
    ) -> Option<(tree_sitter::Node<'t>, tree_sitter::Node<'t>)> {
        match node.kind() {
            "field_initializer" => Some((
                node.child_by_field_name("field")?,
                node.child_by_field_name("value")?,
            )),
            "shorthand_field_initializer" => {
                let ident = node.named_child(0)?;
                Some((ident, ident))
            }
            _ => None,
        }
    }

    fn unmodeled_field_access_macros<'t>(
        &self,
        _root: tree_sitter::Node<'t>,
        owner: Option<tree_sitter::Node<'t>>,
        field: Option<tree_sitter::Node<'t>>,
        source: &str,
    ) -> Vec<String> {
        const OWNERS: &[&str] = &["struct_item", "enum_item", "union_item"];
        let mut owner = owner.or(field).map(crate::syntax::unwrap_attributes);
        while let Some(node) = owner
            && !OWNERS.contains(&node.kind())
        {
            owner = node.parent();
        }
        let Some(owner) = owner else {
            return Vec::new();
        };
        let mut field = field;
        while let Some(node) = field
            && node.kind() != "field_declaration"
        {
            field = node.parent().filter(|parent| parent.id() != owner.id());
        }
        crate::resolution::rust_unmodeled_field_access_macros(owner, field, source)
    }

    fn language(&self) -> Language {
        Language::Rust
    }

    fn qualified_call_separator(&self) -> &'static str {
        "::"
    }

    fn parser_language(&self, _flavor: ParserFlavor) -> tree_sitter::Language {
        tree_sitter_rust::LANGUAGE.into()
    }

    fn structural_spec(&self) -> &'static dyn StructuralSpec {
        &crate::structural::RUST_STRUCTURAL_SPEC
    }

    fn highlight_query(&self) -> Option<&'static str> {
        Some(tree_sitter_rust::HIGHLIGHTS_QUERY)
    }
}
