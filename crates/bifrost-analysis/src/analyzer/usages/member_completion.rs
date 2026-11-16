use tree_sitter::Node;

use super::get_definition::parse_tree_for_language;
use crate::analyzer::common::language_for_file;
use crate::analyzer::semantic_model::SemanticModelSymbolKind;
use crate::analyzer::{CodeUnitType, Language, ProjectFile};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberCompletionSite {
    pub receiver_start_byte: usize,
    pub receiver_end_byte: usize,
    pub prefix: String,
}

pub fn member_completion_site(
    file: &ProjectFile,
    source: &str,
    cursor_byte: usize,
) -> Option<MemberCompletionSite> {
    let language = language_for_file(file);
    let tree = parse_tree_for_language(file, language, source)?;
    member_completion_site_in_tree(language, source, tree.root_node(), cursor_byte).or_else(|| {
        let mut repaired = source.to_string();
        repaired.insert_str(cursor_byte, "__bifrost_completion_probe");
        let repaired_tree = parse_tree_for_language(file, language, &repaired)?;
        member_completion_site_in_tree(language, source, repaired_tree.root_node(), cursor_byte)
    })
}

fn member_completion_site_in_tree(
    language: Language,
    source: &str,
    root: Node<'_>,
    cursor_byte: usize,
) -> Option<MemberCompletionSite> {
    if cursor_byte == 0 || cursor_byte > source.len() {
        return None;
    }
    let focus = root.descendant_for_byte_range(cursor_byte - 1, cursor_byte)?;
    let access =
        ancestors_including_self(focus).find(|node| access_receiver(language, *node).is_some())?;
    let receiver = access_receiver(language, access)?;
    if receiver.end_byte() >= cursor_byte {
        return None;
    }
    let prefix_node = access_member(language, access)
        .filter(|member| member.start_byte() < cursor_byte && cursor_byte <= member.end_byte());
    let prefix = prefix_node
        .and_then(|member| source.get(member.start_byte()..cursor_byte))
        .unwrap_or("");
    if !prefix
        .bytes()
        .all(brokk_bifrost_core::text_utils::is_ident_byte)
    {
        return None;
    }
    Some(MemberCompletionSite {
        receiver_start_byte: receiver.start_byte(),
        receiver_end_byte: receiver.end_byte(),
        prefix: prefix.to_string(),
    })
}

fn ancestors_including_self(node: Node<'_>) -> impl Iterator<Item = Node<'_>> {
    std::iter::successors(Some(node), Node::parent)
}

fn access_receiver(language: Language, node: Node<'_>) -> Option<Node<'_>> {
    let field = match language {
        Language::Rust => "value",
        Language::Go => "operand",
        Language::JavaScript | Language::TypeScript => "object",
        Language::Java | Language::Kotlin | Language::Scala | Language::CSharp => "object",
        Language::Python => "object",
        Language::Php => "object",
        Language::Ruby => "receiver",
        Language::Cpp => "argument",
        Language::None => return None,
    };
    let expected = match language {
        Language::Rust => &["field_expression"][..],
        Language::Go => &["selector_expression"],
        Language::JavaScript | Language::TypeScript => &["member_expression"],
        Language::Java => &["field_access", "method_invocation"],
        Language::Kotlin => &["navigation_expression"],
        Language::Scala => &["field_expression", "call_expression"],
        Language::CSharp => &["member_access_expression", "conditional_access_expression"],
        Language::Python => &["attribute"],
        Language::Php => &[
            "member_access_expression",
            "nullsafe_member_access_expression",
        ],
        Language::Ruby => &["call"],
        Language::Cpp => &["field_expression"],
        Language::None => &[],
    };
    expected
        .contains(&node.kind())
        .then(|| node.child_by_field_name(field))
        .flatten()
}

fn access_member(language: Language, node: Node<'_>) -> Option<Node<'_>> {
    let field = match language {
        Language::Rust => "field",
        Language::Go => "field",
        Language::JavaScript | Language::TypeScript => "property",
        Language::Java | Language::Kotlin | Language::Scala => "field",
        Language::CSharp => "name",
        Language::Python => "attribute",
        Language::Php => "name",
        Language::Ruby => "method",
        Language::Cpp => "field",
        Language::None => return None,
    };
    node.child_by_field_name(field)
}

pub fn semantic_completion_kind(kind: SemanticModelSymbolKind) -> CodeUnitType {
    match kind {
        SemanticModelSymbolKind::Class
        | SemanticModelSymbolKind::Annotation
        | SemanticModelSymbolKind::Delegate
        | SemanticModelSymbolKind::Interface
        | SemanticModelSymbolKind::Trait
        | SemanticModelSymbolKind::Struct
        | SemanticModelSymbolKind::Union
        | SemanticModelSymbolKind::Enum
        | SemanticModelSymbolKind::Record
        | SemanticModelSymbolKind::TypeAlias => CodeUnitType::Class,
        SemanticModelSymbolKind::Constructor
        | SemanticModelSymbolKind::Method
        | SemanticModelSymbolKind::Function => CodeUnitType::Function,
        SemanticModelSymbolKind::Field
        | SemanticModelSymbolKind::Property
        | SemanticModelSymbolKind::Constant
        | SemanticModelSymbolKind::Static
        | SemanticModelSymbolKind::Event => CodeUnitType::Field,
        SemanticModelSymbolKind::Module => CodeUnitType::Module,
        SemanticModelSymbolKind::Macro => CodeUnitType::Macro,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;
    use tempfile::TempDir;

    fn site(path: &str, source: &str, cursor: usize) -> MemberCompletionSite {
        let temp = TempDir::new().unwrap();
        let file = ProjectFile::new(temp.path(), path);
        member_completion_site(&file, source, cursor).unwrap_or_else(|| {
            let language = language_for_file(&file);
            let tree = parse_tree_for_language(&file, language, source).unwrap();
            panic!("{}", tree.root_node().to_sexp())
        })
    }

    #[test]
    #[hardwon(
        "#3422: Parses a real incomplete Rust field expression and verifies the adapter reads its receiver with an empty member prefix"
    )]
    fn incomplete_rust_field_expression_exposes_receiver_and_empty_prefix() {
        let source = "fn main() { let xs = vec![1i32, 2, 3]; xs.\n}";
        let cursor = source.find("xs.\n").unwrap() + "xs.".len();
        let result = site("src/main.rs", source, cursor);
        assert_eq!(
            &source[result.receiver_start_byte..result.receiver_end_byte],
            "xs"
        );
        assert_eq!(result.prefix, "");
    }

    #[test]
    #[hardwon(
        "#3422: Parses recovered Go selector syntax and verifies both receiver range and the written partial member prefix"
    )]
    fn incomplete_go_selector_exposes_receiver_and_prefix() {
        let source = "package main\nfunc f(xs Widget) { xs.Ru\n}";
        let cursor = source.find("xs.Ru\n").unwrap() + "xs.Ru".len();
        let result = site("main.go", source, cursor);
        assert_eq!(
            &source[result.receiver_start_byte..result.receiver_end_byte],
            "xs"
        );
        assert_eq!(result.prefix, "Ru");
    }

    #[test]
    #[hardwon(
        "#3422: Parses a real trailing Go selector and checks the receiver survives when no member identifier exists yet"
    )]
    fn incomplete_go_selector_exposes_receiver_and_empty_prefix() {
        let source = "package main\nfunc f() { os.\n}";
        let cursor = source.find("os.\n").unwrap() + "os.".len();
        let result = site("main.go", source, cursor);
        assert_eq!(
            &source[result.receiver_start_byte..result.receiver_end_byte],
            "os"
        );
        assert_eq!(result.prefix, "");
    }
}
