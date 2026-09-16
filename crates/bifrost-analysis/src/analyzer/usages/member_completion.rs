use std::sync::Arc;

use tree_sitter::Node;

use super::get_definition::{go_imported_package_at_range, parse_tree_for_language};
use super::get_type::{TypeLookupRequest, TypeLookupStatus, resolve_type_batch};
use crate::analyzer::common::language_for_file;
use crate::analyzer::semantic_model::{
    SemanticModelCompleteness, SemanticModelOverlayDisposition, SemanticModelSymbol,
    SemanticModelSymbolKind,
};
use crate::analyzer::{
    AnalyzerDefinitionLookup, BoundedDefinitionLookup, CodeUnit, CodeUnitType, IAnalyzer, Language,
    ProjectFile, sort_units,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberCompletionSite {
    pub receiver_start_byte: usize,
    pub receiver_end_byte: usize,
    pub prefix: String,
}

#[derive(Debug, Clone)]
pub enum MemberCompletionCandidate {
    Workspace(CodeUnit),
    SemanticModel {
        name: String,
        kind: SemanticModelSymbolKind,
        signature: Option<String>,
    },
}

impl MemberCompletionCandidate {
    pub fn name(&self) -> &str {
        match self {
            Self::Workspace(unit) => unit.terminal_name(),
            Self::SemanticModel { name, .. } => name,
        }
    }
}

#[derive(Debug, Clone)]
pub struct MemberCompletionResult {
    pub candidates: Vec<MemberCompletionCandidate>,
    pub incomplete: bool,
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

pub fn complete_members(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: Arc<String>,
    site: &MemberCompletionSite,
) -> MemberCompletionResult {
    let [outcome] = resolve_type_batch(
        analyzer,
        vec![TypeLookupRequest {
            file: file.clone(),
            source: Some(Arc::clone(&source)),
            line: None,
            column: None,
            start_byte: Some(site.receiver_start_byte),
            end_byte: Some(site.receiver_end_byte),
        }],
    )
    .try_into()
    .expect("one member-completion type request returns one outcome");

    let mut incomplete = outcome.status != TypeLookupStatus::Resolved || outcome.types.len() != 1;
    let go_import_path = (language_for_file(file) == Language::Go)
        .then(|| {
            go_imported_package_at_range(
                analyzer,
                file,
                source.as_str(),
                site.receiver_start_byte,
                site.receiver_end_byte,
            )
        })
        .flatten();
    let receiver_is_go_package = go_import_path.is_some();
    let lookup = AnalyzerDefinitionLookup::new(analyzer, language_for_file(file));
    let overlay = analyzer.semantic_model_overlay();
    let mut workspace = Vec::new();
    let mut modeled = Vec::new();
    let mut modeled_owner_ids = Vec::new();

    for resolved_type in outcome.types {
        for definition in resolved_type.definitions {
            workspace.extend(lookup.fqn_direct_children(&definition.fq_name()));
        }
        if let Some(owner_id) = resolved_type.semantic_model_id {
            modeled_owner_ids.push(owner_id);
        }
    }

    if let Some(import_path) = go_import_path {
        let Some(overlay) = overlay.as_ref() else {
            incomplete = true;
            return MemberCompletionResult {
                candidates: Vec::new(),
                incomplete,
            };
        };
        let owners = overlay.symbols_named(&import_path);
        if owners.disposition != SemanticModelOverlayDisposition::Unique
            || owners.records.len() != 1
        {
            incomplete = true;
        } else {
            let owner = owners.records[0];
            if owner.language == "go"
                && owner.kind == SemanticModelSymbolKind::Module
                && owner.owner_id.is_none()
                && !owner.provenance.ambiguous
            {
                modeled_owner_ids.push(owner.id.clone());
            } else {
                incomplete = true;
            }
        }
    }

    modeled_owner_ids.sort();
    modeled_owner_ids.dedup();
    if receiver_is_go_package && modeled_owner_ids.len() == 1 {
        incomplete = false;
    }
    for owner_id in modeled_owner_ids {
        let Some(overlay) = overlay.as_ref() else {
            incomplete = true;
            continue;
        };
        let owners = overlay.symbols_with_id(&owner_id);
        if owners.disposition != SemanticModelOverlayDisposition::Unique
            || owners.records.len() != 1
        {
            incomplete = true;
            continue;
        }
        let owner = owners.records[0];
        let namespace_owner = owner.kind == SemanticModelSymbolKind::Module;
        let members = overlay.members_of(&owner_id);
        incomplete |= owner.provenance.completeness != SemanticModelCompleteness::Complete
            || members.disposition != SemanticModelOverlayDisposition::Unique
            || members.records.iter().any(|member| {
                member.provenance.completeness != SemanticModelCompleteness::Complete
                    || member.provenance.ambiguous
            });
        modeled.extend(
            members
                .records
                .into_iter()
                .filter(|member| {
                    member.externally_visible()
                        && if namespace_owner {
                            member.is_static()
                        } else {
                            member.has_receiver()
                        }
                })
                .cloned(),
        );
    }

    sort_units(&mut workspace);
    workspace.dedup();
    modeled.sort_by(|left, right| {
        (&left.name, &left.signature, &left.id).cmp(&(&right.name, &right.signature, &right.id))
    });
    modeled.dedup_by(|left, right| left.id == right.id);

    let prefix = site.prefix.as_str();
    let mut candidates = workspace
        .into_iter()
        .filter(|unit| unit.terminal_name().starts_with(prefix))
        .map(MemberCompletionCandidate::Workspace)
        .chain(
            modeled
                .into_iter()
                .filter(|member| member.name.starts_with(prefix))
                .map(semantic_candidate),
        )
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| left.name().cmp(right.name()));
    candidates.dedup_by(|left, right| left.name() == right.name());

    MemberCompletionResult {
        candidates,
        incomplete,
    }
}

fn semantic_candidate(symbol: SemanticModelSymbol) -> MemberCompletionCandidate {
    MemberCompletionCandidate::SemanticModel {
        name: symbol.name,
        kind: symbol.kind,
        signature: symbol.signature,
    }
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
    if !prefix.bytes().all(is_identifier_byte) {
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

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
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
