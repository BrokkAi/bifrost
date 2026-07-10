use lsp_types::{
    SemanticToken, SemanticTokenModifier, SemanticTokenType, SemanticTokens, SemanticTokensLegend,
    SemanticTokensParams, SemanticTokensResult,
};
use tree_sitter::Node;

use crate::analyzer::common::{is_unparseable_source, language_for_file};
use crate::analyzer::declaration_range::DeclarationNameRangeContext;
use crate::analyzer::usages::get_definition::{
    DefinitionLookupRequest, resolve_definition_batch_with_source,
};
use crate::analyzer::{CodeUnitType, Language, Project, Range as ByteRange, WorkspaceAnalyzer};
use crate::hash::HashSet;
use crate::lsp::conversion::byte_offset_to_position;
use crate::lsp::handlers::util::read_document_for_uri;

const NAMESPACE_TOKEN: u32 = 0;
const TYPE_TOKEN: u32 = 1;
const FUNCTION_TOKEN: u32 = 2;
const PROPERTY_TOKEN: u32 = 3;
const MACRO_TOKEN: u32 = 4;
const DECLARATION_MODIFIER: u32 = 1;

pub(crate) fn legend() -> SemanticTokensLegend {
    SemanticTokensLegend {
        token_types: vec![
            SemanticTokenType::NAMESPACE,
            SemanticTokenType::TYPE,
            SemanticTokenType::FUNCTION,
            SemanticTokenType::PROPERTY,
            SemanticTokenType::MACRO,
        ],
        token_modifiers: vec![SemanticTokenModifier::DECLARATION],
    }
}

pub fn handle(
    workspace: &WorkspaceAnalyzer,
    project: &dyn Project,
    params: &SemanticTokensParams,
) -> Option<SemanticTokensResult> {
    Some(SemanticTokensResult::Tokens(build_tokens(
        workspace, project, params,
    )))
}

fn build_tokens(
    workspace: &WorkspaceAnalyzer,
    project: &dyn Project,
    params: &SemanticTokensParams,
) -> SemanticTokens {
    let Some((file, content, line_starts)) =
        read_document_for_uri(project, &params.text_document.uri)
    else {
        return empty_tokens();
    };
    let language = language_for_file(&file);
    if language == Language::None || is_unparseable_source(&content) {
        return empty_tokens();
    }

    let context = DeclarationNameRangeContext::new(&file, content);
    let Some(root) = context.root_node() else {
        return empty_tokens();
    };
    let analyzer = workspace.analyzer();

    let mut declarations = Vec::new();
    for code_unit in analyzer.declarations(&file) {
        let Some(token_type) = token_type_for_kind(code_unit.kind()) else {
            continue;
        };
        for range in context.name_ranges(analyzer, code_unit) {
            declarations.push(AbsoluteToken::new(range, token_type, DECLARATION_MODIFIER));
        }
    }
    declarations.sort_unstable();
    declarations.dedup();

    let candidate_ranges = reference_candidate_ranges(root, language);
    let declaration_ranges: HashSet<_> = declarations.iter().map(AbsoluteToken::key).collect();
    let unresolved_ranges: Vec<_> = candidate_ranges
        .into_iter()
        .filter(|range| !declaration_ranges.contains(&(range.start_byte, range.end_byte)))
        .collect();

    let requests = unresolved_ranges
        .iter()
        .map(|range| DefinitionLookupRequest {
            file: file.clone(),
            line: None,
            column: None,
            start_byte: Some(range.start_byte),
            end_byte: Some(range.end_byte),
        })
        .collect();
    let source = context.shared_content();
    let outcomes = resolve_definition_batch_with_source(analyzer, requests, file, source);

    let mut references = Vec::new();
    for (range, outcome) in unresolved_ranges.into_iter().zip(outcomes) {
        let Some(token_type) = common_definition_token_type(&outcome.definitions) else {
            continue;
        };
        references.push(AbsoluteToken::new(range, token_type, 0));
    }
    references.sort_unstable();
    references.dedup();
    references.retain(|reference| !overlaps_sorted(&declarations, reference));

    declarations.extend(references);
    declarations.sort_unstable();
    declarations.dedup();
    let absolute = discard_overlaps(declarations);

    SemanticTokens {
        result_id: None,
        data: encode_relative_tokens(context.content(), &line_starts, &absolute),
    }
}

fn empty_tokens() -> SemanticTokens {
    SemanticTokens {
        result_id: None,
        data: Vec::new(),
    }
}

fn token_type_for_kind(kind: CodeUnitType) -> Option<u32> {
    match kind {
        CodeUnitType::Module => Some(NAMESPACE_TOKEN),
        CodeUnitType::Class => Some(TYPE_TOKEN),
        CodeUnitType::Function => Some(FUNCTION_TOKEN),
        CodeUnitType::Field => Some(PROPERTY_TOKEN),
        CodeUnitType::Macro => Some(MACRO_TOKEN),
        CodeUnitType::FileScope => None,
    }
}

fn common_definition_token_type(definitions: &[crate::analyzer::CodeUnit]) -> Option<u32> {
    let mut common = None;
    for definition in definitions {
        let token_type = token_type_for_kind(definition.kind())?;
        match common {
            Some(existing) if existing != token_type => return None,
            None => common = Some(token_type),
            _ => {}
        }
    }
    common
}

fn reference_candidate_ranges(root: Node<'_>, language: Language) -> Vec<ByteRange> {
    let mut ranges = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.named_child_count() == 0
            && is_reference_identifier_node(language, node.kind())
            && node.start_byte() < node.end_byte()
        {
            ranges.push(ByteRange {
                start_byte: node.start_byte(),
                end_byte: node.end_byte(),
                start_line: node.start_position().row,
                end_line: node.end_position().row,
            });
        }

        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    ranges.sort_unstable();
    ranges.dedup();
    ranges
}

fn is_reference_identifier_node(language: Language, kind: &str) -> bool {
    if language == Language::None {
        return false;
    }
    if kind == "identifier" || kind.ends_with("_identifier") {
        return true;
    }
    match language {
        Language::Php => kind == "name",
        Language::Ruby => matches!(
            kind,
            "constant" | "instance_variable" | "class_variable" | "global_variable"
        ),
        _ => false,
    }
}

fn discard_overlaps(tokens: Vec<AbsoluteToken>) -> Vec<AbsoluteToken> {
    let mut accepted: Vec<AbsoluteToken> = Vec::with_capacity(tokens.len());
    for token in tokens {
        if accepted
            .last()
            .is_some_and(|previous| previous.end_byte > token.start_byte)
        {
            continue;
        }
        accepted.push(token);
    }
    accepted
}

fn overlaps_sorted(tokens: &[AbsoluteToken], candidate: &AbsoluteToken) -> bool {
    let index = tokens.partition_point(|token| token.end_byte <= candidate.start_byte);
    tokens
        .get(index)
        .is_some_and(|token| token.start_byte < candidate.end_byte)
}

fn encode_relative_tokens(
    content: &str,
    line_starts: &[usize],
    tokens: &[AbsoluteToken],
) -> Vec<SemanticToken> {
    let mut encoded = Vec::with_capacity(tokens.len());
    let mut previous_line = 0;
    let mut previous_start = 0;
    for token in tokens {
        let start = byte_offset_to_position(content, line_starts, token.start_byte);
        let end = byte_offset_to_position(content, line_starts, token.end_byte);
        if start.line != end.line || start.character >= end.character {
            continue;
        }
        let delta_line = start.line - previous_line;
        let delta_start = if delta_line == 0 {
            start.character - previous_start
        } else {
            start.character
        };
        encoded.push(SemanticToken {
            delta_line,
            delta_start,
            length: end.character - start.character,
            token_type: token.token_type,
            token_modifiers_bitset: token.modifiers,
        });
        previous_line = start.line;
        previous_start = start.character;
    }
    encoded
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct AbsoluteToken {
    start_byte: usize,
    end_byte: usize,
    token_type: u32,
    modifiers: u32,
}

impl AbsoluteToken {
    fn new(range: ByteRange, token_type: u32, modifiers: u32) -> Self {
        Self {
            start_byte: range.start_byte,
            end_byte: range.end_byte,
            token_type,
            modifiers,
        }
    }

    fn key(&self) -> (usize, usize) {
        (self.start_byte, self.end_byte)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::usages::get_definition::parse_tree_for_language;
    use lsp_types::SemanticTokenModifier;
    use std::path::PathBuf;

    fn range(start_byte: usize, end_byte: usize) -> ByteRange {
        ByteRange {
            start_byte,
            end_byte,
            start_line: 0,
            end_line: 0,
        }
    }

    #[test]
    fn legend_is_stable_and_matches_code_unit_mapping() {
        let legend = legend();
        assert_eq!(
            legend
                .token_types
                .iter()
                .map(SemanticTokenType::as_str)
                .collect::<Vec<_>>(),
            ["namespace", "type", "function", "property", "macro"]
        );
        assert_eq!(
            legend
                .token_modifiers
                .iter()
                .map(SemanticTokenModifier::as_str)
                .collect::<Vec<_>>(),
            ["declaration"]
        );
        assert_eq!(token_type_for_kind(CodeUnitType::Module), Some(0));
        assert_eq!(token_type_for_kind(CodeUnitType::Class), Some(1));
        assert_eq!(token_type_for_kind(CodeUnitType::Function), Some(2));
        assert_eq!(token_type_for_kind(CodeUnitType::Field), Some(3));
        assert_eq!(token_type_for_kind(CodeUnitType::Macro), Some(4));
        assert_eq!(token_type_for_kind(CodeUnitType::FileScope), None);
    }

    #[test]
    fn relative_encoding_counts_utf16_and_handles_crlf() {
        let source = "// 😀\r\nclass Café {\r\n  Café value;\r\n}\r\n";
        let class_start = source.find("Café").expect("class identifier");
        let field_type_start = source[class_start + 1..]
            .find("Café")
            .map(|offset| class_start + 1 + offset)
            .expect("field type");
        let tokens = vec![
            AbsoluteToken::new(
                range(class_start, class_start + "Café".len()),
                TYPE_TOKEN,
                1,
            ),
            AbsoluteToken::new(
                range(field_type_start, field_type_start + "Café".len()),
                TYPE_TOKEN,
                0,
            ),
        ];
        let encoded = encode_relative_tokens(
            source,
            &crate::text_utils::compute_line_starts(source),
            &tokens,
        );
        assert_eq!(
            encoded,
            vec![
                SemanticToken {
                    delta_line: 1,
                    delta_start: 6,
                    length: 4,
                    token_type: TYPE_TOKEN,
                    token_modifiers_bitset: 1,
                },
                SemanticToken {
                    delta_line: 1,
                    delta_start: 2,
                    length: 4,
                    token_type: TYPE_TOKEN,
                    token_modifiers_bitset: 0,
                },
            ]
        );
    }

    #[test]
    fn declaration_overlap_wins_and_output_is_deterministic() {
        let reference = AbsoluteToken::new(range(4, 8), TYPE_TOKEN, 0);
        let declaration = AbsoluteToken::new(range(4, 8), TYPE_TOKEN, DECLARATION_MODIFIER);
        let later = AbsoluteToken::new(range(12, 16), FUNCTION_TOKEN, 0);

        let mut declarations = vec![declaration];
        let mut references = vec![later, reference];
        references.sort_unstable();
        references.retain(|candidate| !overlaps_sorted(&declarations, candidate));
        declarations.extend(references);
        declarations.sort_unstable();

        assert_eq!(declarations, [declaration, later]);
    }

    #[test]
    fn candidate_ranges_come_from_structured_nodes_in_each_language() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        let fixtures = [
            (Language::Java, "A.java", "class A { void f() { f(); } }"),
            (
                Language::Go,
                "a.go",
                "package p\ntype A struct{}\nfunc f() { f() }\n",
            ),
            (Language::Cpp, "a.cpp", "class A {}; void f() { f(); }"),
            (
                Language::JavaScript,
                "a.js",
                "class A { f() { this.f(); } }",
            ),
            (
                Language::TypeScript,
                "a.ts",
                "class A { f(): void { this.f(); } }",
            ),
            (
                Language::Python,
                "a.py",
                "class A:\n    def f(self):\n        self.f()\n",
            ),
            (Language::Rust, "a.rs", "struct A; fn f() { f(); }"),
            (
                Language::Php,
                "a.php",
                "<?php class A { function f() { $this->f(); } }",
            ),
            (
                Language::Scala,
                "A.scala",
                "class A { def f(): Unit = f() }",
            ),
            (Language::CSharp, "A.cs", "class A { void F() { F(); } }"),
            (
                Language::Ruby,
                "a.rb",
                "class A\n  def f\n    f\n  end\nend\n",
            ),
        ];

        for (language, path, source) in fixtures {
            let file = crate::analyzer::ProjectFile::new(&root, PathBuf::from(path));
            let tree = parse_tree_for_language(&file, language, source)
                .unwrap_or_else(|| panic!("failed to parse {language:?}"));
            let ranges = reference_candidate_ranges(tree.root_node(), language);
            assert!(
                !ranges.is_empty(),
                "expected structured identifier candidates for {language:?}"
            );
        }
        assert!(is_reference_identifier_node(Language::Php, "name"));
        assert!(is_reference_identifier_node(Language::Ruby, "constant"));
        assert!(!is_reference_identifier_node(Language::None, "identifier"));
        assert!(!is_reference_identifier_node(
            Language::Java,
            "string_literal"
        ));
    }
}
