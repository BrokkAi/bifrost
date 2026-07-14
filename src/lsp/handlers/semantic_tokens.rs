use crate::analyzer::common::{is_unparseable_source, language_for_file};
use crate::analyzer::declaration_range::DeclarationNameRangeContext;
#[cfg(test)]
use crate::analyzer::reference_candidates::reference_candidate_ranges;
use crate::analyzer::reference_candidates::{
    ReferenceCandidateRanges, semantic_token_candidate_ranges,
};
use crate::analyzer::usages::get_definition::{
    DefinitionLookupRequest, resolve_definition_batch_with_source,
};
use crate::analyzer::{
    CodeUnitType, IAnalyzer, Language, Project, Range as ByteRange, WorkspaceAnalyzer,
};
use crate::hash::HashSet;
use crate::lsp::conversion::byte_offset_to_position;
use crate::lsp::handlers::util::read_document_for_uri;
use lsp_types::{
    SemanticToken, SemanticTokenModifier, SemanticTokenType, SemanticTokens, SemanticTokensLegend,
    SemanticTokensParams, SemanticTokensResult,
};

const NAMESPACE_TOKEN: u32 = 0;
const TYPE_TOKEN: u32 = 1;
const FUNCTION_TOKEN: u32 = 2;
const PROPERTY_TOKEN: u32 = 3;
const MACRO_TOKEN: u32 = 4;
const DECLARATION_MODIFIER: u32 = 1;
const MAX_SEMANTIC_TOKEN_SOURCE_BYTES: usize = 1_000_000;
const MAX_SEMANTIC_TOKEN_CANDIDATES: usize = 10_000;
const MAX_GO_REFERENCE_WORKSPACE_FILES: usize = 64;
const MAX_GO_REFERENCE_WORKSPACE_SOURCE_BYTES: usize = 2_000_000;

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
    if language == Language::None
        || !source_within_budget(&content)
        || is_unparseable_source(&content)
    {
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
        for range in context.name_ranges(analyzer, &code_unit) {
            declarations.push(AbsoluteToken::new(range, token_type, DECLARATION_MODIFIER));
        }
    }
    declarations.sort_unstable();
    declarations.dedup();

    let candidate_ranges =
        match semantic_token_candidate_ranges(root, language, MAX_SEMANTIC_TOKEN_CANDIDATES) {
            ReferenceCandidateRanges::Complete(ranges) => ranges,
            ReferenceCandidateRanges::LimitExceeded { .. } => return empty_tokens(),
        };
    let declaration_ranges: HashSet<_> = declarations.iter().map(AbsoluteToken::key).collect();
    let unresolved_ranges: Vec<_> = if reference_resolution_within_budget(analyzer, language) {
        candidate_ranges
            .into_iter()
            .filter(|range| !declaration_ranges.contains(&(range.start_byte, range.end_byte)))
            .collect()
    } else {
        Vec::new()
    };

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

fn source_within_budget(content: &str) -> bool {
    content.len() <= MAX_SEMANTIC_TOKEN_SOURCE_BYTES
}

fn reference_resolution_within_budget(analyzer: &dyn IAnalyzer, language: Language) -> bool {
    if language != Language::Go {
        return true;
    }
    go_workspace_sizes_within_budget(
        analyzer
            .analyzed_files()
            .into_iter()
            .filter(|file| language_for_file(file) == Language::Go)
            .map(|file| analyzer.indexed_source(&file).map(|source| source.len())),
    )
}

fn go_workspace_sizes_within_budget(sizes: impl IntoIterator<Item = Option<usize>>) -> bool {
    let mut file_count = 0;
    let mut source_bytes = 0_usize;
    for size in sizes {
        file_count += 1;
        if file_count > MAX_GO_REFERENCE_WORKSPACE_FILES {
            return false;
        }
        let Some(size) = size else {
            return false;
        };
        let Some(next_source_bytes) = source_bytes.checked_add(size) else {
            return false;
        };
        source_bytes = next_source_bytes;
        if source_bytes > MAX_GO_REFERENCE_WORKSPACE_SOURCE_BYTES {
            return false;
        }
    }
    true
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
    fn semantic_token_candidates_come_from_structured_nodes_in_each_language() {
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
            let ReferenceCandidateRanges::Complete(ranges) = semantic_token_candidate_ranges(
                tree.root_node(),
                language,
                MAX_SEMANTIC_TOKEN_CANDIDATES,
            ) else {
                panic!("candidate budget exceeded for {language:?}");
            };
            assert!(
                !ranges.is_empty(),
                "expected structured identifier candidates for {language:?}"
            );
        }
        assert!(
            crate::analyzer::reference_candidates::is_reference_candidate_node(
                Language::Php,
                "name"
            )
        );
        assert!(
            crate::analyzer::reference_candidates::is_reference_candidate_node(
                Language::Ruby,
                "constant"
            )
        );
        assert!(
            !crate::analyzer::reference_candidates::is_reference_candidate_node(
                Language::None,
                "identifier"
            )
        );
        assert!(
            !crate::analyzer::reference_candidates::is_reference_candidate_node(
                Language::Java,
                "string_literal"
            )
        );
    }

    #[test]
    fn candidate_ranges_include_structured_non_identifier_references() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        let fixtures = [
            (
                Language::Cpp,
                "a.cpp",
                "struct Value { Value operator+(Value); ~Value(); }; void f(Value value) { value.operator+(value); value.~Value(); }",
                &["operator+", "~Value"][..],
            ),
            (
                Language::Rust,
                "a.rs",
                "mod parent { pub fn f() {} mod child { fn g() { self::g(); super::f(); crate::parent::f(); } } }",
                &["self", "super", "crate"][..],
            ),
            (
                Language::JavaScript,
                "a.js",
                "class A { f() { this.f(); } }",
                &["this"][..],
            ),
            (
                Language::TypeScript,
                "a.ts",
                "class A { f(): void { this.f(); } }",
                &["this"][..],
            ),
        ];

        for (language, path, source, expected) in fixtures {
            let file = crate::analyzer::ProjectFile::new(&root, PathBuf::from(path));
            let tree = parse_tree_for_language(&file, language, source)
                .unwrap_or_else(|| panic!("failed to parse {language:?}"));
            let ReferenceCandidateRanges::Complete(ranges) =
                crate::analyzer::reference_candidates::reference_candidate_ranges(
                    tree.root_node(),
                    language,
                    1_000,
                )
            else {
                panic!("candidate budget exceeded for {language:?}");
            };
            let candidate_texts = ranges
                .iter()
                .map(|range| &source[range.start_byte..range.end_byte])
                .collect::<Vec<_>>();
            for expected in expected {
                assert!(
                    candidate_texts.contains(expected),
                    "expected `{expected}` among {language:?} candidates: {candidate_texts:?}"
                );
            }

            let ReferenceCandidateRanges::Complete(semantic_ranges) =
                semantic_token_candidate_ranges(tree.root_node(), language, 1_000)
            else {
                panic!("semantic token budget exceeded for {language:?}");
            };
            let semantic_texts = semantic_ranges
                .iter()
                .map(|range| &source[range.start_byte..range.end_byte])
                .collect::<Vec<_>>();
            for expected in expected {
                assert!(
                    !semantic_texts.contains(expected),
                    "semantic-token frontier unexpectedly included `{expected}` for {language:?}"
                );
            }
        }
    }

    #[test]
    fn candidate_collection_stops_at_the_request_budget() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        let file = crate::analyzer::ProjectFile::new(&root, PathBuf::from("Many.java"));
        let mut source = String::from("class Many { void f() {\n");
        for _ in 0..=MAX_SEMANTIC_TOKEN_CANDIDATES {
            source.push_str("f();\n");
        }
        source.push_str("} }\n");
        let tree = parse_tree_for_language(&file, Language::Java, &source).expect("parse Java");

        let collected = semantic_token_candidate_ranges(
            tree.root_node(),
            Language::Java,
            MAX_SEMANTIC_TOKEN_CANDIDATES,
        );
        assert!(matches!(
            collected,
            ReferenceCandidateRanges::LimitExceeded { limit, ranges }
                if limit == MAX_SEMANTIC_TOKEN_CANDIDATES
                    && ranges.len() == MAX_SEMANTIC_TOKEN_CANDIDATES
        ));
    }

    #[test]
    fn reference_candidates_exclude_non_reference_literals() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().canonicalize().expect("canonical root");
        let file = crate::analyzer::ProjectFile::new(&root, PathBuf::from("Values.java"));
        let source = "class Values { void target() {} void caller() { 123; \"text\"; target(); } }";
        let tree = parse_tree_for_language(&file, Language::Java, source).expect("parse Java");
        let ReferenceCandidateRanges::Complete(ranges) = reference_candidate_ranges(
            tree.root_node(),
            Language::Java,
            MAX_SEMANTIC_TOKEN_CANDIDATES,
        ) else {
            panic!("small structured candidate set must be complete");
        };
        let candidate_text = ranges
            .iter()
            .map(|range| &source[range.start_byte..range.end_byte])
            .collect::<Vec<_>>();
        assert!(!candidate_text.contains(&"123"));
        assert!(!candidate_text.contains(&"\"text\""));
        assert!(candidate_text.contains(&"target"));
    }

    #[test]
    fn source_budget_has_an_inclusive_boundary() {
        assert!(source_within_budget(
            &"x".repeat(MAX_SEMANTIC_TOKEN_SOURCE_BYTES)
        ));
        assert!(!source_within_budget(
            &"x".repeat(MAX_SEMANTIC_TOKEN_SOURCE_BYTES + 1)
        ));
    }

    #[test]
    fn go_reference_workspace_budget_bounds_files_bytes_and_read_failures() {
        assert!(go_workspace_sizes_within_budget([Some(
            MAX_GO_REFERENCE_WORKSPACE_SOURCE_BYTES
        )]));
        assert!(!go_workspace_sizes_within_budget([Some(
            MAX_GO_REFERENCE_WORKSPACE_SOURCE_BYTES + 1
        )]));
        assert!(!go_workspace_sizes_within_budget(vec![
            Some(1);
            MAX_GO_REFERENCE_WORKSPACE_FILES
                + 1
        ]));
        assert!(!go_workspace_sizes_within_budget([None]));
    }
}
