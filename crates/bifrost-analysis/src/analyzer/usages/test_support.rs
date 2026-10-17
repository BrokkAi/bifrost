use crate::analyzer::structural::{FileFacts, NormalizedKind};
use crate::analyzer::usages::get_definition::BoundedResolution;
use crate::analyzer::usages::receiver_analysis::{ReceiverAnalysisBudget, ReceiverBudgetLimit};
use crate::analyzer::usages::reference_site::ResolvedReferenceSite;
use crate::analyzer::{IAnalyzer, Language, ProjectFile, Range};
use crate::path_utils::rel_path_string;
use crate::test_support::AnalyzerFixture;
use tree_sitter::Tree;

pub(crate) fn byte_range(source: &str, needle: &str) -> Range {
    let start_byte = source.rfind(needle).expect("call expression exists");
    Range {
        start_byte,
        end_byte: start_byte + needle.len(),
        start_line: 0,
        end_line: 0,
    }
}

pub(crate) fn call_node_id(source: &str, facts: &FileFacts, call_text: &str) -> u32 {
    let start = source.rfind(call_text).expect("call text exists");
    let end = start + call_text.len();
    facts
        .nodes()
        .iter()
        .enumerate()
        .find(|(_, node)| {
            node.kind == NormalizedKind::Call
                && node.range.start_byte == start
                && node.range.end_byte == end
        })
        .map(|(id, _)| u32::try_from(id).expect("node id fits u32"))
        .expect("call node exists at the text span")
}

pub(crate) fn wide_deep_member_fixture(
    language: Language,
    file_name: &str,
    source: String,
    expression: &str,
    member: &str,
    parse_tree: impl FnOnce(&str) -> Option<Tree>,
) -> (
    AnalyzerFixture,
    ProjectFile,
    String,
    Tree,
    ResolvedReferenceSite,
) {
    let fixture = AnalyzerFixture::new_for_language(language, &[(file_name, &source)]);
    let file = ProjectFile::new(fixture.project_root(), file_name);
    let tree = parse_tree(&source).expect("member fixture tree");
    let expression_start = source
        .rfind(expression)
        .expect("member expression in fixture source");
    let start_byte = expression_start
        + expression
            .rfind(member)
            .expect("member name in fixture expression");
    let end_byte = start_byte + member.len();
    let start_line = source[..start_byte]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1;
    let site = ResolvedReferenceSite {
        path: rel_path_string(&file),
        text: member.to_string(),
        range: Range {
            start_byte,
            end_byte,
            start_line,
            end_line: start_line,
        },
        focus_start_byte: start_byte,
        focus_end_byte: end_byte,
    };
    (fixture, file, source, tree, site)
}

pub(crate) fn assert_scope_budget_exceeded<T: std::fmt::Debug>(
    outcome: &BoundedResolution<T>,
    budget: ReceiverAnalysisBudget,
) {
    assert!(
        matches!(
            outcome,
            BoundedResolution::Exceeded {
                limit: ReceiverBudgetLimit::ScopeNodes,
                work,
            } if work.scope_nodes == budget.max_scope_nodes
        ),
        "{outcome:#?}"
    );
}

pub(crate) fn activate_semantic_pack(
    analyzer: &dyn IAnalyzer,
    source_id: &str,
    source: &[u8],
    request: &crate::analyzer::semantic_model::SemanticModelActivationRequest,
) {
    use crate::analyzer::semantic_model::{
        CatalogOptions, CompilerOptions, SemanticModelRuntimeOutcome, SemanticPackCatalog,
        SessionPackSource, SessionPackSourceKind, SourceFormat, acquire_active_semantic_models,
        compile_source,
    };

    let pack = compile_source(SourceFormat::Json, source, &CompilerOptions::default())
        .unwrap_or_else(|diagnostics| {
            panic!("semantic-pack fixture must compile: {diagnostics:#?}")
        });
    let catalog =
        SemanticPackCatalog::open_ephemeral(CatalogOptions::default()).expect("ephemeral catalog");
    catalog
        .register_session_pack(
            &pack,
            &SessionPackSource {
                kind: SessionPackSourceKind::Embedded,
                source_id: source_id.to_owned(),
            },
        )
        .expect("register semantic-pack fixture");
    let SemanticModelRuntimeOutcome::Ready { .. } = acquire_active_semantic_models(
        analyzer,
        &catalog,
        None,
        request,
        &crate::cancellation::CancellationToken::new(),
    ) else {
        panic!("semantic-pack fixture must activate");
    };
}
