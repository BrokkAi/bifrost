use brokk_bifrost_analysis::test_support::AnalyzerFixture;
use brokk_bifrost_core::analyzer::model::{Language, ProjectFile};
use brokk_bifrost_core::cancellation::CancellationToken;

use crate::program_point_selection::{PointSelectionRefusal, SourcePosition, select_program_point};
use crate::site_context::{SiteLocation, SiteRole, SiteValue, UnknownValueCause};

const SOURCE: &str = "struct Marker;\n\nasync fn work() -> i64 {\n    7\n}\n\nasync fn run() -> i64 {\n    work().await\n}\n";

const CSHARP: &str = "class Cleanup {\n    static void Close() {}\n    static int Run(bool flag) {\n        try {\n            if (flag) {\n                return 1;\n            }\n            return 2;\n        } finally {\n            Close();\n        }\n    }\n}\n";

fn select(
    position: SourcePosition,
    role: SiteRole,
) -> Result<crate::program_point_selection::SelectedProgramPoint, PointSelectionRefusal> {
    select_in(Language::Rust, "src/lib.rs", SOURCE, position, role)
}

fn select_in(
    language: Language,
    path: &str,
    source: &str,
    position: SourcePosition,
    role: SiteRole,
) -> Result<crate::program_point_selection::SelectedProgramPoint, PointSelectionRefusal> {
    let fixture = AnalyzerFixture::new_for_language(language, &[(path, source)]);
    let file = ProjectFile::new(fixture.project_root(), path);
    select_program_point(
        &fixture.analyzer,
        &file,
        position,
        role,
        &CancellationToken::default(),
    )
}

#[test]
fn exact_await_selects_one_point_with_its_source_site() {
    let offset = SOURCE.find("await").expect("await keyword");
    let selected = select(SourcePosition::ByteOffset(offset), SiteRole::Value)
        .unwrap_or_else(|refusal| panic!("await selection refused: {refusal:?}"));
    let SiteLocation::Source {
        text,
        start_line,
        start_column,
        ..
    } = &selected.site.site
    else {
        panic!("a source site: {:?}", selected.site.site);
    };
    assert_eq!(text, "work().await");
    assert_eq!((*start_line, *start_column), (8, 5));
    assert_eq!(
        selected.site.value,
        SiteValue::Unknown(UnknownValueCause::NotConstant)
    );
    // The same node by line and column.
    let by_line = select(
        SourcePosition::LineColumn {
            line: 8,
            column: 12,
        },
        SiteRole::Value,
    )
    .expect("line/column selection");
    assert_eq!(by_line.point.id(), selected.point.id());
}

#[test]
fn a_call_lowered_twice_is_ambiguous() {
    let offset = CSHARP.find("Close();").expect("finally call");
    let refusal = select_in(
        Language::CSharp,
        "Cleanup.cs",
        CSHARP,
        SourcePosition::ByteOffset(offset),
        SiteRole::Call,
    )
    .expect_err("the finally block is lowered once per exit route");
    match refusal {
        PointSelectionRefusal::Ambiguous(points) => assert!(points.len() > 1, "{points:?}"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_position_outside_every_admissible_node_is_refused() {
    let refusal = select(SourcePosition::ByteOffset(0), SiteRole::Call)
        .expect_err("no call contains the struct keyword");
    assert!(matches!(refusal, PointSelectionRefusal::NoNodeAtPosition));
}

#[test]
fn a_node_without_a_program_point_is_unsupported_not_nearest() {
    let offset = SOURCE.find("Marker").expect("struct name");
    let refusal = select(SourcePosition::ByteOffset(offset), SiteRole::Value)
        .expect_err("a struct declaration has no program point");
    assert!(
        matches!(refusal, PointSelectionRefusal::UnsupportedNode(_)),
        "{refusal:?}"
    );
}
