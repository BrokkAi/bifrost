//! #1726: `namespace_of_file` and `namespace_of_file_limited` share one memo
//! cell, so whichever one runs first serves its answer to the other. These
//! tests pin the one rule both must apply -- the namespace of the file's first
//! top-level declaration in source order -- and prove the two spellings agree
//! in either call order.
//!
//! Every fixture opens `Zeta` before `Alpha` on purpose. `CodeUnit`'s `Ord`
//! compares `package_name` first, so a fallback that scanned the file's
//! `BTreeSet` of declarations reported `Alpha`, while the file's first
//! namespace is `Zeta`.

use crate::common::csharp_analyzer_with_files;
use brokk_bifrost::CSharpAnalyzer;

/// A file whose later namespace sorts before the one it opens with.
const TWO_NAMESPACES: &str = r#"
namespace Zeta
{
    public class ZetaType { }
}

namespace Alpha
{
    public class AlphaType { }
}
"#;

fn limited(analyzer: &CSharpAnalyzer, file: &brokk_bifrost::ProjectFile) -> String {
    let batch = analyzer.namespace_of_file_limited(file, usize::MAX);
    assert!(
        batch.complete,
        "an unbounded budget must never report a truncated batch: {batch:?}"
    );
    batch.rows.into_iter().next().unwrap_or_default()
}

#[test]
fn two_namespace_file_reports_the_first_in_source_order_from_the_plain_spelling() {
    let (project, analyzer) = csharp_analyzer_with_files(&[("Types.cs", TWO_NAMESPACES)]);
    let file = project.file("Types.cs");

    assert_eq!(analyzer.namespace_of_file(&file), "Zeta");
}

#[test]
fn two_namespace_file_reports_the_first_in_source_order_from_the_bounded_spelling() {
    let (project, analyzer) = csharp_analyzer_with_files(&[("Types.cs", TWO_NAMESPACES)]);
    let file = project.file("Types.cs");

    assert_eq!(limited(&analyzer, &file), "Zeta");
}

/// The exact repro from #1726: bounded first, then plain, on one analyzer.
#[test]
fn bounded_then_plain_agree_through_the_shared_memo() {
    let (project, analyzer) = csharp_analyzer_with_files(&[("Types.cs", TWO_NAMESPACES)]);
    let file = project.file("Types.cs");

    let bounded = limited(&analyzer, &file);
    let plain = analyzer.namespace_of_file(&file);

    assert_eq!(bounded, plain);
    assert_eq!(plain, "Zeta");
}

/// The reverse order, on a second analyzer with an empty memo.
#[test]
fn plain_then_bounded_agree_through_the_shared_memo() {
    let (project, analyzer) = csharp_analyzer_with_files(&[("Types.cs", TWO_NAMESPACES)]);
    let file = project.file("Types.cs");

    let plain = analyzer.namespace_of_file(&file);
    let bounded = limited(&analyzer, &file);

    assert_eq!(plain, bounded);
    assert_eq!(plain, "Zeta");
}

/// A file-scoped namespace applies to following siblings rather than to a body,
/// which is a different path through the extractor and must land on the same
/// rule.
#[test]
fn file_scoped_namespace_answers_from_its_declarations() {
    let (project, analyzer) = csharp_analyzer_with_files(&[(
        "Scoped.cs",
        r#"
namespace Zeta.Inner;

public class ScopedType { }
"#,
    )]);
    let file = project.file("Scoped.cs");

    assert_eq!(analyzer.namespace_of_file(&file), "Zeta.Inner");
    assert_eq!(limited(&analyzer, &file), "Zeta.Inner");
}

/// Near miss: one namespace, so no ordering can distinguish the spellings. The
/// answer must still be that namespace rather than an empty string.
#[test]
fn single_namespace_file_answers_with_it() {
    let (project, analyzer) = csharp_analyzer_with_files(&[(
        "Single.cs",
        r#"
namespace Alpha
{
    public class OnlyType { }
}
"#,
    )]);
    let file = project.file("Single.cs");

    assert_eq!(analyzer.namespace_of_file(&file), "Alpha");
    assert_eq!(limited(&analyzer, &file), "Alpha");
}

/// Near miss: a file that declares nothing has no namespace, and neither
/// spelling may invent one.
#[test]
fn file_without_declarations_answers_empty() {
    let (project, analyzer) = csharp_analyzer_with_files(&[
        ("UsingsOnly.cs", "using System;\nusing System.Text;\n"),
        (
            "Other.cs",
            "namespace Alpha { public class OtherType { } }\n",
        ),
    ]);
    let file = project.file("UsingsOnly.cs");

    assert_eq!(analyzer.namespace_of_file(&file), "");
    assert_eq!(limited(&analyzer, &file), "");
}

/// A budget too small to reach any declaration must report an incomplete batch
/// rather than an empty namespace, and must not poison the shared memo for the
/// plain spelling.
#[test]
fn exhausted_budget_reports_incomplete_and_leaves_the_memo_empty() {
    let (project, analyzer) = csharp_analyzer_with_files(&[("Types.cs", TWO_NAMESPACES)]);
    let file = project.file("Types.cs");

    let batch = analyzer.namespace_of_file_limited(&file, 1);
    assert!(!batch.complete, "budget 1 cannot reach a declaration");
    assert!(batch.rows.is_empty());

    assert_eq!(analyzer.namespace_of_file(&file), "Zeta");
}
