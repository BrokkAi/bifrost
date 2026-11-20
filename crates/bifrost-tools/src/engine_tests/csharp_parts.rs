use crate::inline_project::InlineTestProject;
use brokk_bifrost_analysis::analyzer::store::resolution_operation::{
    SelectedResolutionOperationInput, SelectedResolutionOperationOpenOutcome,
    csharp_parts::{
        CSharpPartAgreement, CSharpPartConflict, CSharpPartGroups, CSharpPartShape,
        probe_part_groups,
    },
};
use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionLanguage;
use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::ephemeral_store_context;
use brokk_bifrost_analysis::analyzer::{AnalyzerConfig, WorkspaceAnalyzer};
use brokk_bifrost_core::{analyzer::Language, cancellation::CancellationToken};

const APP: &str = "<Project Sdk=\"Microsoft.NET.Sdk\" />";

/// Build the selected C# operation for `files`, then run `body` with a reader of
/// part groups. The selected C# reader needs the trial flag before the process
/// reads it, so the test re-executes itself once with the flag set.
fn with_parts(
    test: &str,
    files: &[(&str, &str)],
    body: impl FnOnce(&dyn Fn(&str, &[&str]) -> CSharpPartGroups),
) {
    if std::env::var_os("BIFROST_TRIAL_NATIVE_CSHARP").is_none() {
        let name = format!("engine_tests::csharp_parts::{test}");
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &name, "--nocapture"])
            .env("BIFROST_TRIAL_NATIVE_CSHARP", "1")
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"),
            "child ran: {output:?}"
        );
        return;
    }
    let mut project = InlineTestProject::with_language(Language::CSharp);
    for (path, text) in files {
        project = project.file(path, *text);
    }
    let fixture = project.build();
    let context = ephemeral_store_context(fixture.project_dyn().as_ref()).unwrap();
    let workspace_id = context.workspace_id.clone();
    let store = std::sync::Arc::clone(&context.store);
    let workspace = WorkspaceAnalyzer::build_with_store_context_for_test(
        fixture.project_dyn(),
        AnalyzerConfig::default(),
        context,
    )
    .unwrap();
    let snapshots = store
        .workspace_snapshots_for_current_languages(&workspace_id, &["csharp".to_owned()])
        .unwrap();
    let languages = [SelectedResolutionLanguage::with_epoch(
        "csharp",
        Language::CSharp,
        brokk_bifrost_analysis::analyzer::store::resolution::csharp_trial_bundle_epoch(),
    )];
    let cancellation = CancellationToken::new();
    let project = fixture.project_dyn();
    let services =
        brokk_bifrost_analysis::analyzer::native_points::selected_analyzer_services_for_test(
            brokk_bifrost_analysis::analyzer::resolve_analyzer::<
                brokk_bifrost_csharp_analysis::analyzer::csharp::CSharpAnalyzer,
            >(workspace.analyzer())
            .expect("C# analyzer"),
        );
    let SelectedResolutionOperationOpenOutcome::Ready(operation) = store
        .open_selected_resolution_operation(
            SelectedResolutionOperationInput::new(
                project.as_ref(),
                &workspace_id,
                &snapshots,
                &languages,
                &[],
            )
            .with_analyzer(&services),
            &cancellation,
        )
        .unwrap()
    else {
        panic!("selected C# operation");
    };
    body(&|path: &str, nesting: &[&str]| {
        probe_part_groups(
            &operation,
            &snapshots["csharp"],
            path,
            &nesting
                .iter()
                .map(|name| (*name).to_owned())
                .collect::<Vec<_>>(),
            &cancellation,
        )
        .unwrap()
        .expect("part groups")
    });
}

fn agreed(groups: &CSharpPartGroups) -> (CSharpPartShape, Vec<&str>) {
    match &groups.agreement {
        CSharpPartAgreement::Agreed { shape, parts } => (
            *shape,
            parts.iter().map(|part| part.path.as_str()).collect(),
        ),
        CSharpPartAgreement::Open(reason) => panic!("expected agreement, got {reason:?}"),
    }
}

fn open(groups: &CSharpPartGroups) {
    assert!(
        matches!(groups.agreement, CSharpPartAgreement::Open(_)),
        "expected open agreement: {:?}",
        groups.agreement
    );
}

#[test]
fn csharp_parts_group_top_level_parts_across_files() {
    with_parts(
        "csharp_parts_group_top_level_parts_across_files",
        &[
            ("App/App.csproj", APP),
            ("App/A.cs", "partial class C { int a; }"),
            ("App/B.cs", "partial class C { int b; }"),
            ("App/Other.cs", "class D {}"),
            ("App/Ns.cs", "namespace N { partial class C {} }"),
            ("App/Single.cs", "class One {}"),
        ],
        |read| {
            // The namespace N type shares the name but is a different type.
            assert_eq!(
                agreed(&read("App/A.cs", &["C"])),
                (CSharpPartShape::Partial, vec!["App/A.cs", "App/B.cs"])
            );
            assert_eq!(
                agreed(&read("App/B.cs", &["C"])),
                (CSharpPartShape::Partial, vec!["App/A.cs", "App/B.cs"])
            );
            assert_eq!(
                agreed(&read("App/Ns.cs", &["C"])),
                (CSharpPartShape::Partial, vec!["App/Ns.cs"])
            );
            assert_eq!(
                agreed(&read("App/Single.cs", &["One"])),
                (CSharpPartShape::Singleton, vec!["App/Single.cs"])
            );
        },
    );
}

#[test]
fn csharp_parts_group_two_parts_in_one_file() {
    with_parts(
        "csharp_parts_group_two_parts_in_one_file",
        &[
            ("App/App.csproj", APP),
            ("App/S.cs", "partial class C {} partial class C {}"),
        ],
        |read| {
            let groups = read("App/S.cs", &["C"]);
            let CSharpPartAgreement::Agreed { shape, parts } = &groups.agreement else {
                panic!("agreement: {:?}", groups.agreement);
            };
            assert_eq!(*shape, CSharpPartShape::Partial);
            assert_eq!(parts.len(), 2, "{parts:?}");
            assert_ne!(parts[0].definition, parts[1].definition);
            assert!(parts.iter().all(|part| part.path == "App/S.cs"));
        },
    );
}

#[test]
fn csharp_parts_group_nested_and_generic_parts() {
    with_parts(
        "csharp_parts_group_nested_and_generic_parts",
        &[
            ("App/App.csproj", APP),
            (
                "App/A.cs",
                "partial class Outer { partial class Inner {} partial class Solo {} }",
            ),
            (
                "App/B.cs",
                "partial class Outer { partial class Inner {} class Other {} }",
            ),
            ("App/G1.cs", "partial class G<T> {}"),
            ("App/G2.cs", "partial class G<T> {}"),
            ("App/G3.cs", "partial class G<T, U> {}"),
            (
                "App/Same.cs",
                "partial class Q { partial class R {} partial class R {} }",
            ),
        ],
        |read| {
            assert_eq!(
                agreed(&read("App/A.cs", &["Outer", "Inner"])),
                (CSharpPartShape::Partial, vec!["App/A.cs", "App/B.cs"])
            );
            assert_eq!(
                agreed(&read("App/B.cs", &["Outer", "Inner"])),
                (CSharpPartShape::Partial, vec!["App/A.cs", "App/B.cs"])
            );
            assert_eq!(
                agreed(&read("App/A.cs", &["Outer", "Solo"])),
                (CSharpPartShape::Partial, vec!["App/A.cs"])
            );
            assert_eq!(
                agreed(&read("App/B.cs", &["Outer", "Other"])),
                (CSharpPartShape::Singleton, vec!["App/B.cs"])
            );
            assert_eq!(
                agreed(&read("App/G1.cs", &["G`1"])),
                (CSharpPartShape::Partial, vec!["App/G1.cs", "App/G2.cs"])
            );
            assert_eq!(
                agreed(&read("App/G3.cs", &["G`2"])),
                (CSharpPartShape::Partial, vec!["App/G3.cs"])
            );
            let same = read("App/Same.cs", &["Q", "R"]);
            let (shape, paths) = agreed(&same);
            assert_eq!(shape, CSharpPartShape::Partial);
            assert_eq!(paths, vec!["App/Same.cs", "App/Same.cs"]);
        },
    );
}

#[test]
fn csharp_parts_flag_nonpartial_duplicates() {
    with_parts(
        "csharp_parts_flag_nonpartial_duplicates",
        &[
            ("App/App.csproj", APP),
            ("App/D1.cs", "class Dup {}"),
            ("App/D2.cs", "partial class Dup {}"),
            ("App/E1.cs", "class Twice {}"),
            ("App/E2.cs", "class Twice {}"),
            ("App/N1.cs", "partial class Host { class Mix {} }"),
            ("App/N2.cs", "partial class Host { partial class Mix {} }"),
        ],
        |read| {
            let conflict = CSharpPartShape::Conflicted(CSharpPartConflict::DuplicateNonPartial);
            assert_eq!(
                agreed(&read("App/D1.cs", &["Dup"])),
                (conflict, vec!["App/D1.cs", "App/D2.cs"])
            );
            assert_eq!(
                agreed(&read("App/E2.cs", &["Twice"])),
                (conflict, vec!["App/E1.cs", "App/E2.cs"])
            );
            assert_eq!(
                agreed(&read("App/N1.cs", &["Host", "Mix"])),
                (conflict, vec!["App/N1.cs", "App/N2.cs"])
            );
        },
    );
}

#[test]
fn csharp_parts_combine_compilation_placements_by_agreement() {
    let linked = "<Project Sdk=\"Microsoft.NET.Sdk\"><ItemGroup><Compile Include=\"../Shared/A.cs\" /><Compile Include=\"../Shared/E.cs\" /></ItemGroup></Project>";
    with_parts(
        "csharp_parts_combine_compilation_placements_by_agreement",
        &[
            ("P1/P1.csproj", linked),
            ("P2/P2.csproj", linked),
            ("Shared/A.cs", "partial class C {}"),
            ("Shared/E.cs", "partial class E {}"),
            ("P2/B.cs", "partial class C {}"),
        ],
        |read| {
            // Shared A is in both compilations; B only in P2: the per-placement
            // groups differ, so the combined answer is open.
            let both = read("Shared/A.cs", &["C"]);
            assert_eq!(both.per_placement.len(), 2);
            let mut sizes: Vec<_> = both
                .per_placement
                .iter()
                .map(|group| (group.placement.project_path.clone(), group.parts.len()))
                .collect();
            sizes.sort();
            assert_eq!(sizes[0].1 + sizes[1].1, 3, "{sizes:?}");
            open(&both);
            // B belongs to P2 alone, whose group is proven.
            let only = read("P2/B.cs", &["C"]);
            assert_eq!(only.per_placement.len(), 1);
            assert_eq!(
                agreed(&only),
                (CSharpPartShape::Partial, vec!["P2/B.cs", "Shared/A.cs"])
            );
            // E is identical in both placements, so they agree.
            let agree = read("Shared/E.cs", &["E"]);
            assert_eq!(agree.per_placement.len(), 2);
            assert_eq!(
                agreed(&agree),
                (CSharpPartShape::Partial, vec!["Shared/E.cs"])
            );
        },
    );
}

#[test]
fn csharp_parts_open_without_compilation_membership() {
    with_parts(
        "csharp_parts_open_without_compilation_membership",
        &[
            ("App/App.csproj", APP),
            ("Loose/A.cs", "partial class C {}"),
            ("Loose/B.cs", "partial class C {}"),
        ],
        |read| {
            let groups = read("Loose/A.cs", &["C"]);
            open(&groups);
            assert!(groups.per_placement.is_empty());
        },
    );
}
