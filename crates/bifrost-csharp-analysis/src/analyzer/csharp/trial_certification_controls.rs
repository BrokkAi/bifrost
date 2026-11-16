//! Acceptance controls for the selected C# compilation input identity.
use super::*;
use crate::inline_project::{BuiltInlineTestProject, InlineTestProject};
use brokk_bifrost_analysis::analyzer::store::resolution_operation::ConfigurationCertificate;
use brokk_bifrost_test_macros::hardwon;

fn fixture() -> (BuiltInlineTestProject, CSharpAnalyzer) {
    let fixture = InlineTestProject::with_language(Language::CSharp)
        .file("App.csproj", "<Project Sdk=\"Microsoft.NET.Sdk\" />")
        .file("A.cs", "namespace Demo { class A { B field; } }")
        .file("B.cs", "namespace Demo { class B {} }")
        .build();
    let analyzer = CSharpAnalyzer::from_project(fixture.project().clone());
    (fixture, analyzer)
}

#[test]
#[cfg(unix)]
#[hardwon("#12280: omitted projects and compile roots certified stale compilation membership")]
fn omitted_configuration_and_compile_roots_refuse_certification() {
    for (sdk, body, props, omitted, file, expected) in [
        (
            "Microsoft.NET.Sdk",
            "",
            "",
            "Hidden.csproj",
            true,
            ConfigurationCertificate::Uncertified,
        ),
        (
            "Microsoft.NET.Sdk",
            "",
            "",
            "App/hidden",
            false,
            ConfigurationCertificate::Uncertified,
        ),
        (
            "Microsoft.NET.Sdk",
            "",
            "<ItemGroup><Compile Include=\"../Shared/**/*.cs\" /></ItemGroup>",
            "Shared/hidden",
            false,
            ConfigurationCertificate::Uncertified,
        ),
        (
            "Microsoft.NET.Sdk",
            "",
            "<ItemGroup><Compile Include=\"../Shared/Deep/**/*.cs\" /></ItemGroup>",
            "Shared",
            false,
            ConfigurationCertificate::Uncertified,
        ),
        (
            "Microsoft.NET.Sdk",
            "",
            "",
            "Other/hidden",
            false,
            ConfigurationCertificate::Certified,
        ),
        (
            "Microsoft.NET.Sdk.Razor",
            "",
            "",
            "Other/hidden",
            false,
            ConfigurationCertificate::Uncertified,
        ),
        (
            "Microsoft.NET.Sdk",
            "<ItemGroup><AdditionalFiles Include=\"../Other/**/*\" /></ItemGroup>",
            "",
            "Other/hidden",
            false,
            ConfigurationCertificate::Uncertified,
        ),
        (
            "Microsoft.NET.Sdk",
            "PACKAGE",
            "",
            "Other/hidden",
            false,
            ConfigurationCertificate::Uncertified,
        ),
    ] {
        let body = if body == "PACKAGE" {
            "<Import Project=\"obj/App.csproj.nuget.g.props\" />"
        } else {
            body
        };
        let project = format!("<Project Sdk=\"{sdk}\">{body}</Project>");
        let props = format!("<Project>{props}</Project>");
        let fixture = InlineTestProject::with_language(Language::CSharp)
            .file("App/App.csproj", &project)
            .file("App/Directory.Build.props", &props)
            .file("App/obj/App.csproj.nuget.g.props", if body.contains("nuget.g.props") { "<Project><Import Project=\"../../Packages/Generator/build/Generator.props\" /></Project>" } else { "<Project />" })
            .file("Packages/Generator/build/Generator.props", if body.contains("nuget.g.props") { "<Project><ItemGroup><AdditionalFiles Include=\"../Other/**/*\" /></ItemGroup></Project>" } else { "<Project />" })
            .file("App/A.cs", "class A {}")
            .build();
        let initial = CSharpAnalyzer::from_project(fixture.project().clone());
        let snapshot = initial.inner.selected_workspace_snapshots()["csharp"].clone();
        let identity = *initial.compilation_input_digest().unwrap().as_bytes();
        let target = tempfile::tempdir().unwrap();
        let destination = fixture.root().join(omitted);
        std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
        if file {
            let target_file = target.path().join("project.csproj");
            std::fs::write(&target_file, "<Project />").unwrap();
            std::os::unix::fs::symlink(target_file, &destination).unwrap();
        } else {
            std::os::unix::fs::symlink(target.path(), &destination).unwrap();
        }
        let request = initial.clone_with_project(fixture.project_dyn());
        let connection = initial.inner.analyzer_store().read_conn().unwrap();
        assert_eq!(
            request.certify_selected_configuration(
                Language::CSharp,
                &snapshot,
                &identity,
                &connection
            ),
            expected,
            "{sdk} {body} {props} {omitted}"
        );
    }
}

#[test]
#[hardwon("#8837: native C# readers used selected membership without the configuration fact")]
fn selected_configuration_certifies_cold_and_hot() {
    let (_fixture, analyzer) = fixture();
    let snapshot = analyzer.inner.selected_workspace_snapshots()["csharp"].clone();
    let identity = *analyzer.compilation_input_digest().unwrap().as_bytes();
    let connection = analyzer.inner.analyzer_store().read_conn().unwrap();
    for _ in 0..2 {
        let (certificate, reads) =
            brokk_bifrost_analysis::analyzer::capture_query_reads(&analyzer, || {
                IAnalyzer::certify_selected_configuration(
                    &analyzer,
                    Language::CSharp,
                    &snapshot,
                    &identity,
                    &connection,
                )
            });
        assert_eq!(certificate, ConfigurationCertificate::Certified);
        assert!(
            !reads.keys().is_empty(),
            "a certified read must record the configuration fact"
        );
    }
}

#[test]
#[cfg(any(unix, windows))]
#[hardwon("#12280: an omitted configuration symlink still certified persisted C# membership")]
fn configuration_symlink_refuses_certification_with_identical_inputs() {
    let (fixture, _) = fixture();
    let contents = "<Project />";
    std::fs::write(fixture.root().join("Actual.props"), contents).unwrap();
    let props = fixture.root().join("Directory.Build.props");
    std::fs::write(&props, contents).unwrap();
    let initial = CSharpAnalyzer::from_project(fixture.project().clone());
    let snapshot = initial.inner.selected_workspace_snapshots()["csharp"].clone();
    let identity = *initial.compilation_input_digest().unwrap().as_bytes();
    std::fs::remove_file(&props).unwrap();
    #[cfg(unix)]
    let linked = std::os::unix::fs::symlink("Actual.props", &props);
    #[cfg(windows)]
    let linked = std::os::windows::fs::symlink_file("Actual.props", &props);
    match linked {
        Ok(()) => {}
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::Unsupported
            ) =>
        {
            eprintln!("skipping configuration symlink case: platform refuses links: {error}");
            return;
        }
        Err(error) => panic!("create configuration symlink: {error}"),
    }
    let request = initial.clone_with_project(fixture.project_dyn());
    assert_eq!(
        *request.compilation_input_digest().unwrap().as_bytes(),
        identity,
        "the omission must refuse certification even when all retained bytes still match"
    );
    assert!(request.workspace_content_identity().is_some());
    let connection = initial.inner.analyzer_store().read_conn().unwrap();
    for _ in 0..2 {
        let (certificate, reads) =
            brokk_bifrost_analysis::analyzer::capture_query_reads(&request, || {
                request.certify_selected_configuration(
                    Language::CSharp,
                    &snapshot,
                    &identity,
                    &connection,
                )
            });
        assert_eq!(certificate, ConfigurationCertificate::Uncertified);
        assert!(reads.reuse_refused());
    }
}

/// An explicit Compile item holds a file whatever its extension, so an omitted
/// symlink there is source the compilation lost, though no C# path rule claims
/// the name. A symlink at a path no Compile item names is not.
#[test]
#[cfg(unix)]
#[hardwon(
    "#12280: an omitted symlink at an explicit non-.cs Compile item left the compilation certified complete"
)]
fn omitted_explicit_non_cs_compile_item_refuses_certification() {
    // (certificate, workspace content key before, workspace content key after)
    let observe = |link: &str| {
        let fixture = InlineTestProject::with_language(Language::CSharp)
            .file(
                "App/App.csproj",
                "<Project Sdk=\"Microsoft.NET.Sdk\"><ItemGroup><Compile Include=\"Generated.code\" /></ItemGroup></Project>",
            )
            .file("App/A.cs", "class A {}")
            .file("App/Actual.code", "class B {}")
            .build();
        let initial = CSharpAnalyzer::from_project(fixture.project().clone());
        let snapshot = initial.inner.selected_workspace_snapshots()["csharp"].clone();
        let identity = *initial.compilation_input_digest().unwrap().as_bytes();
        let before = initial.compilation_config_identities().unwrap().2;
        std::os::unix::fs::symlink(
            fixture.root().join("App/Actual.code"),
            fixture.root().join(link),
        )
        .unwrap();
        let request = initial.clone_with_project(fixture.project_dyn());
        let connection = initial.inner.analyzer_store().read_conn().unwrap();
        let certificate = request.certify_selected_configuration(
            Language::CSharp,
            &snapshot,
            &identity,
            &connection,
        );
        (
            certificate,
            before,
            request.compilation_config_identities().unwrap().2,
        )
    };
    let (certificate, before, after) = observe("App/Generated.code");
    assert_eq!(
        certificate,
        ConfigurationCertificate::Uncertified,
        "the omitted symlink is the explicit Compile item"
    );
    assert_ne!(
        before, after,
        "the content key moves with the authority, or a product cached under the certified one is reused"
    );
    let (certificate, before, after) = observe("App/notes.txt");
    assert_eq!(
        certificate,
        ConfigurationCertificate::Certified,
        "a symlink no Compile item names changes nothing"
    );
    assert_eq!(before, after, "and folds nothing into the content key");
}

#[test]
#[hardwon("#8837: native C# readers used selected membership without the configuration fact")]
fn stale_selected_configuration_is_uncertified() {
    let (_fixture, analyzer) = fixture();
    let snapshot = analyzer.inner.selected_workspace_snapshots()["csharp"].clone();
    let mut stale = *analyzer.compilation_input_digest().unwrap().as_bytes();
    stale[0] ^= 1;
    let connection = analyzer.inner.analyzer_store().read_conn().unwrap();
    assert_eq!(
        IAnalyzer::certify_selected_configuration(
            &analyzer,
            Language::CSharp,
            &snapshot,
            &stale,
            &connection
        ),
        ConfigurationCertificate::Uncertified
    );
}

#[test]
#[hardwon("#8837: native C# readers used selected membership without the configuration fact")]
fn oversized_configuration_cannot_certify() {
    let (fixture, initial) = fixture();
    let snapshot = initial.inner.selected_workspace_snapshots()["csharp"].clone();
    fixture
        .file("Directory.Build.props")
        .write("x".repeat(2 * 1024 * 1024 + 1))
        .unwrap();
    let analyzer = CSharpAnalyzer::from_project(fixture.project().clone());
    let connection = analyzer.inner.analyzer_store().read_conn().unwrap();
    let (certificate, reads) =
        brokk_bifrost_analysis::analyzer::capture_query_reads(&analyzer, || {
            IAnalyzer::certify_selected_configuration(
                &analyzer,
                Language::CSharp,
                &snapshot,
                &[0; 32],
                &connection,
            )
        });
    assert_eq!(certificate, ConfigurationCertificate::Uncertified);
    assert!(reads.reuse_refused());
}

#[test]
#[hardwon("#8837: native C# readers used selected membership without the configuration fact")]
fn unsaved_configuration_overlay_refuses_reuse() {
    use brokk_bifrost_core::analyzer::project::OverlayProject;
    let (fixture, initial) = fixture();
    let snapshot = initial.inner.selected_workspace_snapshots()["csharp"].clone();
    let identity = *initial.compilation_input_digest().unwrap().as_bytes();
    let connection = initial.inner.analyzer_store().read_conn().unwrap();
    assert_eq!(
        IAnalyzer::certify_selected_configuration(
            &initial,
            Language::CSharp,
            &snapshot,
            &identity,
            &connection
        ),
        ConfigurationCertificate::Certified,
    );
    let overlay = Arc::new(OverlayProject::new(fixture.project_dyn()));
    assert!(overlay.set(
        fixture.file("App.csproj").abs_path(),
        "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup /></Project>".to_owned(),
    ));
    let request = initial.clone_with_project(Arc::new(overlay.snapshot()));
    let (certificate, reads) =
        brokk_bifrost_analysis::analyzer::capture_query_reads(&request, || {
            IAnalyzer::certify_selected_configuration(
                &request,
                Language::CSharp,
                &snapshot,
                &identity,
                &connection,
            )
        });
    assert_eq!(certificate, ConfigurationCertificate::Uncertified);
    assert!(reads.reuse_refused());
}

#[test]
#[hardwon("#8837: native C# readers used selected membership without the configuration fact")]
fn absent_configuration_becoming_present_changes_identity() {
    let (fixture, initial) = fixture();
    let old_identity = *initial.compilation_input_digest().unwrap().as_bytes();
    fixture.file("Directory.Build.props").write("").unwrap();
    let updated = CSharpAnalyzer::from_project(fixture.project().clone());
    let snapshot = updated.inner.selected_workspace_snapshots()["csharp"].clone();
    let new_identity = *updated.compilation_input_digest().unwrap().as_bytes();
    assert_ne!(old_identity, new_identity);
    let connection = updated.inner.analyzer_store().read_conn().unwrap();
    assert_eq!(
        IAnalyzer::certify_selected_configuration(
            &updated,
            Language::CSharp,
            &snapshot,
            &old_identity,
            &connection,
        ),
        ConfigurationCertificate::Uncertified,
    );
    assert_eq!(
        IAnalyzer::certify_selected_configuration(
            &updated,
            Language::CSharp,
            &snapshot,
            &new_identity,
            &connection,
        ),
        ConfigurationCertificate::Certified,
    );
}

#[test]
#[cfg(unix)]
#[hardwon("#12546: open membership still proved Visible")]
fn hidden_directory_opens_membership_without_changing_configuration() {
    use brokk_bifrost_analysis::analyzer::capture_query_reads;
    use brokk_bifrost_analysis::analyzer::usages::get_definition::{
        DefinitionLookupRequest, DefinitionLookupStatus, resolve_definition_batch,
    };
    use brokk_bifrost_core::analyzer::capabilities::{
        CSharpCompilationMembershipCompleteness, CSharpCompilationMembershipOpenCause,
        ImportAnalysisProvider,
    };
    use brokk_bifrost_csharp::graph_support::CSharpCompilationVisibility;

    use brokk_bifrost_core::cancellation::CancellationToken;

    let source = "class Use { Library.Widget field; }";
    let fixture = InlineTestProject::with_language(Language::CSharp)
        .file("App/App.csproj", "<Project Sdk=\"Microsoft.NET.Sdk\" />")
        .file("App/Use.cs", source)
        .file("App/Peer.cs", "class Peer {}")
        .file(
            "Library/Library.csproj",
            "<Project Sdk=\"Microsoft.NET.Sdk\" />",
        )
        .file(
            "Library/Widget.cs",
            "namespace Library { public class Widget {} }",
        )
        .build();
    let initial = CSharpAnalyzer::from_project(fixture.project().clone());
    let caller = fixture.file("App/Use.cs");
    let target = fixture.file("Library/Widget.cs");
    let peer = fixture.file("App/Peer.cs");
    assert_eq!(
        initial.compilation_visibility(&caller, &peer),
        Some(CSharpCompilationVisibility::Visible)
    );
    let snapshot = initial.inner.selected_workspace_snapshots()["csharp"].clone();
    let identity = *initial.compilation_input_digest().unwrap().as_bytes();
    assert_eq!(
        initial.compilation_membership_completeness(),
        CSharpCompilationMembershipCompleteness::Complete
    );
    assert_eq!(
        initial.compilation_visibility(&caller, &target),
        Some(CSharpCompilationVisibility::NotVisible)
    );
    assert!(
        initial
            .compilation_inventory_obligations(&caller)
            .unwrap()
            .is_empty()
    );
    let lookup = |analyzer: &CSharpAnalyzer| {
        let scope = AnalyzerQueryScope::new(analyzer);
        let start = source.find("Widget").unwrap();
        resolve_definition_batch(
            analyzer,
            scope.token(),
            vec![DefinitionLookupRequest {
                file: caller.clone(),
                line: None,
                column: None,
                start_byte: Some(start),
                end_byte: Some(start + "Widget".len()),
            }],
        )
        .pop()
        .unwrap()
    };
    let before = lookup(&initial);
    assert!(
        before.definitions.is_empty(),
        "unreferenced project's type must be filtered: {before:?}"
    );
    // Warm every wrapper that can reuse a membership-dependent answer.
    let wrappers: [fn(&CSharpAnalyzer, &ProjectFile, &ProjectFile); 5] = [
        |analyzer, caller, _| {
            analyzer.imported_code_units_of(caller);
        },
        |analyzer, _, target| {
            analyzer.referencing_files_of(target);
        },
        |analyzer, _, _| {
            let scope = AnalyzerQueryScope::new(analyzer);
            analyzer.global_static_using_types(scope.token());
        },
        |analyzer, _, _| {
            let scope = AnalyzerQueryScope::new(analyzer);
            analyzer.usage_global_static_using_types(scope.token());
        },
        |analyzer, _, target| {
            CSharpDeadCodeBulk
                .build(
                    analyzer,
                    &analyzer
                        .declarations(target)
                        .into_iter()
                        .collect::<Vec<_>>(),
                )
                .expect("dead-code edge build");
        },
    ];
    for wrapper in wrappers {
        wrapper(&initial, &caller, &target);
    }
    let hidden = tempfile::tempdir().unwrap();
    // No listed source lives under this directory, and it is outside both
    // visible projects' roots. A project there could include ../App/Use.cs.
    let omitted = fixture.root().join("Other");
    std::os::unix::fs::symlink(hidden.path(), &omitted).unwrap();
    let changed = BTreeSet::from([ProjectFile::new(fixture.root(), "Other")]);
    let warm = initial.update(&changed);
    let cold = CSharpAnalyzer::from_project(fixture.project().clone());
    let mut answers = Vec::new();
    for analyzer in [&warm, &cold] {
        for _ in 0..2 {
            assert_eq!(
                analyzer.compilation_membership_completeness().cause(),
                Some(CSharpCompilationMembershipOpenCause::DirectoryOmitted)
            );
            let (visibility, reads) =
                capture_query_reads(analyzer, || analyzer.compilation_visibility(&caller, &peer));
            assert_eq!(visibility, Some(CSharpCompilationVisibility::Unresolved));
            assert!(
                reads.keys().iter().any(|key| matches!(
                    key,
                    brokk_bifrost_analysis::analyzer::ReadKey::Lookup {
                        question: brokk_bifrost_analysis::analyzer::LookupQuestion::WorkspaceFact {
                            family: WorkspaceFactFamily::CSharpCompilationMembershipCompleteness,
                            ..
                        },
                        ..
                    }
                )),
                "positive visibility must retain membership authority: {:?}",
                reads.keys()
            );
            let connection = analyzer.inner.analyzer_store().read_conn().unwrap();
            assert_eq!(
                analyzer.certify_selected_configuration(
                    Language::CSharp,
                    &snapshot,
                    &identity,
                    &connection
                ),
                ConfigurationCertificate::Certified,
                "outside-roots omission changes membership evidence, not listed configuration authority"
            );
            assert_eq!(
                analyzer.compilation_visibility(&caller, &target),
                Some(CSharpCompilationVisibility::Unresolved)
            );
            assert!(
                !analyzer
                    .compilation_inventory_obligations(&caller)
                    .unwrap()
                    .is_empty()
            );
            let (_, complete, cause) = analyzer
                .global_using_dependencies(std::slice::from_ref(&caller), &[])
                .unwrap();
            assert!(!complete);
            assert_eq!(
                cause,
                Some(CSharpCompilationMembershipOpenCause::DirectoryOmitted)
            );
            let dependencies = analyzer
                .additional_direct_file_dependencies(
                    std::slice::from_ref(&caller),
                    &CancellationToken::new(),
                )
                .unwrap();
            assert!(!dependencies.complete);
            assert_eq!(dependencies.membership_cause, cause);
            // #12546: MultiAnalyzer dropped the membership cause.
            let composite = brokk_bifrost_analysis::analyzer::multi_analyzer::MultiAnalyzer::new(
                std::collections::BTreeMap::from([(
                    Language::CSharp,
                    brokk_bifrost_analysis::analyzer::multi_analyzer::AnalyzerDelegate::new(
                        analyzer.clone(),
                    ),
                )]),
            );
            let composite_dependencies = composite
                .additional_direct_file_dependencies(
                    std::slice::from_ref(&caller),
                    &CancellationToken::new(),
                )
                .unwrap();
            assert!(!composite_dependencies.complete);
            assert_eq!(composite_dependencies.membership_cause, cause);
            for wrapper in wrappers {
                let ((), reads) =
                    capture_query_reads(analyzer, || wrapper(analyzer, &caller, &target));
                assert!(
                reads.keys().iter().any(|key| matches!(
                    key,
                    brokk_bifrost_analysis::analyzer::ReadKey::Lookup {
                        question: brokk_bifrost_analysis::analyzer::LookupQuestion::WorkspaceFact {
                            family: WorkspaceFactFamily::CSharpCompilationMembershipCompleteness,
                            ..
                        },
                        ..
                    }
                )),
                "memo hits must replay discovery authority: {:?}",
                reads.keys()
            );
            }
            let answer = lookup(analyzer);
            assert!(
                matches!(
                    answer.status,
                    DefinitionLookupStatus::Incomplete | DefinitionLookupStatus::Ambiguous
                ),
                "{answer:?}"
            );
            assert!(
                answer
                    .definitions
                    .iter()
                    .any(|unit| unit.fq_name() == "Library.Widget"),
                "hidden membership must keep the candidate: {answer:?}"
            );
            answers.push(format!(
                "{:?}:{:?}:{:?}",
                answer.status, answer.definitions, answer.diagnostics
            ));
        }
    }
    assert!(
        answers.windows(2).all(|pair| pair[0] == pair[1]),
        "warm and cold answers differ: {answers:#?}"
    );

    // Discovery doubt adds a cause; it must not replace an already open
    // configuration inventory's diagnostic evidence.
    std::fs::remove_file(&omitted).unwrap();
    let restored_warm = warm.update(&changed);
    let restored_cold = CSharpAnalyzer::from_project(fixture.project().clone());
    for analyzer in [&restored_warm, &restored_cold] {
        assert_eq!(
            analyzer.compilation_visibility(&caller, &peer),
            Some(CSharpCompilationVisibility::Visible)
        );
    }
    fixture
        .file("App/App.csproj")
        .write("<Project Sdk=\"Microsoft.NET.Sdk\"><Import Project=\"Missing.props\" /></Project>")
        .unwrap();
    let known_open = CSharpAnalyzer::from_project(fixture.project().clone());
    let prior = known_open
        .compilation_inventory_obligations(&caller)
        .unwrap();
    assert!(
        !prior.is_empty(),
        "missing import must leave an inventory obligation"
    );
    std::os::unix::fs::symlink(hidden.path(), &omitted).unwrap();
    let discovered_open = known_open.update(&changed);
    let combined = discovered_open
        .compilation_inventory_obligations(&caller)
        .unwrap();
    assert!(
        prior.iter().all(|reason| combined.contains(reason)),
        "discovery replaced existing obligations: prior={prior:?}, combined={combined:?}"
    );
    assert!(
        combined
            .iter()
            .any(|reason| reason.contains("DirectoryOmitted")),
        "{combined:?}"
    );
}
