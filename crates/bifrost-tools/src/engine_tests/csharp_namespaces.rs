use crate::inline_project::InlineTestProject;
use brokk_bifrost_analysis::analyzer::resolution::ResolutionLookupSemanticRecipe;
use brokk_bifrost_analysis::analyzer::store::resolution_operation::package_context::SelectedPackageRows;
use brokk_bifrost_analysis::analyzer::store::resolution_operation::{
    SelectedResolutionOperationInput, SelectedResolutionOperationOpenOutcome,
    csharp_namespaces::probe_namespace_members,
};
use brokk_bifrost_analysis::analyzer::store::resolution_selection::SelectedResolutionLanguage;
use brokk_bifrost_analysis::analyzer::store::resolution_stage::codec::{
    encode_node, encode_semantic,
};
use brokk_bifrost_analysis::analyzer::tree_sitter_analyzer::single_connection_store_context_for_test;
use brokk_bifrost_analysis::analyzer::{AnalyzerConfig, WorkspaceAnalyzer};
use brokk_bifrost_core::analyzer::resolution_facts::ResolutionNamespace;
use brokk_bifrost_core::{analyzer::Language, cancellation::CancellationToken};

#[test]
fn csharp_namespace_members_use_selected_names_and_exact_levels() {
    if std::env::var_os("BIFROST_TRIAL_NATIVE_CSHARP").is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap()).args(["--exact", "engine_tests::csharp_namespaces::csharp_namespace_members_use_selected_names_and_exact_levels", "--nocapture"]).env("BIFROST_TRIAL_NATIVE_CSHARP", "1").output().unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"),
            "child ran: {output:?}"
        );
        print!("{}", String::from_utf8_lossy(&output.stdout));
        return;
    }
    let multi =
        "namespace A { class X {} } namespace A.B { class X {} } namespace Other { class X {} }";
    let fixture = InlineTestProject::with_language(Language::CSharp)
        .file("App/App.csproj", "<Project Sdk=\"Microsoft.NET.Sdk\"><ItemGroup><ProjectReference Include=\"../Lib/Lib.csproj\" /></ItemGroup></Project>")
        .file("Lib/Lib.csproj", "<Project Sdk=\"Microsoft.NET.Sdk\" />")
        .file("Hidden/Hidden.csproj", "<Project Sdk=\"Microsoft.NET.Sdk\" />")
        .file("App/Caller.cs", "namespace A.B { class Caller { X field; } }")
        .file("App/Inner.cs", "namespace A.B { class X {} }")
        .file("App/Multi.cs", multi)
        .file("Lib/Outer.cs", "namespace A { public class X {} }")
        .file("Hidden/Hidden.cs", "namespace A.B { class X {} }")
        .file("App/Global.cs", "class X {}")
        .build();
    let context = single_connection_store_context_for_test(fixture.project_dyn().as_ref()).unwrap();
    let workspace_id = context.workspace_id.clone();
    let store = std::sync::Arc::clone(&context.store);
    let _workspace = WorkspaceAnalyzer::build_with_store_context_for_test(
        fixture.project_dyn(),
        AnalyzerConfig::default(),
        context,
    )
    .unwrap();
    let snapshots = store
        .workspace_snapshots_for_current_languages(&workspace_id, &["csharp".to_owned()])
        .unwrap();
    let languages = [SelectedResolutionLanguage::new("csharp", Language::CSharp)];
    let cancellation = CancellationToken::new();
    let project = fixture.project_dyn();
    let SelectedResolutionOperationOpenOutcome::Ready(operation) = store
        .open_selected_resolution_operation(
            SelectedResolutionOperationInput::new(
                project.as_ref(),
                &workspace_id,
                &snapshots,
                &languages,
                &[],
            ),
            &cancellation,
        )
        .unwrap()
    else {
        panic!("selected C# operation");
    };
    let read = |segments: &[&str]| {
        probe_namespace_members(
            &operation,
            &snapshots["csharp"],
            "App/Caller.cs",
            &segments.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>(),
            &cancellation,
        )
        .unwrap()
        .unwrap()
    };
    assert_eq!(
        read(&["A", "B"]),
        vec![
            ("App/Inner.cs".to_owned(), "A.B.X".to_owned()),
            ("App/Multi.cs".to_owned(), "A.B.X".to_owned())
        ]
    );
    assert_eq!(
        read(&["A"]),
        vec![
            ("App/Multi.cs".to_owned(), "A.X".to_owned()),
            ("Lib/Outer.cs".to_owned(), "A.X".to_owned())
        ]
    );
    assert_eq!(
        read(&[]),
        vec![("App/Global.cs".to_owned(), "X".to_owned())]
    );
    let mount = operation
        .mount_table()
        .mount_for_path("csharp", "App/Inner.cs")
        .unwrap()
        .unwrap();
    let names = operation.ready.shared_names();
    let lookup =
        ResolutionLookupSemanticRecipe::new(Language::CSharp, ResolutionNamespace::Type, "X")
            .semantic(&names);
    let renamed =
        ResolutionLookupSemanticRecipe::new(Language::CSharp, ResolutionNamespace::Type, "Renamed")
            .semantic(&names);
    let SelectedPackageRows::Ready(members) = operation
        .ready
        .selected_package_members_for_lookup(mount.ordinal(), lookup, &cancellation)
        .unwrap()
    else {
        panic!("source member");
    };
    let member = members[0];
    operation.ready.inventory.with_owned_temp_write(|conn| {
        conn.execute("INSERT INTO temp.selected_resolution_stage_producers(host_ordinal,bridge_identity,content_digest) VALUES(?1,?2,?3)", rusqlite::params![mount.ordinal().get(), [41u8;32].as_slice(), [42u8;32].as_slice()])?;
        conn.execute("INSERT INTO temp.selected_resolution_stage_package_members(host_ordinal,producer_id,token_key,domain_shared,definition_key,source_site,root_scope_key,namespace,lookup_shared) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)", rusqlite::params![mount.ordinal().get(), conn.last_insert_rowid(), encode_semantic(member.token), member.domain.shared_name_id().unwrap().get(), encode_semantic(member.definition), member.source_site.get(), encode_node(member.root_scope), member.namespace.label(), renamed.shared_name_id().unwrap().get()])?;
        Ok(())
    }).unwrap();
    assert_eq!(
        read(&["A", "B"]),
        vec![("App/Multi.cs".to_owned(), "A.B.X".to_owned())]
    );
}
