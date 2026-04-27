mod common;

use brokk_analyzer::{
    CodeUnit, CodeUnitType, GoAnalyzer, IAnalyzer, Language, ProjectFile, TestProject,
    TypeAliasProvider,
};
use common::{assert_code_eq, go_fixture_project, normalize_nonempty_lines};
use std::collections::BTreeSet;
use tempfile::tempdir;

const PROXYGROUP_TEST_REGRESSION_SOURCE: &str =
    include_str!("fixtures/proxygroup_test_regression.go");

fn fixture_analyzer() -> GoAnalyzer {
    GoAnalyzer::from_project(go_fixture_project())
}

fn definition(analyzer: &GoAnalyzer, fq_name: &str) -> CodeUnit {
    analyzer
        .get_definitions(fq_name)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("missing definition for {fq_name}"))
}

fn inline_project(files: &[(&str, &str)]) -> TestProject {
    let temp = tempdir().unwrap();
    for (path, contents) in files {
        ProjectFile::new(temp.path().to_path_buf(), path)
            .write(*contents)
            .unwrap();
    }
    TestProject::new(temp.keep(), Language::Go)
}

#[test]
fn test_determine_package_name_cases() {
    let analyzer = fixture_analyzer();
    assert_eq!(
        "main",
        analyzer.determine_package_name("package main\n\nfunc main() {}")
    );
    assert_eq!(
        "mypkg",
        analyzer.determine_package_name(
            "package mypkg\n\nimport \"fmt\"\n\nfunc Hello() { fmt.Println(\"Hello\") }"
        )
    );
    assert_eq!(
        "main",
        analyzer.determine_package_name("// comment\npackage main /* another comment */")
    );
    assert_eq!("", analyzer.determine_package_name("func main() {}"));
    assert_eq!("", analyzer.determine_package_name(""));
}

#[test]
fn test_determine_package_name_from_fixtures() {
    let analyzer = fixture_analyzer();
    let root = analyzer.project().root().to_path_buf();

    assert_eq!(
        "main",
        analyzer.determine_package_name(
            &ProjectFile::new(root.clone(), "packages.go")
                .read_to_string()
                .unwrap()
        )
    );
    assert_eq!(
        "anotherpkg",
        analyzer.determine_package_name(
            &ProjectFile::new(root.clone(), "anotherpkg/another.go")
                .read_to_string()
                .unwrap()
        )
    );
    assert_eq!(
        "",
        analyzer.determine_package_name(
            &ProjectFile::new(root.clone(), "nopkg.go")
                .read_to_string()
                .unwrap()
        )
    );
    assert_eq!(
        "",
        analyzer
            .determine_package_name(&ProjectFile::new(root, "empty.go").read_to_string().unwrap())
    );
}

#[test]
fn test_go_declarations_and_fq_names() {
    let analyzer = fixture_analyzer();
    let file = ProjectFile::new(analyzer.project().root().to_path_buf(), "declarations.go");
    let declarations = analyzer.get_declarations(&file);
    let fq_names: BTreeSet<_> = declarations.iter().map(CodeUnit::fq_name).collect();

    let expected = BTreeSet::from([
        "declpkg.MyTopLevelFunction".to_string(),
        "declpkg.MyStruct".to_string(),
        "declpkg.MyInterface".to_string(),
        "declpkg.anotherFunc".to_string(),
        "declpkg._module_.MyGlobalVar".to_string(),
        "declpkg._module_.MyGlobalConst".to_string(),
        "declpkg.MyStruct.GetFieldA".to_string(),
        "declpkg.MyStruct.FieldA".to_string(),
        "declpkg.MyInterface.DoSomething".to_string(),
        "declpkg.Uint32Map".to_string(),
        "declpkg._module_.StringAlias".to_string(),
        "declpkg.MyInt".to_string(),
        "declpkg.MyInt.String".to_string(),
        "declpkg.GroupedNamedType".to_string(),
        "declpkg._module_.GroupedAlias".to_string(),
    ]);
    assert_eq!(expected, fq_names);
    assert_eq!(15, declarations.len());

    assert!(analyzer.is_type_alias(&definition(&analyzer, "declpkg._module_.StringAlias")));
    assert!(analyzer.is_type_alias(&definition(&analyzer, "declpkg._module_.GroupedAlias")));
    assert!(!declarations.contains(&CodeUnit::new(
        file.clone(),
        CodeUnitType::Field,
        "declpkg",
        "_module_.Uint32Map",
    )));
    assert!(!declarations.contains(&CodeUnit::new(
        file,
        CodeUnitType::Field,
        "declpkg",
        "_module_.GroupedNamedType",
    )));
}

#[test]
fn test_go_summary_includes_methods_for_external_receiver_types() {
    let analyzer = GoAnalyzer::from_project(inline_project(&[(
        "diskcache.go",
        r#"
        package ipnlocal

        type diskCache struct {
            dir string
            cache int
        }

        func (b *LocalBackend) writeNetmapToDiskLocked() {}
        func (b *LocalBackend) loadDiskCacheLocked() {}
        func (b *LocalBackend) discardDiskCacheLocked() {}
        "#,
    )]));
    let file = ProjectFile::new(analyzer.project().root().to_path_buf(), "diskcache.go");

    assert_code_eq(
        r#"
        # ipnlocal
        - diskCache
          - dir
          - cache
        # ipnlocal.LocalBackend
        - writeNetmapToDiskLocked
        - loadDiskCacheLocked
        - discardDiskCacheLocked
        "#,
        &analyzer.summarize_symbols(&file),
    );
}

#[test]
fn test_go_summary_orders_same_file_receiver_methods_after_fields() {
    let analyzer = GoAnalyzer::from_project(inline_project(&[(
        "wrap.go",
        r#"
        package tstun

        func (pc *peerConfigTable) snat() {}
        func (pc *peerConfigTable) dnat() {}

        type peerConfigTable struct {
            nativeAddr4 int
            nativeAddr6 int
        }

        func (pc *peerConfigTable) String() string {
            return ""
        }
        "#,
    )]));
    let file = ProjectFile::new(analyzer.project().root().to_path_buf(), "wrap.go");

    assert_code_eq(
        r#"
        # tstun
        - peerConfigTable
          - nativeAddr4
          - nativeAddr6
          - String
          - snat
          - dnat
        "#,
        &analyzer.summarize_symbols(&file),
    );
}

#[test]
fn test_go_summary_recovers_top_level_functions_from_error_nodes() {
    let analyzer = GoAnalyzer::from_project(inline_project(&[(
        "proxygroup_test.go",
        PROXYGROUP_TEST_REGRESSION_SOURCE,
    )]));
    let file = ProjectFile::new(
        analyzer.project().root().to_path_buf(),
        "proxygroup_test.go",
    );
    let summary = analyzer.summarize_symbols(&file);

    assert!(
        summary.contains("- TestProxyGroup\n"),
        "Expected TestProxyGroup to appear in the summary. Summary was:\n{summary}"
    );
}

#[test]
fn test_go_summary_includes_nested_anonymous_struct_fields() {
    let analyzer = GoAnalyzer::from_project(inline_project(&[(
        "tsrecorder.go",
        r#"
        package main

        type prefs struct {
            Config struct {
                NodeID string
                UserProfile struct {
                    LoginName string
                }
            }

            AdvertiseServices []string
        }
        "#,
    )]));
    let file = ProjectFile::new(analyzer.project().root().to_path_buf(), "tsrecorder.go");

    assert_code_eq(
        r#"
        # main
        - prefs
          - Config
            - NodeID
            - UserProfile
              - LoginName
          - AdvertiseServices
        "#,
        &analyzer.summarize_symbols(&file),
    );
}

#[test]
fn test_grouped_function_typed_go_vars_are_reported_as_declarations() {
    let analyzer = GoAnalyzer::from_project(inline_project(&[(
        "debug.go",
        r#"
        package cli

        var (
            debugCaptureCmd   func() error
            debugPortmapCmd   func() error
            debugPeerRelayCmd func() error
        )
        "#,
    )]));
    let file = ProjectFile::new(analyzer.project().root().to_path_buf(), "debug.go");
    let fq_names: BTreeSet<_> = analyzer
        .get_declarations(&file)
        .iter()
        .map(CodeUnit::fq_name)
        .collect();

    assert_eq!(
        BTreeSet::from([
            "cli._module_.debugCaptureCmd".to_string(),
            "cli._module_.debugPortmapCmd".to_string(),
            "cli._module_.debugPeerRelayCmd".to_string(),
        ]),
        fq_names
    );
}

#[test]
fn test_replicated_anonymous_go_struct_members_do_not_copy_source_ranges() {
    let analyzer = GoAnalyzer::from_project(inline_project(&[(
        "settings.go",
        r#"
        package main

        type prefs struct {
            Config, OldConfig struct {
                NodeID string
            }
        }
        "#,
    )]));

    let original = definition(&analyzer, "main.prefs.Config.NodeID");
    let replicated = definition(&analyzer, "main.prefs.OldConfig.NodeID");

    assert!(
        !analyzer.ranges_of(&original).is_empty(),
        "the first inline member keeps the real source range"
    );
    assert!(
        analyzer.ranges_of(&replicated).is_empty(),
        "replicated sibling members should not reuse the first member's source range"
    );
}

#[test]
fn test_go_definitions_skeletons_and_members() {
    let analyzer = fixture_analyzer();
    let file = ProjectFile::new(analyzer.project().root().to_path_buf(), "declarations.go");

    assert_eq!(
        CodeUnit::new(
            file.clone(),
            CodeUnitType::Function,
            "declpkg",
            "MyTopLevelFunction"
        ),
        definition(&analyzer, "declpkg.MyTopLevelFunction").without_signature()
    );
    assert_eq!(
        CodeUnit::new(file.clone(), CodeUnitType::Class, "declpkg", "MyStruct"),
        definition(&analyzer, "declpkg.MyStruct").without_signature()
    );
    assert!(analyzer.get_definitions("declpkg.NonExistent").is_empty());

    assert_code_eq(
        "func MyTopLevelFunction(param int) string { ... }",
        &analyzer
            .get_skeleton(&definition(&analyzer, "declpkg.MyTopLevelFunction"))
            .unwrap(),
    );
    assert_code_eq(
        "func anotherFunc() { ... }",
        &analyzer
            .get_skeleton(&definition(&analyzer, "declpkg.anotherFunc"))
            .unwrap(),
    );
    assert_code_eq(
        r#"
        type MyInterface interface {
          DoSomething()
        }
        "#,
        &analyzer
            .get_skeleton(&definition(&analyzer, "declpkg.MyInterface"))
            .unwrap(),
    );
    assert_code_eq(
        r#"
        type MyStruct struct {
          FieldA int
          func (s MyStruct) GetFieldA() int { ... }
        }
        "#,
        &analyzer
            .get_skeleton(&definition(&analyzer, "declpkg.MyStruct"))
            .unwrap(),
    );
    assert_code_eq(
        "MyGlobalVar int = 42",
        &analyzer
            .get_skeleton(&definition(&analyzer, "declpkg._module_.MyGlobalVar"))
            .unwrap(),
    );
    assert_code_eq(
        "MyGlobalConst = \"hello_const\"",
        &analyzer
            .get_skeleton(&definition(&analyzer, "declpkg._module_.MyGlobalConst"))
            .unwrap(),
    );
    assert_code_eq(
        "func (s MyStruct) GetFieldA() int { ... }",
        &analyzer
            .get_skeleton(&definition(&analyzer, "declpkg.MyStruct.GetFieldA"))
            .unwrap(),
    );
    assert_code_eq(
        r#"
        type MyStruct struct {
          FieldA int
          [...]
        }
        "#,
        &analyzer
            .get_skeleton_header(&definition(&analyzer, "declpkg.MyStruct"))
            .unwrap(),
    );
    assert_code_eq(
        r#"
        type MyInterface interface {
          [...]
        }
        "#,
        &analyzer
            .get_skeleton_header(&definition(&analyzer, "declpkg.MyInterface"))
            .unwrap(),
    );

    let my_struct_members =
        analyzer.get_members_in_class(&definition(&analyzer, "declpkg.MyStruct"));
    assert_eq!(
        BTreeSet::from([
            "declpkg.MyStruct.FieldA".to_string(),
            "declpkg.MyStruct.GetFieldA".to_string()
        ]),
        my_struct_members
            .into_iter()
            .map(|cu| cu.fq_name())
            .collect()
    );
    let my_interface_members =
        analyzer.get_members_in_class(&definition(&analyzer, "declpkg.MyInterface"));
    assert_eq!(
        BTreeSet::from(["declpkg.MyInterface.DoSomething".to_string()]),
        my_interface_members
            .into_iter()
            .map(|cu| cu.fq_name())
            .collect()
    );
}

#[test]
fn test_go_sources_and_symbols() {
    let analyzer = fixture_analyzer();

    assert_eq!(
        normalize_nonempty_lines("type MyStruct struct {\n\tFieldA int\n}",),
        normalize_nonempty_lines(
            &analyzer
                .get_source(&definition(&analyzer, "declpkg.MyStruct"), true)
                .unwrap()
        )
    );
    assert_eq!(
        normalize_nonempty_lines("type MyInterface interface {\n\tDoSomething()\n}",),
        normalize_nonempty_lines(
            &analyzer
                .get_source(&definition(&analyzer, "declpkg.MyInterface"), true)
                .unwrap()
        )
    );
    assert_eq!(
        normalize_nonempty_lines(
            "func MyTopLevelFunction(param int) string {\n\treturn \"hello\"\n}",
        ),
        normalize_nonempty_lines(
            &analyzer
                .get_source(&definition(&analyzer, "declpkg.MyTopLevelFunction"), true)
                .unwrap()
        )
    );
    assert_eq!(
        normalize_nonempty_lines(
            "// Add this method for MyStruct\nfunc (s MyStruct) GetFieldA() int {\n\treturn s.FieldA\n}",
        ),
        normalize_nonempty_lines(
            &analyzer
                .get_source(&definition(&analyzer, "declpkg.MyStruct.GetFieldA"), true)
                .unwrap()
        )
    );
    assert!(
        analyzer
            .get_source(
                &CodeUnit::new(
                    ProjectFile::new(analyzer.project().root().to_path_buf(), "declarations.go"),
                    CodeUnitType::Class,
                    "declpkg",
                    "NonExistentClass"
                ),
                true
            )
            .is_none()
    );

    let file = ProjectFile::new(analyzer.project().root().to_path_buf(), "declarations.go");
    let input = BTreeSet::from([
        CodeUnit::new(
            file.clone(),
            CodeUnitType::Function,
            "declpkg",
            "MyTopLevelFunction",
        ),
        CodeUnit::new(file.clone(), CodeUnitType::Class, "declpkg", "MyStruct"),
        CodeUnit::new(file.clone(), CodeUnitType::Class, "declpkg", "MyInterface"),
        CodeUnit::new(
            file.clone(),
            CodeUnitType::Field,
            "declpkg",
            "_module_.MyGlobalVar",
        ),
        CodeUnit::new(
            file.clone(),
            CodeUnitType::Field,
            "declpkg",
            "_module_.MyGlobalConst",
        ),
        CodeUnit::new(
            file.clone(),
            CodeUnitType::Function,
            "declpkg",
            "anotherFunc",
        ),
        CodeUnit::new(
            file.clone(),
            CodeUnitType::Field,
            "declpkg",
            "MyStruct.FieldA",
        ),
        CodeUnit::new(
            file.clone(),
            CodeUnitType::Function,
            "declpkg",
            "MyStruct.GetFieldA",
        ),
        CodeUnit::new(
            file,
            CodeUnitType::Function,
            "declpkg",
            "MyInterface.DoSomething",
        ),
    ]);
    assert_eq!(
        BTreeSet::from([
            "MyTopLevelFunction".to_string(),
            "MyStruct".to_string(),
            "MyInterface".to_string(),
            "MyGlobalVar".to_string(),
            "MyGlobalConst".to_string(),
            "anotherFunc".to_string(),
            "FieldA".to_string(),
            "GetFieldA".to_string(),
            "DoSomething".to_string(),
        ]),
        analyzer.get_symbols(&input)
    );
}

#[test]
fn test_go_package_name_in_fqns_and_inline_field_cases() {
    let analyzer = fixture_analyzer();
    let file = ProjectFile::new(analyzer.project().root().to_path_buf(), "mypkg/mypkg.go");
    let fqns: BTreeSet<_> = analyzer
        .get_declarations(&file)
        .into_iter()
        .map(|cu| cu.fq_name())
        .collect();
    assert!(fqns.contains("mypkg.MyFunc"));
    assert!(fqns.contains("mypkg.MyType"));
    assert!(
        !fqns
            .iter()
            .any(|fqn| fqn == "mypkg" || fqn.starts_with("package"))
    );

    let inline = GoAnalyzer::from_project(inline_project(&[(
        "fields.go",
        r#"
        package declpkg

        type StructName struct {
            Field1, Field2, Field3 int
            Address1, Address2     string `json:"address"`
        }
        "#,
    )]));
    assert_code_eq(
        "Field1 int",
        &inline
            .get_skeleton(&definition(&inline, "declpkg.StructName.Field1"))
            .unwrap(),
    );
    assert_code_eq(
        "Field2 int",
        &inline
            .get_skeleton(&definition(&inline, "declpkg.StructName.Field2"))
            .unwrap(),
    );
    assert_code_eq(
        "Field3 int",
        &inline
            .get_skeleton(&definition(&inline, "declpkg.StructName.Field3"))
            .unwrap(),
    );
    assert_code_eq(
        "Address1 string `json:\"address\"`",
        &inline
            .get_skeleton(&definition(&inline, "declpkg.StructName.Address1"))
            .unwrap(),
    );
    assert_code_eq(
        "Address2 string `json:\"address\"`",
        &inline
            .get_skeleton(&definition(&inline, "declpkg.StructName.Address2"))
            .unwrap(),
    );
}

#[test]
fn test_go_inline_consts_and_initializer_truncation() {
    let inline = GoAnalyzer::from_project(inline_project(&[(
        "parser.go",
        r#"
        package yaml

        type yaml_parser_state_t int

        const (
            yaml_PARSE_STREAM_START_STATE yaml_parser_state_t = iota
            yaml_PARSE_FLOW_MAPPING_VALUE_STATE
        )
        "#,
    )]));
    assert!(
        !inline
            .get_definitions("yaml._module_.yaml_PARSE_FLOW_MAPPING_VALUE_STATE")
            .is_empty()
    );
    assert_code_eq(
        "yaml_PARSE_STREAM_START_STATE yaml_parser_state_t = iota",
        &inline
            .get_skeleton(&definition(
                &inline,
                "yaml._module_.yaml_PARSE_STREAM_START_STATE",
            ))
            .unwrap(),
    );

    let inline = GoAnalyzer::from_project(inline_project(&[(
        "fields.go",
        r#"
        package main
        var simpleInt int = 42
        var simpleString string = "hello"
        var complexObj = NewComplexObject("some", "args")
        var inlineStruct = struct{A int}{A: 1}
        "#,
    )]));
    assert_eq!(
        "simpleInt int = 42",
        inline.get_skeletons(&ProjectFile::new(
            inline.project().root().to_path_buf(),
            "fields.go"
        ))[&definition(&inline, "main._module_.simpleInt")]
            .trim()
    );
    assert_eq!(
        "simpleString string = \"hello\"",
        inline.get_skeletons(&ProjectFile::new(
            inline.project().root().to_path_buf(),
            "fields.go"
        ))[&definition(&inline, "main._module_.simpleString")]
            .trim()
    );
    assert_eq!(
        "complexObj",
        inline
            .get_skeleton(&definition(&inline, "main._module_.complexObj"))
            .unwrap()
            .trim()
    );
    assert_eq!(
        "inlineStruct",
        inline
            .get_skeleton(&definition(&inline, "main._module_.inlineStruct"))
            .unwrap()
            .trim()
    );

    let multi = GoAnalyzer::from_project(inline_project(&[(
        "multi.go",
        r#"
        package main
        var a, b = 1, complexFunc()
        "#,
    )]));
    assert_eq!(
        "a",
        multi
            .get_skeleton(&definition(&multi, "main._module_.a"))
            .unwrap()
            .trim()
    );
    assert_eq!(
        "b",
        multi
            .get_skeleton(&definition(&multi, "main._module_.b"))
            .unwrap()
            .trim()
    );
}
