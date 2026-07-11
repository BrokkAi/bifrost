use brokk_bifrost::{
    IAnalyzer, ImportAnalysisProvider, Language, ProjectFile, RustAnalyzer, TestProject,
};
use tempfile::tempdir;

fn rust_project(files: &[(&str, &str)]) -> TestProject {
    let temp = tempdir().unwrap();
    for (path, contents) in files {
        ProjectFile::new(temp.path().to_path_buf(), path)
            .write(*contents)
            .unwrap();
    }
    TestProject::new(temp.keep(), Language::Rust)
}

#[test]
fn test_import_statement_shapes() {
    let basic = RustAnalyzer::from_project(rust_project(&[(
        "src/main.rs",
        "use std::collections::HashMap;",
    )]));
    let basic_file = ProjectFile::new(basic.project().root().to_path_buf(), "src/main.rs");
    assert_eq!(
        vec!["use std::collections::HashMap;".to_string()],
        basic.import_statements(&basic_file)
    );

    let nested = RustAnalyzer::from_project(rust_project(&[(
        "src/main.rs",
        "use std::collections::{HashMap, HashSet};",
    )]));
    let nested_file = ProjectFile::new(nested.project().root().to_path_buf(), "src/main.rs");
    let imports = nested.import_statements(&nested_file);
    assert!(imports.contains(&"use std::collections::HashMap;".to_string()));
    assert!(imports.contains(&"use std::collections::HashSet;".to_string()));

    let alias = RustAnalyzer::from_project(rust_project(&[(
        "src/main.rs",
        "use std::collections::HashMap as MyMap;",
    )]));
    let alias_file = ProjectFile::new(alias.project().root().to_path_buf(), "src/main.rs");
    assert_eq!(
        vec!["use std::collections::HashMap as MyMap;".to_string()],
        alias.import_statements(&alias_file)
    );

    let wildcard =
        RustAnalyzer::from_project(rust_project(&[("src/main.rs", "use std::collections::*;")]));
    let wildcard_file = ProjectFile::new(wildcard.project().root().to_path_buf(), "src/main.rs");
    assert_eq!(
        vec!["use std::collections::*;".to_string()],
        wildcard.import_statements(&wildcard_file)
    );

    let self_import = RustAnalyzer::from_project(rust_project(&[(
        "src/main.rs",
        "use std::io::{self, Read, Write};",
    )]));
    let self_file = ProjectFile::new(self_import.project().root().to_path_buf(), "src/main.rs");
    let imports = self_import.import_statements(&self_file);
    assert!(imports.contains(&"use std::io;".to_string()));
    assert!(imports.contains(&"use std::io::Read;".to_string()));
    assert!(imports.contains(&"use std::io::Write;".to_string()));

    let grouped_alias_self = RustAnalyzer::from_project(rust_project(&[(
        "src/main.rs",
        "use models::{self, MemoryRepository as Repo, OtherRepository};",
    )]));
    let grouped_file = ProjectFile::new(
        grouped_alias_self.project().root().to_path_buf(),
        "src/main.rs",
    );
    let imports = grouped_alias_self.import_statements(&grouped_file);
    assert!(imports.contains(&"use models;".to_string()));
    assert!(imports.contains(&"use models::MemoryRepository as Repo;".to_string()));
    assert!(imports.contains(&"use models::OtherRepository;".to_string()));

    let nested_groups = RustAnalyzer::from_project(rust_project(&[(
        "src/main.rs",
        "use app::{env::{env_init}, service::{self, Service as S}};",
    )]));
    let nested_file = ProjectFile::new(nested_groups.project().root().to_path_buf(), "src/main.rs");
    let imports = nested_groups.import_statements(&nested_file);
    assert!(imports.contains(&"use app::env::env_init;".to_string()));
    assert!(imports.contains(&"use app::service;".to_string()));
    assert!(imports.contains(&"use app::service::Service as S;".to_string()));

    let public_reexports = RustAnalyzer::from_project(rust_project(&[(
        "src/main.rs",
        "pub use service::{build_service, MemoryRepository as Repo, Service};",
    )]));
    let public_file = ProjectFile::new(
        public_reexports.project().root().to_path_buf(),
        "src/main.rs",
    );
    let imports = public_reexports.import_statements(&public_file);
    assert!(imports.contains(&"pub use service::build_service;".to_string()));
    assert!(imports.contains(&"pub use service::MemoryRepository as Repo;".to_string()));
    assert!(imports.contains(&"pub use service::Service;".to_string()));

    let restricted_reexports = RustAnalyzer::from_project(rust_project(&[(
        "src/main.rs",
        "pub(crate) use service::{Foo as CrateFoo, Bar};\npub(self) use service::Hidden;",
    )]));
    let restricted_file = ProjectFile::new(
        restricted_reexports.project().root().to_path_buf(),
        "src/main.rs",
    );
    let imports = restricted_reexports.import_statements(&restricted_file);
    assert!(imports.contains(&"pub(crate) use service::Foo as CrateFoo;".to_string()));
    assert!(imports.contains(&"pub(crate) use service::Bar;".to_string()));
    assert!(imports.contains(&"pub(self) use service::Hidden;".to_string()));
    assert!(!imports.contains(&"pub use service::Foo as CrateFoo;".to_string()));
    assert!(!imports.contains(&"pub use service::Bar;".to_string()));
    assert!(!imports.contains(&"pub use service::Hidden;".to_string()));
}

#[test]
fn test_structured_import_info_for_group_alias_self_and_wildcard() {
    let analyzer = RustAnalyzer::from_project(rust_project(&[(
        "src/main.rs",
        r#"
        use models::{self, MemoryRepository as Repo, OtherRepository};
        use models::*;
        "#,
    )]));
    let file = ProjectFile::new(analyzer.project().root().to_path_buf(), "src/main.rs");
    let import_infos = analyzer.import_info_of(&file);

    assert!(import_infos.iter().any(|info| {
        info.raw_snippet == "use models;"
            && !info.is_wildcard
            && info.identifier.as_deref() == Some("models")
            && info.alias.is_none()
    }));
    assert!(import_infos.iter().any(|info| {
        info.raw_snippet == "use models::MemoryRepository as Repo;"
            && !info.is_wildcard
            && info.identifier.as_deref() == Some("MemoryRepository")
            && info.alias.as_deref() == Some("Repo")
    }));
    assert!(import_infos.iter().any(|info| {
        info.raw_snippet == "use models::OtherRepository;"
            && !info.is_wildcard
            && info.identifier.as_deref() == Some("OtherRepository")
            && info.alias.is_none()
    }));
    assert!(import_infos.iter().any(|info| {
        info.raw_snippet == "use models::*;"
            && info.is_wildcard
            && info.identifier.is_none()
            && info.alias.is_none()
    }));
}

#[test]
fn test_type_alias_detection_via_import_suite() {
    let analyzer = RustAnalyzer::from_project(rust_project(&[(
        "src/main.rs",
        "type MyResult<T> = Result<T, Error>;",
    )]));
    let file = ProjectFile::new(analyzer.project().root().to_path_buf(), "src/main.rs");
    let alias = analyzer
        .declarations(&file)
        .into_iter()
        .find(|cu| cu.identifier() == "MyResult")
        .unwrap();
    assert!(analyzer.is_type_alias(&alias));
    assert!(
        analyzer
            .type_alias_provider()
            .is_some_and(|provider| provider.is_type_alias(&alias))
    );
}

#[test]
fn test_resolve_imports_semantic_cases() {
    let semantic = RustAnalyzer::from_project(rust_project(&[
        ("src/my_module.rs", "pub struct MyStruct;"),
        (
            "src/main.rs",
            r#"
            use crate::my_module::MyStruct;
            fn main() { let _s = MyStruct; }
            "#,
        ),
    ]));
    let main_file = ProjectFile::new(semantic.project().root().to_path_buf(), "src/main.rs");
    let imported = semantic.imported_code_units_of(&main_file);
    assert!(imported.iter().any(|cu| cu.identifier() == "MyStruct"));

    let aliased = RustAnalyzer::from_project(rust_project(&[
        ("src/lib.rs", "pub struct TargetStruct;"),
        (
            "src/main.rs",
            r#"
            use crate::TargetStruct as AliasStruct;
            fn main() { let _s = AliasStruct; }
            "#,
        ),
    ]));
    let main_file = ProjectFile::new(aliased.project().root().to_path_buf(), "src/main.rs");
    let imported = aliased.imported_code_units_of(&main_file);
    assert!(imported.iter().any(|cu| cu.identifier() == "TargetStruct"));

    let nested = RustAnalyzer::from_project(rust_project(&[
        ("src/shared/models.rs", "pub struct TargetStruct;"),
        (
            "src/nested/app/user.rs",
            r#"
            use crate::shared::models::TargetStruct;
            fn use_type() { let _t = TargetStruct; }
            "#,
        ),
    ]));
    let user_file = ProjectFile::new(
        nested.project().root().to_path_buf(),
        "src/nested/app/user.rs",
    );
    let imported = nested.imported_code_units_of(&user_file);
    assert!(imported.iter().any(|cu| cu.identifier() == "TargetStruct"));

    // `super` at a crate root is invalid Rust ("too many leading `super` keywords"),
    // so a root-file `use super::X` must not resolve to anything.
    let super_root = RustAnalyzer::from_project(rust_project(&[
        ("src/lib.rs", "pub struct ExternalStruct;"),
        (
            "src/main.rs",
            r#"
            use super::ExternalStruct;
            fn main() {}
            "#,
        ),
    ]));
    let main_file = ProjectFile::new(super_root.project().root().to_path_buf(), "src/main.rs");
    let imported = super_root.imported_code_units_of(&main_file);
    assert!(
        !imported
            .iter()
            .any(|cu| cu.identifier() == "ExternalStruct"),
        "`use super::X` at a crate root is invalid and must not resolve"
    );

    // A legitimate (non-root) `super::` import does resolve: from `pkg::nested`,
    // `super` is `pkg`, so `super::service::Service` reaches `pkg::service`.
    let super_relative = RustAnalyzer::from_project(rust_project(&[
        ("src/pkg/service.rs", "pub struct Service;"),
        (
            "src/pkg/nested/mod.rs",
            r#"
            use super::service::Service;
            fn run() { let _s = Service; }
            "#,
        ),
    ]));
    let nested_file = ProjectFile::new(
        super_relative.project().root().to_path_buf(),
        "src/pkg/nested/mod.rs",
    );
    let imported = super_relative.imported_code_units_of(&nested_file);
    assert!(
        imported.iter().any(|cu| cu.identifier() == "Service"),
        "`use super::service::Service` from pkg::nested should resolve to pkg::service::Service"
    );
}

#[test]
fn test_rust_referencing_files_uses_resolved_import_targets() {
    let analyzer = RustAnalyzer::from_project(rust_project(&[
        ("src/shared/models.rs", "pub struct TargetStruct;"),
        (
            "src/main.rs",
            r#"
            use crate::shared::models::TargetStruct;
            fn main() { let _t = TargetStruct; }
            "#,
        ),
    ]));
    let target = ProjectFile::new(
        analyzer.project().root().to_path_buf(),
        "src/shared/models.rs",
    );
    let consumer = ProjectFile::new(analyzer.project().root().to_path_buf(), "src/main.rs");

    assert_eq!(
        std::collections::BTreeSet::from([consumer]),
        analyzer.referencing_files_of(&target).into_iter().collect()
    );
}
