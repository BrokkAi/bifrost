#[cfg(test)]
mod rust_indirect_table_tests {

    use std::collections::BTreeSet;

    use brokk_bifrost_core::analyzer::model::ProjectFile;

    use brokk_bifrost_analysis::analyzer::usages::candidates::usage_ecosystem_files;

    use brokk_bifrost_core::analyzer::model::Language;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    #[hardwon(
        "6074c794e6bd: Verifies batched importer prefetch respects language ecosystems instead of crossing into unrelated candidate rows"
    )]
    fn importer_prefetch_scope_follows_language_ecosystems() {
        let root = std::env::temp_dir();
        let files = [
            ProjectFile::new(root.clone(), "lib.rs"),
            ProjectFile::new(root.clone(), "Main.java"),
            ProjectFile::new(root.clone(), "Main.scala"),
            ProjectFile::new(root.clone(), "Main.kt"),
            ProjectFile::new(root.clone(), "app.js"),
            ProjectFile::new(root, "app.ts"),
        ];
        let relative_paths = |selected: Vec<ProjectFile>| {
            selected
                .into_iter()
                .map(|file| file.rel_path().to_string_lossy().into_owned())
                .collect::<BTreeSet<_>>()
        };

        assert_eq!(
            relative_paths(usage_ecosystem_files(files.clone(), Language::Rust)),
            BTreeSet::from(["lib.rs".to_string()])
        );
        assert_eq!(
            relative_paths(usage_ecosystem_files(files.clone(), Language::Java)),
            BTreeSet::from([
                "Main.java".to_string(),
                "Main.kt".to_string(),
                "Main.scala".to_string(),
            ])
        );
        assert_eq!(
            relative_paths(usage_ecosystem_files(files, Language::TypeScript)),
            BTreeSet::from(["app.js".to_string(), "app.ts".to_string()])
        );
    }
}
