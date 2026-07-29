//! Behaviour tests for Kotlin name resolution (issue #1237): structured
//! imports, the file relationships they create, supertype hierarchy, and the
//! shared JVM dependency realm.

mod common;

use brokk_bifrost::{CodeUnit, ImportAnalysisProvider, KotlinAnalyzer, Language, ProjectFile};
use common::InlineTestProject;

fn kotlin_analyzer(files: &[(&str, &str)]) -> (common::BuiltInlineTestProject, KotlinAnalyzer) {
    let mut project = InlineTestProject::with_language(Language::Kotlin);
    for (path, contents) in files {
        project = project.file(*path, *contents);
    }
    let built = project.build();
    let analyzer = KotlinAnalyzer::new(built.project_dyn());
    (built, analyzer)
}

fn imported_names(analyzer: &KotlinAnalyzer, file: &ProjectFile) -> Vec<String> {
    let mut names: Vec<String> = analyzer
        .imported_code_units_of(file)
        .iter()
        .map(CodeUnit::fq_name)
        .collect();
    names.sort();
    names
}

const LIBRARY: &str = "package lib\n\
     \n\
     open class Base\n\
     \n\
     interface Contract\n\
     \n\
     class Outer {\n\
         class Inner\n\
     }\n\
     \n\
     object Registry {\n\
         fun register(): Int = 1\n\
     }\n\
     \n\
     fun topLevelHelper(): Int = 2\n\
     \n\
     val topLevelProperty: Int = 3\n";

#[test]
fn kotlin_explicit_import_resolves_to_the_declaration() {
    let (built, analyzer) = kotlin_analyzer(&[
        ("lib/Library.kt", LIBRARY),
        (
            "app/App.kt",
            "package app\n\nimport lib.Base\n\nclass App\n",
        ),
    ]);

    assert_eq!(
        imported_names(&analyzer, &built.file("app/App.kt")),
        vec!["lib.Base".to_string()]
    );
}

#[test]
fn kotlin_import_reaches_nested_types_and_object_members() {
    let (built, analyzer) = kotlin_analyzer(&[
        ("lib/Library.kt", LIBRARY),
        (
            "app/App.kt",
            "package app\n\
             \n\
             import lib.Outer.Inner\n\
             import lib.Registry.register\n\
             \n\
             class App\n",
        ),
    ]);

    assert_eq!(
        imported_names(&analyzer, &built.file("app/App.kt")),
        vec![
            "lib.Outer.Inner".to_string(),
            "lib.Registry.register".to_string(),
        ],
        "a Kotlin fully-qualified name is dotted all the way down, so a nested \
         type and an object member are ordinary import targets"
    );
}

#[test]
fn kotlin_aliased_import_resolves_to_the_original_declaration() {
    let (built, analyzer) = kotlin_analyzer(&[
        ("lib/Library.kt", LIBRARY),
        (
            "app/App.kt",
            "package app\n\nimport lib.Base as Parent\n\nclass App\n",
        ),
    ]);

    assert_eq!(
        imported_names(&analyzer, &built.file("app/App.kt")),
        vec!["lib.Base".to_string()],
        "an alias renames the binding, not the declaration it points at"
    );

    let imports = analyzer.import_info_of(&built.file("app/App.kt"));
    assert_eq!(imports.len(), 1);
    assert_eq!(imports[0].alias.as_deref(), Some("Parent"));
    assert_eq!(imports[0].identifier.as_deref(), Some("Parent"));
}

#[test]
fn kotlin_star_import_binds_every_top_level_declaration_in_a_package() {
    let (built, analyzer) = kotlin_analyzer(&[
        ("lib/Library.kt", LIBRARY),
        ("app/App.kt", "package app\n\nimport lib.*\n\nclass App\n"),
    ]);

    let names = imported_names(&analyzer, &built.file("app/App.kt"));
    for expected in [
        "lib.Base",
        "lib.Contract",
        "lib.Outer",
        "lib.Registry",
        "lib.topLevelHelper",
        "lib.topLevelProperty",
    ] {
        assert!(
            names.iter().any(|name| name == expected),
            "missing {expected} in {names:#?}"
        );
    }
    assert!(
        !names.iter().any(|name| name == "lib.Outer.Inner"),
        "a package star import does not reach nested declarations"
    );
}

#[test]
fn kotlin_star_import_of_an_object_binds_its_members() {
    let (built, analyzer) = kotlin_analyzer(&[
        ("lib/Library.kt", LIBRARY),
        (
            "app/App.kt",
            "package app\n\nimport lib.Registry.*\n\nclass App\n",
        ),
    ]);

    assert_eq!(
        imported_names(&analyzer, &built.file("app/App.kt")),
        vec!["lib.Registry.register".to_string()]
    );
}

#[test]
fn kotlin_import_of_a_name_that_does_not_exist_resolves_to_nothing() {
    let (built, analyzer) = kotlin_analyzer(&[
        ("lib/Library.kt", LIBRARY),
        (
            "app/App.kt",
            "package app\n\
             \n\
             import lib.NoSuchType\n\
             import missing.pkg.*\n\
             \n\
             class App\n",
        ),
    ]);

    assert!(
        imported_names(&analyzer, &built.file("app/App.kt")).is_empty(),
        "an unresolvable import stays unresolved rather than binding a guess"
    );
}

#[test]
fn kotlin_same_package_files_reference_each_other_without_an_import() {
    let (built, analyzer) = kotlin_analyzer(&[
        ("app/Base.kt", "package app\n\nopen class Base\n"),
        (
            "app/Child.kt",
            "package app\n\nclass Child {\n    fun make(): Base = Base()\n}\n",
        ),
        ("other/Unrelated.kt", "package other\n\nclass Unrelated\n"),
    ]);

    let referencing = analyzer.referencing_files_of(&built.file("app/Base.kt"));
    assert!(
        referencing.contains(&built.file("app/Child.kt")),
        "same-package files see each other with no import: {referencing:#?}"
    );
    assert!(!referencing.contains(&built.file("other/Unrelated.kt")));
}

#[test]
fn kotlin_importing_file_is_recorded_as_a_referencing_file() {
    let (built, analyzer) = kotlin_analyzer(&[
        ("lib/Library.kt", LIBRARY),
        (
            "app/App.kt",
            "package app\n\nimport lib.Base\n\nclass App : Base()\n",
        ),
        ("other/Unrelated.kt", "package other\n\nclass Unrelated\n"),
    ]);

    let referencing = analyzer.referencing_files_of(&built.file("lib/Library.kt"));
    assert!(referencing.contains(&built.file("app/App.kt")));
    assert!(!referencing.contains(&built.file("other/Unrelated.kt")));
}

#[test]
fn kotlin_object_reference_makes_a_same_package_file_a_referrer() {
    // `Registry` is an `object`, so `Registry.register()` spells it as a value,
    // not as a type — the only way to name a Kotlin singleton.
    let (built, analyzer) = kotlin_analyzer(&[
        (
            "app/Registry.kt",
            "package app\n\nobject Registry {\n    fun register(): Int = 1\n}\n",
        ),
        (
            "app/Caller.kt",
            "package app\n\nfun call(): Int = Registry.register()\n",
        ),
    ]);

    assert!(
        analyzer
            .referencing_files_of(&built.file("app/Registry.kt"))
            .contains(&built.file("app/Caller.kt"))
    );
}

#[test]
fn kotlin_could_import_file_follows_explicit_star_and_package_reach() {
    let (built, analyzer) = kotlin_analyzer(&[
        ("lib/Library.kt", LIBRARY),
        (
            "app/App.kt",
            "package app\n\nimport lib.Base\n\nclass App\n",
        ),
        ("app/Sibling.kt", "package app\n\nclass Sibling\n"),
        ("far/Far.kt", "package far\n\nclass Far\n"),
    ]);

    let app = built.file("app/App.kt");
    let imports = analyzer.import_info_of(&app);
    assert!(analyzer.could_import_file(&app, &imports, &built.file("lib/Library.kt")));
    assert!(analyzer.could_import_file(&app, &imports, &built.file("app/Sibling.kt")));
    assert!(!analyzer.could_import_file(&app, &imports, &built.file("far/Far.kt")));
    assert!(
        !analyzer.could_import_file(&app, &imports, &app),
        "a file never imports itself"
    );
}
