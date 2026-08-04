//! Behaviour tests for Kotlin name resolution (issue #1237): structured
//! imports, the file relationships they create, supertype hierarchy, and the
//! shared JVM dependency realm.

use crate::common::InlineTestProject;
use brokk_bifrost::CodeUnitIndex;
use brokk_bifrost::{
    AnalyzerConfig, CodeUnit, ImportAnalysisProvider, JvmAnalyzerConfig, JvmExternalArtifact,
    JvmExternalDependencies, KotlinAnalyzer, Language, ProjectFile, TypeHierarchyProvider,
};
use std::io::Write;

fn kotlin_analyzer(
    files: &[(&str, &str)],
) -> (crate::common::BuiltInlineTestProject, KotlinAnalyzer) {
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

// ---------------------------------------------------------------------------
// Type hierarchy
// ---------------------------------------------------------------------------

fn ancestor_names(analyzer: &KotlinAnalyzer, fq_name: &str) -> Vec<String> {
    let unit = analyzer
        .get_definitions(fq_name)
        .into_iter()
        .find(CodeUnit::is_class)
        .unwrap_or_else(|| panic!("no class declaration named {fq_name}"));
    let mut names: Vec<String> = analyzer
        .get_direct_ancestors(&unit)
        .iter()
        .map(CodeUnit::fq_name)
        .collect();
    names.sort();
    names
}

fn descendant_names(analyzer: &KotlinAnalyzer, fq_name: &str) -> Vec<String> {
    let unit = analyzer
        .get_definitions(fq_name)
        .into_iter()
        .find(CodeUnit::is_class)
        .unwrap_or_else(|| panic!("no class declaration named {fq_name}"));
    let mut names: Vec<String> = analyzer
        .get_direct_descendants(&unit)
        .iter()
        .map(CodeUnit::fq_name)
        .collect();
    names.sort();
    names
}

const HIERARCHY_LIBRARY: &str = "package lib\n\
     \n\
     open class Base(val seed: Int)\n\
     \n\
     interface Contract\n\
     \n\
     interface Logged\n\
     \n\
     open class Outer {\n\
         open class Nested\n\
     }\n";

#[test]
fn kotlin_same_package_supertype_needs_no_import() {
    let (_built, analyzer) = kotlin_analyzer(&[(
        "app/Types.kt",
        "package app\n\nopen class Base\n\nclass Child : Base()\n",
    )]);

    assert_eq!(ancestor_names(&analyzer, "app.Child"), vec!["app.Base"]);
}

#[test]
fn kotlin_supertype_resolves_through_an_explicit_import() {
    let (_built, analyzer) = kotlin_analyzer(&[
        ("lib/Library.kt", HIERARCHY_LIBRARY),
        (
            "app/Child.kt",
            "package app\n\nimport lib.Base\n\nclass Child : Base(1)\n",
        ),
    ]);

    assert_eq!(ancestor_names(&analyzer, "app.Child"), vec!["lib.Base"]);
}

#[test]
fn kotlin_supertype_resolves_through_an_aliased_import() {
    let (_built, analyzer) = kotlin_analyzer(&[
        ("lib/Library.kt", HIERARCHY_LIBRARY),
        (
            "app/Child.kt",
            "package app\n\nimport lib.Base as Parent\n\nclass Child : Parent(1)\n",
        ),
    ]);

    assert_eq!(
        ancestor_names(&analyzer, "app.Child"),
        vec!["lib.Base"],
        "the alias names the binding; the ancestor is the declaration it points at"
    );
}

#[test]
fn kotlin_supertype_resolves_through_a_star_import() {
    let (_built, analyzer) = kotlin_analyzer(&[
        ("lib/Library.kt", HIERARCHY_LIBRARY),
        (
            "app/Child.kt",
            "package app\n\nimport lib.*\n\nclass Child : Base(1), Contract, Logged\n",
        ),
    ]);

    assert_eq!(
        ancestor_names(&analyzer, "app.Child"),
        vec!["lib.Base", "lib.Contract", "lib.Logged"]
    );
}

#[test]
fn kotlin_supertype_resolves_a_fully_qualified_name_without_an_import() {
    let (_built, analyzer) = kotlin_analyzer(&[
        ("lib/Library.kt", HIERARCHY_LIBRARY),
        ("app/Child.kt", "package app\n\nclass Child : lib.Base(1)\n"),
    ]);

    assert_eq!(ancestor_names(&analyzer, "app.Child"), vec!["lib.Base"]);
}

#[test]
fn kotlin_supertype_resolves_a_nested_owner_path() {
    let (_built, analyzer) = kotlin_analyzer(&[
        ("lib/Library.kt", HIERARCHY_LIBRARY),
        (
            "app/Child.kt",
            "package app\n\nimport lib.Outer\n\nclass Child : Outer.Nested()\n",
        ),
    ]);

    assert_eq!(
        ancestor_names(&analyzer, "app.Child"),
        vec!["lib.Outer.Nested"]
    );
}

#[test]
fn kotlin_nested_class_names_a_sibling_without_qualification() {
    let (_built, analyzer) = kotlin_analyzer(&[(
        "app/Outer.kt",
        "package app\n\
         \n\
         class Outer {\n\
             open class Sibling\n\
             class Child : Sibling()\n\
         }\n",
    )]);

    assert_eq!(
        ancestor_names(&analyzer, "app.Outer.Child"),
        vec!["app.Outer.Sibling"],
        "a nested declaration sees its owner's other members without qualification"
    );
}

#[test]
fn kotlin_class_names_a_type_inherited_from_its_superclass() {
    let (_built, analyzer) = kotlin_analyzer(&[(
        "app/Types.kt",
        "package app\n\
         \n\
         open class Holder {\n\
             open class Carried\n\
         }\n\
         \n\
         open class Middle : Holder()\n\
         \n\
         class Leaf : Middle() {\n\
             class Uses : Carried()\n\
         }\n",
    )]);

    assert_eq!(
        ancestor_names(&analyzer, "app.Leaf.Uses"),
        vec!["app.Holder.Carried"],
        "an inherited nested type is in scope through the whole superclass chain"
    );
}

#[test]
fn kotlin_object_and_companion_carry_their_own_supertypes() {
    let (_built, analyzer) = kotlin_analyzer(&[
        ("lib/Library.kt", HIERARCHY_LIBRARY),
        (
            "app/Types.kt",
            "package app\n\
             \n\
             import lib.Contract\n\
             \n\
             object Catalog : Contract\n\
             \n\
             class Owner {\n\
                 companion object : Contract\n\
             }\n",
        ),
    ]);

    assert_eq!(
        ancestor_names(&analyzer, "app.Catalog"),
        vec!["lib.Contract"]
    );
    assert_eq!(
        ancestor_names(&analyzer, "app.Owner.Companion"),
        vec!["lib.Contract"]
    );
    assert!(
        ancestor_names(&analyzer, "app.Owner").is_empty(),
        "a companion's supertype belongs to the companion, not to its owner"
    );
}

#[test]
fn kotlin_interface_delegation_names_the_interface_not_the_delegate() {
    let (_built, analyzer) = kotlin_analyzer(&[
        ("lib/Library.kt", HIERARCHY_LIBRARY),
        (
            "app/Child.kt",
            "package app\n\
             \n\
             import lib.Logged\n\
             \n\
             class Child(logger: Logged) : Logged by logger\n",
        ),
    ]);

    assert_eq!(ancestor_names(&analyzer, "app.Child"), vec!["lib.Logged"]);
}

#[test]
fn kotlin_descendants_invert_every_resolved_supertype() {
    let (_built, analyzer) = kotlin_analyzer(&[
        ("lib/Library.kt", HIERARCHY_LIBRARY),
        (
            "app/Children.kt",
            "package app\n\
             \n\
             import lib.Base\n\
             import lib.Contract\n\
             \n\
             open class First : Base(1), Contract\n\
             class Second : First()\n",
        ),
        (
            "wild/Child.kt",
            "package wild\n\nimport lib.*\n\nclass Wildcard : Base(2)\n",
        ),
    ]);

    assert_eq!(
        descendant_names(&analyzer, "lib.Base"),
        vec!["app.First", "wild.Wildcard"]
    );
    assert_eq!(
        descendant_names(&analyzer, "lib.Contract"),
        vec!["app.First"]
    );
    assert_eq!(descendant_names(&analyzer, "app.First"), vec!["app.Second"]);
    assert!(descendant_names(&analyzer, "app.Second").is_empty());
}

#[test]
fn kotlin_unresolvable_supertype_yields_no_ancestor() {
    let (_built, analyzer) = kotlin_analyzer(&[(
        "app/Child.kt",
        "package app\n\nclass Child : SomeMissingLibraryType()\n",
    )]);

    assert!(
        ancestor_names(&analyzer, "app.Child").is_empty(),
        "a supertype from an unconfigured dependency stays unresolved rather \
         than becoming a fabricated declaration"
    );
}

#[test]
fn kotlin_ambiguous_star_imports_resolve_to_nothing() {
    let (_built, analyzer) = kotlin_analyzer(&[
        ("one/Base.kt", "package one\n\nopen class Base\n"),
        ("two/Base.kt", "package two\n\nopen class Base\n"),
        (
            "app/Child.kt",
            "package app\n\
             \n\
             import one.*\n\
             import two.*\n\
             \n\
             class Child : Base()\n",
        ),
    ]);

    assert!(
        ancestor_names(&analyzer, "app.Child").is_empty(),
        "two star imports binding the same simple name is ambiguous in Kotlin; \
         resolution must report that rather than pick a winner"
    );
}

#[test]
fn kotlin_explicit_import_wins_over_a_same_package_declaration() {
    let (_built, analyzer) = kotlin_analyzer(&[
        ("lib/Library.kt", HIERARCHY_LIBRARY),
        (
            "app/Base.kt",
            "package app\n\nopen class Base(val seed: Int)\n",
        ),
        (
            "app/Child.kt",
            "package app\n\nimport lib.Base\n\nclass Child : Base(1)\n",
        ),
    ]);

    assert_eq!(
        ancestor_names(&analyzer, "app.Child"),
        vec!["lib.Base"],
        "an explicit import outranks the file's own package"
    );
}

#[test]
fn kotlin_hierarchy_identities_stay_source_level() {
    let (_built, analyzer) = kotlin_analyzer(&[(
        "app/Types.kt",
        "package app\n\
         \n\
         interface Contract\n\
         \n\
         object Catalog : Contract\n\
         \n\
         class Owner {\n\
             companion object Factory : Contract\n\
         }\n",
    )]);

    let mut descendants = descendant_names(&analyzer, "app.Contract");
    descendants.sort();
    assert_eq!(descendants, vec!["app.Catalog", "app.Owner.Factory"]);
    assert!(
        descendants
            .iter()
            .all(|name| !name.contains('$') && !name.contains("Kt")),
        "no compiler-generated JVM name may appear in a Kotlin identity"
    );
}

// ---------------------------------------------------------------------------
// Shared JVM dependency realm
// ---------------------------------------------------------------------------

/// Write a `-sources.jar` containing one Kotlin entry, without needing a
/// Kotlin toolchain on the machine running the test.
fn write_kotlin_source_jar(path: &std::path::Path, entry: &str, contents: &str) {
    let file = std::fs::File::create(path).expect("create source jar");
    let mut zip = zip::ZipWriter::new(file);
    zip.start_file(
        entry,
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored),
    )
    .expect("start jar entry");
    zip.write_all(contents.as_bytes()).expect("write jar entry");
    zip.finish().expect("finish source jar");
}

fn analyzer_with_kotlin_dependency(
    files: &[(&str, &str)],
) -> (
    crate::common::BuiltInlineTestProject,
    tempfile::TempDir,
    KotlinAnalyzer,
) {
    let mut project = InlineTestProject::with_language(Language::Kotlin);
    for (path, contents) in files {
        project = project.file(*path, *contents);
    }
    let built = project.build();

    let jar_dir = tempfile::tempdir().expect("create jar dir");
    let source_jar = jar_dir.path().join("dep-1.0-sources.jar");
    write_kotlin_source_jar(
        &source_jar,
        "com/example/dep/ExternalService.kt",
        "package com.example.dep\n\
         \n\
         open class ExternalService {\n\
             class Nested\n\
         }\n\
         \n\
         internal class ModulePrivate\n",
    );

    let config = AnalyzerConfig {
        jvm: JvmAnalyzerConfig {
            external_dependencies: JvmExternalDependencies {
                artifact_paths: vec![JvmExternalArtifact {
                    artifact_path: source_jar,
                    source_artifact_path: None,
                    ..JvmExternalArtifact::default()
                }],
                ..JvmExternalDependencies::default()
            },
            ..JvmAnalyzerConfig::default()
        },
        ..AnalyzerConfig::default()
    };
    let analyzer = KotlinAnalyzer::new_with_config(built.project_dyn(), config);
    (built, jar_dir, analyzer)
}

#[test]
fn kotlin_resolves_external_jvm_types_without_creating_declarations() {
    let (built, _jar_dir, analyzer) = analyzer_with_kotlin_dependency(&[(
        "app/App.kt",
        "package app\n\
         \n\
         import com.example.dep.ExternalService\n\
         \n\
         class App\n",
    )]);
    let app = built.file("app/App.kt");

    assert!(analyzer.is_known_type_name_in_file(&app, "ExternalService"));
    assert!(analyzer.is_known_type_name_in_file(&app, "ExternalService.Nested"));
    assert!(analyzer.is_known_type_name_in_file(&app, "com.example.dep.ExternalService"));
    assert!(
        !analyzer.is_known_type_name_in_file(&app, "ModulePrivate"),
        "an `internal` dependency type is not nameable from another artifact"
    );
    assert!(
        !analyzer.is_known_type_name_in_file(&app, "NoSuchDependencyType"),
        "a missing name stays explicitly unknown"
    );

    assert!(
        analyzer
            .resolve_type_name_in_file(&app, "ExternalService")
            .is_none(),
        "external types must never be fabricated as workspace declarations"
    );
    assert!(
        analyzer
            .get_all_declarations()
            .into_iter()
            .all(|unit| !unit.fq_name().starts_with("com.example.dep.")),
        "external dependency types must not leak into the declaration index"
    );
}

#[test]
fn kotlin_supertype_from_a_dependency_jar_is_known_but_has_no_ancestor_unit() {
    let (built, _jar_dir, analyzer) = analyzer_with_kotlin_dependency(&[(
        "app/Child.kt",
        "package app\n\
         \n\
         import com.example.dep.ExternalService\n\
         \n\
         class Child : ExternalService()\n",
    )]);

    assert!(analyzer.is_known_type_name_in_file(&built.file("app/Child.kt"), "ExternalService"));
    assert!(
        ancestor_names(&analyzer, "app.Child").is_empty(),
        "the hierarchy holds workspace declarations; a dependency supertype is \
         known but has no CodeUnit to point at"
    );
}

#[test]
fn kotlin_without_a_classpath_leaves_dependency_names_unknown() {
    let (built, analyzer) = kotlin_analyzer(&[(
        "app/App.kt",
        "package app\n\nimport com.example.dep.ExternalService\n\nclass App\n",
    )]);

    assert!(
        !analyzer.is_known_type_name_in_file(&built.file("app/App.kt"), "ExternalService"),
        "with no configured or discovered classpath an import stays unresolved, \
         never silently known"
    );
}

// ---------------------------------------------------------------------------
// Explicitly unsupported outcomes
// ---------------------------------------------------------------------------

#[test]
fn kotlin_multiplatform_source_sets_index_but_do_not_gain_platform_default_imports() {
    // Kotlin/JVM is this tier's target. A multiplatform layout is still
    // indexed — declarations, imports, and hierarchy all work — but a name that
    // would only be visible through a Kotlin/JS or Kotlin/Native default import
    // is not claimed as resolvable.
    let (built, analyzer) = kotlin_analyzer(&[
        (
            "src/commonMain/kotlin/app/Shared.kt",
            "package app\n\nopen class Shared\n",
        ),
        (
            "src/jvmMain/kotlin/app/JvmImpl.kt",
            "package app\n\nclass JvmImpl : Shared()\n",
        ),
        (
            "src/jsMain/kotlin/app/JsImpl.kt",
            "package app\n\nclass JsImpl : Shared()\n",
        ),
    ]);

    // Every source set is indexed, and same-package resolution works across
    // them because they declare the same package.
    assert_eq!(ancestor_names(&analyzer, "app.JvmImpl"), vec!["app.Shared"]);
    assert_eq!(ancestor_names(&analyzer, "app.JsImpl"), vec!["app.Shared"]);

    // `Promise` is a Kotlin/JS default import (`kotlin.js.*`), which this tier
    // deliberately does not model.
    assert!(
        !analyzer
            .is_known_type_name_in_file(&built.file("src/jsMain/kotlin/app/JsImpl.kt"), "Promise"),
        "a Kotlin/JS default import is not claimed on a Kotlin/JVM analyzer"
    );
}

#[test]
fn kotlin_expect_and_actual_declarations_index_without_a_claimed_link() {
    // `expect`/`actual` is a multiplatform compiler relationship, not a
    // supertype relationship. Both sides are ordinary declarations here and no
    // link between them is asserted.
    let (_built, analyzer) = kotlin_analyzer(&[
        (
            "src/commonMain/kotlin/app/Clock.kt",
            "package app\n\nexpect class Clock {\n    fun now(): Long\n}\n",
        ),
        (
            "src/jvmMain/kotlin/app/Clock.kt",
            "package app\n\nactual class Clock {\n    actual fun now(): Long = 0L\n}\n",
        ),
    ]);

    let declarations: Vec<String> = analyzer
        .get_definitions("app.Clock")
        .iter()
        .map(CodeUnit::fq_name)
        .collect();
    assert!(
        declarations.len() >= 2,
        "both the expect and the actual declaration are indexed: {declarations:?}"
    );
    assert!(
        ancestor_names(&analyzer, "app.Clock").is_empty(),
        "expect/actual is not inheritance and must not be reported as such"
    );
}

#[test]
fn kotlin_generated_jvm_surfaces_never_appear_in_an_identity() {
    let (built, analyzer) = kotlin_analyzer(&[(
        "app/Facade.kt",
        "package app\n\
         \n\
         interface Contract\n\
         \n\
         class Owner : Contract {\n\
             companion object {\n\
                 fun create(): Owner = Owner()\n\
             }\n\
         }\n\
         \n\
         fun topLevel(): Int = 1\n",
    )]);

    let names: Vec<String> = analyzer
        .get_all_declarations()
        .iter()
        .map(CodeUnit::fq_name)
        .collect();
    assert!(
        names.iter().any(|name| name == "app.Owner.Companion"),
        "an anonymous companion is named by its Kotlin spelling: {names:?}"
    );
    assert!(
        names.iter().all(|name| !name.contains('$')),
        "no `$` encoding may reach an identity: {names:?}"
    );
    assert!(
        names.iter().all(|name| !name.contains("FacadeKt")),
        "the generated file facade is not a declaration: {names:?}"
    );

    // The same holds on the resolution paths this issue adds.
    assert_eq!(ancestor_names(&analyzer, "app.Owner"), vec!["app.Contract"]);
    assert!(
        !analyzer.is_known_type_name_in_file(&built.file("app/Facade.kt"), "FacadeKt"),
        "a name that only exists as a compiler artifact must not resolve"
    );
}
