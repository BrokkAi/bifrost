//! Behavior tests for Kotlin core indexing (issue #1236): detection,
//! declaration forms, signatures, skeletons, duplicate-name owners,
//! incremental updates, mixed-language routing, and explicit `.kts` limits.

mod common;

use brokk_bifrost::{IAnalyzer, KotlinAnalyzer, Language, ProjectFile, TypeAliasProvider};
use common::InlineTestProject;
use std::collections::BTreeSet;

fn kotlin_analyzer(files: &[(&str, &str)]) -> (common::BuiltInlineTestProject, KotlinAnalyzer) {
    let mut project = InlineTestProject::with_language(Language::Kotlin);
    for (path, contents) in files {
        project = project.file(*path, *contents);
    }
    let built = project.build();
    let analyzer = KotlinAnalyzer::new(built.project_dyn());
    (built, analyzer)
}

fn declaration_names(analyzer: &dyn IAnalyzer) -> BTreeSet<String> {
    analyzer
        .all_declarations()
        .map(|unit| unit.fq_name())
        .collect()
}

const LIBRARY_KT: &str = r#"package com.example.library

import java.time.Instant
import kotlin.collections.List

data class Book(val title: String, val copies: Int = 1) {
    val available: Boolean
        get() = copies > 0

    fun describe(): String = "$title ($copies)"

    companion object {
        fun of(title: String): Book = Book(title)
    }
}

interface Shelver {
    fun shelve(book: Book)
}

object Catalog : Shelver {
    private val books = mutableListOf<Book>()

    override fun shelve(book: Book) {
        books.add(book)
    }
}

enum class Genre(val code: String) {
    FICTION("F"),
    REFERENCE("R") {
        override fun lendable(): Boolean = false
    };

    open fun lendable(): Boolean = true
}

annotation class Catalogued(val shelf: String)

typealias Inventory = Map<String, Book>

fun Book.stamp(timestamp: Instant): Book = this

fun checkout(book: Book, count: Int = 1): List<Book> = List(count) { book }
"#;

#[test]
fn kotlin_files_are_detected_and_indexed() {
    let (built, analyzer) = kotlin_analyzer(&[("src/Library.kt", LIBRARY_KT)]);
    assert_eq!(
        built.languages(),
        BTreeSet::from([Language::Kotlin]),
        "kt extension must infer the Kotlin analyzer language"
    );
    let file = built.file("src/Library.kt");
    assert!(analyzer.is_analyzed(&file));
    assert!(analyzer.analyzed_files().contains(&file));
    assert!(
        analyzer
            .parse_errors(&file)
            .is_some_and(|errors| errors.is_empty())
    );
    assert_eq!(
        analyzer.import_statements(&file),
        vec![
            "import java.time.Instant".to_string(),
            "import kotlin.collections.List".to_string(),
        ]
    );
}

#[test]
fn principal_declaration_forms_have_stable_source_identities() {
    let (_built, analyzer) = kotlin_analyzer(&[("src/Library.kt", LIBRARY_KT)]);
    let names = declaration_names(&analyzer);
    for expected in [
        "com.example.library.Book",
        "com.example.library.Book.Book",
        "com.example.library.Book.title",
        "com.example.library.Book.copies",
        "com.example.library.Book.available",
        "com.example.library.Book.describe",
        "com.example.library.Book.Companion",
        "com.example.library.Book.Companion.of",
        "com.example.library.Shelver",
        "com.example.library.Shelver.shelve",
        "com.example.library.Catalog",
        "com.example.library.Catalog.books",
        "com.example.library.Catalog.shelve",
        "com.example.library.Genre",
        "com.example.library.Genre.FICTION",
        "com.example.library.Genre.REFERENCE",
        "com.example.library.Genre.lendable",
        "com.example.library.Catalogued",
        "com.example.library.Inventory",
        "com.example.library.stamp",
        "com.example.library.checkout",
    ] {
        assert!(names.contains(expected), "missing {expected} in {names:#?}");
    }

    // Source identities must not carry compiler-generated JVM names or
    // absolute paths.
    for name in &names {
        assert!(!name.contains('$'), "JVM-encoded identity leaked: {name}");
        assert!(!name.contains("LibraryKt"), "file facade leaked: {name}");
        assert!(!name.contains('/'), "path-shaped identity: {name}");
    }
}

#[test]
fn definitions_resolve_by_fully_qualified_name() {
    let (_built, analyzer) = kotlin_analyzer(&[("src/Library.kt", LIBRARY_KT)]);
    let book = analyzer.get_definitions("com.example.library.Book");
    assert_eq!(book.len(), 1);
    assert!(book[0].is_class());

    let of = analyzer.get_definitions("com.example.library.Book.Companion.of");
    assert_eq!(of.len(), 1);
    assert!(of[0].is_function());

    let alias = analyzer.get_definitions("com.example.library.Inventory");
    assert_eq!(alias.len(), 1);
    assert!(analyzer.is_type_alias(&alias[0]));
}

#[test]
fn ownership_follows_source_nesting() {
    let (built, analyzer) = kotlin_analyzer(&[("src/Library.kt", LIBRARY_KT)]);
    let file = built.file("src/Library.kt");

    let top_level: BTreeSet<String> = analyzer
        .top_level_declarations(&file)
        .into_iter()
        .map(|unit| unit.fq_name())
        .collect();
    for expected in [
        "com.example.library.Book",
        "com.example.library.Catalog",
        "com.example.library.stamp",
        "com.example.library.checkout",
    ] {
        assert!(top_level.contains(expected), "missing {expected}");
    }
    assert!(
        !top_level.contains("com.example.library.Book.describe"),
        "members must not be top-level"
    );

    let book = analyzer
        .get_definitions("com.example.library.Book")
        .remove(0);
    let children: BTreeSet<String> = analyzer
        .direct_children(&book)
        .into_iter()
        .map(|unit| unit.fq_name())
        .collect();
    for expected in [
        "com.example.library.Book.title",
        "com.example.library.Book.copies",
        "com.example.library.Book.available",
        "com.example.library.Book.describe",
        "com.example.library.Book.Companion",
    ] {
        assert!(children.contains(expected), "missing child {expected}");
    }

    let describe = analyzer
        .get_definitions("com.example.library.Book.describe")
        .remove(0);
    assert_eq!(
        analyzer.parent_of(&describe).map(|unit| unit.fq_name()),
        Some("com.example.library.Book".to_string())
    );
}

#[test]
fn signatures_and_metadata_render_kotlin_headers() {
    let (_built, analyzer) = kotlin_analyzer(&[("src/Library.kt", LIBRARY_KT)]);

    let book = analyzer
        .get_definitions("com.example.library.Book")
        .remove(0);
    assert_eq!(
        analyzer.signatures(&book),
        vec!["data class Book(val title: String, val copies: Int = 1) {"]
    );

    let stamp = analyzer
        .get_definitions("com.example.library.stamp")
        .remove(0);
    assert_eq!(
        analyzer.signatures(&stamp),
        vec!["fun Book.stamp(timestamp: Instant): Book"],
        "extension receiver must stay visible in the signature"
    );

    let checkout = analyzer
        .get_definitions("com.example.library.checkout")
        .remove(0);
    let metadata = analyzer.signature_metadata(&checkout);
    let arity = metadata
        .first()
        .and_then(|metadata| metadata.callable_arity())
        .expect("checkout must carry callable arity");
    assert!(arity.accepts(1) && arity.accepts(2) && !arity.accepts(0) && !arity.accepts(3));
}

#[test]
fn skeletons_render_nested_declarations() {
    let (_built, analyzer) = kotlin_analyzer(&[(
        "src/Shapes.kt",
        r#"package shapes

class Circle(val radius: Double) {
    val area: Double
        get() = 3.14 * radius * radius

    fun scaled(factor: Double): Circle = Circle(radius * factor)

    companion object {
        val UNIT: Circle = Circle(1.0)
    }
}
"#,
    )]);
    let circle = analyzer.get_definitions("shapes.Circle").remove(0);
    let skeleton = analyzer.get_skeleton(&circle).expect("skeleton");
    assert_eq!(
        skeleton,
        "class Circle(val radius: Double) {\n  val radius: Double\n  val area: Double\n  fun scaled(factor: Double): Circle\n  companion object Companion {\n    val UNIT: Circle\n  }\n}"
    );

    let header = analyzer.get_skeleton_header(&circle).expect("header");
    assert!(header.starts_with("class Circle(val radius: Double) {"));
    assert!(
        header.contains("[...]"),
        "header must elide non-field members: {header}"
    );
}

#[test]
fn duplicate_short_names_resolve_to_distinct_owners() {
    let (_built, analyzer) = kotlin_analyzer(&[
        (
            "src/alpha/Worker.kt",
            r#"package alpha

class Worker(val id: Int) {
    fun run(): Int = id
    val label: String = "alpha"
}
"#,
        ),
        (
            "src/beta/Worker.kt",
            r#"package beta

class Worker(val id: Int) {
    fun run(): Int = id * 2
    val label: String = "beta"
}
"#,
        ),
    ]);

    let alpha = analyzer.get_definitions("alpha.Worker");
    let beta = analyzer.get_definitions("beta.Worker");
    assert_eq!(alpha.len(), 1);
    assert_eq!(beta.len(), 1);
    assert_ne!(alpha[0], beta[0]);

    let alpha_run = analyzer.get_definitions("alpha.Worker.run");
    let beta_run = analyzer.get_definitions("beta.Worker.run");
    assert_eq!(alpha_run.len(), 1);
    assert_eq!(beta_run.len(), 1);
    assert_ne!(alpha_run[0], beta_run[0]);

    // A constructor shares its class's spelling but is a distinct callable
    // unit named `Worker.Worker`.
    let constructors = analyzer.get_definitions("alpha.Worker.Worker");
    assert_eq!(constructors.len(), 1);
    assert!(constructors[0].is_function());
    assert!(alpha[0].is_class());
}

#[test]
fn constructors_cover_primary_and_secondary_forms() {
    let (_built, analyzer) = kotlin_analyzer(&[(
        "src/Point.kt",
        r#"package geometry

class Point(val x: Int, val y: Int) {
    constructor(both: Int) : this(both, both)

    fun manhattan(): Int = x + y
}
"#,
    )]);
    let constructors = analyzer.get_definitions("geometry.Point.Point");
    assert_eq!(
        constructors.len(),
        1,
        "primary and secondary constructors share one callable identity"
    );
    let unit = &constructors[0];
    assert!(unit.is_function());
    let signatures = analyzer.signatures(unit);
    assert!(
        signatures
            .iter()
            .any(|signature| signature == "Point(val x: Int, val y: Int)"),
        "missing primary constructor signature: {signatures:?}"
    );
    assert!(
        signatures
            .iter()
            .any(|signature| signature == "constructor(both: Int)"),
        "missing secondary constructor signature: {signatures:?}"
    );
    assert_eq!(analyzer.ranges(unit).len(), 2);
}

#[test]
fn local_callables_are_not_indexed_as_declarations() {
    let (_built, analyzer) = kotlin_analyzer(&[(
        "src/Local.kt",
        r#"package local

fun outer(): Int {
    fun inner(): Int = 1
    val lambda = { value: Int -> value * 2 }
    return inner() + lambda(2)
}

class Holder {
    fun make(): Runnable = object : Runnable {
        override fun run() {}
    }
}
"#,
    )]);
    let names = declaration_names(&analyzer);
    assert!(names.contains("local.outer"));
    assert!(names.contains("local.Holder.make"));
    // Local functions, lambdas, and anonymous objects stay un-indexed in the
    // core tier (usage/CFG tiers model them; see issues #1239/#1241).
    assert!(!names.iter().any(|name| name.contains("inner")));
    assert!(!names.iter().any(|name| name.contains("lambda")));
    assert!(!names.iter().any(|name| name.contains("run")));
}

#[test]
fn malformed_source_recovers_surrounding_declarations() {
    // The stray bracket run parses as a contained ERROR node between two
    // healthy declarations; both neighbors must stay indexed and the parse
    // error must be observable.
    let (built, analyzer) = kotlin_analyzer(&[(
        "src/Broken.kt",
        r#"package broken

fun healthy(): Int = 1

]]]

class Survivor {
    fun still(): Int = 2
}
"#,
    )]);
    let file = built.file("src/Broken.kt");
    let errors = analyzer.parse_errors(&file).expect("parse errors recorded");
    assert!(!errors.is_empty(), "fixture must exercise recovery");

    let names = declaration_names(&analyzer);
    assert!(names.contains("broken.healthy"));
    assert!(names.contains("broken.Survivor"));
    assert!(names.contains("broken.Survivor.still"));
}

#[test]
fn kts_scripts_index_declarations_with_documented_limits() {
    // `.kts` support boundary (issue #1236): declarations in a script are
    // indexed like `.kt` declarations; script *statements* are executable
    // code, not declarations, and script receivers/implicit bindings are not
    // modeled in the core tier.
    let (built, analyzer) = kotlin_analyzer(&[(
        "build.gradle.kts",
        r#"val libraryVersion = "1.2.3"

fun libraryCoordinate(name: String): String = "com.example:$name:$libraryVersion"

class PluginSettings {
    var enabled: Boolean = true
}

println(libraryCoordinate("core"))
"#,
    )]);
    let file = built.file("build.gradle.kts");
    assert!(analyzer.is_analyzed(&file), "kts must be analyzed");

    let names = declaration_names(&analyzer);
    assert!(names.contains("libraryVersion"));
    assert!(names.contains("libraryCoordinate"));
    assert!(names.contains("PluginSettings"));
    assert!(names.contains("PluginSettings.enabled"));
    assert!(
        !names.iter().any(|name| name.contains("println")),
        "script statements are not declarations"
    );
}

#[test]
fn incremental_update_tracks_edits_and_preserves_untouched_identities() {
    let (built, analyzer) = kotlin_analyzer(&[
        (
            "src/First.kt",
            "package inc\n\nclass First {\n    fun old(): Int = 1\n}\n",
        ),
        (
            "src/Second.kt",
            "package inc\n\nclass Second {\n    fun stable(): Int = 2\n}\n",
        ),
    ]);
    assert!(declaration_names(&analyzer).contains("inc.First.old"));
    let stable_before = analyzer.get_definitions("inc.Second.stable").remove(0);

    let first = built.file("src/First.kt");
    ProjectFile::new(built.root().to_path_buf(), "src/First.kt")
        .write("package inc\n\nclass First {\n    fun renamed(): Int = 1\n}\n")
        .expect("rewrite First.kt");

    let updated = analyzer.update(&BTreeSet::from([first]));
    let names = declaration_names(&updated);
    assert!(names.contains("inc.First.renamed"));
    assert!(!names.contains("inc.First.old"));

    let stable_after = updated.get_definitions("inc.Second.stable").remove(0);
    assert_eq!(
        stable_before, stable_after,
        "untouched declarations keep their identity across updates"
    );
}

#[test]
fn mixed_language_workspace_routes_kotlin_and_java() {
    let built = InlineTestProject::new()
        .file(
            "src/Service.kt",
            "package mixed\n\nclass Service {\n    fun serve(): Int = 1\n}\n",
        )
        .file(
            "src/Client.java",
            "package mixed;\n\nclass Client {\n    int use() { return 1; }\n}\n",
        )
        .build();
    assert_eq!(
        built.languages(),
        BTreeSet::from([Language::Java, Language::Kotlin]),
        "extension inference must include Kotlin"
    );

    let workspace = built.workspace_analyzer(brokk_bifrost::AnalyzerConfig::default());
    let analyzer = workspace.analyzer();
    let names = declaration_names(analyzer);
    assert!(
        names.contains("mixed.Service"),
        "missing Kotlin unit: {names:#?}"
    );
    assert!(names.contains("mixed.Service.serve"));
    assert!(
        names.contains("mixed.Client"),
        "missing Java unit: {names:#?}"
    );

    let kotlin_file = built.file("src/Service.kt");
    let java_file = built.file("src/Client.java");
    assert!(analyzer.is_analyzed(&kotlin_file));
    assert!(analyzer.is_analyzed(&java_file));

    // Semantic materialization stays explicitly unsupported for Kotlin
    // until issue #1241, while Java resolves through its provider.
    assert!(
        workspace
            .program_semantics_provider_for_file(&kotlin_file)
            .is_some(),
        "Kotlin routes to a provider that reports Unsupported"
    );
}

#[test]
fn get_source_returns_declaration_text() {
    let (_built, analyzer) = kotlin_analyzer(&[(
        "src/Snippet.kt",
        r#"package snip

class Tool {
    fun use(): String = "in use"
}
"#,
    )]);
    let unit = analyzer.get_definitions("snip.Tool.use").remove(0);
    let source = analyzer.get_source(&unit, false).expect("source");
    assert_eq!(source, "fun use(): String = \"in use\"");
}
