//! Behavior tests for Kotlin core indexing (issue #1236): detection,
//! declaration forms, signatures, skeletons, duplicate-name owners,
//! incremental updates, mixed-language routing, and explicit `.kts` limits.

use crate::common::InlineTestProject;
use brokk_bifrost::CodeUnitIndex;
use brokk_bifrost::{IAnalyzer, KotlinAnalyzer, Language, ProjectFile, TypeAliasProvider};
use std::collections::BTreeSet;

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
        assert!(
            !name.contains('/') && !name.contains('\\'),
            "path-shaped identity: {name}"
        );
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
        // The companion renders as written in source. Its `Companion`
        // identity default is a name-resolution rule and must not leak into
        // rendered text.
        "class Circle(val radius: Double) {\n  val radius: Double\n  val area: Double\n  fun scaled(factor: Double): Circle\n  companion object {\n    val UNIT: Circle\n  }\n}"
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

/// Issue #1345: the index publishes what a Kotlin declaration *wrote* for its
/// return type and, for an extension, its receiver.
///
/// Both were previously recoverable only by re-reading and re-parsing the
/// declaring file, which is affordable for one cursor position and not for the
/// whole-workspace usage-edge pass that asks the same question of every
/// reference.
#[test]
fn kotlin_signature_metadata_publishes_written_return_types_and_extension_receivers() {
    let (_built, analyzer) = kotlin_analyzer(&[("src/Library.kt", LIBRARY_KT)]);
    let facts = |fq: &str| -> (Option<String>, Option<String>) {
        let unit = analyzer.get_definitions(fq).remove(0);
        let metadata = analyzer
            .signature_metadata(&unit)
            .into_iter()
            .next()
            .unwrap_or_else(|| panic!("{fq} must carry signature metadata"));
        (
            metadata.return_type_text().map(str::to_string),
            metadata.extension_receiver_type().map(str::to_string),
        )
    };

    assert_eq!(
        facts("com.example.library.Book.describe"),
        (Some("String".to_string()), None),
        "an ordinary member function publishes its return type and no receiver"
    );
    assert_eq!(
        facts("com.example.library.stamp"),
        (Some("Book".to_string()), Some("Book".to_string())),
        "an extension publishes both what it returns and what it extends"
    );
    assert_eq!(
        facts("com.example.library.checkout").0,
        Some("List".to_string()),
        "a generic return type publishes its nominal name, which is what a \
         consumer resolves; the arguments stay in the rendered signature"
    );
    assert_eq!(
        facts("com.example.library.Book.available"),
        (Some("Boolean".to_string()), None),
        "a property publishes the type it declares"
    );
    assert_eq!(
        facts("com.example.library.Book.title").0,
        Some("String".to_string()),
        "a val constructor parameter is a property and publishes its type too"
    );
    assert_eq!(
        facts("com.example.library.Catalog.shelve"),
        (None, None),
        "a function that writes no return type is absent, not empty: a consumer \
         must be able to tell `not written` from `written as nothing`"
    );
}

/// Issue #1345: the published facts must survive into `.kts`, whose declarations
/// go through the same walk but sit at script top level rather than in a package.
#[test]
fn kts_scripts_publish_written_return_types_and_extension_receivers() {
    let (_built, analyzer) = kotlin_analyzer(&[(
        "build.gradle.kts",
        r#"val libraryVersion: String = "1.2.3"

fun libraryCoordinate(name: String): String = "com.example:$name:$libraryVersion"

fun String.shout(): String = uppercase()

fun untyped() = 1
"#,
    )]);
    let metadata_of = |fq: &str| {
        let unit = analyzer.get_definitions(fq).remove(0);
        analyzer
            .signature_metadata(&unit)
            .into_iter()
            .next()
            .unwrap_or_else(|| panic!("{fq} must carry signature metadata"))
    };

    assert_eq!(
        metadata_of("libraryCoordinate").return_type_text(),
        Some("String")
    );
    assert_eq!(
        metadata_of("libraryVersion").return_type_text(),
        Some("String")
    );
    let shout = metadata_of("shout");
    assert_eq!(shout.extension_receiver_type(), Some("String"));
    assert_eq!(shout.return_type_text(), Some("String"));
    assert_eq!(
        metadata_of("untyped").return_type_text(),
        None,
        "an expression body with no written type infers nothing at index time"
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

    // Semantic materialization is live for Kotlin (#1241) — asserted by
    // materializing, not merely by the provider being present, so unwiring the
    // lowerer would fail here.
    let cancellation = brokk_bifrost::analyzer::semantic::CancellationToken::default();
    let mut budget = brokk_bifrost::analyzer::semantic::SemanticBudget::default();
    let outcome = workspace
        .materialize_program_semantics(
            &kotlin_file,
            &mut brokk_bifrost::analyzer::semantic::SemanticRequest::new(
                &mut budget,
                &cancellation,
            ),
        )
        .expect("Kotlin semantics must resolve to an outcome, not an error");
    let brokk_bifrost::analyzer::semantic::SemanticOutcome::Complete {
        value: artifact, ..
    } = outcome
    else {
        panic!("Kotlin program semantics must materialize completely: {outcome:?}");
    };
    assert!(
        artifact.procedures().iter().any(|procedure| procedure
            .locator()
            .declaration()
            .segments()
            .last()
            .and_then(|segment| segment.name())
            == Some("serve")),
        "Kotlin lowering must publish the file's declared method"
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

#[test]
fn primary_constructor_defaults_are_optional_arguments() {
    // Regression: `class_parameter` owns its own `= default`, unlike a
    // function parameter whose `=` is a sibling in the list. Scanning the
    // list's children (the function rule's shape) found no defaults here and
    // reported every constructor parameter as required.
    let (_built, analyzer) = kotlin_analyzer(&[(
        "src/Defaults.kt",
        r#"package defaults

class Book(val title: String, val copies: Int = 1, val tag: String = "none")

class Exact(val only: Int)

class Spread(vararg val parts: String)

fun freeform(title: String, copies: Int = 1): Int = copies
"#,
    )]);
    let arity_of = |fq: &str| {
        analyzer
            .signature_metadata(&analyzer.get_definitions(fq).remove(0))
            .first()
            .and_then(|metadata| metadata.callable_arity())
            .unwrap_or_else(|| panic!("{fq} must carry callable arity"))
    };

    let book = arity_of("defaults.Book.Book");
    assert!(book.accepts(1), "Book(title) is legal Kotlin");
    assert!(book.accepts(2) && book.accepts(3));
    assert!(!book.accepts(0) && !book.accepts(4));

    let exact = arity_of("defaults.Exact.Exact");
    assert!(exact.accepts(1) && !exact.accepts(0) && !exact.accepts(2));

    let spread = arity_of("defaults.Spread.Spread");
    assert!(
        spread.accepts(0) && spread.accepts(5),
        "vararg accepts any count"
    );

    // The function form must keep working — it takes the other code path.
    let freeform = arity_of("defaults.freeform");
    assert!(freeform.accepts(1) && freeform.accepts(2) && !freeform.accepts(3));
}

#[test]
fn object_signatures_keep_supertypes_and_source_spelling() {
    let (_built, analyzer) = kotlin_analyzer(&[(
        "src/Objects.kt",
        r#"package objects

interface Shelver

object Catalog : Shelver

class Owner {
    companion object Named : Shelver

    class Inner {
        companion object
    }
}
"#,
    )]);
    assert_eq!(
        analyzer.signatures(&analyzer.get_definitions("objects.Catalog").remove(0)),
        vec!["object Catalog : Shelver {"],
        "an object's declared supertype must survive into its signature"
    );
    assert_eq!(
        analyzer.signatures(&analyzer.get_definitions("objects.Owner.Named").remove(0)),
        vec!["companion object Named : Shelver {"]
    );
    assert_eq!(
        analyzer.signatures(
            &analyzer
                .get_definitions("objects.Owner.Inner.Companion")
                .remove(0)
        ),
        vec!["companion object {"],
        "an anonymous companion renders as written, not with its synthetic identity"
    );
}

#[test]
fn enum_entry_override_shares_the_base_member_identity() {
    // Entry-body members are owned by the enum class (Field units own no
    // children), so an override collides with the base member: one CodeUnit
    // carrying both ranges and both signatures. Deliberate, and asserted here
    // so an unintended merge cannot hide behind it.
    let (_built, analyzer) = kotlin_analyzer(&[(
        "src/Genre.kt",
        r#"package shapes

enum class Genre {
    FICTION,
    REFERENCE {
        override fun lendable(): Boolean = false
    };

    open fun lendable(): Boolean = true
}
"#,
    )]);
    let lendable = analyzer.get_definitions("shapes.Genre.lendable");
    assert_eq!(lendable.len(), 1, "base and override share one identity");
    assert_eq!(
        analyzer.ranges(&lendable[0]).len(),
        2,
        "both declaration sites are retained as ranges"
    );
    let signatures = analyzer.signatures(&lendable[0]);
    assert!(
        signatures
            .iter()
            .any(|s| s.starts_with("open fun lendable"))
    );
    assert!(
        signatures
            .iter()
            .any(|s| s.starts_with("override fun lendable"))
    );
}

#[test]
fn generics_sealed_nested_and_init_forms_are_indexed() {
    let (_built, analyzer) = kotlin_analyzer(&[(
        "src/Forms.kt",
        r#"package forms

sealed class Result<out T> {
    class Ok<T>(val value: T) : Result<T>()
    class Err(val reason: String) : Result<Nothing>()
}

class Container<K : Comparable<K>, V>(val key: K) {
    val entries: MutableMap<K, V> = mutableMapOf()

    init {
        entries.clear()
    }

    inner class Cursor {
        fun advance(): Int = 1
    }
}

fun <T : Any> T.describeAll(others: List<T>): String = others.toString()

typealias Handlers<T> = Map<String, (T) -> Unit>
"#,
    )]);
    let names = declaration_names(&analyzer);
    for expected in [
        "forms.Result",
        "forms.Result.Ok",
        "forms.Result.Ok.value",
        "forms.Result.Err",
        "forms.Result.Err.reason",
        "forms.Container",
        "forms.Container.key",
        "forms.Container.entries",
        "forms.Container.Cursor",
        "forms.Container.Cursor.advance",
        "forms.describeAll",
        "forms.Handlers",
    ] {
        assert!(names.contains(expected), "missing {expected} in {names:#?}");
    }

    // Type parameters must not bleed into identities.
    for name in &names {
        assert!(!name.contains('<'), "type parameter leaked into {name}");
    }

    assert_eq!(
        analyzer.signatures(&analyzer.get_definitions("forms.Result.Ok").remove(0)),
        vec!["class Ok<T>(val value: T) : Result<T>() {"]
    );
    assert!(analyzer.is_type_alias(&analyzer.get_definitions("forms.Handlers").remove(0)));
}

#[test]
fn destructuring_property_declares_every_bound_name() {
    let (_built, analyzer) = kotlin_analyzer(&[(
        "src/Destructure.kt",
        r#"package destructure

class Holder {
    val (first, second) = Pair(1, 2)
}
"#,
    )]);
    let names = declaration_names(&analyzer);
    assert!(names.contains("destructure.Holder.first"), "{names:#?}");
    assert!(names.contains("destructure.Holder.second"), "{names:#?}");
}

#[test]
fn backtick_quoted_identifiers_index_under_their_real_name() {
    // Kotlin's backticks are quoting syntax, not part of the name. Keeping
    // them would make the declaration unreachable by its real spelling — and
    // backticked test-method names are idiomatic.
    let (_built, analyzer) = kotlin_analyzer(&[(
        "src/QuotedTest.kt",
        r#"package quoted

class SampleTest {
    fun `serves the request`(): Int = 1
}
"#,
    )]);
    let names = declaration_names(&analyzer);
    assert!(
        names.contains("quoted.SampleTest.serves the request"),
        "backticks must be stripped from the identity: {names:#?}"
    );
    for name in &names {
        assert!(!name.contains('`'), "backtick leaked into identity: {name}");
    }
    assert_eq!(
        analyzer
            .get_definitions("quoted.SampleTest.serves the request")
            .len(),
        1,
        "the declaration must be reachable by its real spelling"
    );
}
