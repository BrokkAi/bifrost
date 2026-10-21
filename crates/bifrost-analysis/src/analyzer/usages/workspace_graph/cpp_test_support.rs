use crate::analyzer::CodeUnitIndex;
use crate::analyzer::usages::workspace_graph::*;
use crate::analyzer::{
    AnalyzerDelegate, JavaAnalyzer, KotlinAnalyzer, MultiAnalyzer, ScalaAnalyzer, TestProject,
};

use std::collections::BTreeMap;

use std::sync::Arc;
/// Every catalog field a graph consumer can observe on one node.
#[doc(hidden)]
pub type CatalogNodeFields = (
    WorkspaceUsageNodeKey,
    CodeUnit,
    Option<Range>,
    Vec<ProjectFile>,
    Vec<DeclarationId>,
);
#[doc(hidden)]
pub fn catalog_node_fields(catalog: &WorkspaceUsageCatalog) -> Vec<CatalogNodeFields> {
    catalog
        .nodes
        .iter()
        .map(|node| {
            (
                node.key.clone(),
                node.primary.clone(),
                node.primary_range,
                node.declaration_files.clone(),
                node.declaration_ids.clone(),
            )
        })
        .collect()
}
/// Two C++ declarations of one entity, in a header and its translation
/// unit.
///
/// C++ and C# omit the exact declaration identity from the group key, so
/// these land in one node. That is the only shape that exercises duplicate
/// grouping, primary selection among several rows, and the file/identity
/// deduplication -- the JVM fixture's rows are all exact identities, so
/// every one of its groups holds exactly one row.
#[doc(hidden)]
pub fn cpp_redeclaration_pair(root: &std::path::Path) -> Vec<CatalogDeclaration> {
    let signature = Some("void Widget::draw()".to_string());
    let declaration = |rel_path: &str, start_line: usize| {
        (
            CodeUnit::with_signature(
                ProjectFile::new(root.to_path_buf(), rel_path),
                crate::analyzer::CodeUnitType::Function,
                "widgets",
                "Widget.draw",
                signature.clone(),
                false,
            ),
            Some(Range {
                start_byte: start_line * 40,
                end_byte: start_line * 40 + 20,
                start_line,
                end_line: start_line,
            }),
        )
    };
    // Deliberately enumerated header first while `lib/widget.cpp` sorts
    // first, so primary selection is decided by source order and not by
    // the order the rows arrived in.
    vec![
        declaration("lib/widget.h", 4),
        declaration("lib/widget.cpp", 12),
    ]
}
/// The inventory the parity and cost-shape tests group: every persisted
/// declaration of the multi-language fixture, its Java module descriptor,
/// and one C++ redeclaration pair.
#[doc(hidden)]
pub fn parity_inventory(
    analyzer: &MultiAnalyzer,
    root: &std::path::Path,
) -> Vec<CatalogDeclaration> {
    let mut declarations = analyzer.all_declarations_with_primary_ranges();
    for file in analyzer.analyzed_files() {
        if is_java_module_descriptor_file(&file) {
            let file_scope = CodeUnit::file_scope(file.clone());
            let range = analyzer
                .ranges(&file_scope)
                .into_iter()
                .min_by_key(range_key);
            declarations.push((file_scope, range));
        }
    }
    declarations.extend(cpp_redeclaration_pair(root));
    declarations
}
/// A persisted multi-language workspace, analyzed twice so the second
/// analyzer reads the same cache-backed summary projections a warm real
/// workspace reads.
#[doc(hidden)]
pub fn persisted_multilanguage_analyzer(root: std::path::PathBuf) -> MultiAnalyzer {
    ProjectFile::new(root.clone(), "module-info.java")
        .write("module example.module {}\n")
        .unwrap();
    ProjectFile::new(root.clone(), "app/Greeter.java")
            .write(
                "package app;\n\npublic class Greeter {\n    public String greet() { return \"hi\"; }\n}\n",
            )
            .unwrap();
    // Scala indexes the anonymous class as a synthetic owner and its `run`
    // as an ordinary declaration, and the Scala summary wrapper prunes
    // synthetic entries out of `children`. So `run` is reachable only
    // through the persisted declaration inventory (#2992).
    ProjectFile::new(root.clone(), "app/Service.scala")
            .write(
                "package app\n\nclass Service {\n  def task(): Runnable = new Runnable {\n    def run(): Unit = println(\"scala\")\n  }\n}\n",
            )
            .unwrap();
    // The Kotlin declaration tier deliberately does not index members of an
    // anonymous object, so this file has no equivalent hidden `run`. It is
    // here so the Kotlin summary wrapper's synthetic pruning is covered by
    // the exact-equality check below.
    ProjectFile::new(root.clone(), "app/Task.kt")
            .write(
                "package app\n\nclass Task(private val label: String) {\n    fun make(): Runnable = object : Runnable {\n        override fun run() {}\n    }\n}\n",
            )
            .unwrap();
    ProjectFile::new(root.clone(), "app/Caller.kt")
        .write("package app\n\nclass Caller {\n    fun call(): String = Greeter().greet()\n}\n")
        .unwrap();

    let project = TestProject::new(root, Language::Java);
    let make_analyzer = || {
        MultiAnalyzer::new(BTreeMap::from([
            (
                Language::Java,
                AnalyzerDelegate::new(JavaAnalyzer::new(Arc::new(project.clone()))),
            ),
            (
                Language::Scala,
                AnalyzerDelegate::new(ScalaAnalyzer::new(Arc::new(project.clone()))),
            ),
            (
                Language::Kotlin,
                AnalyzerDelegate::new(KotlinAnalyzer::new(Arc::new(project.clone()))),
            ),
        ]))
    };
    // The first generation persists the fixture. The second exercises the
    // same cache-backed summary projections used by a warm real workspace.
    drop(make_analyzer());
    make_analyzer()
}

#[doc(hidden)]
pub static CATALOG_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
