use crate::analyzer::CodeUnitIndex;
use crate::analyzer::MultiAnalyzer;
use crate::analyzer::usages::workspace_graph::*;

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
#[doc(hidden)]
pub static CATALOG_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
