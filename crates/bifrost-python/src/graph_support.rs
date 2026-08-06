//! The language half of Python's resolution logic: module lookup, the export
//! index, the import binder, base-class resolution and the skeleton renderer,
//! written as free functions over a source trait instead of as methods on
//! `PythonAnalyzer`.
//!
//! `PythonAnalyzer` (in `brokk-bifrost-analysis`) owns the lazy cells (six moka
//! caches, two `OnceLock`s and a `PoolSafeMemo`) and implements
//! [`PythonAnalysisSource`] out of its own accessors, so the functions below
//! reach back for the memoized products they need without naming the analyzer
//! type.

use brokk_bifrost_core::analyzer::capabilities::ImportAnalysisProvider;
use brokk_bifrost_core::analyzer::model::{CodeUnitType, ImportInfo};
use brokk_bifrost_core::analyzer::prepared_syntax::IndexedFileFacts;
use brokk_bifrost_core::analyzer::usages::model::{
    ExportEntry, ExportIndex, ImportBinder, ImportBinding, ImportKind, ReexportStar,
};
use brokk_bifrost_core::analyzer::{CodeUnit, CodeUnitIndex, ProjectFile};
use brokk_bifrost_core::hash::HashSet;
use std::collections::BTreeSet;
use std::sync::Arc;

use crate::declarations::{collect_python_identifiers, parse_python_tree};
use crate::imports::{
    PythonImportDetails, python_import_details, python_import_infos_from_node,
    python_namespace_binding_module, python_namespace_binding_name, resolve_exported_fqn,
    resolve_import_bindings, resolve_python_relative_module,
};
use crate::usage_index::PythonUsageIndex;

/// The analyzer-resident products Python's language logic resolves through, on
/// top of the two core capability traits it reads declarations and imports
/// with. The analyzer is the only implementor and every method forwards to one
/// of its own accessors, so the cells stay where they are and no free function
/// can reach past this surface.
///
/// The usage index is deliberately absent: [`PythonUsageIndex::build`] and
/// everything it calls take this trait, so the build cannot re-enter the
/// `OnceLock` it is filling. Code that runs once the index exists takes
/// [`PythonUsageSource`].
pub trait PythonAnalysisSource: CodeUnitIndex + ImportAnalysisProvider {
    /// Path-derived module units for `module_fq`; `None` when the store could
    /// not answer the path-symbol query at all.
    fn path_module_fqn(&self, module_fq: &str) -> Option<Vec<CodeUnit>>;

    /// [`Self::path_module_fqn`] for a whole batch, resolved in one store
    /// transaction.
    fn path_module_fqns_batch(&self, module_fqs: &[String]) -> Vec<Option<Vec<CodeUnit>>>;

    fn definition_fqn(&self, fqn: &str) -> Vec<CodeUnit>;

    /// Shared by handle: both products are immutable for the analyzer
    /// generation that cached them, and callers ask for them once per receiver
    /// type, annotation or export name, so deep-cloning the whole map out of
    /// the cache on every hit was pure waste.
    fn import_binder_of(&self, file: &ProjectFile) -> Arc<ImportBinder>;

    fn export_index_of(&self, file: &ProjectFile) -> Arc<ExportIndex>;

    /// Every file's indexed facts, visited in the analyzer's own bulk-read
    /// batches. `None` marks a file the index carries no record for.
    fn visit_file_facts(
        &self,
        files: &[ProjectFile],
        visit: &mut dyn FnMut(&ProjectFile, Option<&dyn IndexedFileFacts>),
    );
}

/// [`PythonAnalysisSource`] plus the built usage index. Everything reached from
/// the export/importer walks needs it; the index build itself must not.
pub trait PythonUsageSource: PythonAnalysisSource {
    fn usage_index(&self) -> &PythonUsageIndex;
}

pub fn extract_type_identifiers(source: &str) -> BTreeSet<String> {
    let Some(tree) = parse_python_tree(source) else {
        return BTreeSet::new();
    };
    let mut identifiers = HashSet::default();
    collect_python_identifiers(tree.root_node(), source, &mut identifiers);
    identifiers.into_iter().collect()
}

pub fn resolve_module_code_unit(
    python: &dyn PythonAnalysisSource,
    module_fq: &str,
) -> Option<CodeUnit> {
    if let Some(units) = python.path_module_fqn(module_fq) {
        return units.into_iter().find(|code_unit| code_unit.is_module());
    }
    python
        .definition_fqn(module_fq)
        .into_iter()
        .find(CodeUnit::is_module)
}

/// Batched sibling of `resolve_module_code_unit`: resolves every FQN's path-symbol lookup in one
/// store transaction instead of one per FQN, then falls back to the (unbatched, rarer)
/// definition-lookup path per FQN exactly as the single-FQN version does. Preserves its per-item
/// semantics precisely, including that a path lookup which succeeds but finds no module unit does
/// *not* fall through to the definition lookup.
pub fn resolve_module_code_units_batch(
    python: &dyn PythonAnalysisSource,
    module_fqs: &[String],
) -> Vec<Option<CodeUnit>> {
    let path_results = python.path_module_fqns_batch(module_fqs);
    let mut results: Vec<Option<CodeUnit>> = vec![None; module_fqs.len()];
    let mut needs_definition_fallback = Vec::new();
    for (i, units) in path_results.into_iter().enumerate() {
        match units {
            Some(units) => results[i] = units.into_iter().find(CodeUnit::is_module),
            None => needs_definition_fallback.push(i),
        }
    }
    for i in needs_definition_fallback {
        results[i] = python
            .definition_fqn(&module_fqs[i])
            .into_iter()
            .find(CodeUnit::is_module);
    }
    results
}

pub fn compute_export_index_of(
    python: &dyn PythonAnalysisSource,
    file: &ProjectFile,
) -> ExportIndex {
    let mut index = ExportIndex::empty();
    let mut events = Vec::new();
    let declarations = python.top_level_declarations(file);
    collect_local_export_events(
        declarations.iter(),
        |code_unit| {
            python
                .ranges(code_unit)
                .iter()
                .map(|range| range.start_byte)
                .min()
                .unwrap_or(usize::MAX)
        },
        &mut events,
    );

    if let Ok(source) = file.read_to_string()
        && let Some(tree) = parse_python_tree(&source)
    {
        collect_reexport_events(
            python,
            file,
            tree.root_node(),
            &source,
            &mut events,
            &mut index,
        );
    } else {
        let imports = python.import_info_of(file);
        collect_reexport_events_from_imports(python, file, &imports, &mut events, &mut index);
    }

    finish_export_index(events, index)
}

pub fn export_index_from_file_facts(
    python: &dyn PythonAnalysisSource,
    file: &ProjectFile,
    facts: &dyn IndexedFileFacts,
    module_name: &str,
    binder: &ImportBinder,
) -> ExportIndex {
    let mut index = ExportIndex::empty();
    let mut events = Vec::new();
    let mut local_names = collect_local_export_events(
        facts.top_level_declarations().iter(),
        |code_unit| {
            facts
                .declaration_ranges(code_unit)
                .into_iter()
                .flatten()
                .map(|range| range.start_byte)
                .min()
                .unwrap_or(usize::MAX)
        },
        &mut events,
    );

    if !facts
        .top_level_declarations()
        .iter()
        .any(CodeUnit::is_module)
        && let Some(identifier) = module_name.rsplit('.').next()
        && !identifier.is_empty()
        && !identifier.starts_with('_')
    {
        local_names.insert(identifier.to_string());
        events.push((
            0,
            identifier.to_string(),
            ExportEntry::Local {
                local_name: identifier.to_string(),
            },
        ));
    }

    if import_order_requires_source(binder, &local_names)
        && let Ok(source) = file.read_to_string()
        && let Some(tree) = parse_python_tree(&source)
    {
        collect_reexport_events(
            python,
            file,
            tree.root_node(),
            &source,
            &mut events,
            &mut index,
        );
    } else {
        collect_reexport_events_from_imports(
            python,
            file,
            facts.imports(),
            &mut events,
            &mut index,
        );
    }

    finish_export_index(events, index)
}

fn collect_local_export_events<'a>(
    declarations: impl IntoIterator<Item = &'a CodeUnit>,
    mut start_byte: impl FnMut(&CodeUnit) -> usize,
    events: &mut Vec<(usize, String, ExportEntry)>,
) -> HashSet<String> {
    let mut local_names = HashSet::default();
    for code_unit in declarations {
        let identifier = code_unit.identifier().trim();
        if identifier.is_empty() {
            continue;
        }
        local_names.insert(identifier.to_string());
        events.push((
            start_byte(code_unit),
            identifier.to_string(),
            ExportEntry::Local {
                local_name: identifier.to_string(),
            },
        ));
    }
    local_names
}

fn finish_export_index(
    mut events: Vec<(usize, String, ExportEntry)>,
    mut index: ExportIndex,
) -> ExportIndex {
    events.sort_by_key(|(start_byte, _, _)| *start_byte);
    for (_, exported_name, entry) in events {
        index.exports_by_name.insert(exported_name, entry);
    }
    index
}

fn collect_reexport_events(
    python: &dyn PythonAnalysisSource,
    file: &ProjectFile,
    root: tree_sitter::Node<'_>,
    source: &str,
    events: &mut Vec<(usize, String, ExportEntry)>,
    index: &mut ExportIndex,
) {
    let mut cursor = root.walk();
    for node in root.named_children(&mut cursor) {
        if node.kind() != "import_from_statement" {
            continue;
        }
        for info in python_import_infos_from_node(node, source) {
            record_single_reexport_event(python, file, &info, events, index);
        }
    }
}

fn collect_reexport_events_from_imports(
    python: &dyn PythonAnalysisSource,
    file: &ProjectFile,
    imports: &[ImportInfo],
    events: &mut Vec<(usize, String, ExportEntry)>,
    index: &mut ExportIndex,
) {
    for import in imports {
        record_single_reexport_event(python, file, import, events, index);
    }
}

fn record_single_reexport_event(
    python: &dyn PythonAnalysisSource,
    file: &ProjectFile,
    import: &ImportInfo,
    events: &mut Vec<(usize, String, ExportEntry)>,
    index: &mut ExportIndex,
) {
    let Some(PythonImportDetails::FromImport {
        module,
        name,
        alias,
        wildcard,
    }) = python_import_details(import)
    else {
        return;
    };
    let start_byte = import
        .path
        .as_ref()
        .map(|path| path.declaration_start_byte)
        .unwrap_or(usize::MAX);
    let resolved_module = if module.starts_with('.') {
        resolve_python_relative_module(file, &module)
    } else {
        Some(module.clone())
    };
    let Some(resolved_module) = resolved_module else {
        return;
    };

    if wildcard {
        index.reexport_stars.push(ReexportStar {
            module_specifier: resolved_module,
        });
        return;
    }
    let exported_name = alias.unwrap_or(name.clone());
    let imported_name = format!("{resolved_module}.{name}");
    if resolve_module_code_unit(python, &imported_name).is_some() {
        events.push((
            start_byte,
            exported_name,
            ExportEntry::ReexportedNamed {
                module_specifier: imported_name,
                imported_name: name,
            },
        ));
        return;
    }
    events.push((
        start_byte,
        exported_name,
        ExportEntry::ReexportedNamed {
            module_specifier: resolved_module,
            imported_name: name,
        },
    ));
}

pub fn import_binder_from_imports(
    python: &dyn PythonAnalysisSource,
    file: &ProjectFile,
    imports: &[ImportInfo],
) -> ImportBinder {
    let mut binder = ImportBinder::empty();

    for import in imports {
        let Some(details) = python_import_details(import) else {
            continue;
        };
        match details {
            PythonImportDetails::Import { module, alias } => {
                let local_name = python_namespace_binding_name(import, alias.as_deref(), &module);
                let module_specifier =
                    python_namespace_binding_module(import, alias.as_deref(), &module);
                binder.bindings.insert(
                    local_name,
                    ImportBinding {
                        module_specifier,
                        namespace_imported_module: Some(module),
                        kind: ImportKind::Namespace,
                        imported_name: None,
                    },
                );
            }
            PythonImportDetails::FromImport {
                module,
                name,
                wildcard,
                ..
            } => {
                let resolved_module = if module.starts_with('.') {
                    resolve_python_relative_module(file, &module)
                } else {
                    Some(module.clone())
                };
                let Some(resolved_module) = resolved_module else {
                    continue;
                };
                if wildcard {
                    continue;
                }
                // Non-wildcard from-imports always populate `identifier`
                // as `alias ?? name` (see `python_import_details`), so
                // `local_name()` reproduces the same alias-first fallback
                // without re-deriving it here.
                let local_name = import
                    .local_name()
                    .map(str::to_string)
                    .unwrap_or_else(|| name.clone());
                let module_candidate = format!("{resolved_module}.{name}");
                if resolve_module_code_unit(python, &module_candidate).is_some() {
                    binder.bindings.insert(
                        local_name,
                        ImportBinding {
                            module_specifier: module_candidate,
                            namespace_imported_module: None,
                            kind: ImportKind::Namespace,
                            imported_name: None,
                        },
                    );
                    continue;
                }
                binder.bindings.insert(
                    local_name,
                    ImportBinding {
                        module_specifier: resolved_module,
                        namespace_imported_module: None,
                        kind: ImportKind::Named,
                        imported_name: Some(name),
                    },
                );
            }
        }
    }

    binder
}

pub fn public_declarations_in_module(
    python: &dyn PythonAnalysisSource,
    module_fq: &str,
) -> Vec<CodeUnit> {
    let Some(module_code_unit) = resolve_module_code_unit(python, module_fq) else {
        return Vec::new();
    };
    python
        .direct_children(&module_code_unit)
        .into_iter()
        .filter(|code_unit| !code_unit.identifier().starts_with('_'))
        .collect()
}

pub fn resolve_base_class(
    python: &dyn PythonAnalysisSource,
    code_unit: &CodeUnit,
    raw: &str,
) -> Option<CodeUnit> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    let binder = python.import_binder_of(code_unit.source());
    if let Some((head, tail)) = trimmed.split_once('.') {
        if let Some(binding) = binder.bindings.get(head)
            && binding.kind == ImportKind::Namespace
        {
            let fq_name = format!("{}.{}", binding.module_specifier, tail);
            return python.definitions(&fq_name).next();
        }
        return python.definitions(trimmed).next();
    }

    if let Some(binding) = binder.bindings.get(trimmed) {
        match binding.kind {
            ImportKind::Namespace => {
                return resolve_module_code_unit(python, &binding.module_specifier);
            }
            ImportKind::Named => {
                let imported_name = binding.imported_name.as_ref()?;
                let fqn = format!("{}.{}", binding.module_specifier, imported_name);
                return resolve_exported_fqn(python, &fqn)
                    .into_iter()
                    .next()
                    .or_else(|| python.definitions(&fqn).next());
            }
            _ => {}
        }
    }

    if python
        .import_info_of(code_unit.source())
        .iter()
        .any(|import| import.is_wildcard)
        && let Some(imported) = resolve_import_bindings(python, code_unit.source()).get(trimmed)
    {
        return Some(imported.clone());
    }

    let local_fq_name = format!("{}.{}", code_unit.package_name(), trimmed);
    python
        .definitions(&local_fq_name)
        .next()
        .or_else(|| python.definitions(trimmed).next())
}

pub fn render_skeleton_recursive(
    index: &dyn CodeUnitIndex,
    code_unit: &CodeUnit,
    indent: &str,
    header_only: bool,
    out: &mut String,
) {
    if let Some(signature) = python_signature(index, code_unit, header_only) {
        for line in signature.lines() {
            out.push_str(indent);
            out.push_str(line);
            out.push('\n');
        }
    }

    let all_children = index.direct_children(code_unit);
    let field_children: Vec<_> = all_children
        .iter()
        .filter(|child| child.is_field())
        .cloned()
        .collect();
    let children = if header_only {
        field_children.clone()
    } else {
        all_children.clone()
    };
    if !children.is_empty() || code_unit.is_class() || code_unit.is_module() {
        let child_indent = format!("{indent}  ");
        for child in children {
            render_skeleton_recursive(index, &child, &child_indent, header_only, out);
        }
        if header_only && all_children.len() > field_children.len() {
            out.push_str(&child_indent);
            out.push_str("[...]\n");
        }
    }
}

fn python_signature(
    index: &dyn CodeUnitIndex,
    code_unit: &CodeUnit,
    _header_only: bool,
) -> Option<String> {
    if code_unit.is_module() {
        return None;
    }

    let source = index.get_source(code_unit, false)?;
    let lines: Vec<_> = source
        .lines()
        .map(str::trim_end)
        .filter(|line| !line.trim().is_empty())
        .collect();
    if lines.is_empty() {
        return None;
    }

    let mut decorators = Vec::new();
    let mut header = None;
    for line in lines {
        let trimmed = line.trim_start();
        if trimmed.starts_with('@') {
            decorators.push(trimmed.to_string());
            continue;
        }
        header = Some(trimmed.to_string());
        break;
    }
    let mut rendered = String::new();
    for decorator in decorators {
        rendered.push_str(&decorator);
        rendered.push('\n');
    }

    let header = header?;
    match code_unit.kind() {
        CodeUnitType::Class => rendered.push_str(&header),
        CodeUnitType::Function => {
            rendered.push_str(header.trim_end_matches(':'));
            rendered.push_str(": ...");
        }
        CodeUnitType::Field | CodeUnitType::Macro => rendered.push_str(header.as_str()),
        CodeUnitType::Module | CodeUnitType::FileScope => return None,
    }
    Some(rendered)
}

fn import_order_requires_source(binder: &ImportBinder, local_names: &HashSet<String>) -> bool {
    binder
        .bindings
        .keys()
        .any(|bound_name| local_names.contains(bound_name))
}
