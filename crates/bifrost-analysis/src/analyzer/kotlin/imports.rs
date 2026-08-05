//! Kotlin structured imports and the file relationships they create (#1237).
//!
//! Issue #1236 recorded a Kotlin file's `import` lines as display strings only.
//! This module turns them into structured facts — a dotted path, whether the
//! import is a star import, and the name it binds — so nothing downstream has
//! to recover that structure by scanning text.
//!
//! Kotlin's import forms are small and entirely file-scoped: there is no
//! `import` inside a block, no static/instance distinction, and no selector
//! list. A header is exactly one of
//!
//! ```text
//! import a.b.C          binds C
//! import a.b.C as D     binds D
//! import a.b.*          binds every name a.b exports
//! ```
//!
//! where the path may name a package member (`a.b.C`), a nested type
//! (`a.b.Outer.Inner`), or a member of an object, companion, or enum
//! (`a.b.Registry.register`). A star import likewise widens either a package or
//! a single object-like owner.
//!
//! Kotlin/JS and Kotlin/Native default imports are deliberately not modelled:
//! see [`KOTLIN_DEFAULT_IMPORT_PACKAGES`].

use crate::analyzer::common::language_for_file as file_language;
use crate::analyzer::jvm::realm::JvmSourceRealm;
use crate::analyzer::tree_walk::{first_named_child_of_kind as first_named_child, named_children};
use crate::analyzer::{
    CodeUnit, IAnalyzer, ImportAnalysisProvider, ImportInfo, Language, ProjectFile,
    StructuredImportPath, build_reverse_file_index,
};
use crate::hash::{HashMap, HashSet};
use std::sync::Arc;
use tree_sitter::Node;

use super::KotlinAnalyzer;

/// The packages every Kotlin/JVM file imports without writing an `import` line.
///
/// The first eight are Kotlin's platform-independent defaults; `java.lang` and
/// `kotlin.jvm` are added only on Kotlin/JVM. Kotlin/JS (`kotlin.js`) and
/// Kotlin/Native (`kotlin.native`) add their own, and this issue targets
/// Kotlin/JVM only — a name that would resolve solely through a Kotlin/JS or
/// Kotlin/Native default import stays unresolved rather than being guessed at,
/// because guessing would claim a resolution the target platform may not have.
pub(crate) const KOTLIN_DEFAULT_IMPORT_PACKAGES: &[&str] = &[
    "kotlin",
    "kotlin.annotation",
    "kotlin.collections",
    "kotlin.comparisons",
    "kotlin.io",
    "kotlin.ranges",
    "kotlin.sequences",
    "kotlin.text",
    "java.lang",
    "kotlin.jvm",
];

/// Read one `import_header` node into a structured [`ImportInfo`], or `None`
/// when the header carries no usable path.
///
/// The path segments come from the `identifier` node's own `simple_identifier`
/// children, one per dotted component, so a malformed or oddly-spaced header
/// cannot smear two segments into one.
pub(crate) fn kotlin_import_info_from_node(node: Node<'_>, source: &str) -> Option<ImportInfo> {
    if node.kind() != "import_header" {
        return None;
    }
    let identifier = first_named_child(node, "identifier")?;
    let segment_nodes: Vec<Node<'_>> = named_children(identifier)
        .into_iter()
        .filter(|child| child.kind() == "simple_identifier")
        .filter(|segment| !super::declarations::kotlin_identifier_text(*segment, source).is_empty())
        .collect();
    let segments: Vec<String> = segment_nodes
        .iter()
        .map(|segment| super::declarations::kotlin_identifier_text(*segment, source).to_string())
        .collect();
    if segments.is_empty() {
        return None;
    }

    let is_wildcard = first_named_child(node, "wildcard_import").is_some();
    let alias_node = first_named_child(node, "import_alias")
        .and_then(|alias| first_named_child(alias, "type_identifier"));
    let alias = alias_node
        .map(|name| super::declarations::kotlin_identifier_text(name, source).to_string())
        .filter(|name| !name.is_empty());
    // The bound name is spelled by the alias token when renamed, and by the
    // path's last segment token otherwise; a star import binds no single name.
    let binder_span = (!is_wildcard)
        .then(|| {
            alias
                .is_some()
                .then_some(alias_node)
                .flatten()
                .or_else(|| segment_nodes.last().copied())
        })
        .flatten()
        .map(crate::analyzer::common::node_span);
    // A star import binds no single name, so it has no bound identifier; every
    // other form binds its alias when renamed and its last segment otherwise.
    let identifier = (!is_wildcard)
        .then(|| {
            alias
                .clone()
                .or_else(|| segments.last().cloned())
                .filter(|name| !name.is_empty())
        })
        .flatten();

    Some(ImportInfo {
        raw_snippet: render_kotlin_import(&segments, is_wildcard, alias.as_deref()),
        is_wildcard,
        identifier,
        alias,
        path: Some(StructuredImportPath {
            segments,
            kind: None,
            // Kotlin imports are file-scoped: they always sit at the top level
            // of the file, never inside a package clause or a declaration, so
            // there is no lexical prefix or enclosing scope to record.
            lexical_prefixes: Vec::new(),
            lexical_scopes: Vec::new(),
            declaration_start_byte: node.start_byte(),
        }),
        binder_span,
    })
}

/// Render the import back to canonical Kotlin source from its structured
/// parts, so `raw_snippet` is a faithful display of what was parsed rather
/// than a slice whose formatting consumers might try to re-parse.
fn render_kotlin_import(segments: &[String], is_wildcard: bool, alias: Option<&str>) -> String {
    let mut rendered = format!("import {}", segments.join("."));
    if is_wildcard {
        rendered.push_str(".*");
    } else if let Some(alias) = alias {
        rendered.push_str(" as ");
        rendered.push_str(alias);
    }
    rendered
}

/// The dotted path an import names, or `None` when the parser recorded no
/// structured path.
pub(crate) fn kotlin_import_path(import: &ImportInfo) -> Option<String> {
    let path = import.path.as_ref()?;
    (!path.segments.is_empty()).then(|| path.render_segments("."))
}

impl KotlinAnalyzer {
    /// Every declaration an import path can name directly.
    ///
    /// Kotlin fully-qualified names are dotted all the way down — package
    /// segments, nested types, and members alike — so `import a.b.Outer.Inner`
    /// and `import a.b.Registry.register` are the same single lookup as
    /// `import a.b.C`, with no need to split the path and walk owners.
    fn declarations_named(&self, fqn: &str, realm: Option<&JvmSourceRealm<'_>>) -> Vec<CodeUnit> {
        let mut units: Vec<CodeUnit> = IAnalyzer::global_usage_definition_index(&self.inner)
            .fqn(fqn)
            .iter()
            .filter(|unit| unit.fq_name() == fqn && !unit.is_synthetic())
            .cloned()
            .collect();
        // A Kotlin file can import a Java or Scala declaration from the same
        // workspace, so the realm's other members answer for the names Kotlin's
        // own index does not hold.
        if let Some(realm) = realm {
            units.extend(realm.peer_declarations_by_fqn(fqn, Language::Kotlin));
        }
        units
    }

    /// The top-level declarations a Kotlin package exports, keyed by package.
    ///
    /// Built once per analyzer generation because a star import has to widen
    /// to a whole package and repeating that scan per file would be quadratic
    /// in workspace size.
    pub(crate) fn top_level_declarations_by_package(&self) -> &HashMap<String, Arc<Vec<CodeUnit>>> {
        self.top_level_declarations_by_package.get_or_init(|| {
            let mut by_package: HashMap<String, Vec<CodeUnit>> = HashMap::default();
            for unit in self.inner.all_declarations() {
                if is_kotlin_importable_top_level(&unit) {
                    by_package
                        .entry(unit.package_name().to_string())
                        .or_default()
                        .push(unit);
                }
            }
            by_package
                .into_iter()
                .map(|(package, units)| (package, Arc::new(units)))
                .collect()
        })
    }

    /// The declarations a star import over `path` makes visible.
    ///
    /// `path` is a package (`import a.b.*`) or a single object-like owner
    /// (`import a.b.Mode.*`, which imports an enum's entries or an object's
    /// members). Both forms are legal Kotlin and are distinguished by what the
    /// workspace actually declares, not by guessing from the spelling.
    fn star_imported_declarations(
        &self,
        path: &str,
        realm: Option<&JvmSourceRealm<'_>>,
    ) -> Vec<CodeUnit> {
        if let Some(units) = self.top_level_declarations_by_package().get(path) {
            return units.as_ref().clone();
        }
        self.declarations_named(path, realm)
            .iter()
            .filter(|owner| owner.is_class())
            .flat_map(|owner| self.inner.direct_children(owner))
            .filter(|unit| !unit.is_synthetic())
            .collect()
    }

    fn resolve_import_infos(
        &self,
        imports: &[ImportInfo],
        realm: Option<&JvmSourceRealm<'_>>,
    ) -> HashSet<CodeUnit> {
        let mut resolved = HashSet::default();
        for import in imports {
            let Some(path) = kotlin_import_path(import) else {
                continue;
            };
            if import.is_wildcard {
                resolved.extend(self.star_imported_declarations(&path, realm));
            } else {
                resolved.extend(self.declarations_named(&path, realm));
            }
        }
        resolved
    }

    /// The declarations a Kotlin file imports, widened to the whole JVM source
    /// realm when a realm view is supplied.
    ///
    /// The realm-aware and realm-less answers are cached separately: a
    /// Kotlin-only result must never be served to a caller that can also see
    /// Java and Scala declarations.
    pub(crate) fn imported_code_units_in_realm(
        &self,
        file: &ProjectFile,
        realm: Option<&JvmSourceRealm<'_>>,
    ) -> HashSet<CodeUnit> {
        let cache = match realm {
            Some(_) => &self.realm_imported_code_units,
            None => &self.imported_code_units,
        };
        if let Some(cached) = cache.get(file) {
            return (*cached).clone();
        }
        if file_language(file) != Language::Kotlin {
            return HashSet::default();
        }
        let imports = self.inner.import_info_of(file);
        let resolved = self.resolve_import_infos(&imports, realm);
        cache.insert(file.clone(), Arc::new(resolved.clone()));
        resolved
    }

    /// Files that can see one another without an import because they declare
    /// the same package and spell one another's names.
    fn same_package_reference_index(&self) -> Arc<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>> {
        self.same_package_reference_index.get_or_build(
            || self.compute_same_package_reference_index(true),
            || self.compute_same_package_reference_index(false),
        )
    }

    fn compute_same_package_reference_index(
        &self,
        parallel: bool,
    ) -> HashMap<ProjectFile, Arc<HashSet<ProjectFile>>> {
        let mut targets_by_package_and_name: HashMap<(String, String), Vec<ProjectFile>> =
            HashMap::default();
        for file in self.inner.all_files() {
            if file_language(&file) != Language::Kotlin {
                continue;
            }
            let package = self.inner.package_name_of(&file).unwrap_or_default();
            for declaration in self.inner.top_level_declarations(&file) {
                targets_by_package_and_name
                    .entry((package.clone(), declaration.identifier().to_string()))
                    .or_default()
                    .push(file.clone());
            }
        }

        let files: Vec<_> = self.inner.all_files();
        build_reverse_file_index(
            &files,
            |candidate| {
                if file_language(candidate) != Language::Kotlin {
                    return Vec::new();
                }
                let package = self.inner.package_name_of(candidate).unwrap_or_default();
                let Some(identifiers) = self.inner.type_identifiers_of(candidate) else {
                    return Vec::new();
                };
                identifiers
                    .iter()
                    .filter_map(|identifier| {
                        targets_by_package_and_name.get(&(package.clone(), identifier.clone()))
                    })
                    .flat_map(|targets| targets.iter().cloned())
                    .collect()
            },
            parallel,
        )
    }
}

impl ImportAnalysisProvider for KotlinAnalyzer {
    fn imported_code_units_of(&self, file: &ProjectFile) -> HashSet<CodeUnit> {
        self.imported_code_units_in_realm(file, None)
    }

    fn import_info_of(&self, file: &ProjectFile) -> Vec<ImportInfo> {
        self.inner.import_info_of(file)
    }

    fn imported_code_units_from_infos(
        &self,
        _file: &ProjectFile,
        imports: &[ImportInfo],
    ) -> Option<HashSet<CodeUnit>> {
        Some(self.resolve_import_infos(imports, None))
    }

    /// Kotlin files that reference `file`.
    ///
    /// Deliberately Kotlin-to-Kotlin, even under a multi-language analyzer.
    /// Answering "which Kotlin files reference this *Java* file" needs both
    /// halves of this index to cross the realm, and only one of them can:
    /// the import half could consult the realm view, but the same-package half
    /// needs each JVM member's files and top-level declarations, which the
    /// realm's forward-query surface does not expose. A half-crossing answer —
    /// imports counted, same-package references silently dropped — would be
    /// worse than a clearly bounded one, so this index stays within one
    /// language.
    ///
    /// The usage graphs do not depend on it crossing: a cross-language JVM type
    /// query widens its own candidate set over every JVM language directly
    /// (`usages/candidates.rs::add_cross_language_jvm_candidates`), so a Kotlin
    /// reference to a Java type is found without this relation having an opinion
    /// about it (#1239 milestone 4).
    fn referencing_files_of(&self, file: &ProjectFile) -> HashSet<ProjectFile> {
        if let Some(cached) = self.referencing_files.get(file) {
            return (*cached).clone();
        }
        if file_language(file) != Language::Kotlin {
            return HashSet::default();
        }
        let reverse_index = crate::analyzer::memoized_reverse_import_index(
            &self.reverse_import_index,
            || self.inner.all_files(),
            |candidate| self.imported_code_units_of(candidate),
        );
        let mut result = reverse_index
            .get(file)
            .map(|files| (**files).clone())
            .unwrap_or_default();
        if let Some(files) = self.same_package_reference_index().get(file) {
            result.extend(files.iter().cloned());
        }

        self.referencing_files
            .insert(file.clone(), Arc::new(result.clone()));
        result
    }

    fn could_import_file(
        &self,
        source_file: &ProjectFile,
        imports: &[ImportInfo],
        target: &ProjectFile,
    ) -> bool {
        if source_file == target {
            return false;
        }
        if file_language(source_file) != Language::Kotlin
            || file_language(target) != Language::Kotlin
        {
            return false;
        }

        let source_package = self.inner.package_name_of(source_file).unwrap_or_default();
        let target_package = self.inner.package_name_of(target).unwrap_or_default();
        if source_package == target_package {
            return true;
        }

        imports.iter().any(|import| {
            let Some(path) = kotlin_import_path(import) else {
                return false;
            };
            if import.is_wildcard {
                return path == target_package
                    || self
                        .star_imported_declarations(&path, None)
                        .iter()
                        .any(|unit| unit.source() == target);
            }
            self.declarations_named(&path, None)
                .iter()
                .any(|unit| unit.source() == target)
        })
    }
}

/// Whether a declaration is one a star import over its package would bind.
///
/// Kotlin packages export top-level types, functions, and properties alike, so
/// this is not restricted to classes the way a type-only import would be. A
/// dotted short name means the declaration is nested inside another one, which
/// a package-level star import does not reach.
fn is_kotlin_importable_top_level(unit: &CodeUnit) -> bool {
    !unit.is_synthetic() && !unit.short_name().contains('.')
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::Parser;

    fn parsed_imports(source: &str) -> Vec<ImportInfo> {
        let mut parser = Parser::new();
        parser
            .set_language(&super::super::language::LANGUAGE.into())
            .expect("load Kotlin grammar");
        let tree = parser.parse(source, None).expect("parse Kotlin source");
        let mut infos = Vec::new();
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            if node.kind() == "import_header" {
                if let Some(info) = kotlin_import_info_from_node(node, source) {
                    infos.push(info);
                }
                continue;
            }
            let mut children = named_children(node);
            children.reverse();
            stack.extend(children);
        }
        infos.sort_by_key(|info| {
            info.path
                .as_ref()
                .map(|path| path.declaration_start_byte)
                .unwrap_or(0)
        });
        infos
    }

    #[test]
    fn kotlin_import_forms_carry_structured_paths_and_bound_names() {
        let infos = parsed_imports(
            "package app\n\
             \n\
             import lib.Service\n\
             import lib.Service as Renamed\n\
             import lib.nested.*\n\
             import lib.Registry.register\n",
        );

        let paths: Vec<String> = infos
            .iter()
            .map(|info| kotlin_import_path(info).expect("structured path"))
            .collect();
        assert_eq!(
            paths,
            vec![
                "lib.Service".to_string(),
                "lib.Service".to_string(),
                "lib.nested".to_string(),
                "lib.Registry.register".to_string(),
            ]
        );

        let bound: Vec<Option<&str>> = infos
            .iter()
            .map(|info| info.identifier.as_deref())
            .collect();
        assert_eq!(
            bound,
            vec![Some("Service"), Some("Renamed"), None, Some("register")]
        );

        assert_eq!(infos[1].alias.as_deref(), Some("Renamed"));
        assert!(infos[2].is_wildcard);
        assert!(!infos[0].is_wildcard && !infos[3].is_wildcard);

        let rendered: Vec<&str> = infos.iter().map(|info| info.raw_snippet.as_str()).collect();
        assert_eq!(
            rendered,
            vec![
                "import lib.Service",
                "import lib.Service as Renamed",
                "import lib.nested.*",
                "import lib.Registry.register",
            ]
        );
    }

    #[test]
    fn kotlin_import_segments_survive_backtick_quoting() {
        let infos = parsed_imports("import lib.`odd name`.Service\n");
        assert_eq!(
            infos[0].path.as_ref().map(|path| path.segments.clone()),
            Some(vec![
                "lib".to_string(),
                "odd name".to_string(),
                "Service".to_string()
            ]),
            "backticks are quoting syntax, not part of a segment's name"
        );
    }
}
