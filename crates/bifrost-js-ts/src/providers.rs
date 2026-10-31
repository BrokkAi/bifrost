//! The source trait both dialects' language logic resolves through, and the
//! uncached half of the shared `ImportAnalysisProvider` policy.
//!
//! `JavascriptAnalyzer` and `TypescriptAnalyzer` wrap the same
//! `TreeSitterAnalyzer`, the same `JsTsMemoCaches` bucket and the same
//! [`AliasResolver`], and differ only in their `Language` tag. Every function
//! here is parameterized over a [`JsTsSource`], so the two analysis-side
//! `impl` blocks reduce to one-line delegations and the resolution policy lives
//! in exactly one place.
//!
//! # Where the caching went
//!
//! The memo bucket is five moka `Cache`s, and moka is deliberately not a
//! dependency of this crate (the Go, Java and C# precedents: `analyzer/go/
//! imports.rs`, `analyzer/java/imports.rs`, `analyzer/csharp/imports.rs` all
//! keep the cache lookup on the analysis side and call the crate for the
//! uncached work). So the trait below exposes *products* rather than the
//! bucket: `usage_index` is the analyzer-cached resolution index, and the
//! get-then-insert wrappers for imported code units, referencing files,
//! relevant imports, import target files and direct ancestors stay in
//! `analyzer/js_ts/providers.rs`, calling the uncached functions here.

use crate::hierarchy::resolve_direct_ancestors;
use crate::imports::{import_info_tokens, resolve_js_ts_import_info_paths};
use crate::source_facts::JsTsFileSourceFacts;
use crate::tsconfig::AliasResolver;
use brokk_bifrost_core::analyzer::capabilities::{ImportAnalysisProvider, TypeHierarchyProvider};
use brokk_bifrost_core::analyzer::model::ImportInfo;
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_core::analyzer::{
    BoundedDefinitionLookup, CodeUnit, CodeUnitIndex, Language, ProjectFile,
};
use brokk_bifrost_core::cancellation::CancellationToken;
use brokk_bifrost_core::hash::{HashMap, HashSet};
use std::sync::Arc;

use crate::graph::resolver::JsTsUsageIndex;

/// The shared surface the JS/TS language logic needs from a concrete analyzer,
/// on top of the three core capability traits it reads declarations, imports and
/// supertypes with: its alias resolver, its language tag, the analyzer-cached
/// usage index, the workspace definition index, and the five
/// `TreeSitterAnalyzer` queries that have no core spelling.
///
/// Implemented once per adapter in `brokk-bifrost-analysis` as trivial field
/// accessors and one-line delegations into the wrapped analyzer, so no free
/// function below can reach past this surface. This crate never names
/// `JavascriptAnalyzer` or `TypescriptAnalyzer`.
///
/// Three of the analyzer queries the providers make are already core:
/// `import_info_of` on [`ImportAnalysisProvider`], `top_level_declarations` and
/// `get_source` on [`CodeUnitIndex`] -- both analyzers' impls of all three are
/// the same one-line delegation the free functions used directly before. The
/// ones named below are not: `all_files` is the analyzed *live* file set
/// (`CodeUnitIndex::analyzed_files` is a different query),
/// `bulk_import_infos` has no core counterpart,
/// `raw_supertypes_of` returns the unresolved supertype spellings that
/// [`TypeHierarchyProvider`] never exposes, and `import_statements` reads
/// the raw import statement text the module skeleton renders.
pub trait JsTsSource: CodeUnitIndex + ImportAnalysisProvider + TypeHierarchyProvider {
    /// Source identities independently of parse-product readiness. Missing
    /// inventory support cannot establish a complete workspace graph.
    fn source_file_inventory(
        &self,
    ) -> brokk_bifrost_core::analyzer::query_batch::QueryBatch<ProjectFile> {
        brokk_bifrost_core::analyzer::query_batch::QueryBatch::incomplete(Vec::new(), 0)
    }

    /// Published source-owned facts for one analyzed file. An unavailable
    /// publication is a graph-build failure; callers must not reparse the
    /// file to synthesize a substitute.
    fn source_facts(&self, _file: &ProjectFile) -> Option<Arc<JsTsFileSourceFacts>> {
        None
    }

    /// The analyzer's shared alias resolver. Returned by handle so a caller
    /// that must own one (the receiver-fact provider) shares this instance's
    /// config memo instead of constructing a resolver whose memo starts cold.
    fn alias_resolver(&self) -> &Arc<AliasResolver>;
    fn language(&self) -> Language;

    /// The analyzed live file set (`TreeSitterAnalyzer::all_files`).
    fn all_files(&self) -> Vec<ProjectFile>;

    /// Import facts for a group of files in one read.
    fn bulk_import_infos(&self, files: &[ProjectFile]) -> HashMap<ProjectFile, Vec<ImportInfo>>;

    /// The supertype names written on `code_unit`, unresolved.
    fn raw_supertypes_of(&self, code_unit: &CodeUnit) -> Vec<String>;

    /// The file's import statements as written, used to render a module skeleton.
    fn import_statements(&self, file: &ProjectFile) -> Vec<String>;

    /// Whether the indexed declaration is a type alias. Distinct from
    /// `TypeAliasProvider::is_type_alias`, which only TypeScript answers: this
    /// reads the analyzer's own index, so both dialects can answer it and only
    /// TypeScript's skeleton path asks.
    ///
    /// The two share a name without ambiguity because `TypeAliasProvider` is
    /// deliberately not a supertrait of this trait, and every caller reaches
    /// this one through `&dyn JsTsSource`.
    fn is_type_alias(&self, code_unit: &CodeUnit) -> bool;

    /// The indexed signatures for `code_unit` exactly as stored. TypeScript's
    /// `CodeUnitIndex::signatures` appends a `;` to alias signatures for
    /// rendering, which the alias skeleton must not double up on.
    fn raw_signatures(&self, code_unit: &CodeUnit) -> Vec<String>;

    /// Run one synchronous resolution step against a step-local bounded
    /// definition lookup. A file scan keeps the callback open for its complete
    /// AST walk, so its receiver provider and nested resolvers share one memo
    /// without publishing lookup state as analyzer-generation state.
    fn with_usage_definitions(
        &self,
        token: QueryToken<'_>,
        read: &mut dyn FnMut(&dyn BoundedDefinitionLookup),
    );

    /// The analyzer-cached JS/TS resolution index for this source's own language,
    /// built on first use. `None` means cancellation or unavailable canonical
    /// source publication; callers must report the structured failure.
    ///
    /// The memo cell behind it is a `PoolSafeMemo` on the analysis-side cache
    /// bucket; this is the product, not the cell.
    fn usage_index(&self, cancellation: Option<&CancellationToken>) -> Option<Arc<JsTsUsageIndex>>;
}

pub(crate) fn with_usage_definitions<R>(
    source: &dyn JsTsSource,
    token: QueryToken<'_>,
    read: impl FnOnce(&dyn BoundedDefinitionLookup) -> R,
) -> R {
    brokk_bifrost_core::analyzer::definition_lookup::with_usage_definitions_once(
        |consumer| source.with_usage_definitions(token, consumer),
        read,
    )
}

// --- ImportAnalysisProvider ------------------------------------------------

/// Resolve every import in `imports` to the declarations it binds.
///
/// The uncached body behind `ImportAnalysisProvider::imported_code_units_of`,
/// whose per-file memo lives on the analysis-side cache bucket.
pub fn resolve_imported_code_units(
    host: &dyn JsTsSource,
    file: &ProjectFile,
    imports: impl IntoIterator<Item = ImportInfo>,
) -> HashSet<CodeUnit> {
    let language = host.language();
    let alias_resolver = host.alias_resolver();
    let mut resolved = HashSet::default();
    for import in imports {
        for target in resolve_js_ts_import_info_paths(file, &import, language, Some(alias_resolver))
        {
            let top_level = host.top_level_declarations(&target);
            if import.is_wildcard {
                resolved.extend(
                    top_level
                        .iter()
                        .filter(|code_unit| !code_unit.is_module())
                        .cloned(),
                );
            } else if let Some(identifier) = import.identifier.as_ref().or(import.alias.as_ref()) {
                let mut matched = false;
                for code_unit in top_level
                    .iter()
                    .filter(|code_unit| code_unit.identifier() == identifier)
                {
                    matched = true;
                    resolved.insert(code_unit.clone());
                }
                if !matched {
                    let module_units = top_level
                        .iter()
                        .filter(|code_unit| code_unit.is_module())
                        .cloned()
                        .collect::<Vec<_>>();
                    if !module_units.is_empty() {
                        resolved.extend(module_units);
                    } else if top_level.len() == 1 && !top_level[0].is_module() {
                        resolved.insert(top_level[0].clone());
                    }
                }
            } else {
                resolved.extend(
                    top_level
                        .iter()
                        .filter(|code_unit| !code_unit.is_module())
                        .cloned(),
                );
            }
        }
    }
    resolved
}

pub fn import_infos_for_files(
    host: &dyn JsTsSource,
    files: &[ProjectFile],
) -> Option<HashMap<ProjectFile, Vec<ImportInfo>>> {
    Some(host.bulk_import_infos(files))
}

pub fn imported_files_from_infos(
    host: &dyn JsTsSource,
    file: &ProjectFile,
    imports: &[ImportInfo],
) -> Option<HashSet<ProjectFile>> {
    Some(resolve_import_files(
        file,
        imports,
        host.language(),
        host.alias_resolver().as_ref(),
    ))
}

fn resolve_import_files(
    file: &ProjectFile,
    imports: &[ImportInfo],
    language: Language,
    aliases: &AliasResolver,
) -> HashSet<ProjectFile> {
    imports
        .iter()
        .flat_map(|import| resolve_js_ts_import_info_paths(file, import, language, Some(aliases)))
        .collect()
}

/// The import snippets of `code_unit`'s file whose bound tokens the unit's own
/// source actually spells, plus every import that binds no token at all.
///
/// The uncached body behind `ImportAnalysisProvider::relevant_imports_for`.
pub fn compute_relevant_imports(
    host: &dyn JsTsSource,
    token: QueryToken<'_>,
    code_unit: &CodeUnit,
) -> HashSet<String> {
    let source = host.get_source(code_unit, false).unwrap_or_default();
    let mut relevant = HashSet::default();
    for import in host.import_info_of(token, code_unit.source()) {
        let tokens = import_info_tokens(&import);
        if tokens.is_empty() || tokens.iter().any(|token| source.contains(token)) {
            relevant.insert(import.raw_snippet.clone());
        }
    }
    relevant
}

/// The file-path resolution targets of `file`'s own imports (module specifier ->
/// file).
///
/// The uncached body behind `could_import_file`. Without the memo the analysis
/// side wraps this in, it re-ran for every (candidate, target) pair the shared
/// usages candidate walker checks -- unbounded per-call cost on a large
/// workspace.
pub fn resolve_import_target_files(
    host: &dyn JsTsSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
) -> HashSet<ProjectFile> {
    let language = host.language();
    let alias_resolver = host.alias_resolver();
    resolve_import_files(
        file,
        &host.import_info_of(token, file),
        language,
        alias_resolver,
    )
}

// --- Skeletons -------------------------------------------------------------

/// A module unit's skeleton is its own import block: both dialects render the
/// same thing, so this is one function rather than a method on each analyzer.
pub fn module_import_skeleton(host: &dyn JsTsSource, code_unit: &CodeUnit) -> Option<String> {
    if !code_unit.is_module() {
        return None;
    }

    let imports = host.import_statements(code_unit.source());
    (!imports.is_empty()).then(|| imports.join("\n"))
}

// --- TypeHierarchyProvider -------------------------------------------------

/// Resolve `code_unit`'s unresolved supertype spellings to declarations.
///
/// The uncached body behind `TypeHierarchyProvider::get_direct_ancestors`.
pub fn compute_direct_ancestors(host: &dyn JsTsSource, code_unit: &CodeUnit) -> Vec<CodeUnit> {
    let Some(index) = host.usage_index(None) else {
        return Vec::new();
    };
    resolve_direct_ancestors(
        host,
        index.as_ref(),
        host.language(),
        host.alias_resolver(),
        code_unit,
        &host.raw_supertypes_of(code_unit),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_core::analyzer::Range;
    use brokk_bifrost_core::analyzer::parsed_file::ParsedFile;
    use brokk_bifrost_core::analyzer::project::{Project, TestProject};
    use std::collections::BTreeSet;

    // A query-only host: declarations and imports are real parser products;
    // the fake replaces only the persistent store's lookup surface.
    struct ImportHost {
        project: Arc<TestProject>,
        aliases: Arc<AliasResolver>,
        language: Language,
        source_facts_available: bool,
        files: HashMap<ProjectFile, ParsedFile>,
    }

    impl CodeUnitIndex for ImportHost {
        fn project(&self) -> &dyn Project {
            self.project.as_ref()
        }
        fn languages(&self) -> BTreeSet<Language> {
            BTreeSet::from([self.language])
        }
        fn all_declarations(&self) -> Box<dyn Iterator<Item = CodeUnit> + '_> {
            Box::new(self.files.values().flat_map(|p| p.ranges.keys().cloned()))
        }
        fn declarations(&self, file: &ProjectFile) -> BTreeSet<CodeUnit> {
            self.files
                .get(file)
                .map(|parsed| parsed.ranges.keys().cloned().collect())
                .unwrap_or_default()
        }
        fn top_level_declarations(&self, file: &ProjectFile) -> Vec<CodeUnit> {
            self.files[file].top_level_declarations.clone()
        }
        fn ranges(&self, unit: &CodeUnit) -> Vec<Range> {
            self.files[unit.source()]
                .ranges
                .get(unit)
                .cloned()
                .unwrap_or_default()
        }
        fn search_definitions(&self, _pattern: &str, _auto_quote: bool) -> BTreeSet<CodeUnit> {
            unimplemented!()
        }
        fn enclosing_code_unit(&self, _file: &ProjectFile, _range: &Range) -> Option<CodeUnit> {
            unimplemented!()
        }
        fn enclosing_code_unit_for_lines(
            &self,
            _file: &ProjectFile,
            _start_line: usize,
            _end_line: usize,
        ) -> Option<CodeUnit> {
            unimplemented!()
        }
        fn get_skeleton(&self, _unit: &CodeUnit) -> Option<String> {
            unimplemented!()
        }
        fn get_skeleton_header(&self, _unit: &CodeUnit) -> Option<String> {
            unimplemented!()
        }
        fn get_source(&self, _unit: &CodeUnit, _include_comments: bool) -> Option<String> {
            unimplemented!()
        }
        fn get_sources(&self, _unit: &CodeUnit, _include_comments: bool) -> BTreeSet<String> {
            unimplemented!()
        }
    }
    impl ImportAnalysisProvider for ImportHost {
        fn imported_code_units_of(&self, _file: &ProjectFile) -> Arc<HashSet<CodeUnit>> {
            unimplemented!()
        }
        fn referencing_files_of(&self, _file: &ProjectFile) -> HashSet<ProjectFile> {
            unimplemented!()
        }
    }
    impl TypeHierarchyProvider for ImportHost {
        fn get_direct_ancestors(
            &self,
            _unit: &CodeUnit,
        ) -> brokk_bifrost_core::analyzer::capabilities::HierarchyAnswer {
            unimplemented!()
        }
        fn get_direct_descendants(
            &self,
            _unit: &CodeUnit,
        ) -> brokk_bifrost_core::analyzer::capabilities::HierarchyAnswer {
            unimplemented!()
        }
    }
    impl JsTsSource for ImportHost {
        fn source_file_inventory(
            &self,
        ) -> brokk_bifrost_core::analyzer::query_batch::QueryBatch<ProjectFile> {
            let files = self.all_files();
            let count = files.len();
            brokk_bifrost_core::analyzer::query_batch::QueryBatch::complete(files, count)
        }
        fn source_facts(&self, file: &ProjectFile) -> Option<Arc<JsTsFileSourceFacts>> {
            if !self.source_facts_available {
                return None;
            }
            let parsed = self.files.get(file)?;
            let publication = parsed.source_facts.as_ref()?;
            let mut declaration_units = HashMap::<_, Vec<_>>::default();
            for (declaration, unit) in &parsed.source_declaration_units {
                declaration_units
                    .entry(*declaration)
                    .or_default()
                    .push(unit.clone());
            }
            Some(Arc::new(JsTsFileSourceFacts {
                source: publication.occurrences.clone(),
                imports: publication.imports.clone(),
                facts: publication.js_ts.clone()?,
                declaration_units,
            }))
        }
        fn alias_resolver(&self) -> &Arc<AliasResolver> {
            &self.aliases
        }
        fn language(&self) -> Language {
            self.language
        }
        fn all_files(&self) -> Vec<ProjectFile> {
            self.files.keys().cloned().collect()
        }
        fn bulk_import_infos(
            &self,
            _files: &[ProjectFile],
        ) -> HashMap<ProjectFile, Vec<ImportInfo>> {
            unimplemented!()
        }
        fn raw_supertypes_of(&self, _unit: &CodeUnit) -> Vec<String> {
            unimplemented!()
        }
        fn import_statements(&self, _file: &ProjectFile) -> Vec<String> {
            unimplemented!()
        }
        fn is_type_alias(&self, _unit: &CodeUnit) -> bool {
            false
        }
        fn raw_signatures(&self, _unit: &CodeUnit) -> Vec<String> {
            unimplemented!()
        }
        fn with_usage_definitions(
            &self,
            _token: QueryToken<'_>,
            _read: &mut dyn FnMut(&dyn BoundedDefinitionLookup),
        ) {
            unimplemented!()
        }
        fn usage_index(
            &self,
            _cancellation: Option<&CancellationToken>,
        ) -> Option<Arc<JsTsUsageIndex>> {
            crate::graph::resolver::build_jsts_usage_index(
                self,
                &self.aliases,
                self.language,
                false,
            )
            .map(Arc::new)
        }
    }

    impl BoundedDefinitionLookup for ImportHost {
        fn fqn(&self, name: &str) -> Vec<CodeUnit> {
            self.all_declarations()
                .filter(|u| u.fq_name() == name)
                .collect()
        }
        fn fqn_in_language(&self, name: &str, _language: Language) -> Vec<CodeUnit> {
            self.fqn(name)
        }
        fn file_identifier(&self, file: &ProjectFile, name: &str) -> Vec<CodeUnit> {
            self.all_declarations()
                .filter(|u| u.source() == file && u.identifier() == name)
                .collect()
        }
        fn package_exists(&self, _package: &str) -> bool {
            false
        }
        fn package_exists_in_language(&self, _package: &str, _language: Language) -> bool {
            false
        }
        fn fqn_prefix_exists(&self, _prefix: &str) -> bool {
            false
        }
        fn fqn_direct_children(&self, _fqn: &str) -> Vec<CodeUnit> {
            Vec::new()
        }
    }

    #[test]
    fn imported_declaration_projection() {
        let root = tempfile::tempdir().unwrap();
        let project = Arc::new(TestProject::new(root.path(), Language::TypeScript));
        let aliases = Arc::new(AliasResolver::new(project.clone() as Arc<dyn Project>));
        let fixtures = [
            (
                "spaces.ts",
                "export interface Item { field:string } export const Item={field:1};",
            ),
            (
                "namespace.ts",
                "export function first(){} export class Second {}",
            ),
            ("default.ts", "export default function Original(){}"),
            (
                "decoy.ts",
                "export function unrelated(){} export class Other {}",
            ),
            (
                "caller.ts",
                "import * as ns from './namespace'; import Alias from './default'; import Missing from './decoy';",
            ),
        ];
        let mut files = HashMap::default();
        for (name, source) in fixtures {
            let file = ProjectFile::new(root.path(), name);
            std::fs::write(file.abs_path(), source).unwrap();
            let tree = crate::test_support::parse_typescript(source);
            files.insert(
                file.clone(),
                crate::typescript::parse_typescript_file(&file, source, &tree),
            );
        }
        let host = ImportHost {
            project,
            aliases,
            language: Language::TypeScript,
            source_facts_available: true,
            files,
        };
        let file = ProjectFile::new(root.path(), "caller.ts");
        let imports = host.files[&file].imports.clone();
        assert_eq!(imports.len(), 3);
        let projected = resolve_imported_code_units(&host, &file, imports);
        let mut names: Vec<_> = projected.iter().map(|u| u.identifier()).collect();
        names.sort_unstable();
        assert_eq!(names, ["Original", "Second", "first"]);
        struct NoExternalSurface;
        impl crate::diagnostics::JsTsExternalSurfaceEvidence for NoExternalSurface {
            fn classify_exported_name(
                &self,
                _module: &str,
                _name: &str,
            ) -> crate::diagnostics::JsTsExportedNameEvidence {
                unimplemented!()
            }
            fn classify_module(&self, _module: &str) -> crate::diagnostics::JsTsModuleEvidence {
                unimplemented!()
            }
        }
        let diagnostics = crate::diagnostics::collect_js_ts_semantic_diagnostics(
            &host,
            &NoExternalSurface,
            &file,
            "process; console; qs7Missing;",
            Language::TypeScript,
            "qs7",
            &host.aliases,
        );
        let messages: Vec<_> = diagnostics
            .diagnostics()
            .iter()
            .map(|d| d.message.as_str())
            .collect();
        assert_eq!(messages, ["Unrecognized JS/TS symbol `qs7Missing`"]);
        // tsc's type/value namespaces select independently declared owners.
        let chain_source = "ns.Item";
        let tree = crate::test_support::parse_typescript(chain_source);
        let member = tree
            .root_node()
            .named_child(0)
            .unwrap()
            .named_child(0)
            .unwrap();
        let crate::access_chain::JsTsImportedMemberChainResolution::Exact(chain) =
            crate::access_chain::resolve_import_member_chain(member, chain_source)
        else {
            panic!("static chain")
        };
        let binding = brokk_bifrost_core::analyzer::usages::model::ImportBinding {
            module_specifier: "./spaces".into(),
            namespace_imported_module: None,
            kind: brokk_bifrost_core::analyzer::usages::model::ImportKind::Namespace,
            imported_name: None,
        };
        for value_position in [true, false] {
            let outcome = crate::imports::resolve_js_ts_imported_member_chain(
                &host,
                &host,
                Language::TypeScript,
                &file,
                &binding,
                &chain,
                Some(&host.aliases),
                value_position,
                Default::default(),
            );
            let brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisOutcome::Precise(owners)=outcome else {panic!("{outcome:?}")};
            assert_eq!(owners.len(), 1, "{owners:?}");
            assert_eq!(
                crate::type_text::jsts_unit_is_type_only(&host, &owners[0].declaration),
                !value_position,
                "{owners:?}"
            );
        }
    }

    #[test]
    fn anonymous_default_class_resolves_in_both_spaces_for_javascript_and_typescript() {
        for (language, extension) in [(Language::JavaScript, "js"), (Language::TypeScript, "ts")] {
            let root = tempfile::tempdir().unwrap();
            let project = Arc::new(TestProject::new(root.path(), language));
            let aliases = Arc::new(AliasResolver::new(project.clone() as Arc<dyn Project>));
            let mut files = HashMap::default();
            for (name, source) in [
                (format!("anonymous.{extension}"), "export default class {}"),
                (format!("caller.{extension}"), ""),
            ] {
                let file = ProjectFile::new(root.path(), name);
                std::fs::write(file.abs_path(), source).unwrap();
                let tree = match language {
                    Language::JavaScript => crate::test_support::parse_javascript(source),
                    Language::TypeScript => crate::test_support::parse_typescript(source),
                    _ => unreachable!(),
                };
                let parsed = match language {
                    Language::JavaScript => {
                        crate::javascript::parse_javascript_file(&file, source, &tree)
                    }
                    Language::TypeScript => {
                        crate::typescript::parse_typescript_file(&file, source, &tree)
                    }
                    _ => unreachable!(),
                };
                files.insert(file, parsed);
            }
            let host = ImportHost {
                project,
                aliases: aliases.clone(),
                language,
                // Keep parser-produced declarations while exercising the
                // resolver's structured fallback for an unavailable export index.
                source_facts_available: false,
                files,
            };
            let caller = ProjectFile::new(root.path(), format!("caller.{extension}"));
            let module_file = ProjectFile::new(root.path(), format!("anonymous.{extension}"));
            assert!(
                host.declarations(&module_file)
                    .iter()
                    .any(|unit| unit.identifier() == "default"),
                "{language:?}: {:?}",
                host.declarations(&module_file)
            );
            for value_position in [true, false] {
                let candidates = crate::imports::resolve_js_ts_module_binding_candidates(
                    &host,
                    &host,
                    language,
                    &caller,
                    "./anonymous",
                    "default",
                    Some(&aliases),
                    value_position,
                );
                assert_eq!(
                    candidates.len(),
                    1,
                    "{language:?}, value_position={value_position}: {candidates:?}"
                );
                assert_eq!(candidates[0].identifier(), "default");
            }
        }
    }
}
