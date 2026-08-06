//! Java's `ImportAnalysisProvider` impl and the memo cells behind it, plus the
//! external half of type-name resolution.
//!
//! What an `import` declaration *says*, and how Java's import, wildcard and
//! same-package tiers decide a written type name, moved to
//! [`brokk_bifrost_jvm::java::imports`] and
//! [`brokk_bifrost_jvm::java::graph_support`]. The caching, the reverse import
//! index and the same-package reference index stay here because they read the
//! analyzer's own cells, and so does everything that consults
//! [`JvmExternalDeclarationIndex`]: that index imports `semantic_model` and
//! cannot cross the crate line.

use super::*;
use crate::analyzer::ImportInfo;
use crate::analyzer::jvm::external::JvmExternalType;
use crate::analyzer::structural::resolution::{PrecedenceTier, RejectionReason};
use crate::analyzer::usages::get_definition::trace;
use brokk_bifrost_jvm::java::graph_support::{
    compute_java_relevant_imports, compute_java_same_package_reference_index,
    java_could_import_file, java_could_import_file_without_source, java_same_package_fqn,
    resolve_java_import_infos, resolve_java_type_name, resolve_java_usage_type_name_in,
};
use brokk_bifrost_jvm::java::imports::non_static_import_path;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum JavaTypeResolution {
    Source(CodeUnit),
    External(JvmExternalType),
}

impl ImportAnalysisProvider for JavaAnalyzer {
    fn imported_code_units_of(&self, file: &ProjectFile) -> HashSet<CodeUnit> {
        self.resolve_imports(file).values().cloned().collect()
    }

    fn import_infos_for_files(
        &self,
        files: &[ProjectFile],
    ) -> Option<HashMap<ProjectFile, Vec<ImportInfo>>> {
        let mut imports_by_file = HashMap::default();
        for (file, facts) in self.inner.bulk_import_facts(files.iter().cloned()) {
            self.memo_caches
                .package_names
                .insert(file.clone(), Arc::from(facts.package_name));
            imports_by_file.insert(file, facts.imports);
        }
        Some(imports_by_file)
    }

    fn referencing_files_of(&self, file: &ProjectFile) -> HashSet<ProjectFile> {
        if let Some(cached) = self.memo_caches.referencing_files.get(file) {
            return (*cached).clone();
        }

        let reverse_index = crate::analyzer::memoized_reverse_import_index(
            &self.memo_caches.reverse_import_index,
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

        self.memo_caches
            .referencing_files
            .insert(file.clone(), Arc::new(result.clone()));
        result
    }

    fn import_info_of(&self, file: &ProjectFile) -> Vec<ImportInfo> {
        self.inner.import_info_of(file)
    }

    fn imported_code_units_from_infos(
        &self,
        _file: &ProjectFile,
        imports: &[ImportInfo],
    ) -> Option<HashSet<CodeUnit>> {
        Some(self.resolve_import_infos(imports).into_values().collect())
    }

    fn relevant_imports_for(&self, code_unit: &CodeUnit) -> HashSet<String> {
        if let Some(cached) = self.memo_caches.relevant_imports.get(code_unit) {
            return (*cached).clone();
        }

        let matched_imports = compute_java_relevant_imports(self, code_unit);
        self.memo_caches
            .relevant_imports
            .insert(code_unit.clone(), Arc::new(matched_imports.clone()));
        matched_imports
    }

    fn could_import_file(
        &self,
        source_file: &ProjectFile,
        imports: &[ImportInfo],
        target: &ProjectFile,
    ) -> bool {
        java_could_import_file(self, source_file, imports, target)
    }
}

impl JavaAnalyzer {
    /// Resolve a source type while a usage query already owns the complete
    /// workspace declaration index. This preserves the same import and package
    /// tiers as forward resolution without serializing every AST type node on
    /// the persisted SQLite connection.
    pub(crate) fn resolve_usage_type_name(
        &self,
        file: &ProjectFile,
        raw_name: &str,
    ) -> Option<CodeUnit> {
        self.resolve_usage_type_name_in(&self.global_usage_definition_index(), file, raw_name)
    }

    /// Resolve a source type against a *supplied* declaration index, applying
    /// Java's own import and package tiers.
    ///
    /// The index is a parameter because Java, Scala, and Kotlin share one JVM
    /// candidate space (issue #1237); see
    /// [`resolve_java_usage_type_name_in`] for what widening it does and does
    /// not change.
    pub(crate) fn resolve_usage_type_name_in(
        &self,
        index: &crate::analyzer::DefinitionIndexHandle<'_>,
        file: &ProjectFile,
        raw_name: &str,
    ) -> Option<CodeUnit> {
        resolve_java_usage_type_name_in(self, index, file, raw_name)
    }
}

impl TestDetectionProvider for JavaAnalyzer {}

impl JavaAnalyzer {
    pub(super) fn same_package_reference_index(
        &self,
    ) -> Arc<HashMap<ProjectFile, Arc<HashSet<ProjectFile>>>> {
        self.memo_caches.same_package_reference_index.get_or_build(
            || compute_java_same_package_reference_index(self, true),
            || compute_java_same_package_reference_index(self, false),
        )
    }

    pub fn could_import_file_without_source(
        &self,
        imports: &[ImportInfo],
        target: &ProjectFile,
    ) -> bool {
        java_could_import_file_without_source(self, imports, target)
    }

    pub(super) fn resolve_imports(&self, file: &ProjectFile) -> Arc<HashMap<String, CodeUnit>> {
        if let Some(cached) = self.memo_caches.resolved_imports.get(file) {
            return cached;
        }

        let resolved = Arc::new(self.resolve_imports_uncached(file));
        self.memo_caches
            .resolved_imports
            .insert(file.clone(), Arc::clone(&resolved));
        resolved
    }

    fn resolve_imports_uncached(&self, file: &ProjectFile) -> HashMap<String, CodeUnit> {
        let imports = self.inner.import_info_of(file);
        self.resolve_import_infos(&imports)
    }

    pub(crate) fn resolve_import_infos(&self, imports: &[ImportInfo]) -> HashMap<String, CodeUnit> {
        resolve_java_import_infos(self, imports)
    }

    pub(crate) fn resolve_type_name_with_external(
        &self,
        file: &ProjectFile,
        raw_name: &str,
    ) -> Option<JavaTypeResolution> {
        let normalized = raw_name.trim();
        if normalized.is_empty() {
            return None;
        }

        if let Some(code_unit) = resolve_java_type_name(self, file, normalized) {
            return Some(JavaTypeResolution::Source(code_unit));
        }

        let external = self.external_declaration_index();
        if external.is_empty() {
            return None;
        }

        let access_package = self.package_name_of(file).unwrap_or_default();
        if normalized.contains('.')
            && let Some(external_type) =
                external.resolve_qualified_name(normalized, &access_package)
        {
            return Some(JavaTypeResolution::External(external_type.clone()));
        }

        if let Some(external_type) =
            self.resolve_external_imports(file, normalized, &access_package)
        {
            return Some(JavaTypeResolution::External(external_type));
        }

        if let Some((first, rest)) = normalized.split_once('.')
            && let Some(owner) =
                self.resolve_visible_external_simple_type(file, first, &access_package)
        {
            let nested_fqn = format!("{}.{}", owner.fqn(), rest);
            if let Some(external_type) =
                external.resolve_qualified_name(&nested_fqn, &access_package)
            {
                return Some(JavaTypeResolution::External(external_type.clone()));
            }
        }

        let same_package = java_same_package_fqn(self, file, normalized);
        if let Some(external_type) = external.resolve_same_package(&access_package, normalized) {
            return Some(JavaTypeResolution::External(external_type.clone()));
        }

        if same_package != normalized
            && let Some(external_type) =
                external.resolve_qualified_name(&same_package, &access_package)
        {
            return Some(JavaTypeResolution::External(external_type.clone()));
        }

        external
            .resolve_java_lang(normalized)
            .cloned()
            .map(JavaTypeResolution::External)
    }

    fn resolve_visible_external_simple_type(
        &self,
        file: &ProjectFile,
        name: &str,
        access_package: &str,
    ) -> Option<JvmExternalType> {
        if let Some(external_type) = self.resolve_external_imports(file, name, access_package) {
            return Some(external_type);
        }

        let external = self.external_declaration_index();
        external
            .resolve_same_package(access_package, name)
            .or_else(|| external.resolve_java_lang(name))
            .cloned()
    }

    fn resolve_external_imports(
        &self,
        file: &ProjectFile,
        name: &str,
        access_package: &str,
    ) -> Option<JvmExternalType> {
        let external = self.external_declaration_index();
        for import in self.inner.import_info_of(file) {
            let Some(import_path) = non_static_import_path(&import) else {
                continue;
            };

            if !import.is_wildcard {
                if import.identifier.as_deref() == Some(name)
                    && let Some(external_type) = external
                        .resolve_explicit_import(&import_path.render_segments("."), access_package)
                {
                    return Some(external_type.clone());
                }
                continue;
            }
        }

        let mut wildcard_match: Option<JvmExternalType> = None;
        for import in self.inner.import_info_of(file) {
            let Some(import_path) = non_static_import_path(&import) else {
                continue;
            };
            if !import.is_wildcard {
                continue;
            }

            let package_name = import_path.render_segments(".");
            let Some(external_type) =
                external.resolve_wildcard_import(&package_name, name, access_package)
            else {
                continue;
            };
            match wildcard_match.as_ref() {
                Some(existing) if existing.fqn() != external_type.fqn() => return None,
                Some(_) => {}
                None => wildcard_match = Some(external_type.clone()),
            }
        }

        wildcard_match
    }
}

/// Stage the tier a type-name lookup resolved at, so the outcome constructor
/// these units flow into records them at that tier.
///
/// The staging is guarded twice, because `resolve_java_type_name_with` also runs
/// for receiver types and owners on the way to an answer: only a lookup for the
/// name the traced resolver path is currently resolving stages anything, and
/// the staged tier is spent only by an outcome that reports these very units.
pub(super) fn trace_tier(normalized: &str, units: &[CodeUnit], tier: PrecedenceTier) {
    if trace::recording() && trace::deep_scope_is(normalized) {
        trace::stage_tier(tier, units.iter().map(CodeUnit::fq_name).collect());
    }
}

/// Record Java's strongest import tier winning, together with the on-demand
/// import routes that were therefore never consulted.
///
/// Java resolves a simple type name against single-type imports before
/// on-demand (`.*`) imports, which is why the wildcard loop runs only when the
/// explicit loop found nothing. The wildcard routes are the resolver's own
/// enumerated import list, not a re-derivation, so recording them as rejected
/// peers reports a decision the resolver made rather than inventing one.
///
/// The rejected route keeps the wildcard marker as its `name` -- an on-demand
/// import binds no single identifier -- and names what it pointed at through
/// `target_segments`, the parser-derived package path `parse_import_info`
/// read from the `import_declaration` node (#1600).
pub(super) fn trace_explicit_import_win(
    file: &ProjectFile,
    normalized: &str,
    unit: Option<&CodeUnit>,
    imports: &[ImportInfo],
) {
    if !trace::recording() || !trace::deep_scope_is(normalized) {
        return;
    }
    if let Some(unit) = unit {
        trace::stage_tier(PrecedenceTier::ExplicitImport, vec![unit.fq_name()]);
    }
    trace::record_all(
        imports
            .iter()
            .filter(|import| import.is_wildcard)
            .map(|import| {
                trace::TraceCandidate::rejected(
                    trace::TraceCandidateRef::ImportBinder {
                        file: file.clone(),
                        node: None,
                        name: trace::WILDCARD_ROUTE_NAME.to_owned(),
                        target_segments: import
                            .path
                            .as_ref()
                            .map(|path| path.segments.clone())
                            .unwrap_or_default(),
                    },
                    Some(PrecedenceTier::WildcardImport),
                    RejectionReason::ShadowedByNearer,
                )
            }),
    );
}
