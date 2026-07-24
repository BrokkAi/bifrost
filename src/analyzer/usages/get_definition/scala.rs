use super::*;
use crate::analyzer::scala::imports::scala_import_infos_from_node;
use crate::analyzer::scala::{
    ScalaExportSelector, ScalaSupertypeLookupPath, ScalaWildcardImportEnvironment,
    ScalaWildcardOwnerFacts, resolve_scala_wildcard_import_environment,
    scala_enclosing_package_root_candidates, scala_enclosing_template_owner_fq_names,
    scala_import_path, scala_import_path_candidates, scala_import_visible_at,
    scala_lexical_scope_path_at, scala_lexical_scope_path_checked, scala_nested_type_candidates,
    scala_package_prefixes_at, scala_package_prefixes_at_checked, scala_type_lookup_segments,
};
use crate::analyzer::usages::scala_graph::local::{
    ScalaLocalBinding, precise_scala_binding, seed_scala_binding,
    seed_scala_binding_with_receiver_declaration,
};
use crate::analyzer::usages::scala_graph::namespace::{
    ScalaDirectAncestorResolution, ScalaTypeNamespaceResolution, ScalaUnindexedTypeBinding,
    resolve_exact_lexical_type_namespace, scala_anonymous_instance_for_template,
    scala_nearest_unindexed_type_binding, scala_qualified_type_root,
    scala_type_reference_is_singleton, scala_unindexed_type_binding_shadows,
};
use crate::analyzer::usages::scala_graph::syntax::{
    ScalaCallArgumentListKind, ScalaCallSiteShape, ScalaCallableParameterList, ScalaCallableRole,
    ScalaCallableSiteRole, ScalaCallableSourceAlternative, ScalaFunctionParameterShape,
    ScalaParameterListKind, ScalaParameterTypeIdentity, ScalaQualifiedStableTypeRole,
    applied_expression_for_reference, call_arities_for_reference, call_site_shape_for_reference,
    is_extractor_reference, is_infix_type_operator_reference, is_scala_case_pattern_binder,
    is_scala_named_argument_assignment, qualified_stable_type_reference,
    scala_callable_alternative_is_candidate, scala_callable_alternative_matches,
    scala_pattern_binder_names, scala_source_facts,
};
use crate::analyzer::usages::scala_graph::{
    method_signature_arity, resolved_extension_receiver_type,
};
use crate::analyzer::usages::target_kind::TypeLookupTargetKind;
use crate::analyzer::{ImportInfo, SignatureMetadata, StructuredImportPath, StructuredImportScope};
use std::cell::Cell;
use std::collections::{HashMap, VecDeque};

struct ForwardScalaExtensionMethod {
    fqn: String,
    receiver_type: Option<String>,
}

#[derive(Clone)]
struct ForwardScalaCallableAlternative {
    role: ScalaCallableRole,
    shape: Vec<ScalaCallableParameterList>,
    parameter_types: Vec<Vec<Option<ScalaParameterTypeIdentity>>>,
    parameter_function_shapes: Vec<Vec<Option<ScalaFunctionParameterShape>>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ScalaOwnerKind {
    Class,
    SingletonObject,
    TypeNamespace,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ScalaOwnerIdentity {
    fqn: String,
    kind: ScalaOwnerKind,
    _declaration: CodeUnit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ScalaReceiverOwner {
    Exact(CodeUnit),
    Logical(String),
}

impl ScalaReceiverOwner {
    fn fq_name(&self) -> String {
        match self {
            Self::Exact(owner) => owner.fq_name(),
            Self::Logical(owner_fqn) => owner_fqn.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ScalaNameResolution {
    Resolved(ScalaOwnerIdentity),
    MissingExplicitImport,
    Ambiguous,
    Unresolved,
}

/// Request-scoped, candidate-query replacement for Scala's global inverted
/// graph resolver.  It resolves only names visible from one file and never
/// enumerates a package or builds `ProjectTypes`.
struct ForwardScalaNameResolver<'a> {
    scala: &'a ScalaAnalyzer,
    support: &'a dyn BoundedDefinitionLookup,
    file: ProjectFile,
    package: Arc<str>,
    package_prefixes: Arc<Vec<String>>,
    lexical_scopes: Arc<Vec<StructuredImportScope>>,
    reference_byte: Option<usize>,
    imports: Arc<Vec<ImportInfo>>,
}

type ScalaNameResolver<'a> = ForwardScalaNameResolver<'a>;

pub(crate) struct ScalaDefinitionProvider<'a> {
    scala: &'a ScalaAnalyzer,
    session: &'a ResolutionSession,
}

impl<'a> ScalaDefinitionProvider<'a> {
    pub(crate) fn new(scala: &'a ScalaAnalyzer, session: &'a ResolutionSession) -> Self {
        Self { scala, session }
    }

    fn direct_children(&self, owner: &CodeUnit) -> Vec<CodeUnit> {
        self.session
            .query_limited_rows(|limit| self.scala.direct_children_limited(owner, limit))
    }

    fn imports(&self, file: &ProjectFile) -> Vec<ImportInfo> {
        self.session
            .query_limited_rows(|limit| self.scala.import_info_of_limited(file, limit))
    }

    fn ranges(&self, unit: &CodeUnit) -> Vec<Range> {
        self.session
            .query_limited_rows(|limit| self.scala.ranges_limited(unit, limit))
    }

    fn signature_metadata(&self, unit: &CodeUnit) -> Vec<SignatureMetadata> {
        self.session
            .query_limited_rows(|limit| self.scala.signature_metadata_limited(unit, limit))
    }

    fn supertype_lookup_paths(&self, unit: &CodeUnit) -> Vec<String> {
        self.session
            .query_limited_rows(|limit| self.scala.supertype_lookup_paths_limited(unit, limit))
    }

    fn raw_supertypes(&self, unit: &CodeUnit) -> Vec<String> {
        self.session
            .query_limited_rows(|limit| self.scala.raw_supertypes_limited(unit, limit))
    }
}

impl BoundedDefinitionLookup for ScalaDefinitionProvider<'_> {
    fn fqn(&self, fqn: &str) -> Vec<CodeUnit> {
        let mut units = self.session.query_limited_rows(|limit| {
            self.scala
                .declaration_candidates_by_fqn_limited(fqn, false, limit, || {
                    self.session.observe_cancellation()
                })
        });
        if units.is_empty() && self.session.observe_cancellation() {
            units = self.session.query_limited_rows(|limit| {
                self.scala
                    .declaration_candidates_by_fqn_limited(fqn, true, limit, || {
                        self.session.observe_cancellation()
                    })
            });
        }
        if units.is_empty()
            && self.session.observe_cancellation()
            && let Some(terminal) = fqn.rsplit('.').next().filter(|name| !name.is_empty())
        {
            let normalized = crate::analyzer::scala::scala_normalize_full_name(fqn);
            let mut identifiers = vec![terminal];
            let plain = terminal.trim_end_matches('$');
            if !plain.is_empty() && plain != terminal {
                identifiers.push(plain);
            }
            for identifier in identifiers {
                units.extend(
                    self.session
                        .query_limited_rows(|limit| {
                            self.scala.declaration_candidates_by_identifier_limited(
                                identifier,
                                limit,
                                || self.session.observe_cancellation(),
                            )
                        })
                        .into_iter()
                        .filter(|unit| {
                            unit.fq_name() == fqn
                                || crate::analyzer::scala::scala_normalize_full_name(
                                    &unit.fq_name(),
                                ) == normalized
                        }),
                );
            }
        }
        sort_units(&mut units);
        units.dedup();
        units
    }

    fn fqn_in_language(&self, fqn: &str, language: Language) -> Vec<CodeUnit> {
        if language == Language::Scala {
            self.fqn(fqn)
        } else {
            // The bounded receiver path does not materialize another
            // language's provider speculatively. An absent cross-language
            // candidate is a resolution boundary, not resource exhaustion.
            Vec::new()
        }
    }

    fn file_identifier(&self, _file: &ProjectFile, _ident: &str) -> Vec<CodeUnit> {
        // Bounded Scala resolution requires a parser-derived lexical/import
        // path or an exact FQN. It intentionally exposes no same-file
        // identifier fallback through the shared lookup trait.
        Vec::new()
    }

    fn fqn_direct_children(&self, fqn: &str) -> Vec<CodeUnit> {
        let mut children = Vec::new();
        for owner in self.fqn(fqn) {
            children.extend(
                self.session
                    .query_limited_rows(|limit| self.scala.direct_children_limited(&owner, limit)),
            );
            if !self.session.observe_cancellation() {
                return Vec::new();
            }
        }
        sort_units(&mut children);
        children.dedup();
        children
    }

    fn fqn_exists(&self, fqn: &str) -> bool {
        !self.fqn(fqn).is_empty()
    }

    fn package_exists(&self, package: &str) -> bool {
        self.session
            .query(|| self.scala.workspace_package_exists(package))
            .unwrap_or(false)
    }

    fn package_exists_in_language(&self, package: &str, language: Language) -> bool {
        if language == Language::Scala {
            self.package_exists(package)
        } else {
            false
        }
    }

    fn fqn_prefix_exists(&self, prefix: &str) -> bool {
        self.session
            .query(|| self.scala.workspace_fqn_prefix_exists(prefix))
            .unwrap_or(false)
    }
}

fn scala_name_resolver_for_unit<'a>(
    scala: &'a ScalaAnalyzer,
    support: &'a dyn BoundedDefinitionLookup,
    unit: &CodeUnit,
) -> ScalaNameResolver<'a> {
    let resolver = ScalaNameResolver::for_file(scala, support, unit.source());
    let Some((package_prefixes, lexical_scopes, reference_byte)) =
        scala.import_lexical_context_for_unit(unit)
    else {
        return resolver;
    };
    resolver.with_lexical_context(package_prefixes, lexical_scopes, reference_byte)
}

impl<'a> ForwardScalaNameResolver<'a> {
    fn for_file(
        scala: &'a ScalaAnalyzer,
        support: &'a dyn BoundedDefinitionLookup,
        file: &ProjectFile,
    ) -> Self {
        Self::for_batch(
            scala,
            support,
            &ScalaDefinitionContext {
                file: file.clone(),
                package: Arc::from(scala_package_name_of(scala, file).unwrap_or_default()),
                imports: Arc::new(scala.import_info_of(file)),
            },
        )
    }

    fn for_batch(
        scala: &'a ScalaAnalyzer,
        support: &'a dyn BoundedDefinitionLookup,
        batch: &ScalaDefinitionContext,
    ) -> Self {
        Self {
            scala,
            support,
            file: batch.file.clone(),
            package: Arc::clone(&batch.package),
            package_prefixes: Arc::new(vec![batch.package.to_string()]),
            lexical_scopes: Arc::new(Vec::new()),
            reference_byte: None,
            imports: Arc::clone(&batch.imports),
        }
    }

    fn with_lexical_context(
        mut self,
        package_prefixes: Vec<String>,
        lexical_scopes: Vec<StructuredImportScope>,
        reference_byte: usize,
    ) -> Self {
        if !package_prefixes.is_empty() {
            self.package_prefixes = Arc::new(package_prefixes);
        }
        self.lexical_scopes = Arc::new(lexical_scopes);
        self.reference_byte = Some(reference_byte);
        self
    }

    fn visible_imports(&self) -> impl Iterator<Item = &ImportInfo> {
        self.imports.iter().filter(|import| {
            self.reference_byte.is_none_or(|reference_byte| {
                scala_import_visible_at(
                    import,
                    &self.package_prefixes,
                    &self.lexical_scopes,
                    reference_byte,
                )
            })
        })
    }

    fn resolve(&self, raw: &str) -> Option<String> {
        match self.resolve_owner(raw, ScalaOwnerKind::Class) {
            ScalaNameResolution::Resolved(owner) => Some(owner.fqn),
            ScalaNameResolution::MissingExplicitImport
            | ScalaNameResolution::Ambiguous
            | ScalaNameResolution::Unresolved => None,
        }
    }

    fn resolve_singleton(&self, raw: &str) -> Option<String> {
        match self.resolve_owner(raw, ScalaOwnerKind::SingletonObject) {
            ScalaNameResolution::Resolved(owner) => Some(owner.fqn),
            ScalaNameResolution::MissingExplicitImport
            | ScalaNameResolution::Ambiguous
            | ScalaNameResolution::Unresolved => None,
        }
    }

    fn resolve_explicit_singleton(&self, raw: &str) -> ScalaNameResolution {
        let simple = raw.trim();
        if simple.is_empty() {
            return ScalaNameResolution::Unresolved;
        }
        self.resolve_explicit_owner_segments(&[simple.to_string()], ScalaOwnerKind::SingletonObject)
    }

    fn resolve_owner(&self, raw: &str, kind: ScalaOwnerKind) -> ScalaNameResolution {
        let simple = raw.trim();
        if simple.is_empty() {
            return ScalaNameResolution::Unresolved;
        }
        self.resolve_owner_segments(&[simple.to_string()], kind)
    }

    /// Resolve only bindings that legally precede Scala's implicit `scala.*`
    /// namespace. Compiler lattice types have no source declaration, but a
    /// lexical/current-package type or an explicit import with the same local
    /// spelling still has ordinary Scala shadowing semantics.
    fn resolve_intrinsic_shadow(&self, name: &str, kind: ScalaOwnerKind) -> ScalaNameResolution {
        let segments = [name.to_string()];
        match self.resolve_explicit_owner_segments(&segments, kind) {
            ScalaNameResolution::Resolved(owner)
                if scala_normalized_fq_name(&owner.fqn) != format!("scala.{name}") =>
            {
                return ScalaNameResolution::Resolved(owner);
            }
            ScalaNameResolution::MissingExplicitImport => {
                let has_non_intrinsic_import = self.visible_imports().any(|import| {
                    if import.is_wildcard {
                        return false;
                    }
                    let Some(path) = scala_import_path(import) else {
                        return false;
                    };
                    let local_name = import
                        .identifier
                        .as_deref()
                        .unwrap_or_else(|| path.rsplit('.').next().unwrap_or(&path));
                    local_name == name && scala_normalized_fq_name(&path) != format!("scala.{name}")
                });
                if has_non_intrinsic_import {
                    return ScalaNameResolution::MissingExplicitImport;
                }
            }
            ScalaNameResolution::Ambiguous => return ScalaNameResolution::Ambiguous,
            ScalaNameResolution::Resolved(_) | ScalaNameResolution::Unresolved => {}
        }

        let mut wildcard_candidates = Vec::new();
        for import in self.visible_imports().filter(|import| import.is_wildcard) {
            let Some(path) = scala_import_path(import) else {
                continue;
            };
            if scala_normalized_fq_name(&path) == "scala" {
                continue;
            }
            wildcard_candidates.extend(
                import_candidate_fq_names(&path, &self.package)
                    .into_iter()
                    .flat_map(|package| scala_nested_type_candidates(package, &segments, false)),
            );
        }
        wildcard_candidates.extend(self.enclosing_owner_qualified_wildcard_candidates(&segments));
        let wildcard = self.resolve_candidate_tier(wildcard_candidates, kind);
        if wildcard != ScalaNameResolution::Unresolved {
            return wildcard;
        }

        for package_prefix in self
            .package_prefixes
            .iter()
            .rev()
            .filter(|prefix| !prefix.is_empty() && prefix.as_str() != "scala")
        {
            let outcome = self.resolve_candidate_tier(
                scala_nested_type_candidates(package_prefix.clone(), &segments, false),
                kind,
            );
            if outcome != ScalaNameResolution::Unresolved {
                return outcome;
            }
        }
        ScalaNameResolution::Unresolved
    }

    /// Owner-qualified spellings of `segments` reached through each visible
    /// wildcard import's relative base, qualified by that import's own
    /// lexically enclosing object/class/trait scopes (innermost first).
    ///
    /// Mirrors the plain package-qualified tier built inline just above (and
    /// in `resolve_owner_segments`) — `import_candidate_fq_names(...)`
    /// flat-mapped through `scala_nested_type_candidates` — but resolves the
    /// import's relative base against its enclosing template scopes first,
    /// exactly like the import-token click path
    /// (`scala_import_reference_outcome`) and the wildcard-imported-member
    /// usage path (`scala_wildcard_imported_member_outcome`) already do.
    /// Without this, `object Status { import Registry._; def f = X.y }`
    /// left the qualified-path root `X` unresolved even though `Registry` is
    /// indexed as a sibling of `Status`.
    fn enclosing_owner_qualified_wildcard_candidates(&self, segments: &[String]) -> Vec<String> {
        let mut candidates = Vec::new();
        for import in self.visible_imports().filter(|import| import.is_wildcard) {
            let Some(structured_path) = import.path.as_ref() else {
                continue;
            };
            let owners = scala_enclosing_template_owner_fq_names(
                self.scala,
                self.scala,
                &self.file,
                structured_path.declaration_start_byte,
            );
            for owner_base in
                scala_owner_qualified_import_candidate_tiers(&owners, &structured_path.segments)
                    .into_iter()
                    .flatten()
            {
                // `owner_base` names the wildcard-imported singleton itself
                // (e.g. `org.http4s.Status$.Registry`); `segments` is looked
                // up *inside* it, so it is used as an owner needing its own
                // `$` decoration here, exactly like any other owner prefix
                // fed into `scala_nested_type_candidates`.
                candidates.extend(scala_nested_type_candidates(owner_base, segments, true));
            }
        }
        candidates
    }

    fn resolve_lookup_path(
        &self,
        path: &ScalaSupertypeLookupPath,
        kind: ScalaOwnerKind,
    ) -> ScalaNameResolution {
        self.resolve_owner_segments(path.segments(), kind)
    }

    fn resolve_type_node(
        &self,
        node: Node<'_>,
        source: &str,
        kind: ScalaOwnerKind,
    ) -> ScalaNameResolution {
        self.resolve_owner_segments(&scala_type_lookup_segments(node, source), kind)
    }

    fn resolve_owner_segments(
        &self,
        segments: &[String],
        kind: ScalaOwnerKind,
    ) -> ScalaNameResolution {
        if segments.is_empty() {
            return ScalaNameResolution::Unresolved;
        }
        if segments.first().is_some_and(|segment| segment == "_root_") {
            return if segments.len() == 1 {
                ScalaNameResolution::Unresolved
            } else {
                self.resolve_absolute_owner_segments(&segments[1..], kind)
            };
        }
        match self.resolve_explicit_owner_segments(segments, kind) {
            ScalaNameResolution::Unresolved => {}
            outcome => return outcome,
        }

        let mut wildcard_candidates = Vec::new();
        for import in self.visible_imports() {
            let Some(path) = scala_import_path(import) else {
                continue;
            };
            if import.is_wildcard {
                wildcard_candidates.extend(
                    import_candidate_fq_names(&path, &self.package)
                        .into_iter()
                        .flat_map(|package| scala_nested_type_candidates(package, segments, false)),
                );
            }
        }
        wildcard_candidates.extend(self.enclosing_owner_qualified_wildcard_candidates(segments));
        let wildcard = self.resolve_candidate_tier(wildcard_candidates, kind);
        if wildcard != ScalaNameResolution::Unresolved {
            return wildcard;
        }

        for package_prefix in self
            .package_prefixes
            .iter()
            .rev()
            .filter(|prefix| !prefix.is_empty())
        {
            let outcome = self.resolve_candidate_tier(
                scala_nested_type_candidates(package_prefix.clone(), segments, false),
                kind,
            );
            if outcome != ScalaNameResolution::Unresolved {
                return outcome;
            }
        }

        let package_root = segments.first().expect("non-empty Scala type path");
        let package_tail = &segments[1..];
        for package in scala_enclosing_package_root_candidates(&self.package_prefixes, package_root)
        {
            if !self.support.package_exists(&package) {
                continue;
            }
            let outcome = self.resolve_candidate_tier(
                scala_nested_type_candidates(package, package_tail, false),
                kind,
            );
            if outcome != ScalaNameResolution::Unresolved {
                return outcome;
            }
        }

        // `scala.*` is imported by every Scala compilation unit. Keep this
        // below explicit, wildcard, current-package, and qualified-package
        // tiers, but above the root namespace so an unrelated workspace
        // fixture cannot capture an ordinary `Seq`/`List` type or companion.
        if segments.len() == 1 {
            let outcome = self.resolve_candidate_tier(
                scala_nested_type_candidates("scala".to_string(), segments, false),
                kind,
            );
            if outcome != ScalaNameResolution::Unresolved {
                return outcome;
            }
        }

        if segments.len() > 1 || self.package_prefixes.iter().all(String::is_empty) {
            return self.resolve_candidate_tier(
                scala_nested_type_candidates(String::new(), segments, false),
                kind,
            );
        }
        ScalaNameResolution::Unresolved
    }

    fn resolve_absolute_owner_segments(
        &self,
        segments: &[String],
        kind: ScalaOwnerKind,
    ) -> ScalaNameResolution {
        for package_len in (1..segments.len()).rev() {
            let package = segments[..package_len].join(".");
            if !self.support.package_exists(&package) {
                continue;
            }
            let outcome = self.resolve_candidate_tier(
                scala_nested_type_candidates(package, &segments[package_len..], false),
                kind,
            );
            if outcome != ScalaNameResolution::Unresolved {
                return outcome;
            }
        }
        self.resolve_candidate_tier(
            scala_nested_type_candidates(String::new(), segments, false),
            kind,
        )
    }

    fn resolve_explicit_owner_segments(
        &self,
        segments: &[String],
        kind: ScalaOwnerKind,
    ) -> ScalaNameResolution {
        self.resolve_explicit_owner_segments_in_range(segments, kind, None)
    }

    fn resolve_explicit_owner_segments_in_range(
        &self,
        segments: &[String],
        kind: ScalaOwnerKind,
        declaration_range: Option<(usize, usize)>,
    ) -> ScalaNameResolution {
        let Some(simple) = segments.last().map(String::as_str) else {
            return ScalaNameResolution::Unresolved;
        };
        let binding = if segments.len() > 1 {
            segments[0].as_str()
        } else {
            simple
        };
        let mut matching_explicit_import = false;
        let mut resolved = Vec::new();
        for import in self.visible_imports() {
            if declaration_range.is_some_and(|(start, end)| {
                import.path.as_ref().is_none_or(|path| {
                    path.declaration_start_byte < start || path.declaration_start_byte >= end
                })
            }) {
                continue;
            }
            let Some(path) = scala_import_path(import) else {
                continue;
            };
            if import.is_wildcard
                || import
                    .identifier
                    .as_deref()
                    .unwrap_or_else(|| path.rsplit('.').next().unwrap_or(&path))
                    != binding
            {
                continue;
            }
            matching_explicit_import = true;
            let tail = &segments[1..];
            let candidate_tiers = if let Some(structured_path) = import.path.as_ref() {
                self.structured_import_type_candidate_tiers(structured_path, tail)
            } else {
                vec![
                    import_candidate_fq_names(&path, &self.package)
                        .into_iter()
                        .flat_map(|candidate| scala_nested_type_candidates(candidate, tail, true))
                        .collect(),
                ]
            };
            for candidates in candidate_tiers {
                match self.resolve_candidate_tier(candidates, kind) {
                    ScalaNameResolution::Resolved(owner) => {
                        resolved.push(owner);
                        break;
                    }
                    ScalaNameResolution::Ambiguous => return ScalaNameResolution::Ambiguous,
                    ScalaNameResolution::MissingExplicitImport
                    | ScalaNameResolution::Unresolved => {}
                }
            }
        }
        resolved.sort();
        resolved.dedup();
        match resolved.as_slice() {
            [owner] => ScalaNameResolution::Resolved(owner.clone()),
            [_, _, ..] => ScalaNameResolution::Ambiguous,
            [] if matching_explicit_import => ScalaNameResolution::MissingExplicitImport,
            [] => ScalaNameResolution::Unresolved,
        }
    }

    fn structured_import_type_candidate_tiers(
        &self,
        path: &StructuredImportPath,
        tail: &[String],
    ) -> Vec<Vec<String>> {
        let mut segments = path.segments.clone();
        segments.extend_from_slice(tail);
        let lexical_prefixes = if path.lexical_prefixes.is_empty() {
            self.package_prefixes.as_slice()
        } else {
            path.lexical_prefixes.as_slice()
        };
        let mut tiers = Vec::new();
        for lexical_package in lexical_prefixes
            .iter()
            .rev()
            .map(String::as_str)
            .chain(std::iter::once(""))
        {
            for package_len in (1..segments.len()).rev() {
                let relative_package = segments[..package_len].join(".");
                let package = if lexical_package.is_empty() {
                    relative_package
                } else {
                    format!("{lexical_package}.{relative_package}")
                };
                if !self.support.package_exists(&package) {
                    continue;
                }
                tiers.push(scala_nested_type_candidates(
                    package,
                    &segments[package_len..],
                    false,
                ));
                break;
            }
            // The import's leading segments may name an object/class in this
            // lexical package rather than a sub-package: `import
            // LocalScheduler.Activation` inside `package com.twitter.concurrent`
            // targets the nested `com.twitter.concurrent.LocalScheduler.Activation`,
            // where `LocalScheduler` is a singleton object, not a package. The
            // `package_exists` split above skips such a path; qualify the whole
            // segment chain under the lexical package as an owner nesting so the
            // same-file nested declaration resolves instead of drawing a false
            // "declaration is not indexed" boundary (issue #1126 twitter
            // `Activation`).
            if !lexical_package.is_empty() {
                tiers.push(scala_nested_type_candidates(
                    lexical_package.to_string(),
                    &segments,
                    false,
                ));
            }
        }
        tiers.push(scala_nested_type_candidates(
            String::new(),
            &segments,
            false,
        ));
        tiers
    }

    fn resolve_wildcard_singleton(&self, name: &str) -> ScalaNameResolution {
        let segments = [name.to_string()];
        let mut owners = Vec::new();
        let environment = self.wildcard_import_environment();
        if environment.ambiguous {
            return ScalaNameResolution::Ambiguous;
        }
        for import_owner in environment.owners {
            let singleton = import_owner.is_singleton();
            let candidates = scala_nested_type_candidates(import_owner.fqn, &segments, singleton);
            let outcome = self.resolve_candidate_tier(candidates, ScalaOwnerKind::SingletonObject);
            match outcome {
                ScalaNameResolution::Resolved(owner) => owners.push(owner),
                ScalaNameResolution::Ambiguous => return ScalaNameResolution::Ambiguous,
                ScalaNameResolution::MissingExplicitImport | ScalaNameResolution::Unresolved => {}
            }
        }
        owners.sort();
        owners.dedup();
        match owners.as_slice() {
            [] => self.resolve_direct_wildcard_singleton(name),
            [owner] => ScalaNameResolution::Resolved(owner.clone()),
            _ => ScalaNameResolution::Ambiguous,
        }
    }

    fn resolve_direct_wildcard_singleton(&self, name: &str) -> ScalaNameResolution {
        let mut owners = Vec::new();
        for import in self.visible_imports().filter(|import| import.is_wildcard) {
            let Some(path) = scala_import_path(import) else {
                continue;
            };
            let import_prefixes = import
                .path
                .as_ref()
                .map(|path| path.lexical_prefixes.as_slice())
                .filter(|prefixes| !prefixes.is_empty())
                .unwrap_or(&self.package_prefixes);
            let mut selected = Vec::new();
            for candidate in scala_import_path_candidates(&path, import_prefixes) {
                for owner in [candidate.clone(), format!("{candidate}$")] {
                    let nested = format!("{owner}.{name}$");
                    selected.extend(
                        self.support
                            .fqn(&nested)
                            .into_iter()
                            .filter(|unit| unit.is_class() && unit.fq_name() == nested)
                            .map(|unit| ScalaOwnerIdentity {
                                fqn: unit.fq_name(),
                                kind: ScalaOwnerKind::SingletonObject,
                                _declaration: unit,
                            }),
                    );
                }
                selected.sort();
                selected.dedup();
                if !selected.is_empty() {
                    break;
                }
            }
            if selected.len() > 1 {
                return ScalaNameResolution::Ambiguous;
            }
            owners.extend(selected);
        }
        owners.sort();
        owners.dedup();
        match owners.as_slice() {
            [] => ScalaNameResolution::Unresolved,
            [owner] => ScalaNameResolution::Resolved(owner.clone()),
            _ => ScalaNameResolution::Ambiguous,
        }
    }

    fn wildcard_import_environment(&self) -> ScalaWildcardImportEnvironment {
        let imports = self.visible_imports().cloned().collect::<Vec<_>>();
        resolve_scala_wildcard_import_environment(
            &imports,
            &self.package_prefixes,
            |declaration_start_byte| {
                scala_enclosing_template_owner_fq_names(
                    self.scala,
                    self.scala,
                    &self.file,
                    declaration_start_byte,
                )
            },
            |candidate| {
                let singleton_fqn = format!("{}$", candidate.trim_end_matches('$'));
                ScalaWildcardOwnerFacts {
                    package: self.support.package_exists(candidate),
                    stable_singleton: self
                        .support
                        .fqn(&singleton_fqn)
                        .into_iter()
                        .any(|unit| unit.is_class() && unit.fq_name() == singleton_fqn),
                }
            },
        )
    }

    fn resolve_candidate_tier(
        &self,
        mut candidates: Vec<String>,
        kind: ScalaOwnerKind,
    ) -> ScalaNameResolution {
        candidates.sort();
        candidates.dedup();
        let mut owners = Vec::new();
        for candidate in candidates {
            let exact = match kind {
                ScalaOwnerKind::Class => candidate.trim_end_matches('$').to_string(),
                ScalaOwnerKind::SingletonObject => {
                    if candidate.ends_with('$') {
                        candidate
                    } else {
                        format!("{candidate}$")
                    }
                }
                ScalaOwnerKind::TypeNamespace => candidate,
            };
            owners.extend(
                self.support
                    .fqn(&exact)
                    .into_iter()
                    .chain(
                        (matches!(kind, ScalaOwnerKind::Class | ScalaOwnerKind::TypeNamespace))
                            .then(|| self.support.fqn_in_language(&exact, Language::Java))
                            .into_iter()
                            .flatten(),
                    )
                    .filter(|unit| {
                        unit.fq_name() == exact
                            && (unit.is_class()
                                || (kind == ScalaOwnerKind::TypeNamespace
                                    && self.scala.is_type_alias(unit)))
                    })
                    .map(|unit| ScalaOwnerIdentity {
                        fqn: unit.fq_name(),
                        kind,
                        _declaration: unit,
                    }),
            );
        }
        owners.sort();
        owners.dedup();
        match owners.as_slice() {
            [] => ScalaNameResolution::Unresolved,
            [owner] => ScalaNameResolution::Resolved(owner.clone()),
            _ => ScalaNameResolution::Ambiguous,
        }
    }

    fn resolve_member(&self, raw: &str) -> Option<String> {
        let simple = raw.trim();
        if simple.is_empty() {
            return None;
        }
        let mut members = Vec::new();
        for import in self.visible_imports().filter(|import| !import.is_wildcard) {
            let Some(path) = import.path.as_ref() else {
                continue;
            };
            let Some((member, owner_segments)) = path.segments.split_last() else {
                continue;
            };
            let visible = import.identifier.as_deref().unwrap_or(member);
            if visible != simple {
                continue;
            }

            let prior_imports = self
                .imports
                .iter()
                .filter(|candidate| {
                    candidate.path.as_ref().is_some_and(|candidate_path| {
                        candidate_path.declaration_start_byte < path.declaration_start_byte
                    })
                })
                .cloned()
                .collect::<Vec<_>>();
            let qualifier_resolver = Self {
                scala: self.scala,
                support: self.support,
                file: self.file.clone(),
                package: path
                    .lexical_prefixes
                    .last()
                    .cloned()
                    .map(Arc::from)
                    .unwrap_or_else(|| Arc::clone(&self.package)),
                package_prefixes: if path.lexical_prefixes.is_empty() {
                    Arc::clone(&self.package_prefixes)
                } else {
                    Arc::new(path.lexical_prefixes.clone())
                },
                lexical_scopes: Arc::new(path.lexical_scopes.clone()),
                reference_byte: Some(path.declaration_start_byte),
                imports: Arc::new(prior_imports),
            };
            if !owner_segments.is_empty()
                && let ScalaNameResolution::Resolved(owner) = qualifier_resolver
                    .resolve_owner_segments(owner_segments, ScalaOwnerKind::SingletonObject)
            {
                members.extend(
                    self.support
                        .fqn_direct_children(&owner.fqn)
                        .into_iter()
                        .filter(|unit| unit.identifier() == member)
                        .filter(|unit| unit.is_function() || unit.is_field())
                        .filter(|unit| !self.scala.is_type_alias(unit))
                        .filter(|unit| {
                            self.scala.structural_parent_of(unit).as_ref()
                                == Some(&owner._declaration)
                        }),
                );
            }

            let flattened = path.render_segments(".");
            let import_prefixes = if path.lexical_prefixes.is_empty() {
                self.package_prefixes.as_slice()
            } else {
                path.lexical_prefixes.as_slice()
            };
            for candidate in scala_import_path_candidates(&flattened, import_prefixes) {
                members.extend(
                    self.support
                        .fqn(&candidate)
                        .into_iter()
                        .filter(|unit| unit.is_function() || unit.is_field())
                        .filter(|unit| !self.scala.is_type_alias(unit)),
                );
            }
        }
        sort_units(&mut members);
        members.dedup();
        let fqn = members.first()?.fq_name();
        members
            .iter()
            .all(|member| member.fq_name() == fqn)
            .then_some(fqn)
    }

    fn visible_extension_methods(&self, member: &str) -> Vec<ForwardScalaExtensionMethod> {
        let mut units = Vec::new();
        for import in self.visible_imports() {
            let Some(path) = scala_import_path(import) else {
                continue;
            };
            if import.is_wildcard {
                for owner in import_candidate_owner_fq_names(&path, &self.package) {
                    units.extend(
                        self.support
                            .fqn_direct_children(&owner)
                            .into_iter()
                            .filter(|unit| unit.identifier() == member),
                    );
                }
            } else if import
                .identifier
                .as_deref()
                .unwrap_or_else(|| path.rsplit('.').next().unwrap_or(&path))
                == member
            {
                for candidate in import_candidate_fq_names(&path, &self.package) {
                    units.extend(self.support.fqn(&candidate));
                }
            }
        }
        units.sort();
        units.dedup();
        units
            .into_iter()
            .filter(|unit| unit.is_function() || unit.is_field())
            .filter_map(|unit| {
                let signature = unit
                    .signature()
                    .map(str::to_string)
                    .or_else(|| self.scala.signatures(&unit).into_iter().next())?;
                signature
                    .starts_with("extension ")
                    .then(|| ForwardScalaExtensionMethod {
                        fqn: unit.fq_name(),
                        receiver_type: resolved_extension_receiver_type(
                            self.scala, &unit, &signature,
                        ),
                    })
            })
            .collect()
    }
}

#[derive(Debug)]
pub(crate) enum ScalaTypeLookupResolution {
    Type {
        fqn: String,
        target_kind: TypeLookupTargetKind,
    },
    InappropriateSymbolContext,
}

pub(crate) fn scala_type_lookup_resolution(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    site: &ResolvedReferenceSite,
) -> Option<ScalaTypeLookupResolution> {
    let scala = resolve_analyzer::<ScalaAnalyzer>(analyzer)?;
    let batch = ScalaDefinitionContext {
        file: file.clone(),
        package: Arc::from(scala_package_name_of(scala, file).unwrap_or_default()),
        imports: Arc::new(scala.import_info_of(file)),
    };
    scala_type_lookup_resolution_with_context(
        analyzer, scala, support, &batch, file, source, root, site, None,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn scala_type_lookup_resolution_in_session(
    analyzer: &dyn IAnalyzer,
    support: &ScalaDefinitionProvider<'_>,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    site: &ResolvedReferenceSite,
    session: &ResolutionSession,
) -> Option<ScalaTypeLookupResolution> {
    let scala = resolve_analyzer::<ScalaAnalyzer>(analyzer)?;
    let batch = bounded_scala_definition_context(scala, file, session);
    let walk = ScalaBoundedWalk::new(session);
    bounded_scala_type_lookup_resolution(scala, support, &batch, file, source, root, site, &walk)
}

#[allow(clippy::too_many_arguments)]
fn scala_type_lookup_resolution_with_context(
    analyzer: &dyn IAnalyzer,
    scala: &ScalaAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    batch: &ScalaDefinitionContext,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    site: &ResolvedReferenceSite,
    session: Option<&ResolutionSession>,
) -> Option<ScalaTypeLookupResolution> {
    let node = scala_smallest_named_node_covering(
        session,
        root,
        site.focus_start_byte,
        site.focus_end_byte,
    )?;
    if !scala_charge_ancestor_path(session, node) {
        return None;
    }
    let (package_prefixes, lexical_scopes) =
        scala_lexical_context_at(session, root, source, node, site.focus_start_byte)?;
    let resolver = ScalaNameResolver::for_batch(scala, support, batch).with_lexical_context(
        package_prefixes,
        lexical_scopes,
        site.focus_start_byte,
    );
    let ctx = ScalaLookupCtx {
        scala,
        analyzer,
        support,
        file,
        source,
        session,
    };
    scala_type_lookup_node_fqn(ctx, &resolver, root, node)
}

fn bounded_scala_definition_context(
    scala: &ScalaAnalyzer,
    file: &ProjectFile,
    session: &ResolutionSession,
) -> ScalaDefinitionContext {
    let package = session
        .query_limited_rows(|limit| scala.namespace_of_file_limited(file, limit))
        .into_iter()
        .next()
        .unwrap_or_default();
    let imports = session.query_limited_rows(|limit| scala.import_info_of_limited(file, limit));
    ScalaDefinitionContext {
        file: file.clone(),
        package: Arc::from(package),
        imports: Arc::new(imports),
    }
}

pub(super) fn resolve_scala(
    analyzer: &dyn IAnalyzer,
    context: &mut DefinitionBatchContext<'_>,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
) -> DefinitionLookupOutcome {
    let Some(scala) = resolve_analyzer::<ScalaAnalyzer>(analyzer) else {
        return no_definition(
            "scala_analyzer_unavailable",
            "Scala analyzer is unavailable",
        );
    };
    let batch = context.scala_context(scala, file);
    let support = context.bounded_support();
    resolve_scala_with_context(
        analyzer, scala, support, &batch, file, source, tree, site, None,
    )
}

pub(crate) fn resolve_scala_bounded(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
    budget: ReceiverAnalysisBudget,
    cancellation: Option<&CancellationToken>,
) -> BoundedResolution<DefinitionLookupOutcome> {
    let session = ResolutionSession::bounded(budget, cancellation);
    let Some(scala) = resolve_analyzer::<ScalaAnalyzer>(analyzer) else {
        return session.finish(no_definition(
            "scala_analyzer_unavailable",
            "Scala analyzer is unavailable",
        ));
    };
    let support = ScalaDefinitionProvider::new(scala, &session);
    let batch = bounded_scala_definition_context(scala, file, &session);
    let walk = ScalaBoundedWalk::new(&session);
    let outcome = bounded_scala_definition_resolution(
        scala, &support, &batch, file, source, tree, site, &walk,
    );
    session.finish(outcome)
}

struct ScalaBoundedWalk<'a> {
    session: &'a ResolutionSession,
    steps: Cell<usize>,
    #[cfg(test)]
    cancellation: Option<(CancellationToken, usize)>,
}

impl<'a> ScalaBoundedWalk<'a> {
    fn new(session: &'a ResolutionSession) -> Self {
        Self {
            session,
            steps: Cell::new(0),
            #[cfg(test)]
            cancellation: None,
        }
    }

    #[cfg(test)]
    fn cancelling_after(
        session: &'a ResolutionSession,
        cancellation: CancellationToken,
        steps: usize,
    ) -> Self {
        Self {
            session,
            steps: Cell::new(0),
            cancellation: Some((cancellation, steps)),
        }
    }

    fn step(&self) -> bool {
        let next = self.steps.get().saturating_add(1);
        self.steps.set(next);
        #[cfg(test)]
        if let Some((cancellation, cancel_after)) = &self.cancellation
            && next == *cancel_after
        {
            cancellation.cancel();
        }
        self.session.scope_step()
    }
}

struct BoundedScalaCtx<'a, 'tree> {
    provider: &'a ScalaDefinitionProvider<'a>,
    batch: &'a ScalaDefinitionContext,
    file: &'a ProjectFile,
    source: &'a str,
    root: Node<'tree>,
    package_prefixes: Vec<String>,
    lexical_scopes: Vec<StructuredImportScope>,
    reference_byte: usize,
    walk: &'a ScalaBoundedWalk<'a>,
}

#[allow(clippy::too_many_arguments)]
fn bounded_scala_type_lookup_resolution(
    _scala: &ScalaAnalyzer,
    provider: &ScalaDefinitionProvider<'_>,
    batch: &ScalaDefinitionContext,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    site: &ResolvedReferenceSite,
    walk: &ScalaBoundedWalk<'_>,
) -> Option<ScalaTypeLookupResolution> {
    let node = bounded_scala_smallest_named_node_covering(
        walk,
        root,
        site.focus_start_byte,
        site.focus_end_byte,
    )?;
    let (package_prefixes, lexical_scopes) =
        bounded_scala_lexical_context(walk, root, source, node, site.focus_start_byte)?;
    let ctx = BoundedScalaCtx {
        provider,
        batch,
        file,
        source,
        root,
        package_prefixes,
        lexical_scopes,
        reference_byte: site.focus_start_byte,
        walk,
    };
    let declaration = bounded_scala_expression_type(&ctx, node, site.focus_start_byte)?;
    Some(ScalaTypeLookupResolution::Type {
        fqn: declaration.fq_name(),
        target_kind: TypeLookupTargetKind::ValueExpression,
    })
}

#[allow(clippy::too_many_arguments)]
fn bounded_scala_definition_resolution(
    _scala: &ScalaAnalyzer,
    provider: &ScalaDefinitionProvider<'_>,
    batch: &ScalaDefinitionContext,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
    walk: &ScalaBoundedWalk<'_>,
) -> DefinitionLookupOutcome {
    let Some(tree) = tree else {
        return no_definition("scala_parse_failed", "Scala source could not be parsed");
    };
    let root = tree.root_node();
    let Some(node) = bounded_scala_smallest_named_node_covering(
        walk,
        root,
        site.focus_start_byte,
        site.focus_end_byte,
    ) else {
        return no_definition(
            "scala_receiver_budget_exhausted",
            "Scala syntax traversal exceeded the receiver-resolution budget",
        );
    };
    let Some((package_prefixes, lexical_scopes)) =
        bounded_scala_lexical_context(walk, root, source, node, site.focus_start_byte)
    else {
        return no_definition(
            "scala_receiver_budget_exhausted",
            "Scala lexical-context traversal exceeded the receiver-resolution budget",
        );
    };
    let ctx = BoundedScalaCtx {
        provider,
        batch,
        file,
        source,
        root,
        package_prefixes,
        lexical_scopes,
        reference_byte: site.focus_start_byte,
        walk,
    };

    if let Some(reference) = bounded_scala_member_reference(&ctx, node) {
        let Some(owner) = bounded_scala_expression_type(
            &ctx,
            reference.receiver,
            reference.receiver.start_byte(),
        ) else {
            return no_definition(
                SCALA_UNSUPPORTED_RECEIVER,
                format!(
                    "receiver for Scala member `{}` has no bounded structured type",
                    scala_node_text(reference.member, source).trim()
                ),
            );
        };
        let member_name = scala_node_text(reference.member, source).trim();
        let direct = if reference.receiver_scope == ScalaBoundedReceiverScope::Super {
            ScalaBoundedMemberCandidates::NoMatch
        } else {
            bounded_scala_applicable_direct_members(&ctx, &owner, member_name, reference.call_shape)
        };
        match direct {
            ScalaBoundedMemberCandidates::Found {
                candidates,
                overload_ambiguous: true,
            } => {
                return bounded_scala_ambiguous_candidates(
                    candidates,
                    format!(
                        "Scala member `{member_name}` has multiple applicable overloads on `{}`",
                        owner.fq_name()
                    ),
                );
            }
            ScalaBoundedMemberCandidates::Found {
                candidates,
                overload_ambiguous: false,
            } => return candidates_outcome(candidates),
            ScalaBoundedMemberCandidates::Unknown => {
                return no_definition(
                    SCALA_UNSUPPORTED_RECEIVER,
                    format!(
                        "Scala member `{member_name}` on `{}` has incomplete callable applicability metadata",
                        owner.fq_name()
                    ),
                );
            }
            ScalaBoundedMemberCandidates::NoMatch => {}
        }
        match bounded_scala_inherited_members(&ctx, &owner, member_name, reference.call_shape) {
            ScalaBoundedMemberCandidates::Found {
                candidates,
                overload_ambiguous: true,
            } => {
                return bounded_scala_ambiguous_candidates(
                    candidates,
                    format!(
                        "Scala inherited member `{member_name}` has multiple applicable overloads for `{}`",
                        owner.fq_name()
                    ),
                );
            }
            ScalaBoundedMemberCandidates::Found {
                candidates,
                overload_ambiguous: false,
            } => return candidates_outcome(candidates),
            ScalaBoundedMemberCandidates::Unknown => {
                return no_definition(
                    SCALA_UNSUPPORTED_RECEIVER,
                    format!(
                        "Scala hierarchy for `{}` is incomplete while resolving inherited member `{member_name}`",
                        owner.fq_name()
                    ),
                );
            }
            ScalaBoundedMemberCandidates::NoMatch => {}
        }
        if reference.receiver_scope == ScalaBoundedReceiverScope::Super {
            return no_definition(
                SCALA_UNSUPPORTED_RECEIVER,
                format!(
                    "explicit Scala `super` scope for `{}` has no applicable inherited member `{member_name}`",
                    owner.fq_name()
                ),
            );
        }
        match bounded_scala_extension_members(
            &ctx,
            reference.member,
            &owner,
            member_name,
            reference.call_shape,
        ) {
            ScalaBoundedMemberCandidates::Found {
                candidates,
                overload_ambiguous: true,
            } => {
                return bounded_scala_ambiguous_candidates(
                    candidates,
                    format!(
                        "Scala extension member `{member_name}` has multiple applicable overloads for `{}`",
                        owner.fq_name()
                    ),
                );
            }
            ScalaBoundedMemberCandidates::Found {
                candidates,
                overload_ambiguous: false,
            } => return candidates_outcome(candidates),
            ScalaBoundedMemberCandidates::Unknown => {
                return no_definition(
                    SCALA_UNSUPPORTED_RECEIVER,
                    format!(
                        "Scala extension member `{member_name}` has unresolved visibility or applicability for `{}`",
                        owner.fq_name()
                    ),
                );
            }
            ScalaBoundedMemberCandidates::NoMatch => {}
        }
        return no_definition(
            SCALA_UNSUPPORTED_RECEIVER,
            format!(
                "receiver for Scala member `{member_name}` resolved to `{}`, but no applicable direct, inherited, or exact extension member was found",
                owner.fq_name()
            ),
        );
    }

    if bounded_scala_is_type_node(node)
        && let Some(declaration) = bounded_scala_resolve_type_node(&ctx, node)
    {
        return candidates_outcome(vec![declaration]);
    }

    if matches!(node.kind(), "identifier" | "operator_identifier")
        && let Some(owner) = bounded_scala_nearest_enclosing_owner(&ctx, node)
    {
        let name = scala_node_text(node, source).trim();
        let candidates = bounded_scala_direct_members(&ctx, &owner, name);
        if !candidates.is_empty() {
            return candidates_outcome(candidates);
        }
    }

    no_definition(
        "no_indexed_definition",
        format!(
            "`{}` did not resolve through bounded structured Scala lookup",
            site.text
        ),
    )
}

fn bounded_scala_smallest_named_node_covering<'tree>(
    walk: &ScalaBoundedWalk<'_>,
    mut node: Node<'tree>,
    start: usize,
    end: usize,
) -> Option<Node<'tree>> {
    if !walk.step() || node.start_byte() > start || node.end_byte() < end {
        return None;
    }
    loop {
        let mut containing = None;
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if !walk.step() {
                return None;
            }
            if child.start_byte() <= start && child.end_byte() >= end {
                containing = Some(child);
                break;
            }
        }
        match containing {
            Some(child) => node = child,
            None => return Some(node),
        }
    }
}

fn bounded_scala_lexical_context(
    walk: &ScalaBoundedWalk<'_>,
    root: Node<'_>,
    source: &str,
    reference_node: Node<'_>,
    reference_byte: usize,
) -> Option<(Vec<String>, Vec<StructuredImportScope>)> {
    let mut inspect = |_: Node<'_>| walk.step();
    let package_prefixes =
        scala_package_prefixes_at_checked(root, source, reference_byte, &mut inspect)?;
    let lexical_scopes =
        scala_lexical_scope_path_checked(reference_node, |_: Node<'_>| walk.step())?;
    Some((package_prefixes, lexical_scopes))
}

#[derive(Clone, Copy)]
enum ScalaBoundedCallShape {
    Access,
    Ordinary(usize),
    Unsupported,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ScalaBoundedReceiverScope {
    Ordinary,
    Super,
}

#[derive(Clone, Copy)]
struct ScalaBoundedMemberReference<'tree> {
    receiver: Node<'tree>,
    member: Node<'tree>,
    call_shape: ScalaBoundedCallShape,
    receiver_scope: ScalaBoundedReceiverScope,
}

fn bounded_scala_member_reference<'tree>(
    ctx: &BoundedScalaCtx<'_, 'tree>,
    mut node: Node<'tree>,
) -> Option<ScalaBoundedMemberReference<'tree>> {
    loop {
        match node.kind() {
            "field_expression" => {
                let receiver = node.child_by_field_name("value")?;
                if !ctx.walk.step() {
                    return None;
                }
                let member = node.child_by_field_name("field")?;
                if !ctx.walk.step() {
                    return None;
                }
                let call_shape = bounded_scala_member_call_shape(ctx, node)?;
                let receiver_scope = if scala_node_text(receiver, ctx.source).trim() == "super" {
                    ScalaBoundedReceiverScope::Super
                } else {
                    ScalaBoundedReceiverScope::Ordinary
                };
                return Some(ScalaBoundedMemberReference {
                    receiver,
                    member,
                    call_shape,
                    receiver_scope,
                });
            }
            "infix_expression" => {
                let member = node.child_by_field_name("operator")?;
                if !ctx.walk.step() {
                    return None;
                }
                let right_associative = scala_node_text(member, ctx.source).trim().ends_with(':');
                let receiver =
                    node.child_by_field_name(if right_associative { "right" } else { "left" })?;
                if !ctx.walk.step() {
                    return None;
                }
                return Some(ScalaBoundedMemberReference {
                    receiver,
                    member,
                    call_shape: ScalaBoundedCallShape::Ordinary(1),
                    receiver_scope: ScalaBoundedReceiverScope::Ordinary,
                });
            }
            "postfix_expression" => {
                let mut member = None;
                let mut children = Vec::new();
                let mut cursor = node.walk();
                for child in node.named_children(&mut cursor) {
                    if !ctx.walk.step() {
                        return None;
                    }
                    if matches!(child.kind(), "identifier" | "operator_identifier") {
                        member = Some(child);
                    }
                    children.push(child);
                }
                let member = member?;
                let receiver = children
                    .into_iter()
                    .find(|child| child.end_byte() <= member.start_byte())?;
                return Some(ScalaBoundedMemberReference {
                    receiver,
                    member,
                    call_shape: ScalaBoundedCallShape::Ordinary(0),
                    receiver_scope: ScalaBoundedReceiverScope::Ordinary,
                });
            }
            _ => {}
        }
        let parent = node.parent()?;
        if !ctx.walk.step() {
            return None;
        }
        if !matches!(
            parent.kind(),
            "call_expression"
                | "generic_function"
                | "field_expression"
                | "infix_expression"
                | "postfix_expression"
        ) {
            return None;
        }
        node = parent;
    }
}

fn bounded_scala_member_call_shape(
    ctx: &BoundedScalaCtx<'_, '_>,
    field: Node<'_>,
) -> Option<ScalaBoundedCallShape> {
    let mut function = field;
    let Some(mut parent) = function.parent() else {
        return Some(ScalaBoundedCallShape::Access);
    };
    if !ctx.walk.step() {
        return None;
    }
    if parent.kind() == "generic_function" {
        let generic_function = parent.child_by_field_name("function")?;
        if !ctx.walk.step() {
            return None;
        }
        if generic_function != function {
            return Some(ScalaBoundedCallShape::Access);
        }
        function = parent;
        let Some(call_parent) = function.parent() else {
            return Some(ScalaBoundedCallShape::Access);
        };
        if !ctx.walk.step() {
            return None;
        }
        parent = call_parent;
    }
    if parent.kind() != "call_expression" {
        return Some(ScalaBoundedCallShape::Access);
    }
    let applied = parent.child_by_field_name("function")?;
    if !ctx.walk.step() {
        return None;
    }
    if applied != function {
        return Some(ScalaBoundedCallShape::Access);
    }
    let arguments = parent.child_by_field_name("arguments")?;
    if !ctx.walk.step() {
        return None;
    }
    if arguments.kind() != "arguments" {
        return Some(
            if matches!(arguments.kind(), "block" | "case_block" | "colon_argument") {
                ScalaBoundedCallShape::Ordinary(1)
            } else {
                ScalaBoundedCallShape::Unsupported
            },
        );
    }
    let mut arity = 0usize;
    let mut unsupported = false;
    let mut cursor = arguments.walk();
    for argument in arguments.named_children(&mut cursor) {
        if !ctx.walk.step() {
            return None;
        }
        unsupported |= is_scala_named_argument_assignment(argument);
        arity = arity.checked_add(1)?;
    }
    Some(if unsupported {
        ScalaBoundedCallShape::Unsupported
    } else {
        ScalaBoundedCallShape::Ordinary(arity)
    })
}

#[derive(Clone, Copy)]
enum BoundedScalaBinding<'tree> {
    DeclaredType(Node<'tree>),
    Initializer(Node<'tree>),
}

#[derive(Clone, Copy)]
struct BoundedScalaBindingFact<'tree> {
    declaration_start: usize,
    binding: BoundedScalaBinding<'tree>,
}

fn bounded_scala_expression_type<'tree>(
    ctx: &BoundedScalaCtx<'_, 'tree>,
    mut expression: Node<'tree>,
    mut cutoff_start: usize,
) -> Option<CodeUnit> {
    // Members are collected outside-in. Redirecting an identifier to its
    // initializer keeps walking the same explicit state machine, so even a
    // very long chain of local aliases never consumes the Rust call stack.
    let mut members = Vec::new();
    let mut bindings = None;
    let mut first_member_scope = ScalaBoundedReceiverScope::Ordinary;
    let mut owner = loop {
        if !ctx.walk.step() {
            return None;
        }
        match expression.kind() {
            "call_expression" => {
                let function = expression
                    .child_by_field_name("function")
                    .or_else(|| expression.named_child(0))?;
                if !ctx.walk.step() {
                    return None;
                }
                match function.kind() {
                    "field_expression" => {
                        let member = function.child_by_field_name("field")?;
                        if !ctx.walk.step() {
                            return None;
                        }
                        let name = scala_node_text(member, ctx.source).trim();
                        if name.is_empty() {
                            return None;
                        }
                        members.push(name.to_string());
                        expression = function.child_by_field_name("value")?;
                        if !ctx.walk.step() {
                            return None;
                        }
                    }
                    "identifier" | "operator_identifier" => {
                        let name = scala_node_text(function, ctx.source).trim();
                        if name.is_empty() {
                            return None;
                        }
                        members.push(name.to_string());
                        break bounded_scala_nearest_enclosing_owner(ctx, function)?;
                    }
                    "instance_expression" => {
                        break bounded_scala_constructed_type(ctx, function)?;
                    }
                    _ => return None,
                }
            }
            "identifier" | "operator_identifier" | "type_identifier" => {
                let name = scala_node_text(expression, ctx.source).trim();
                if matches!(name, "this" | "super") {
                    if name == "super" {
                        first_member_scope = ScalaBoundedReceiverScope::Super;
                    }
                    break bounded_scala_nearest_enclosing_owner(ctx, expression)?;
                }
                if bindings.is_none() {
                    bindings = Some(bounded_scala_bindings_before(ctx, cutoff_start)?);
                }
                if let Some(binding) = bindings.as_ref().and_then(|bindings| {
                    bounded_scala_visible_binding(bindings, name, cutoff_start)
                }) {
                    match binding {
                        BoundedScalaBinding::DeclaredType(type_node) => {
                            break bounded_scala_resolve_type_node(ctx, type_node)?;
                        }
                        BoundedScalaBinding::Initializer(initializer) => {
                            if initializer.start_byte() >= cutoff_start {
                                return None;
                            }
                            cutoff_start = initializer.start_byte();
                            expression = initializer;
                            continue;
                        }
                    }
                }
                break bounded_scala_resolve_segments(ctx, &[name.to_string()], true)
                    .or_else(|| bounded_scala_resolve_segments(ctx, &[name.to_string()], false))?;
            }
            "instance_expression" => {
                break bounded_scala_constructed_type(ctx, expression)?;
            }
            kind if bounded_scala_is_type_kind(kind) => {
                break bounded_scala_resolve_type_node(ctx, expression)?;
            }
            "parenthesized_expression" => {
                let mut cursor = expression.walk();
                let mut children = expression.named_children(&mut cursor);
                let child = children.next()?;
                if children.next().is_some() || !ctx.walk.step() {
                    return None;
                }
                expression = child;
            }
            _ => return None,
        }
    };
    for (index, member) in members.iter().rev().enumerate() {
        let receiver_scope = if index == 0 {
            first_member_scope
        } else {
            ScalaBoundedReceiverScope::Ordinary
        };
        owner = bounded_scala_member_return_type(ctx, &owner, member, receiver_scope)?;
    }
    Some(owner)
}

fn bounded_scala_member_return_type(
    ctx: &BoundedScalaCtx<'_, '_>,
    owner: &CodeUnit,
    member: &str,
    receiver_scope: ScalaBoundedReceiverScope,
) -> Option<CodeUnit> {
    let selected = if receiver_scope == ScalaBoundedReceiverScope::Super {
        bounded_scala_inherited_members(ctx, owner, member, ScalaBoundedCallShape::Access)
    } else {
        match bounded_scala_applicable_direct_members(
            ctx,
            owner,
            member,
            ScalaBoundedCallShape::Access,
        ) {
            ScalaBoundedMemberCandidates::NoMatch => {
                bounded_scala_inherited_members(ctx, owner, member, ScalaBoundedCallShape::Access)
            }
            direct => direct,
        }
    };
    let candidates = match selected {
        ScalaBoundedMemberCandidates::Found {
            candidates,
            overload_ambiguous: false,
        } => candidates
            .into_iter()
            .filter(CodeUnit::is_function)
            .collect::<Vec<_>>(),
        ScalaBoundedMemberCandidates::NoMatch
        | ScalaBoundedMemberCandidates::Found {
            overload_ambiguous: true,
            ..
        }
        | ScalaBoundedMemberCandidates::Unknown => return None,
    };
    let mut resolved = Vec::new();
    for candidate in candidates {
        if !ctx.walk.step() {
            return None;
        }
        let metadata = ctx.provider.signature_metadata(&candidate);
        if metadata.is_empty() {
            return None;
        }
        for signature in metadata {
            if !ctx.walk.step() || signature.bare_return_type_parameter().is_some() {
                return None;
            }
            let identity = signature.return_type_identity()?;
            let name = identity.nominal_name_with(|| ctx.walk.step())?;
            resolved.push(bounded_scala_resolve_metadata_type(ctx, &candidate, name)?);
        }
    }
    sort_units(&mut resolved);
    resolved.dedup();
    match resolved.as_slice() {
        [declaration] => Some(declaration.clone()),
        _ => None,
    }
}

fn bounded_scala_resolve_metadata_type(
    ctx: &BoundedScalaCtx<'_, '_>,
    owner: &CodeUnit,
    name: &crate::analyzer::StructuredTypeName,
) -> Option<CodeUnit> {
    if name.path().is_empty() {
        return None;
    }

    if name.is_absolute() {
        return bounded_scala_metadata_type_tier(
            ctx,
            scala_nested_type_candidates(String::new(), name.path(), false),
        )
        .unique();
    }

    // Lexically enclosing types are the first exact tier. The callable's
    // parser-derived scope is persisted with its signature, so an unrelated
    // same-file declaration can never enter this lookup by identifier alone.
    for depth in (1..=name.lexical_scope().len()).rev() {
        if !ctx.walk.step() {
            return None;
        }
        let mut prefix = Vec::with_capacity(depth.saturating_add(1));
        if !owner.package_name().is_empty() {
            prefix.push(owner.package_name().to_string());
        };
        prefix.extend_from_slice(&name.lexical_scope()[..depth]);
        match bounded_scala_metadata_type_tier(
            ctx,
            scala_nested_type_candidates(prefix.join("."), name.path(), false),
        ) {
            ScalaMetadataTypeTier::Empty => {}
            ScalaMetadataTypeTier::Unique(declaration) => return Some(declaration),
            ScalaMetadataTypeTier::Ambiguous => return None,
        };
    }

    let owner_start = ctx
        .provider
        .ranges(owner)
        .into_iter()
        .map(|range| range.start_byte)
        .min()?;
    let mut explicit_claim = false;
    let mut imported = Vec::new();
    let mut visible_wildcard = false;
    for import in ctx.provider.imports(owner.source()) {
        if !ctx.walk.step() {
            return None;
        }
        if !bounded_scala_metadata_import_visible(&import, owner, owner_start) {
            continue;
        }
        let Some(path) = import.path.as_ref() else {
            continue;
        };
        if import.is_wildcard {
            visible_wildcard = true;
            continue;
        }
        let Some(imported_name) = path.segments.last() else {
            continue;
        };
        if import.identifier.as_deref().unwrap_or(imported_name) != name.path()[0] {
            continue;
        }
        explicit_claim = true;
        let mut imported_path = path.segments.clone();
        imported_path.extend_from_slice(&name.path()[1..]);

        let mut selected = ScalaMetadataTypeTier::Empty;
        for prefix in path
            .lexical_prefixes
            .iter()
            .rev()
            .map(String::as_str)
            .chain(std::iter::once(""))
        {
            if !ctx.walk.step() {
                return None;
            }
            selected = bounded_scala_metadata_type_tier(
                ctx,
                scala_nested_type_candidates(prefix.to_string(), &imported_path, false),
            );
            if !matches!(selected, ScalaMetadataTypeTier::Empty) {
                break;
            }
        }
        match selected {
            ScalaMetadataTypeTier::Empty => {}
            ScalaMetadataTypeTier::Unique(declaration) => imported.push(declaration),
            ScalaMetadataTypeTier::Ambiguous => return None,
        }
    }
    if explicit_claim {
        sort_units(&mut imported);
        imported.dedup();
        return match imported.as_slice() {
            [declaration] => Some(declaration.clone()),
            _ => None,
        };
    }

    // A wildcard can introduce an identity that is absent from persisted
    // evidence. Do not silently prefer a package/global spelling across it.
    if visible_wildcard {
        return None;
    }

    if !owner.package_name().is_empty() {
        match bounded_scala_metadata_type_tier(
            ctx,
            scala_nested_type_candidates(owner.package_name().to_string(), name.path(), false),
        ) {
            ScalaMetadataTypeTier::Empty => {}
            ScalaMetadataTypeTier::Unique(declaration) => return Some(declaration),
            ScalaMetadataTypeTier::Ambiguous => return None,
        }
    }

    // Qualified paths and declarations in the empty package may name a global
    // declaration directly. A simple name in a non-empty package needs
    // `_root_` to cross that boundary.
    if name.path().len() > 1 || owner.package_name().is_empty() {
        return bounded_scala_metadata_type_tier(
            ctx,
            scala_nested_type_candidates(String::new(), name.path(), false),
        )
        .unique();
    }
    None
}

fn bounded_scala_metadata_import_visible(
    import: &ImportInfo,
    owner: &CodeUnit,
    owner_start: usize,
) -> bool {
    let Some(path) = import.path.as_ref() else {
        return true;
    };
    path.declaration_start_byte <= owner_start
        && (path.lexical_prefixes.is_empty()
            || path
                .lexical_prefixes
                .last()
                .is_some_and(|prefix| prefix == owner.package_name()))
        && path
            .lexical_scopes
            .iter()
            .all(|scope| scope.start_byte <= owner_start && owner_start <= scope.end_byte)
}

enum ScalaMetadataTypeTier {
    Empty,
    Unique(CodeUnit),
    Ambiguous,
}

impl ScalaMetadataTypeTier {
    fn unique(self) -> Option<CodeUnit> {
        match self {
            Self::Unique(declaration) => Some(declaration),
            Self::Empty | Self::Ambiguous => None,
        }
    }
}

fn bounded_scala_metadata_type_tier(
    ctx: &BoundedScalaCtx<'_, '_>,
    mut fqns: Vec<String>,
) -> ScalaMetadataTypeTier {
    fqns.sort();
    fqns.dedup();
    let mut declarations = Vec::new();
    for fqn in fqns {
        if !ctx.walk.step() {
            return ScalaMetadataTypeTier::Ambiguous;
        }
        declarations.extend(
            ctx.provider
                .fqn(&fqn)
                .into_iter()
                .filter(|unit| unit.is_class() && unit.fq_name() == fqn),
        );
    }
    sort_units(&mut declarations);
    declarations.dedup();
    match declarations.as_slice() {
        [] => ScalaMetadataTypeTier::Empty,
        [declaration] => ScalaMetadataTypeTier::Unique(declaration.clone()),
        _ => ScalaMetadataTypeTier::Ambiguous,
    }
}

fn bounded_scala_constructed_type(
    ctx: &BoundedScalaCtx<'_, '_>,
    mut node: Node<'_>,
) -> Option<CodeUnit> {
    while node.kind() == "call_expression" {
        if !ctx.walk.step() {
            return None;
        }
        node = node.child_by_field_name("function")?;
    }
    if node.kind() != "instance_expression" {
        return None;
    }
    let mut type_node = None;
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if !ctx.walk.step() {
            return None;
        }
        if matches!(
            child.kind(),
            "arguments" | "template_body" | "block" | "indented_block"
        ) {
            continue;
        }
        if type_node.replace(child).is_some() {
            return None;
        }
    }
    let type_node = type_node?;
    if matches!(
        type_node.kind(),
        "compound_type" | "infix_type" | "intersection_type" | "with_type"
    ) {
        return None;
    }
    bounded_scala_resolve_type_node(ctx, type_node)
}

fn bounded_scala_bindings_before<'tree>(
    ctx: &BoundedScalaCtx<'_, 'tree>,
    cutoff_start: usize,
) -> Option<HashMap<String, Vec<BoundedScalaBindingFact<'tree>>>> {
    let mut stack = vec![ctx.root];
    let mut bindings = HashMap::<String, Vec<BoundedScalaBindingFact<'tree>>>::new();
    while let Some(node) = stack.pop() {
        if !ctx.walk.step() {
            return None;
        }
        if node.start_byte() >= cutoff_start {
            continue;
        }
        let enters_scope = SCALA_SCOPE_NODES.contains(&node.kind());
        let contains_cutoff = node.start_byte() <= cutoff_start && cutoff_start < node.end_byte();
        if enters_scope && !contains_cutoff {
            continue;
        }
        match node.kind() {
            "parameter" | "class_parameter" => {
                let name_node = node.child_by_field_name("name");
                if let Some(name_node) = name_node {
                    if !ctx.walk.step() {
                        return None;
                    }
                    let name = scala_node_text(name_node, ctx.source).trim();
                    if !name.is_empty()
                        && let Some(type_node) = node.child_by_field_name("type")
                    {
                        if !ctx.walk.step() {
                            return None;
                        }
                        bindings.entry(name.to_string()).or_default().push(
                            BoundedScalaBindingFact {
                                declaration_start: node.start_byte(),
                                binding: BoundedScalaBinding::DeclaredType(type_node),
                            },
                        );
                    }
                }
            }
            "val_definition" | "var_definition" => {
                if let Some(pattern) = node.child_by_field_name("pattern") {
                    if !ctx.walk.step() {
                        return None;
                    }
                    let binding = if let Some(type_node) = node.child_by_field_name("type") {
                        if !ctx.walk.step() {
                            return None;
                        }
                        Some(BoundedScalaBinding::DeclaredType(type_node))
                    } else if let Some(value) = node.child_by_field_name("value") {
                        if !ctx.walk.step() {
                            return None;
                        }
                        Some(BoundedScalaBinding::Initializer(value))
                    } else {
                        None
                    };
                    if let Some(binding) = binding {
                        for name in bounded_scala_pattern_names(ctx, pattern)? {
                            bindings
                                .entry(name)
                                .or_default()
                                .push(BoundedScalaBindingFact {
                                    declaration_start: node.start_byte(),
                                    binding,
                                });
                        }
                    }
                }
            }
            _ => {}
        }
        let mut children = Vec::new();
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if !ctx.walk.step() {
                return None;
            }
            if child.start_byte() >= cutoff_start {
                break;
            }
            children.push(child);
        }
        children.reverse();
        stack.extend(children);
    }
    Some(bindings)
}

fn bounded_scala_visible_binding<'tree>(
    bindings: &HashMap<String, Vec<BoundedScalaBindingFact<'tree>>>,
    name: &str,
    cutoff_start: usize,
) -> Option<BoundedScalaBinding<'tree>> {
    bindings
        .get(name)?
        .iter()
        .rev()
        .find_map(|fact| (fact.declaration_start < cutoff_start).then_some(fact.binding))
}

fn bounded_scala_pattern_names(
    ctx: &BoundedScalaCtx<'_, '_>,
    pattern: Node<'_>,
) -> Option<Vec<String>> {
    let mut stack = vec![pattern];
    let mut names = Vec::new();
    while let Some(node) = stack.pop() {
        if !ctx.walk.step() {
            return None;
        }
        if matches!(node.kind(), "identifier" | "operator_identifier") {
            let name = scala_node_text(node, ctx.source).trim();
            if !name.is_empty() {
                names.push(name.to_string());
            }
            continue;
        }
        if matches!(
            node.kind(),
            "stable_identifier"
                | "stable_type_identifier"
                | "type_identifier"
                | "given_pattern"
                | "literal"
                | "wildcard"
        ) {
            continue;
        }
        let mut cursor = node.walk();
        let mut children = Vec::new();
        for child in node.named_children(&mut cursor) {
            if !ctx.walk.step() {
                return None;
            }
            children.push(child);
        }
        children.reverse();
        stack.extend(children);
    }
    Some(names)
}

fn bounded_scala_resolve_type_node(
    ctx: &BoundedScalaCtx<'_, '_>,
    node: Node<'_>,
) -> Option<CodeUnit> {
    let segments = bounded_scala_type_segments(ctx, node)?;
    bounded_scala_resolve_segments(ctx, &segments, false)
}

fn bounded_scala_type_segments(
    ctx: &BoundedScalaCtx<'_, '_>,
    root: Node<'_>,
) -> Option<Vec<String>> {
    let mut segments = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if !ctx.walk.step() {
            return None;
        }
        match node.kind() {
            "identifier" | "operator_identifier" | "type_identifier" => {
                let segment = scala_node_text(node, ctx.source).trim();
                if !segment.is_empty() {
                    segments.push(segment.to_string());
                }
            }
            "type_arguments" | "arguments" | "annotation" | "structural_type" => {}
            _ => {
                let mut cursor = node.walk();
                let mut children = Vec::new();
                for child in node.named_children(&mut cursor) {
                    if !ctx.walk.step() {
                        return None;
                    }
                    children.push(child);
                }
                children.reverse();
                stack.extend(children);
            }
        }
    }
    (!segments.is_empty()).then_some(segments)
}

fn bounded_scala_resolve_segments(
    ctx: &BoundedScalaCtx<'_, '_>,
    segments: &[String],
    singleton: bool,
) -> Option<CodeUnit> {
    if segments.is_empty() {
        return None;
    }
    let mut candidate_fqns = Vec::new();
    let root_name = &segments[0];
    for import in ctx.batch.imports.iter().filter(|import| {
        scala_import_visible_at(
            import,
            &ctx.package_prefixes,
            &ctx.lexical_scopes,
            ctx.reference_byte,
        )
    }) {
        let Some(path) = import.path.as_ref() else {
            continue;
        };
        if import.is_wildcard {
            for prefix in path
                .lexical_prefixes
                .iter()
                .rev()
                .map(String::as_str)
                .chain(std::iter::once(""))
            {
                let base = if prefix.is_empty() {
                    path.render_segments(".")
                } else {
                    format!("{prefix}.{}", path.render_segments("."))
                };
                candidate_fqns.extend(scala_nested_type_candidates(base, segments, true));
            }
            continue;
        }
        let Some(imported) = path.segments.last() else {
            continue;
        };
        if import.identifier.as_deref().unwrap_or(imported) != root_name {
            continue;
        }
        let mut imported_segments = path.segments.clone();
        imported_segments.extend_from_slice(&segments[1..]);
        candidate_fqns.push(imported_segments.join("."));
    }
    for prefix in ctx
        .package_prefixes
        .iter()
        .rev()
        .map(String::as_str)
        .chain(std::iter::once(""))
    {
        candidate_fqns.extend(scala_nested_type_candidates(
            prefix.to_string(),
            segments,
            false,
        ));
    }
    if segments.len() == 1 {
        candidate_fqns.extend(scala_nested_type_candidates(
            "scala".to_string(),
            segments,
            false,
        ));
    }
    if singleton {
        for candidate in &mut candidate_fqns {
            if !candidate.ends_with('$') {
                candidate.push('$');
            }
        }
    }
    candidate_fqns.sort();
    candidate_fqns.dedup();

    let mut declarations = Vec::new();
    for fqn in candidate_fqns {
        declarations.extend(
            ctx.provider
                .fqn(&fqn)
                .into_iter()
                .filter(|unit| unit.is_class() && unit.fq_name() == fqn),
        );
        if !ctx.walk.session.observe_cancellation() {
            return None;
        }
    }
    sort_units(&mut declarations);
    declarations.dedup();
    match declarations.as_slice() {
        [declaration] => Some(declaration.clone()),
        _ => None,
    }
}

fn bounded_scala_nearest_enclosing_owner(
    ctx: &BoundedScalaCtx<'_, '_>,
    node: Node<'_>,
) -> Option<CodeUnit> {
    bounded_scala_enclosing_owners(ctx, node).and_then(|owners| owners.into_iter().next())
}

fn bounded_scala_enclosing_owners(
    ctx: &BoundedScalaCtx<'_, '_>,
    mut node: Node<'_>,
) -> Option<Vec<CodeUnit>> {
    let mut declarations = Vec::new();
    while let Some(parent) = node.parent() {
        if !ctx.walk.step() {
            return None;
        }
        if matches!(
            parent.kind(),
            "class_definition" | "object_definition" | "trait_definition" | "enum_definition"
        ) {
            let name = parent.child_by_field_name("name")?;
            if !ctx.walk.step() {
                return None;
            }
            let name_text = scala_node_text(name, ctx.source).trim();
            if name_text.is_empty() {
                return None;
            }
            declarations.push((
                parent,
                if parent.kind() == "object_definition" {
                    format!("{name_text}$")
                } else {
                    name_text.to_string()
                },
            ));
        }
        node = parent;
    }

    declarations.reverse();
    let package = ctx
        .package_prefixes
        .last()
        .map(String::as_str)
        .unwrap_or(ctx.batch.package.as_ref());
    let mut path = Vec::new();
    let mut owners = Vec::new();
    for (declaration_node, segment) in declarations {
        if !ctx.walk.step() {
            return None;
        }
        path.push(segment);
        let relative = path.join(".");
        let fqn = if package.is_empty() {
            relative
        } else {
            format!("{package}.{relative}")
        };
        let mut candidates = Vec::new();
        for candidate in ctx.provider.fqn(&fqn) {
            if !ctx.walk.step() {
                return None;
            }
            if !candidate.is_class() || candidate.fq_name() != fqn || candidate.source() != ctx.file
            {
                continue;
            }
            let mut exact_range = false;
            for range in ctx.provider.ranges(&candidate) {
                if !ctx.walk.step() {
                    return None;
                }
                exact_range |= range.start_byte == declaration_node.start_byte()
                    && range.end_byte == declaration_node.end_byte();
            }
            if exact_range {
                candidates.push(candidate);
            }
        }
        sort_units(&mut candidates);
        candidates.dedup();
        match candidates.as_slice() {
            [owner] => owners.push(owner.clone()),
            [] => return None,
            _ => return None,
        }
    }
    owners.reverse();
    Some(owners)
}

fn bounded_scala_direct_members(
    ctx: &BoundedScalaCtx<'_, '_>,
    owner: &CodeUnit,
    name: &str,
) -> Vec<CodeUnit> {
    let mut candidates = ctx
        .provider
        .direct_children(owner)
        .into_iter()
        .filter(|candidate| candidate.identifier() == name)
        .filter(|candidate| candidate.is_function() || candidate.is_field())
        .collect::<Vec<_>>();
    sort_units(&mut candidates);
    candidates.dedup();
    candidates
}

enum ScalaBoundedAncestorResolution {
    Resolved(Vec<CodeUnit>),
    Unknown,
}

enum ScalaBoundedTypeResolution {
    Missing,
    Unique(CodeUnit),
    Unknown,
}

fn bounded_scala_direct_ancestors(
    ctx: &BoundedScalaCtx<'_, '_>,
    owner: &CodeUnit,
) -> ScalaBoundedAncestorResolution {
    let raw_supertypes = ctx.provider.raw_supertypes(owner);
    if !ctx.walk.step() {
        return ScalaBoundedAncestorResolution::Unknown;
    }
    let encoded_paths = ctx.provider.supertype_lookup_paths(owner);
    if !ctx.walk.step() || raw_supertypes.len() != encoded_paths.len() {
        return ScalaBoundedAncestorResolution::Unknown;
    }
    if encoded_paths.is_empty() {
        return ScalaBoundedAncestorResolution::Resolved(Vec::new());
    }

    let Some(owner_start) = ctx
        .provider
        .ranges(owner)
        .into_iter()
        .map(|range| range.start_byte)
        .min()
    else {
        return ScalaBoundedAncestorResolution::Unknown;
    };
    if !ctx.walk.step() {
        return ScalaBoundedAncestorResolution::Unknown;
    }
    let imports = ctx.provider.imports(owner.source());
    if !ctx.walk.step() {
        return ScalaBoundedAncestorResolution::Unknown;
    }

    let mut ancestors = Vec::new();
    for encoded in encoded_paths {
        if !ctx.walk.step() {
            return ScalaBoundedAncestorResolution::Unknown;
        }
        let Some(path) = ScalaSupertypeLookupPath::decode(&encoded) else {
            return ScalaBoundedAncestorResolution::Unknown;
        };
        match bounded_scala_resolve_supertype_path(ctx, owner, &path, owner_start, &imports) {
            ScalaBoundedTypeResolution::Unique(ancestor) => ancestors.push(ancestor),
            ScalaBoundedTypeResolution::Missing | ScalaBoundedTypeResolution::Unknown => {
                return ScalaBoundedAncestorResolution::Unknown;
            }
        }
    }
    sort_units(&mut ancestors);
    ancestors.dedup();
    ScalaBoundedAncestorResolution::Resolved(ancestors)
}

fn bounded_scala_resolve_supertype_path(
    ctx: &BoundedScalaCtx<'_, '_>,
    owner: &CodeUnit,
    path: &ScalaSupertypeLookupPath,
    owner_start: usize,
    imports: &[ImportInfo],
) -> ScalaBoundedTypeResolution {
    let segments = path.segments();
    if segments.is_empty() {
        return ScalaBoundedTypeResolution::Unknown;
    }
    if segments.first().is_some_and(|segment| segment == "_root_") {
        if segments.len() == 1 {
            return ScalaBoundedTypeResolution::Unknown;
        }
        return bounded_scala_type_tier(
            ctx,
            scala_nested_type_candidates(String::new(), &segments[1..], false),
        );
    }

    let binding = &segments[0];
    let mut explicit_claim = false;
    let mut explicit = Vec::new();
    for import in imports {
        if !ctx.walk.step() {
            return ScalaBoundedTypeResolution::Unknown;
        }
        if !scala_import_visible_at(
            import,
            path.package_prefixes(),
            path.lexical_scopes(),
            owner_start,
        ) || import.is_wildcard
        {
            continue;
        }
        let Some(import_path) = import.path.as_ref() else {
            continue;
        };
        let Some(imported_name) = import_path.segments.last() else {
            return ScalaBoundedTypeResolution::Unknown;
        };
        if import.identifier.as_deref().unwrap_or(imported_name) != binding {
            continue;
        }
        explicit_claim = true;
        let mut imported_path = import_path.segments.clone();
        imported_path.extend_from_slice(&segments[1..]);
        match bounded_scala_prefixed_type_tiers(ctx, &import_path.lexical_prefixes, &imported_path)
        {
            ScalaBoundedTypeResolution::Missing => {}
            ScalaBoundedTypeResolution::Unique(declaration) => explicit.push(declaration),
            ScalaBoundedTypeResolution::Unknown => return ScalaBoundedTypeResolution::Unknown,
        }
    }
    if explicit_claim {
        sort_units(&mut explicit);
        explicit.dedup();
        return match explicit.as_slice() {
            [declaration] => ScalaBoundedTypeResolution::Unique(declaration.clone()),
            [] | [_, _, ..] => ScalaBoundedTypeResolution::Unknown,
        };
    }

    let mut saw_wildcard = false;
    let mut wildcard = Vec::new();
    for import in imports {
        if !ctx.walk.step() {
            return ScalaBoundedTypeResolution::Unknown;
        }
        if !import.is_wildcard
            || !scala_import_visible_at(
                import,
                path.package_prefixes(),
                path.lexical_scopes(),
                owner_start,
            )
        {
            continue;
        }
        saw_wildcard = true;
        let Some(import_path) = import.path.as_ref() else {
            return ScalaBoundedTypeResolution::Unknown;
        };
        let mut imported_path = import_path.segments.clone();
        imported_path.extend_from_slice(segments);
        match bounded_scala_prefixed_type_tiers(ctx, &import_path.lexical_prefixes, &imported_path)
        {
            ScalaBoundedTypeResolution::Missing => {}
            ScalaBoundedTypeResolution::Unique(declaration) => wildcard.push(declaration),
            ScalaBoundedTypeResolution::Unknown => return ScalaBoundedTypeResolution::Unknown,
        }
    }
    if saw_wildcard {
        sort_units(&mut wildcard);
        wildcard.dedup();
        return match wildcard.as_slice() {
            [declaration] => ScalaBoundedTypeResolution::Unique(declaration.clone()),
            [] | [_, _, ..] => ScalaBoundedTypeResolution::Unknown,
        };
    }

    for package_prefix in path
        .package_prefixes()
        .iter()
        .rev()
        .filter(|prefix| !prefix.is_empty())
    {
        if !ctx.walk.step() {
            return ScalaBoundedTypeResolution::Unknown;
        }
        match bounded_scala_type_tier(
            ctx,
            scala_nested_type_candidates(package_prefix.clone(), segments, false),
        ) {
            ScalaBoundedTypeResolution::Missing => {}
            resolved => return resolved,
        }
    }
    if !owner.package_name().is_empty()
        && !path
            .package_prefixes()
            .iter()
            .any(|prefix| prefix == owner.package_name())
    {
        match bounded_scala_type_tier(
            ctx,
            scala_nested_type_candidates(owner.package_name().to_string(), segments, false),
        ) {
            ScalaBoundedTypeResolution::Missing => {}
            resolved => return resolved,
        }
    }
    if segments.len() > 1 || owner.package_name().is_empty() {
        return bounded_scala_type_tier(
            ctx,
            scala_nested_type_candidates(String::new(), segments, false),
        );
    }
    ScalaBoundedTypeResolution::Missing
}

fn bounded_scala_prefixed_type_tiers(
    ctx: &BoundedScalaCtx<'_, '_>,
    prefixes: &[String],
    segments: &[String],
) -> ScalaBoundedTypeResolution {
    for prefix in prefixes
        .iter()
        .rev()
        .map(String::as_str)
        .chain(std::iter::once(""))
    {
        if !ctx.walk.step() {
            return ScalaBoundedTypeResolution::Unknown;
        }
        match bounded_scala_type_tier(
            ctx,
            scala_nested_type_candidates(prefix.to_string(), segments, false),
        ) {
            ScalaBoundedTypeResolution::Missing => {}
            resolved => return resolved,
        }
    }
    ScalaBoundedTypeResolution::Missing
}

fn bounded_scala_type_tier(
    ctx: &BoundedScalaCtx<'_, '_>,
    fqns: Vec<String>,
) -> ScalaBoundedTypeResolution {
    match bounded_scala_metadata_type_tier(ctx, fqns) {
        ScalaMetadataTypeTier::Empty => ScalaBoundedTypeResolution::Missing,
        ScalaMetadataTypeTier::Unique(declaration) => {
            ScalaBoundedTypeResolution::Unique(declaration)
        }
        ScalaMetadataTypeTier::Ambiguous => ScalaBoundedTypeResolution::Unknown,
    }
}

fn bounded_scala_next_ancestor_frontier(
    ctx: &BoundedScalaCtx<'_, '_>,
    frontier: &[CodeUnit],
    discovered: &mut HashSet<CodeUnit>,
) -> ScalaBoundedAncestorResolution {
    let mut next = Vec::new();
    for current in frontier {
        if !ctx.walk.step() {
            return ScalaBoundedAncestorResolution::Unknown;
        }
        let direct = match bounded_scala_direct_ancestors(ctx, current) {
            ScalaBoundedAncestorResolution::Resolved(direct) => direct,
            ScalaBoundedAncestorResolution::Unknown => {
                return ScalaBoundedAncestorResolution::Unknown;
            }
        };
        for ancestor in direct {
            if !ctx.walk.step() {
                return ScalaBoundedAncestorResolution::Unknown;
            }
            if discovered.insert(ancestor.clone()) {
                next.push(ancestor);
            }
        }
    }
    sort_units(&mut next);
    next.dedup();
    ScalaBoundedAncestorResolution::Resolved(next)
}

fn bounded_scala_inherited_members(
    ctx: &BoundedScalaCtx<'_, '_>,
    owner: &CodeUnit,
    name: &str,
    call_shape: ScalaBoundedCallShape,
) -> ScalaBoundedMemberCandidates {
    let mut frontier = vec![owner.clone()];
    let mut discovered = HashSet::default();
    discovered.insert(owner.clone());
    loop {
        let next = match bounded_scala_next_ancestor_frontier(ctx, &frontier, &mut discovered) {
            ScalaBoundedAncestorResolution::Resolved(next) => next,
            ScalaBoundedAncestorResolution::Unknown => {
                return ScalaBoundedMemberCandidates::Unknown;
            }
        };
        if next.is_empty() {
            return ScalaBoundedMemberCandidates::NoMatch;
        }

        let mut candidates = Vec::new();
        let mut overload_ambiguous = false;
        for ancestor in &next {
            if !ctx.walk.step() {
                return ScalaBoundedMemberCandidates::Unknown;
            }
            match bounded_scala_applicable_direct_members(ctx, ancestor, name, call_shape) {
                ScalaBoundedMemberCandidates::NoMatch => {}
                ScalaBoundedMemberCandidates::Found {
                    candidates: mut found,
                    overload_ambiguous: ambiguous,
                } => {
                    candidates.append(&mut found);
                    overload_ambiguous |= ambiguous;
                }
                ScalaBoundedMemberCandidates::Unknown => {
                    return ScalaBoundedMemberCandidates::Unknown;
                }
            }
        }
        sort_units(&mut candidates);
        candidates.dedup();
        if !candidates.is_empty() {
            return ScalaBoundedMemberCandidates::Found {
                candidates,
                overload_ambiguous,
            };
        }
        frontier = next;
    }
}

enum ScalaBoundedConformance {
    Yes,
    No,
    Unknown,
}

fn bounded_scala_receiver_conforms_to(
    ctx: &BoundedScalaCtx<'_, '_>,
    receiver: &CodeUnit,
    expected: &CodeUnit,
) -> ScalaBoundedConformance {
    if receiver == expected {
        return ScalaBoundedConformance::Yes;
    }
    let mut frontier = vec![receiver.clone()];
    let mut discovered = HashSet::default();
    discovered.insert(receiver.clone());
    loop {
        let next = match bounded_scala_next_ancestor_frontier(ctx, &frontier, &mut discovered) {
            ScalaBoundedAncestorResolution::Resolved(next) => next,
            ScalaBoundedAncestorResolution::Unknown => {
                return ScalaBoundedConformance::Unknown;
            }
        };
        if next.is_empty() {
            return ScalaBoundedConformance::No;
        }
        for ancestor in &next {
            if !ctx.walk.step() {
                return ScalaBoundedConformance::Unknown;
            }
            if ancestor == expected {
                return ScalaBoundedConformance::Yes;
            }
        }
        frontier = next;
    }
}

enum ScalaBoundedMemberCandidates {
    NoMatch,
    Found {
        candidates: Vec<CodeUnit>,
        overload_ambiguous: bool,
    },
    Unknown,
}

fn bounded_scala_ambiguous_candidates(
    candidates: Vec<CodeUnit>,
    message: String,
) -> DefinitionLookupOutcome {
    let mut outcome = candidates_outcome(candidates);
    outcome.status = DefinitionLookupStatus::Ambiguous;
    outcome.diagnostics.push(DefinitionLookupDiagnostic {
        kind: "ambiguous_definition".to_string(),
        message,
    });
    outcome
}

enum ScalaBoundedCandidateApplicability {
    NotCandidate,
    Inapplicable,
    Applicable { overload_ambiguous: bool },
    Unknown,
}

fn bounded_scala_applicable_direct_members(
    ctx: &BoundedScalaCtx<'_, '_>,
    owner: &CodeUnit,
    name: &str,
    call_shape: ScalaBoundedCallShape,
) -> ScalaBoundedMemberCandidates {
    let direct = bounded_scala_direct_members(ctx, owner, name);
    let mut candidates = Vec::new();
    let mut overload_ambiguous = false;
    for candidate in direct {
        if !ctx.walk.step() {
            return ScalaBoundedMemberCandidates::Unknown;
        }
        match bounded_scala_direct_candidate_applicability(ctx, &candidate, call_shape) {
            ScalaBoundedCandidateApplicability::NotCandidate
            | ScalaBoundedCandidateApplicability::Inapplicable => {}
            ScalaBoundedCandidateApplicability::Applicable {
                overload_ambiguous: candidate_ambiguous,
            } => {
                overload_ambiguous |= candidate_ambiguous;
                candidates.push(candidate);
            }
            ScalaBoundedCandidateApplicability::Unknown => {
                return ScalaBoundedMemberCandidates::Unknown;
            }
        }
    }
    sort_units(&mut candidates);
    candidates.dedup();
    if candidates.is_empty() {
        ScalaBoundedMemberCandidates::NoMatch
    } else {
        ScalaBoundedMemberCandidates::Found {
            candidates,
            overload_ambiguous,
        }
    }
}

fn bounded_scala_direct_candidate_applicability(
    ctx: &BoundedScalaCtx<'_, '_>,
    candidate: &CodeUnit,
    call_shape: ScalaBoundedCallShape,
) -> ScalaBoundedCandidateApplicability {
    if candidate.is_field() {
        return match call_shape {
            ScalaBoundedCallShape::Access => ScalaBoundedCandidateApplicability::Applicable {
                overload_ambiguous: false,
            },
            ScalaBoundedCallShape::Ordinary(_) | ScalaBoundedCallShape::Unsupported => {
                ScalaBoundedCandidateApplicability::Unknown
            }
        };
    }
    if !candidate.is_function() {
        return ScalaBoundedCandidateApplicability::NotCandidate;
    }
    let metadata = ctx.provider.signature_metadata(candidate);
    if metadata.is_empty() {
        return ScalaBoundedCandidateApplicability::Unknown;
    }
    let mut applicable = 0usize;
    let mut saw_ordinary = false;
    let mut saw_unknown = false;
    for signature in metadata {
        if !ctx.walk.step() {
            return ScalaBoundedCandidateApplicability::Unknown;
        }
        if scala_signature_is_extension(&signature) {
            continue;
        }
        saw_ordinary = true;
        match call_shape {
            ScalaBoundedCallShape::Access => applicable = applicable.saturating_add(1),
            ScalaBoundedCallShape::Ordinary(arity) => match signature.callable_arity() {
                Some(callable_arity) if callable_arity.accepts(arity) => {
                    applicable = applicable.saturating_add(1);
                }
                Some(_) => {}
                None => saw_unknown = true,
            },
            ScalaBoundedCallShape::Unsupported => saw_unknown = true,
        }
    }
    if !saw_ordinary {
        return ScalaBoundedCandidateApplicability::NotCandidate;
    }
    if saw_unknown {
        return ScalaBoundedCandidateApplicability::Unknown;
    }
    if applicable == 0 {
        ScalaBoundedCandidateApplicability::Inapplicable
    } else {
        ScalaBoundedCandidateApplicability::Applicable {
            overload_ambiguous: applicable > 1,
        }
    }
}

fn scala_signature_is_extension(metadata: &SignatureMetadata) -> bool {
    metadata.extension_receiver_type_identity().is_some()
        || metadata.extension_receiver_type().is_some()
}

fn bounded_scala_extension_members(
    ctx: &BoundedScalaCtx<'_, '_>,
    site: Node<'_>,
    receiver: &CodeUnit,
    name: &str,
    call_shape: ScalaBoundedCallShape,
) -> ScalaBoundedMemberCandidates {
    let Some(enclosing_owners) = bounded_scala_enclosing_owners(ctx, site) else {
        return ScalaBoundedMemberCandidates::Unknown;
    };

    // A lexically enclosing extension scope wins over imported extensions.
    // Each owner is its own tier, nearest first.
    for owner in &enclosing_owners {
        if !ctx.walk.step() {
            return ScalaBoundedMemberCandidates::Unknown;
        }
        let direct = ctx
            .provider
            .direct_children(owner)
            .into_iter()
            .filter(|candidate| candidate.identifier() == name)
            .collect::<Vec<_>>();
        match bounded_scala_select_extension_candidates(ctx, direct, receiver, call_shape) {
            ScalaBoundedMemberCandidates::NoMatch => {}
            selected => return selected,
        }
    }

    // A top-level extension from this compilation unit has lexical-definition
    // precedence. Same-package extensions from other files are the lowest
    // binding tier and are retained for consideration after imports.
    let package = ctx
        .package_prefixes
        .last()
        .map(String::as_str)
        .unwrap_or(ctx.batch.package.as_ref());
    let package_candidate = if package.is_empty() {
        name.to_string()
    } else {
        format!("{package}.{name}")
    };
    let (same_file_package_candidates, other_file_package_candidates): (Vec<_>, Vec<_>) = ctx
        .provider
        .fqn(&package_candidate)
        .into_iter()
        .partition(|candidate| candidate.source() == ctx.file);
    match bounded_scala_select_extension_candidates(
        ctx,
        same_file_package_candidates,
        receiver,
        call_shape,
    ) {
        ScalaBoundedMemberCandidates::NoMatch => {}
        selected => return selected,
    }

    let mut explicit_candidates = Vec::new();
    let mut explicit_overload_ambiguous = false;
    let mut unresolved_explicit_claim = false;
    for import in ctx.batch.imports.iter() {
        if !ctx.walk.step() {
            return ScalaBoundedMemberCandidates::Unknown;
        }
        let Some(visible) = bounded_scala_import_visible_at(ctx, import) else {
            return ScalaBoundedMemberCandidates::Unknown;
        };
        if !visible || import.is_wildcard {
            continue;
        }
        let Some(path) = import.path.as_ref() else {
            unresolved_explicit_claim = true;
            continue;
        };
        let Some((imported_name, owner_segments)) = path.segments.split_last() else {
            unresolved_explicit_claim = true;
            continue;
        };
        if import.identifier.as_deref().unwrap_or(imported_name) != name {
            continue;
        }
        let Some(declarations) = bounded_scala_imported_member_candidates(
            ctx,
            &enclosing_owners,
            path,
            owner_segments,
            imported_name,
        ) else {
            return ScalaBoundedMemberCandidates::Unknown;
        };
        if declarations.is_empty() {
            unresolved_explicit_claim = true;
            continue;
        }
        match bounded_scala_select_extension_candidates(ctx, declarations, receiver, call_shape) {
            ScalaBoundedMemberCandidates::NoMatch => {}
            ScalaBoundedMemberCandidates::Found {
                mut candidates,
                overload_ambiguous,
            } => {
                explicit_candidates.append(&mut candidates);
                explicit_overload_ambiguous |= overload_ambiguous;
            }
            ScalaBoundedMemberCandidates::Unknown => {
                return ScalaBoundedMemberCandidates::Unknown;
            }
        }
    }
    if unresolved_explicit_claim {
        return ScalaBoundedMemberCandidates::Unknown;
    }
    sort_units(&mut explicit_candidates);
    explicit_candidates.dedup();
    if !explicit_candidates.is_empty() {
        return ScalaBoundedMemberCandidates::Found {
            candidates: explicit_candidates,
            overload_ambiguous: explicit_overload_ambiguous,
        };
    }

    let mut wildcard_candidates = Vec::new();
    let mut wildcard_overload_ambiguous = false;
    let mut unresolved_wildcard_claim = false;
    for import in ctx.batch.imports.iter() {
        if !ctx.walk.step() {
            return ScalaBoundedMemberCandidates::Unknown;
        }
        let Some(visible) = bounded_scala_import_visible_at(ctx, import) else {
            return ScalaBoundedMemberCandidates::Unknown;
        };
        if !visible || !import.is_wildcard {
            continue;
        }
        let Some(path) = import.path.as_ref() else {
            unresolved_wildcard_claim = true;
            continue;
        };
        let Some(declarations) = bounded_scala_imported_member_candidates(
            ctx,
            &enclosing_owners,
            path,
            &path.segments,
            name,
        ) else {
            return ScalaBoundedMemberCandidates::Unknown;
        };
        if declarations.is_empty() {
            unresolved_wildcard_claim = true;
            continue;
        }
        match bounded_scala_select_extension_candidates(ctx, declarations, receiver, call_shape) {
            ScalaBoundedMemberCandidates::NoMatch => {}
            ScalaBoundedMemberCandidates::Found {
                mut candidates,
                overload_ambiguous,
            } => {
                wildcard_candidates.append(&mut candidates);
                wildcard_overload_ambiguous |= overload_ambiguous;
            }
            ScalaBoundedMemberCandidates::Unknown => {
                return ScalaBoundedMemberCandidates::Unknown;
            }
        }
    }
    if unresolved_wildcard_claim {
        return ScalaBoundedMemberCandidates::Unknown;
    }
    sort_units(&mut wildcard_candidates);
    wildcard_candidates.dedup();
    if !wildcard_candidates.is_empty() {
        return ScalaBoundedMemberCandidates::Found {
            candidates: wildcard_candidates,
            overload_ambiguous: wildcard_overload_ambiguous,
        };
    }
    bounded_scala_select_extension_candidates(
        ctx,
        other_file_package_candidates,
        receiver,
        call_shape,
    )
}

fn bounded_scala_select_extension_candidates(
    ctx: &BoundedScalaCtx<'_, '_>,
    declarations: Vec<CodeUnit>,
    receiver: &CodeUnit,
    call_shape: ScalaBoundedCallShape,
) -> ScalaBoundedMemberCandidates {
    let mut candidates = Vec::new();
    let mut overload_ambiguous = false;
    for candidate in declarations {
        if !ctx.walk.step() {
            return ScalaBoundedMemberCandidates::Unknown;
        }
        match bounded_scala_extension_candidate_applicability(ctx, &candidate, receiver, call_shape)
        {
            ScalaBoundedCandidateApplicability::NotCandidate
            | ScalaBoundedCandidateApplicability::Inapplicable => {}
            ScalaBoundedCandidateApplicability::Applicable {
                overload_ambiguous: candidate_ambiguous,
            } => {
                overload_ambiguous |= candidate_ambiguous;
                candidates.push(candidate);
            }
            ScalaBoundedCandidateApplicability::Unknown => {
                return ScalaBoundedMemberCandidates::Unknown;
            }
        }
    }
    sort_units(&mut candidates);
    candidates.dedup();
    if candidates.is_empty() {
        ScalaBoundedMemberCandidates::NoMatch
    } else {
        ScalaBoundedMemberCandidates::Found {
            candidates,
            overload_ambiguous,
        }
    }
}

fn bounded_scala_extension_candidate_applicability(
    ctx: &BoundedScalaCtx<'_, '_>,
    candidate: &CodeUnit,
    receiver: &CodeUnit,
    call_shape: ScalaBoundedCallShape,
) -> ScalaBoundedCandidateApplicability {
    if !candidate.is_function() {
        return ScalaBoundedCandidateApplicability::NotCandidate;
    }
    let metadata = ctx.provider.signature_metadata(candidate);
    if metadata.is_empty() {
        return ScalaBoundedCandidateApplicability::Unknown;
    }
    let mut saw_extension = false;
    let mut saw_unknown = false;
    let mut applicable = 0usize;
    for signature in metadata {
        if !ctx.walk.step() {
            return ScalaBoundedCandidateApplicability::Unknown;
        }
        if !scala_signature_is_extension(&signature) {
            continue;
        }
        saw_extension = true;
        let Some(identity) = signature.extension_receiver_type_identity() else {
            saw_unknown = true;
            continue;
        };
        if identity.generic_argument_count().is_some() {
            saw_unknown = true;
            continue;
        }
        let Some(name) = identity.nominal_name_with(|| ctx.walk.step()) else {
            saw_unknown = true;
            continue;
        };
        let mut receiver_is_type_parameter = false;
        if name.path().len() == 1 {
            for parameter in signature.type_parameters() {
                if !ctx.walk.step() {
                    return ScalaBoundedCandidateApplicability::Unknown;
                }
                receiver_is_type_parameter |= parameter == &name.path()[0];
            }
        }
        if receiver_is_type_parameter {
            saw_unknown = true;
            continue;
        }
        let Some(extension_receiver) = bounded_scala_resolve_metadata_type(ctx, candidate, name)
        else {
            saw_unknown = true;
            continue;
        };
        match bounded_scala_receiver_conforms_to(ctx, receiver, &extension_receiver) {
            ScalaBoundedConformance::Yes => {}
            ScalaBoundedConformance::No => continue,
            ScalaBoundedConformance::Unknown => {
                saw_unknown = true;
                continue;
            }
        }
        match call_shape {
            ScalaBoundedCallShape::Access => applicable = applicable.saturating_add(1),
            ScalaBoundedCallShape::Ordinary(arity) => match signature.callable_arity() {
                Some(callable_arity) if callable_arity.accepts(arity) => {
                    applicable = applicable.saturating_add(1);
                }
                Some(_) => {}
                None => saw_unknown = true,
            },
            ScalaBoundedCallShape::Unsupported => saw_unknown = true,
        }
    }
    if !saw_extension {
        return ScalaBoundedCandidateApplicability::NotCandidate;
    }
    if saw_unknown {
        return ScalaBoundedCandidateApplicability::Unknown;
    }
    if applicable == 0 {
        ScalaBoundedCandidateApplicability::Inapplicable
    } else {
        ScalaBoundedCandidateApplicability::Applicable {
            overload_ambiguous: applicable > 1,
        }
    }
}

fn bounded_scala_imported_member_candidates(
    ctx: &BoundedScalaCtx<'_, '_>,
    enclosing_owners: &[CodeUnit],
    path: &StructuredImportPath,
    owner_segments: &[String],
    member: &str,
) -> Option<Vec<CodeUnit>> {
    let mut prefixes = Vec::new();
    for owner in enclosing_owners {
        if !ctx.walk.step() {
            return None;
        }
        prefixes.push(owner.fq_name());
    }
    let lexical_prefixes = if path.lexical_prefixes.is_empty() {
        &ctx.package_prefixes
    } else {
        &path.lexical_prefixes
    };
    for prefix in lexical_prefixes.iter().rev() {
        if !ctx.walk.step() {
            return None;
        }
        prefixes.push(prefix.clone());
    }
    prefixes.push(String::new());

    for prefix in prefixes {
        if !ctx.walk.step() {
            return None;
        }
        let fqns = bounded_scala_import_member_fqns(ctx, &prefix, owner_segments, member)?;
        let mut declarations = Vec::new();
        for fqn in fqns {
            if !ctx.walk.step() {
                return None;
            }
            declarations.extend(
                ctx.provider
                    .fqn(&fqn)
                    .into_iter()
                    .filter(|unit| unit.fq_name() == fqn),
            );
        }
        sort_units(&mut declarations);
        declarations.dedup();
        if !declarations.is_empty() {
            return Some(declarations);
        }
    }
    Some(Vec::new())
}

fn bounded_scala_import_visible_at(
    ctx: &BoundedScalaCtx<'_, '_>,
    import: &ImportInfo,
) -> Option<bool> {
    let Some(path) = import.path.as_ref() else {
        return Some(true);
    };
    if path.declaration_start_byte > ctx.reference_byte {
        return Some(false);
    }
    if !path.lexical_prefixes.is_empty()
        && path.lexical_prefixes.last() != ctx.package_prefixes.last()
    {
        return Some(false);
    }
    if path.lexical_scopes.len() > ctx.lexical_scopes.len() {
        return Some(false);
    }
    for (import_scope, active_scope) in path.lexical_scopes.iter().zip(&ctx.lexical_scopes) {
        if !ctx.walk.step() {
            return None;
        }
        if import_scope != active_scope {
            return Some(false);
        }
    }
    Some(true)
}

fn bounded_scala_import_member_fqns(
    ctx: &BoundedScalaCtx<'_, '_>,
    prefix: &str,
    owner_segments: &[String],
    member: &str,
) -> Option<Vec<String>> {
    if member.is_empty() {
        return Some(Vec::new());
    }
    let direct_owner = bounded_scala_append_import_segments(ctx, prefix, owner_segments, false)?;
    let mut candidates = vec![if direct_owner.is_empty() {
        member.to_string()
    } else {
        format!("{direct_owner}.{member}")
    }];

    // Every split is a parser-derived interpretation of the import path's
    // package prefix versus nested stable-owner suffix. Exact FQN queries
    // discard spellings that do not exist; no identifier fallback is used.
    for split in 0..owner_segments.len() {
        if !ctx.walk.step() {
            return None;
        }
        let package_suffix = &owner_segments[..split];
        let type_suffix = &owner_segments[split..];
        let package_prefix =
            bounded_scala_append_import_segments(ctx, prefix, package_suffix, false)?;
        let direct =
            bounded_scala_append_import_segments(ctx, &package_prefix, type_suffix, false)?;
        let nested = bounded_scala_append_import_segments(ctx, &package_prefix, type_suffix, true)?;
        for mut owner in [direct, nested] {
            if !owner.ends_with('$') {
                owner.push('$');
            }
            candidates.push(format!("{owner}.{member}"));
        }
    }
    candidates.sort();
    candidates.dedup();
    Some(candidates)
}

fn bounded_scala_append_import_segments(
    ctx: &BoundedScalaCtx<'_, '_>,
    prefix: &str,
    segments: &[String],
    mark_intermediate_owners: bool,
) -> Option<String> {
    let mut path = prefix.to_string();
    for (index, segment) in segments.iter().enumerate() {
        if !ctx.walk.step() {
            return None;
        }
        if segment.is_empty() {
            return None;
        }
        if !path.is_empty() {
            path.push('.');
        }
        path.push_str(segment);
        if mark_intermediate_owners && index + 1 < segments.len() {
            path.push('$');
        }
    }
    Some(path)
}

fn bounded_scala_is_type_node(node: Node<'_>) -> bool {
    bounded_scala_is_type_kind(node.kind())
}

fn bounded_scala_is_type_kind(kind: &str) -> bool {
    matches!(
        kind,
        "type_identifier"
            | "stable_type_identifier"
            | "generic_type"
            | "projected_type"
            | "applied_constructor_type"
            | "singleton_type"
            | "annotated_type"
    )
}

#[allow(clippy::too_many_arguments)]
fn resolve_scala_with_context(
    analyzer: &dyn IAnalyzer,
    scala: &ScalaAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    batch: &ScalaDefinitionContext,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
    session: Option<&ResolutionSession>,
) -> DefinitionLookupOutcome {
    let Some(tree) = tree else {
        return no_definition("scala_parse_failed", "Scala source could not be parsed");
    };
    let root = tree.root_node();
    let Some(node) = scala_smallest_named_node_covering(
        session,
        root,
        site.focus_start_byte,
        site.focus_end_byte,
    ) else {
        return no_definition(
            "no_indexed_definition",
            format!(
                "`{}` did not resolve to an indexed Scala definition",
                site.text
            ),
        );
    };
    if !scala_charge_ancestor_path(session, node) {
        return no_definition(
            "scala_resolution_budget_exceeded",
            "Scala syntax traversal exceeded the receiver-resolution budget",
        );
    }
    if let Some(outcome) = scala_import_reference_outcome(
        analyzer,
        scala,
        support,
        &batch.imports,
        file,
        source,
        node,
        site.focus_start_byte,
        site.focus_end_byte,
    ) {
        return outcome;
    }
    if scala_is_declaration_name(node) {
        return no_definition(
            "declaration_or_import_site",
            format!("`{}` is not a Scala reference site", site.text),
        );
    }
    if is_scala_case_pattern_binder(node) {
        return no_definition(
            "local_variable_reference",
            format!("`{}` is a local Scala pattern binding", site.text),
        );
    }
    let qualified_type_root = scala_qualified_type_root(node);
    let qualified_type_segments = scala_type_lookup_segments(qualified_type_root, source);
    let structured_type_reference = node.kind() == "type_identifier"
        || matches!(
            qualified_type_root.kind(),
            "stable_type_identifier"
                | "projected_type"
                | "singleton_type"
                | "generic_type"
                | "applied_constructor_type"
                | "annotated_type"
        );
    if structured_type_reference
        && !scala_type_reference_is_singleton(qualified_type_root)
        && let Some(root_name) = qualified_type_segments.first()
        && scala_unindexed_type_binding_shadows(source, qualified_type_root, root_name)
    {
        return no_definition(
            "local_type_binding",
            format!(
                "`{}` is a local Scala type binding without a stable indexed identity",
                site.text
            ),
        );
    }

    let Some((package_prefixes, lexical_scopes)) =
        scala_lexical_context_at(session, root, source, node, node.start_byte())
    else {
        return no_definition(
            "scala_resolution_budget_exceeded",
            "Scala lexical-context traversal exceeded the receiver-resolution budget",
        );
    };
    let resolver = ScalaNameResolver::for_batch(scala, support, batch).with_lexical_context(
        package_prefixes,
        lexical_scopes,
        node.start_byte(),
    );
    let ctx = ScalaLookupCtx {
        scala,
        analyzer,
        support,
        file,
        source,
        session,
    };
    // A compiler lattice type remains a type even when tree-sitter exposes a
    // union leaf as a bare identifier recovery shape. Resolve that structured
    // type role before term-role handling can select a source-backed singleton
    // fixture such as an illegal `package scala; object Null` declaration.
    // `resolve_scala_type` still honors legal lexical and imported type
    // shadows before rejecting an unshadowed compiler intrinsic.
    if (structured_type_reference || scala_is_type_position(node))
        && !scala_type_reference_is_singleton(qualified_type_root)
        && scala_compiler_intrinsic_type_reference(&qualified_type_segments).is_some()
    {
        return resolve_scala_type(ctx, &resolver, root, qualified_type_root);
    }
    if let Some(outcome) = resolve_scala_focused_qualified_path(
        ctx,
        &resolver,
        root,
        node,
        site.focus_start_byte,
        site.focus_end_byte,
    ) {
        return outcome;
    }
    if let Some(outcome) = resolve_scala_parser_proven_term_role(ctx, &resolver, root, node) {
        return outcome;
    }
    if scala_type_reference_is_singleton(qualified_type_root) {
        return resolve_scala_type(ctx, &resolver, root, qualified_type_root);
    }
    // Tree-sitter exposes infix type operators (and recovery-shaped `extends`
    // operands) as ordinary identifiers. Preserve that parser-proven type
    // role before the generic identifier branch can consult the term
    // namespace and select a same-named companion object.
    if is_infix_type_operator_reference(node) {
        return resolve_scala_type(ctx, &resolver, root, node);
    }
    if let Some(outcome) = resolve_scala_bare_apply_fast_path(
        scala, analyzer, support, file, source, root, node, &resolver, session,
    ) {
        return outcome;
    }

    match scala_reference_node(node) {
        Some(ScalaReferenceNode::Type(type_node)) => {
            resolve_scala_type(ctx, &resolver, root, type_node)
        }
        Some(ScalaReferenceNode::Constructor(constructor)) => {
            resolve_scala_constructor(ctx, &resolver, constructor)
        }
        Some(ScalaReferenceNode::Call(call)) => resolve_scala_call(ctx, &resolver, root, call),
        Some(ScalaReferenceNode::NamedArgument { call, name }) => {
            resolve_scala_named_argument(ctx, &resolver, call, name)
        }
        Some(ScalaReferenceNode::InfixCall(call)) => {
            resolve_scala_infix_call(ctx, &resolver, root, call)
        }
        Some(ScalaReferenceNode::PostfixCall(call)) => {
            resolve_scala_postfix_call(ctx, &resolver, root, call)
        }
        Some(ScalaReferenceNode::Field(field)) => resolve_scala_field(ctx, &resolver, root, field),
        Some(ScalaReferenceNode::StableIdentifier(identifier)) => {
            resolve_scala_stable_identifier(ctx, &resolver, root, identifier)
        }
        Some(ScalaReferenceNode::Identifier(identifier)) => {
            let text = scala_node_text(identifier, source).trim();
            if text.is_empty() {
                return no_definition("no_reference_text", "Scala identifier is blank");
            }
            if scala_lexical_binding_declares_name_before(
                root,
                source,
                text,
                identifier.start_byte(),
            ) {
                return no_definition(
                    "local_variable_reference",
                    format!("`{text}` is a local Scala value"),
                );
            }
            if let Some(outcome) =
                scala_explicit_local_member_import_outcome(ctx, &resolver, root, identifier, text)
            {
                return outcome;
            }
            if let Some(fqn) = resolver.resolve_member(text) {
                return scala_fqn_outcome(support, &fqn, text);
            }
            if let Some(owner) =
                scala_enclosing_class(ctx.analyzer, ctx.support, ctx.file, identifier.start_byte())
            {
                match scala_exact_owner_member_candidate_units(ctx, &owner, text, false) {
                    ScalaExactMemberResolution::Found(mut candidates) => {
                        candidates.retain(|unit| {
                            !ctx.scala.is_type_alias(unit)
                                && !scala_constructor_only_callable(ctx.scala, unit)
                        });
                        if !candidates.is_empty() {
                            return candidates_outcome(candidates);
                        }
                    }
                    ScalaExactMemberResolution::Ambiguous => {
                        return no_definition(
                            "ambiguous_scala_enclosing_member",
                            format!("`{text}` has multiple physical enclosing-owner definitions"),
                        );
                    }
                    ScalaExactMemberResolution::NoMatch => {}
                }
            }
            if let Some(fqn) = scala_resolve_visible_term(ctx, &resolver, identifier, text) {
                return scala_fqn_outcome(support, &fqn, text);
            }
            match resolver.resolve_explicit_singleton(text) {
                ScalaNameResolution::Resolved(owner) => {
                    return scala_fqn_outcome(support, &owner.fqn, text);
                }
                ScalaNameResolution::MissingExplicitImport => {
                    return boundary(format!(
                        "`{text}` is bound by an explicit Scala import whose declaration is not indexed in this workspace"
                    ));
                }
                ScalaNameResolution::Ambiguous => {
                    return no_definition(
                        "ambiguous_scala_explicit_import",
                        format!("Scala explicit imports expose multiple `{text}` objects"),
                    );
                }
                ScalaNameResolution::Unresolved => {}
            }
            if let Some(imported_member) = scala_wildcard_imported_member_outcome(ctx, text, None) {
                return imported_member;
            }
            if scala_import_boundary_for_name(scala, support, file, text) {
                return boundary(format!(
                    "`{text}` appears to cross a Scala import boundary not indexed in this workspace"
                ));
            }
            no_definition(
                "no_indexed_definition",
                format!("`{text}` did not resolve to an indexed Scala definition"),
            )
        }
        None => no_definition(
            "unsupported_scala_reference_shape",
            format!(
                "`{}` is a Scala `{}` reference shape that get_definition does not resolve yet",
                site.text,
                node.kind()
            ),
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn scala_import_reference_outcome(
    analyzer: &dyn IAnalyzer,
    scala: &ScalaAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    import_infos: &[ImportInfo],
    file: &ProjectFile,
    source: &str,
    node: Node<'_>,
    focus_start_byte: usize,
    focus_end_byte: usize,
) -> Option<DefinitionLookupOutcome> {
    let mut current = node;
    let import = loop {
        if current.kind() == "import_declaration" {
            break current;
        }
        current = current.parent()?;
    };
    if node.parent().is_some_and(|parent| {
        matches!(
            parent.kind(),
            "as_renamed_identifier" | "arrow_renamed_identifier"
        ) && parent.child_by_field_name("alias") == Some(node)
    }) {
        return Some(no_definition(
            "declaration_or_import_site",
            format!(
                "`{}` declares a local Scala import alias",
                scala_node_text(node, source)
            ),
        ));
    }

    let name = scala_node_text(node, source).trim();
    if name.is_empty() {
        return None;
    }
    let mut infos = import_infos
        .iter()
        .filter(|info| {
            info.path
                .as_ref()
                .is_some_and(|path| path.declaration_start_byte == import.start_byte())
        })
        .cloned()
        .collect::<Vec<_>>();
    if infos.is_empty() {
        infos = scala_import_infos_from_node(import, source);
    }
    let resolver = ScalaNameResolver::for_file(scala, support, file);
    // A relative Scala import resolves against its enclosing object/class/trait
    // scopes before the package (Scala §4.7's "qualified idents"), innermost
    // scope first. Existing candidate generation here only ever qualified a
    // relative path against package-level lexical prefixes, so an import like
    // `object Status { import Registry._ }` never tried the enclosing-template
    // spelling `Status$.Registry$` even when `Registry` is indexed as a nested
    // sibling declaration.
    let enclosing_owners =
        scala_enclosing_template_owner_fq_names(analyzer, scala, file, import.start_byte());
    let selected_name = node.parent().is_some_and(|parent| {
        matches!(
            parent.kind(),
            "as_renamed_identifier" | "arrow_renamed_identifier"
        ) && parent.child_by_field_name("name") == Some(node)
    }) || node
        .parent()
        .is_some_and(|parent| parent.kind() == "namespace_selectors");
    let relevant = infos.into_iter().filter(|info| {
        if !selected_name {
            return true;
        }
        info.path
            .as_ref()
            .and_then(|path| path.segments.last())
            .is_some_and(|segment| segment == name)
    });
    let mut saw_relevant = false;
    for info in relevant {
        saw_relevant = true;
        if let Some(structured_path) = info.path.as_ref() {
            if let Some(focus_index) =
                scala_direct_import_segment_index(import, focus_start_byte, focus_end_byte)
                && focus_index + 1 < structured_path.segments.len()
                && structured_path.segments[focus_index] == scala_node_text(node, source).trim()
            {
                let prefix_segments = &structured_path.segments[..=focus_index];
                let prefix = prefix_segments.join(".");
                for owner_tier in
                    scala_owner_qualified_import_candidate_tiers(&enclosing_owners, prefix_segments)
                {
                    if let Some(indexed) = scala_fqn_probe(support, owner_tier) {
                        return Some(candidates_outcome(indexed));
                    }
                }
                let lexical_prefixes = if structured_path.lexical_prefixes.is_empty() {
                    resolver.package_prefixes.as_slice()
                } else {
                    structured_path.lexical_prefixes.as_slice()
                };
                for candidate in scala_import_path_candidates(&prefix, lexical_prefixes) {
                    if let Some(indexed) = scala_fqn_probe(support, vec![candidate.clone()]) {
                        return Some(candidates_outcome(indexed));
                    }
                    if support.package_exists(&candidate) {
                        return Some(boundary(format!(
                            "`{prefix}` is a Scala import package segment without a declaration target"
                        )));
                    }
                }
            }
            // Enclosing-owner-qualified candidates take precedence over
            // package-lexical-prefix ones: they mirror the nearer scope Scala
            // actually binds against first. Unlike the package-based tier
            // loop below, this check is not gated by `selected_name` — it must
            // also resolve a plain base-path click such as `Registry` in
            // `import Registry._`, which is neither a selector nor an alias.
            for owner_tier in scala_owner_qualified_import_candidate_tiers(
                &enclosing_owners,
                &structured_path.segments,
            ) {
                if let Some(indexed) = scala_fqn_probe(support, owner_tier) {
                    return Some(candidates_outcome(indexed));
                }
            }
            for tier in resolver.structured_import_type_candidate_tiers(structured_path, &[]) {
                if let Some(indexed) = scala_fqn_probe(support, tier) {
                    return selected_name.then(|| candidates_outcome(indexed));
                }
            }
        }
        let Some(path) = scala_import_path(&info) else {
            continue;
        };
        for candidate in import_candidate_fq_names(
            &path,
            &scala_package_name_of(scala, file).unwrap_or_default(),
        ) {
            if support.fqn_exists(&candidate)
                || support.fqn_exists(&format!("{candidate}$"))
                || support.fqn_exists(&scala_normalized_fq_name(&candidate))
            {
                return None;
            }
        }
    }
    saw_relevant.then(|| {
        boundary(format!(
            "`{name}` is part of a Scala import whose declaration is not indexed in this workspace"
        ))
    })
}

/// Candidate spellings of `segments` qualified by each enclosing owner in
/// turn (innermost first), reusing `scala_nested_type_candidates` so `$`
/// companion-object spelling stays in one place rather than being
/// hand-built here. Each returned tier corresponds to one enclosing owner;
/// callers probe tiers in order so the nearest enclosing scope wins.
fn scala_owner_qualified_import_candidate_tiers(
    owners: &[String],
    segments: &[String],
) -> Vec<Vec<String>> {
    owners
        .iter()
        .map(|owner| {
            scala_nested_type_candidates(owner.trim_end_matches('$').to_string(), segments, true)
        })
        .collect()
}

/// Probe `candidates` (and their trailing-`$` companion-object spellings)
/// against the workspace's indexed fqns, returning the sorted, deduped hits.
fn scala_fqn_probe(
    support: &dyn BoundedDefinitionLookup,
    candidates: Vec<String>,
) -> Option<Vec<CodeUnit>> {
    let mut indexed = candidates
        .into_iter()
        .flat_map(|candidate| {
            support
                .fqn(&candidate)
                .into_iter()
                .chain(support.fqn(&format!("{candidate}$")))
        })
        .collect::<Vec<_>>();
    sort_units(&mut indexed);
    indexed.dedup();
    (!indexed.is_empty()).then_some(indexed)
}

/// Return the parser-defined position of a simple import-path segment. Scala's
/// grammar exposes `import a.b.C` as ordered direct identifier children of the
/// declaration; selector names and aliases are nested below their selector
/// node and deliberately do not participate in this package-prefix check.
fn scala_direct_import_segment_index(
    import: Node<'_>,
    focus_start_byte: usize,
    focus_end_byte: usize,
) -> Option<usize> {
    let mut cursor = import.walk();
    import
        .named_children(&mut cursor)
        .filter(|child| {
            matches!(
                child.kind(),
                "identifier" | "type_identifier" | "operator_identifier"
            )
        })
        .position(|child| {
            child.start_byte() <= focus_start_byte && focus_end_byte <= child.end_byte()
        })
}

struct ScalaFocusedQualifiedPath<'tree> {
    segments: Vec<(Node<'tree>, String)>,
    focus_index: usize,
}

/// Preserve the parser's segment boundaries for a qualified path. The generic
/// string lookup helper intentionally flattens a complete type, which is right
/// when resolving its terminal declaration but loses which prefix the caller
/// selected in `Outer.Middle.Terminal`.
fn scala_focused_qualified_path<'tree>(
    node: Node<'tree>,
    source: &str,
    focus_start_byte: usize,
    focus_end_byte: usize,
) -> Option<ScalaFocusedQualifiedPath<'tree>> {
    let mut path = node;
    while let Some(parent) = path.parent().filter(|parent| {
        matches!(
            parent.kind(),
            "field_expression"
                | "stable_identifier"
                | "stable_type_identifier"
                | "projected_type"
                | "singleton_type"
                | "generic_type"
                | "applied_constructor_type"
                | "annotated_type"
        )
    }) {
        path = parent;
    }

    let mut nodes = Vec::new();
    let mut stack = vec![path];
    while let Some(current) = stack.pop() {
        match current.kind() {
            "identifier" | "operator_identifier" | "type_identifier" | "this" => {
                let segment = scala_node_text(current, source).trim();
                if !segment.is_empty() {
                    nodes.push((current, segment.to_string()));
                }
            }
            "type_arguments" | "arguments" | "annotation" | "structural_type" => {}
            _ => {
                let mut cursor = current.walk();
                let mut children = current.named_children(&mut cursor).collect::<Vec<_>>();
                children.reverse();
                stack.extend(children);
            }
        }
    }
    if nodes.len() <= 1 {
        return None;
    }
    let focus_index = nodes.iter().position(|(segment, _)| {
        segment.start_byte() <= focus_start_byte && focus_end_byte <= segment.end_byte()
    })?;
    Some(ScalaFocusedQualifiedPath {
        segments: nodes,
        focus_index,
    })
}

fn resolve_scala_focused_qualified_path(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver<'_>,
    root: Node<'_>,
    node: Node<'_>,
    focus_start_byte: usize,
    focus_end_byte: usize,
) -> Option<DefinitionLookupOutcome> {
    let path = scala_focused_qualified_path(node, ctx.source, focus_start_byte, focus_end_byte)?;
    let names = path
        .segments
        .iter()
        .map(|(_, name)| name.as_str())
        .collect::<Vec<_>>();

    // An owner-qualified self type denotes a child of the exact physical
    // enclosing declaration. A global FQN lookup is insufficient when JVM/JS
    // source sets contain identical rendered owner names.
    if path.focus_index + 1 == names.len() && names.len() >= 3 && names[names.len() - 2] == "this" {
        let owner_name = names[names.len() - 3];
        let member = names[names.len() - 1];
        let owner = scala_enclosing_class(
            ctx.analyzer,
            ctx.support,
            ctx.file,
            path.segments[path.focus_index].0.start_byte(),
        )?;
        if owner.identifier().trim_end_matches('$') != owner_name {
            return Some(no_definition(
                "no_indexed_definition",
                format!(
                    "`{}` is not a child of the enclosing Scala owner",
                    names.join(".")
                ),
            ));
        }
        let mut candidates = ctx
            .support
            .fqn_direct_children(&owner.fq_name())
            .into_iter()
            .filter(|unit| unit.identifier().trim_end_matches('$') == member)
            .filter(|unit| unit.source() == owner.source())
            .filter(|unit| ctx.scala.structural_parent_of(unit).as_ref() == Some(&owner))
            .filter(|unit| unit.is_class() || ctx.scala.is_type_alias(unit))
            .collect::<Vec<_>>();
        sort_units(&mut candidates);
        candidates.dedup();
        return Some(match candidates.as_slice() {
            [_] => candidates_outcome(candidates),
            [] => no_definition(
                "no_indexed_definition",
                format!("`{member}` is not an indexed child of `{owner_name}.this`"),
            ),
            _ => no_definition(
                "ambiguous_scala_type",
                format!("`{owner_name}.this.{member}` has multiple physical child declarations"),
            ),
        });
    }

    // Terminal resolution must continue through the normal field/type role so
    // a missing child cannot silently return its successfully resolved owner.
    if path.focus_index + 1 == names.len() {
        return None;
    }
    let root_name = names[0];
    let bindings = scala_bindings_before(ctx, resolver, root, focus_start_byte);
    if bindings.is_shadowed(root_name)
        || scala_lexical_binding_declares_name_before(root, ctx.source, root_name, focus_start_byte)
    {
        return Some(no_definition(
            "local_variable_reference",
            format!("`{root_name}` is a local Scala value"),
        ));
    }
    let prefix = names[..=path.focus_index]
        .iter()
        .map(|name| (*name).to_string())
        .collect::<Vec<_>>();
    let display = prefix.join(".");
    if prefix.len() == 1
        && let Some(imported_member) = resolver.resolve_member(root_name)
    {
        return Some(scala_fqn_outcome(ctx.support, &imported_member, &display));
    }
    match scala_exact_enclosing_singleton_path(ctx, focus_start_byte, &prefix) {
        ScalaExactMemberResolution::Found(candidates) => {
            return Some(candidates_outcome(candidates));
        }
        ScalaExactMemberResolution::Ambiguous => {
            return Some(no_definition(
                "ambiguous_scala_type",
                format!("`{display}` resolves to multiple physical Scala owners"),
            ));
        }
        ScalaExactMemberResolution::NoMatch => {}
    }
    let singleton = resolver.resolve_owner_segments(&prefix, ScalaOwnerKind::SingletonObject);
    let missing_singleton_import = singleton == ScalaNameResolution::MissingExplicitImport;
    match singleton {
        ScalaNameResolution::Resolved(owner) => {
            return Some(scala_fqn_outcome(ctx.support, &owner.fqn, &display));
        }
        ScalaNameResolution::Ambiguous => {
            return Some(no_definition(
                "ambiguous_scala_type",
                format!("`{display}` resolves to multiple physical Scala owners"),
            ));
        }
        ScalaNameResolution::MissingExplicitImport | ScalaNameResolution::Unresolved => {}
    }
    Some(
        match resolver.resolve_owner_segments(&prefix, ScalaOwnerKind::Class) {
            ScalaNameResolution::Resolved(owner) => {
                scala_fqn_outcome(ctx.support, &owner.fqn, &display)
            }
            ScalaNameResolution::Ambiguous => no_definition(
                "ambiguous_scala_type",
                format!("`{display}` resolves to multiple physical Scala owners"),
            ),
            ScalaNameResolution::MissingExplicitImport => boundary(format!(
                "`{root_name}` is bound by an explicit Scala import whose declaration is not indexed in this workspace"
            )),
            ScalaNameResolution::Unresolved if missing_singleton_import => boundary(format!(
                "`{root_name}` is bound by an explicit Scala import whose declaration is not indexed in this workspace"
            )),
            ScalaNameResolution::Unresolved => no_definition(
                "no_indexed_definition",
                format!("`{display}` did not resolve to an indexed Scala owner"),
            ),
        },
    )
}

fn scala_exact_enclosing_singleton_path(
    ctx: ScalaLookupCtx<'_>,
    focus_start_byte: usize,
    segments: &[String],
) -> ScalaExactMemberResolution {
    let Some(mut lexical_owner) =
        scala_enclosing_class(ctx.analyzer, ctx.support, ctx.file, focus_start_byte)
    else {
        return ScalaExactMemberResolution::NoMatch;
    };
    loop {
        let mut owner = lexical_owner.clone();
        let mut index = 0;
        if owner.identifier().trim_end_matches('$') == segments[0] && owner.fq_name().ends_with('$')
        {
            index = 1;
        }
        let mut matched = index > 0;
        while index < segments.len() {
            let segment = &segments[index];
            let mut children = ctx
                .support
                .fqn_direct_children(&owner.fq_name())
                .into_iter()
                .filter(|unit| unit.is_class() && unit.fq_name().ends_with('$'))
                .filter(|unit| unit.identifier().trim_end_matches('$') == segment)
                .filter(|unit| unit.source() == owner.source())
                .filter(|unit| ctx.scala.structural_parent_of(unit).as_ref() == Some(&owner))
                .collect::<Vec<_>>();
            sort_units(&mut children);
            children.dedup();
            match children.as_slice() {
                [child] => {
                    owner = child.clone();
                    matched = true;
                }
                [] => {
                    matched = false;
                    break;
                }
                [_, _, ..] => return ScalaExactMemberResolution::Ambiguous,
            }
            index += 1;
        }
        if matched && index == segments.len() {
            return ScalaExactMemberResolution::Found(vec![owner]);
        }
        let Some(parent) = ctx.scala.structural_parent_of(&lexical_owner) else {
            return ScalaExactMemberResolution::NoMatch;
        };
        lexical_owner = parent;
    }
}

/// Resolve a qualified type member supplied by a parser-recorded Scala 3
/// `export`. Export aliases have no declaration of their own, so return the
/// original exact declaration behind the export while retaining physical
/// owner/source identity throughout the nested-owner walk.
fn scala_exact_exported_qualified_type(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver<'_>,
    node: Node<'_>,
) -> ScalaTypeNamespaceResolution {
    let segments = scala_type_lookup_segments(node, ctx.source);
    let Some((member, owner_segments)) = segments.split_last() else {
        return ScalaTypeNamespaceResolution::NoMatch;
    };
    if owner_segments.is_empty() {
        return ScalaTypeNamespaceResolution::NoMatch;
    }

    let exporter =
        match scala_exact_enclosing_singleton_path(ctx, node.start_byte(), owner_segments) {
            ScalaExactMemberResolution::Found(mut candidates) if candidates.len() == 1 => {
                candidates.remove(0)
            }
            ScalaExactMemberResolution::Found(_) | ScalaExactMemberResolution::Ambiguous => {
                return ScalaTypeNamespaceResolution::NoMatch;
            }
            ScalaExactMemberResolution::NoMatch => {
                match resolver
                    .resolve_owner_segments(owner_segments, ScalaOwnerKind::SingletonObject)
                {
                    ScalaNameResolution::Resolved(owner) => owner._declaration,
                    ScalaNameResolution::Ambiguous => return ScalaTypeNamespaceResolution::NoMatch,
                    ScalaNameResolution::MissingExplicitImport
                    | ScalaNameResolution::Unresolved => {
                        return ScalaTypeNamespaceResolution::NoMatch;
                    }
                }
            }
        };

    if ctx.scala.export_infos_for_owner(&exporter).is_empty() {
        return ScalaTypeNamespaceResolution::NoMatch;
    }
    let direct_fqn = format!("{}.{member}", exporter.fq_name());
    let mut direct = ctx
        .support
        .fqn(&direct_fqn)
        .into_iter()
        .filter(|unit| unit.fq_name() == direct_fqn)
        .filter(|unit| unit.source() == exporter.source())
        .filter(|unit| ctx.scala.structural_parent_of(unit).as_ref() == Some(&exporter))
        .filter(|unit| unit.is_class() || ctx.scala.is_type_alias(unit))
        .collect::<Vec<_>>();
    sort_units(&mut direct);
    direct.dedup();
    match direct.as_slice() {
        [declaration] => {
            return ScalaTypeNamespaceResolution::Resolved(declaration.clone());
        }
        [_, _, ..] => return ScalaTypeNamespaceResolution::Ambiguous,
        [] => {}
    }

    let mut declarations = Vec::new();
    let mut matched_export = false;
    for export in ctx.scala.export_infos_for_owner(&exporter) {
        let named_sources = export
            .selectors
            .iter()
            .filter_map(|selector| match selector {
                ScalaExportSelector::Named { source_name, .. } => Some(source_name.clone()),
                ScalaExportSelector::Wildcard | ScalaExportSelector::GivenWildcard => None,
            })
            .collect::<HashSet<_>>();
        let Some(source_owner) =
            scala_exact_nested_singleton_owner(ctx, &exporter, &export.owner_path)
        else {
            // A parser-proven export may target an external owner which is
            // absent from this workspace. That is not evidence that a
            // declaration behind the export is missing or ambiguous.
            continue;
        };
        matched_export |= named_sources.contains(member);
        for selector in export.selectors {
            let source_name = match selector {
                ScalaExportSelector::Wildcard if !named_sources.contains(member) => member.clone(),
                ScalaExportSelector::Named {
                    source_name,
                    visible_name: Some(visible_name),
                } if visible_name == *member => source_name,
                ScalaExportSelector::GivenWildcard
                | ScalaExportSelector::Wildcard
                | ScalaExportSelector::Named {
                    visible_name: None, ..
                }
                | ScalaExportSelector::Named { .. } => continue,
            };
            matched_export = true;
            let target_fqn = format!("{}.{source_name}", source_owner.fq_name());
            declarations.extend(
                ctx.support
                    .fqn(&target_fqn)
                    .into_iter()
                    .filter(|unit| unit.fq_name() == target_fqn)
                    .filter(|unit| unit.source() == source_owner.source())
                    .filter(|unit| {
                        ctx.scala.structural_parent_of(unit).as_ref() == Some(&source_owner)
                    })
                    .filter(|unit| unit.is_class() || ctx.scala.is_type_alias(unit)),
            );
        }
    }
    sort_units(&mut declarations);
    declarations.dedup();
    match declarations.as_slice() {
        [declaration] => ScalaTypeNamespaceResolution::Resolved(declaration.clone()),
        [_, _, ..] => ScalaTypeNamespaceResolution::Ambiguous,
        [] if matched_export => ScalaTypeNamespaceResolution::AuthoritativeMiss,
        [] => ScalaTypeNamespaceResolution::NoMatch,
    }
}

fn scala_exact_nested_singleton_owner(
    ctx: ScalaLookupCtx<'_>,
    exporter: &CodeUnit,
    path: &[String],
) -> Option<CodeUnit> {
    let mut owner = exporter.clone();
    for segment in path {
        let nested_fqn = format!("{}.{segment}$", owner.fq_name());
        let mut candidates = ctx
            .support
            .fqn(&nested_fqn)
            .into_iter()
            .filter(|unit| unit.is_class() && unit.fq_name() == nested_fqn)
            .filter(|unit| unit.source() == owner.source())
            .filter(|unit| ctx.scala.structural_parent_of(unit).as_ref() == Some(&owner))
            .collect::<Vec<_>>();
        sort_units(&mut candidates);
        candidates.dedup();
        let [candidate] = candidates.as_slice() else {
            return None;
        };
        owner = candidate.clone();
    }
    Some(owner)
}

fn resolve_scala_parser_proven_term_role(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver<'_>,
    root: Node<'_>,
    node: Node<'_>,
) -> Option<DefinitionLookupOutcome> {
    if let Some(reference) = qualified_stable_type_reference(node, ctx.source)
        && matches!(
            reference.role,
            ScalaQualifiedStableTypeRole::Apply | ScalaQualifiedStableTypeRole::Extractor
        )
    {
        let root_name = reference
            .segments
            .first()
            .expect("qualified Scala term has a root segment");
        if reference.role == ScalaQualifiedStableTypeRole::Apply
            && resolver.resolve_member(root_name).is_some()
        {
            return None;
        }
        if scala_lexical_binding_declares_name_before(
            root,
            ctx.source,
            root_name,
            node.start_byte(),
        ) {
            return None;
        }
        let display_name = reference.segments.join(".");
        return Some(
            match resolver
                .resolve_owner_segments(&reference.segments, ScalaOwnerKind::SingletonObject)
            {
                ScalaNameResolution::Resolved(owner) => match reference.role {
                    ScalaQualifiedStableTypeRole::Apply => scala_apply_or_constructor_outcome(
                        ctx.scala,
                        ctx.support,
                        ctx.file,
                        &owner.fqn,
                        &display_name,
                        call_site_shape_for_reference(reference.expression).as_ref(),
                    ),
                    ScalaQualifiedStableTypeRole::Extractor => scala_extractor_outcome(
                        ctx,
                        &owner,
                        &display_name,
                        call_site_shape_for_reference(reference.expression).as_ref(),
                    ),
                    ScalaQualifiedStableTypeRole::Type
                    | ScalaQualifiedStableTypeRole::Constructor => unreachable!(),
                },
                ScalaNameResolution::MissingExplicitImport => boundary(format!(
                    "`{root_name}` is bound by an explicit Scala import whose declaration is not indexed in this workspace"
                )),
                ScalaNameResolution::Ambiguous => no_definition(
                    "ambiguous_scala_term_namespace",
                    format!("`{display_name}` resolves to multiple physical Scala objects"),
                ),
                ScalaNameResolution::Unresolved
                    if reference.role == ScalaQualifiedStableTypeRole::Extractor =>
                {
                    let resolution = scala_exact_extractor_class_owner(ctx, resolver, node)
                        .map(ScalaNameResolution::Resolved)
                        .unwrap_or_else(|| {
                            resolver
                                .resolve_owner_segments(&reference.segments, ScalaOwnerKind::Class)
                        });
                    match resolution {
                        ScalaNameResolution::Resolved(owner) => scala_extractor_class_outcome(
                            ctx,
                            &owner,
                            &display_name,
                            call_site_shape_for_reference(reference.expression).as_ref(),
                        ),
                        ScalaNameResolution::MissingExplicitImport => boundary(format!(
                            "`{root_name}` is bound by an explicit Scala import whose declaration is not indexed in this workspace"
                        )),
                        ScalaNameResolution::Ambiguous => no_definition(
                            "ambiguous_scala_term_namespace",
                            format!(
                                "`{display_name}` resolves to multiple physical Scala extractor classes"
                            ),
                        ),
                        ScalaNameResolution::Unresolved => no_definition(
                            "no_applicable_scala_callable",
                            format!("`{display_name}` has no indexed Scala extractor owner"),
                        ),
                    }
                }
                ScalaNameResolution::Unresolved => return None,
            },
        );
    }

    if !is_extractor_reference(node) {
        return None;
    }
    let name = scala_node_text(node, ctx.source).trim();
    if name.is_empty() {
        return Some(no_definition(
            "no_reference_text",
            "Scala extractor reference is blank",
        ));
    }
    if scala_lexical_binding_declares_name_before(root, ctx.source, name, node.start_byte()) {
        return Some(no_definition(
            "local_variable_reference",
            format!("`{name}` is a local Scala value"),
        ));
    }
    let resolution = match resolver.resolve_explicit_singleton(name) {
        ScalaNameResolution::Unresolved => match resolver.resolve_wildcard_singleton(name) {
            ScalaNameResolution::Unresolved => {
                resolver.resolve_owner(name, ScalaOwnerKind::SingletonObject)
            }
            outcome => outcome,
        },
        outcome => outcome,
    };
    Some(match resolution {
        ScalaNameResolution::Resolved(owner) => scala_extractor_outcome(
            ctx,
            &owner,
            name,
            call_site_shape_for_reference(node).as_ref(),
        ),
        ScalaNameResolution::MissingExplicitImport => boundary(format!(
            "`{name}` is bound by an explicit Scala import whose declaration is not indexed in this workspace"
        )),
        ScalaNameResolution::Ambiguous => no_definition(
            "ambiguous_scala_term_namespace",
            format!("`{name}` resolves to multiple physical Scala objects"),
        ),
        ScalaNameResolution::Unresolved => {
            let resolution = scala_exact_extractor_class_owner(ctx, resolver, node)
                .map(ScalaNameResolution::Resolved)
                .unwrap_or_else(|| resolver.resolve_owner(name, ScalaOwnerKind::Class));
            match resolution {
                ScalaNameResolution::Resolved(owner) => scala_extractor_class_outcome(
                    ctx,
                    &owner,
                    name,
                    call_site_shape_for_reference(node).as_ref(),
                ),
                ScalaNameResolution::MissingExplicitImport => boundary(format!(
                    "`{name}` is bound by an explicit Scala import whose declaration is not indexed in this workspace"
                )),
                ScalaNameResolution::Ambiguous => no_definition(
                    "ambiguous_scala_term_namespace",
                    format!("`{name}` resolves to multiple physical Scala extractor classes"),
                ),
                ScalaNameResolution::Unresolved => no_definition(
                    "no_applicable_scala_callable",
                    format!("`{name}` has no indexed Scala extractor owner"),
                ),
            }
        }
    })
}

fn scala_extractor_outcome(
    ctx: ScalaLookupCtx<'_>,
    owner: &ScalaOwnerIdentity,
    reference: &str,
    call_shape: Option<&ScalaCallSiteShape>,
) -> DefinitionLookupOutcome {
    let mut candidates = ["unapply", "unapplySeq"]
        .into_iter()
        .flat_map(|member| ctx.support.fqn(&format!("{}.{member}", owner.fqn)))
        .filter(|unit| unit.is_function())
        .filter(|unit| ctx.scala.structural_parent_of(unit).as_ref() == Some(&owner._declaration))
        .collect::<Vec<_>>();
    sort_units(&mut candidates);
    candidates.dedup();
    match scala_physical_callable_candidates(ctx.scala, candidates) {
        ScalaPhysicalCallableCandidates::Unique(candidates) => {
            return candidates_outcome(candidates);
        }
        ScalaPhysicalCallableCandidates::Ambiguous => {
            return no_definition(
                "ambiguous_scala_callable",
                format!("`{reference}` has multiple physical extractor owners"),
            );
        }
        ScalaPhysicalCallableCandidates::NoCandidates => {}
    }

    let class_fqn = owner.fqn.trim_end_matches('$');
    let class_units = ctx
        .support
        .fqn(class_fqn)
        .into_iter()
        .filter(|unit| {
            unit.is_class()
                && unit.fq_name() == class_fqn
                && unit.source() == owner._declaration.source()
        })
        .collect::<Vec<_>>();
    if let [class] = class_units.as_slice() {
        let constructor_name = scala_constructor_member_name(class_fqn);
        let constructor_fqn = format!("{class_fqn}.{constructor_name}");
        let constructors = ctx
            .support
            .fqn(&constructor_fqn)
            .into_iter()
            .filter(|unit| unit.is_function() && unit.fq_name() == constructor_fqn)
            .filter(|unit| ctx.scala.structural_parent_of(unit).as_ref() == Some(class))
            .collect::<Vec<_>>();
        match scala_physical_callable_candidates(
            ctx.scala,
            scala_filter_callable_units(
                ctx.scala,
                constructors,
                call_shape,
                ScalaCallableSiteRole::PrimaryConstruction,
            ),
        ) {
            ScalaPhysicalCallableCandidates::Unique(candidates) => {
                return candidates_outcome(candidates);
            }
            ScalaPhysicalCallableCandidates::Ambiguous => {
                return no_definition(
                    "ambiguous_scala_callable",
                    format!("`{reference}` has multiple physical extractor constructors"),
                );
            }
            ScalaPhysicalCallableCandidates::NoCandidates => {}
        }
    }
    no_definition(
        "no_applicable_scala_callable",
        format!(
            "`{reference}` has no indexed companion `unapply`, `unapplySeq`, or primary extractor constructor"
        ),
    )
}

/// Case-class companions may be parser-synthetic and therefore have no
/// physical object CodeUnit. In a parser-proven extractor role, retain the
/// exact imported class and validate its synthetic primary constructor instead
/// of falling back into the type namespace. Parameterized enum cases project a
/// uniquely validated constructor back to the physical case-class declaration;
/// ordinary case classes retain the constructor as their callable identity.
fn scala_extractor_class_outcome(
    ctx: ScalaLookupCtx<'_>,
    class: &ScalaOwnerIdentity,
    reference: &str,
    call_shape: Option<&ScalaCallSiteShape>,
) -> DefinitionLookupOutcome {
    let class_fqn = class.fqn.trim_end_matches('$');
    let constructor_name = scala_constructor_member_name(class_fqn);
    let constructor_fqn = format!("{class_fqn}.{constructor_name}");
    let constructors = ctx
        .support
        .fqn(&constructor_fqn)
        .into_iter()
        .filter(|unit| unit.is_function() && unit.fq_name() == constructor_fqn)
        .filter(|unit| ctx.scala.structural_parent_of(unit).as_ref() == Some(&class._declaration))
        .collect::<Vec<_>>();
    match scala_physical_callable_candidates(
        ctx.scala,
        scala_filter_callable_units(
            ctx.scala,
            constructors,
            call_shape,
            ScalaCallableSiteRole::PrimaryConstruction,
        ),
    ) {
        ScalaPhysicalCallableCandidates::Unique(candidates) => {
            if ctx.scala.is_full_enum_case_declaration(&class._declaration) {
                candidates_outcome(vec![class._declaration.clone()])
            } else {
                candidates_outcome(candidates)
            }
        }
        ScalaPhysicalCallableCandidates::Ambiguous => no_definition(
            "ambiguous_scala_callable",
            format!("`{reference}` has multiple physical extractor constructor owners"),
        ),
        ScalaPhysicalCallableCandidates::NoCandidates => no_definition(
            "no_applicable_scala_callable",
            format!("`{reference}` has no indexed synthetic extractor constructor"),
        ),
    }
}

fn scala_exact_extractor_class_owner(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver<'_>,
    node: Node<'_>,
) -> Option<ScalaOwnerIdentity> {
    let declaration = scala_resolve_visible_type_declaration(ctx, resolver, node)
        .filter(|unit| unit.is_class() && !ctx.scala.is_type_alias(unit))?;
    Some(ScalaOwnerIdentity {
        fqn: declaration.fq_name(),
        kind: ScalaOwnerKind::Class,
        _declaration: declaration,
    })
}

#[allow(clippy::too_many_arguments)]
fn resolve_scala_bare_apply_fast_path(
    scala: &ScalaAnalyzer,
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    node: Node<'_>,
    resolver: &ScalaNameResolver<'_>,
    session: Option<&ResolutionSession>,
) -> Option<DefinitionLookupOutcome> {
    let Some(ScalaReferenceNode::Call(call)) = scala_reference_node(node) else {
        return None;
    };
    let function = call.child_by_field_name("function")?;
    if !matches!(function.kind(), "identifier" | "type_identifier") {
        return None;
    }
    let name = scala_node_text(function, source).trim();
    if name.is_empty() {
        return None;
    }
    let ctx = ScalaLookupCtx {
        scala,
        analyzer,
        support,
        file,
        source,
        session,
    };
    let call_shape = scala_call_site_shape(ctx, root, function);
    let active_path_declares_name = match scala_active_path_declares_name_before_in_session(
        session,
        root,
        source,
        name,
        function.start_byte(),
    ) {
        Some(declares_name) => declares_name,
        None => {
            return Some(no_definition(
                "scala_resolution_budget_exceeded",
                "Scala bare-call shadow traversal exceeded the receiver-resolution budget",
            ));
        }
    };
    if active_path_declares_name
        || scala_enclosing_member_shadows_bare_call(
            scala,
            analyzer,
            support,
            file,
            function.start_byte(),
            name,
        )
        || scala_imported_member_shadows_bare_call(scala, support, file, name, call_shape.as_ref())
        || resolver.resolve_wildcard_singleton(name) != ScalaNameResolution::Unresolved
    {
        return None;
    }

    let local_segments = [name.to_string()];
    if resolver.resolve_explicit_singleton(name) == ScalaNameResolution::Unresolved {
        match scala_exact_lexical_singleton_for_call(ctx, function, name) {
            ScalaExactMemberResolution::Found(mut owners) => {
                let owner = owners.pop().expect("found lexical singleton owner");
                return Some(scala_exact_singleton_apply_outcome(
                    ctx,
                    &owner,
                    name,
                    call_shape.as_ref(),
                ));
            }
            ScalaExactMemberResolution::Ambiguous => {
                return Some(no_definition(
                    "ambiguous_scala_lexical_singleton",
                    format!("`{name}` has multiple physical lexical singleton definitions"),
                ));
            }
            ScalaExactMemberResolution::NoMatch => {}
        }
        match scala_exact_lexical_type_namespace(ctx, resolver, function) {
            ScalaTypeNamespaceResolution::Resolved(owner)
                if owner.is_class() && !scala.is_type_alias(&owner) =>
            {
                return Some(scala_exact_type_apply_or_constructor_outcome(
                    ctx,
                    &owner,
                    name,
                    call_shape.as_ref(),
                ));
            }
            ScalaTypeNamespaceResolution::AuthoritativeMiss => {
                return Some(no_definition(
                    "local_type_binding",
                    format!("`{name}` is a local Scala type binding without a callable identity"),
                ));
            }
            ScalaTypeNamespaceResolution::Ambiguous => {
                return Some(no_definition(
                    "ambiguous_scala_type",
                    format!("`{name}` resolves to multiple exact Scala type declarations"),
                ));
            }
            ScalaTypeNamespaceResolution::Resolved(_) | ScalaTypeNamespaceResolution::NoMatch => {}
        }
        if let Some(owner_fqn) =
            scala_same_file_type_fqn(ctx, &local_segments, ScalaOwnerKind::Class)
        {
            return Some(scala_apply_or_constructor_outcome(
                scala,
                support,
                file,
                &owner_fqn,
                name,
                call_shape.as_ref(),
            ));
        }
    }
    let owner_fqn = resolver
        .resolve_singleton(name)
        .or_else(|| resolver.resolve(name))?;
    Some(scala_apply_or_constructor_outcome(
        scala,
        support,
        file,
        &owner_fqn,
        name,
        call_shape.as_ref(),
    ))
}

fn scala_exact_lexical_singleton_for_call(
    ctx: ScalaLookupCtx<'_>,
    reference: Node<'_>,
    name: &str,
) -> ScalaExactMemberResolution {
    let range = Range {
        start_byte: reference.start_byte(),
        end_byte: reference.end_byte(),
        start_line: reference.start_position().row,
        end_line: reference.end_position().row,
    };
    let mut current = ctx.analyzer.enclosing_code_unit(ctx.file, &range);
    while let Some(owner) = current {
        current = ctx.scala.structural_parent_of(&owner);
        if !owner.is_class() {
            continue;
        }
        let mut candidates = ctx
            .support
            .fqn_direct_children(&owner.fq_name())
            .into_iter()
            .filter(|candidate| {
                candidate.is_class()
                    && candidate.identifier().trim_end_matches('$') == name
                    && candidate.fq_name().ends_with('$')
            })
            .filter(|candidate| candidate.source() == owner.source())
            .filter(|candidate| ctx.scala.structural_parent_of(candidate).as_ref() == Some(&owner))
            .collect::<Vec<_>>();
        sort_units(&mut candidates);
        candidates.dedup();
        match candidates.len() {
            0 => {}
            1 => {
                let has_class_companion = ctx
                    .support
                    .fqn_direct_children(&owner.fq_name())
                    .into_iter()
                    .any(|candidate| {
                        candidate.is_class()
                            && candidate.identifier().trim_end_matches('$') == name
                            && !candidate.fq_name().ends_with('$')
                            && candidate.source() == owner.source()
                            && ctx.scala.structural_parent_of(&candidate).as_ref() == Some(&owner)
                    });
                if !has_class_companion {
                    return ScalaExactMemberResolution::Found(candidates);
                }
            }
            _ => return ScalaExactMemberResolution::Ambiguous,
        }
    }
    ScalaExactMemberResolution::NoMatch
}

fn scala_exact_singleton_apply_outcome(
    ctx: ScalaLookupCtx<'_>,
    owner: &CodeUnit,
    reference: &str,
    call_shape: Option<&ScalaCallSiteShape>,
) -> DefinitionLookupOutcome {
    let apply_fqn = format!("{}.apply", owner.fq_name());
    let mut units = ctx
        .support
        .fqn(&apply_fqn)
        .into_iter()
        .filter(|unit| unit.is_function() && unit.fq_name() == apply_fqn)
        .filter(|unit| ctx.scala.structural_parent_of(unit).as_ref() == Some(owner))
        .collect::<Vec<_>>();
    sort_units(&mut units);
    if let Some(call_shape) = call_shape
        && let [arguments] = call_shape.lists.as_slice()
        && arguments.kind == ScalaCallArgumentListKind::Ordinary
    {
        let exact_arity = units
            .iter()
            .filter(|candidate| {
                method_signature_arity(ctx.scala, candidate) == Some(arguments.arity)
            })
            .cloned()
            .collect::<Vec<_>>();
        match exact_arity.len() {
            0 => {}
            1 => units = exact_arity,
            _ => {
                return no_definition(
                    "ambiguous_scala_callable",
                    format!(
                        "`{reference}` has multiple same-arity lexical singleton `apply` overloads"
                    ),
                );
            }
        }
    }
    let candidates = scala_filter_callable_units(
        ctx.scala,
        units,
        call_shape,
        ScalaCallableSiteRole::Ordinary,
    );
    match scala_physical_callable_candidates(ctx.scala, candidates) {
        ScalaPhysicalCallableCandidates::Unique(candidates) => candidates_outcome(candidates),
        ScalaPhysicalCallableCandidates::Ambiguous => no_definition(
            "ambiguous_scala_callable",
            format!("`{reference}` has multiple physical lexical singleton `apply` definitions"),
        ),
        ScalaPhysicalCallableCandidates::NoCandidates => no_definition(
            "no_applicable_scala_callable",
            format!("`{reference}` has no applicable lexical singleton `apply`"),
        ),
    }
}

fn scala_exact_type_apply_or_constructor_outcome(
    ctx: ScalaLookupCtx<'_>,
    owner: &CodeUnit,
    reference: &str,
    call_shape: Option<&ScalaCallSiteShape>,
) -> DefinitionLookupOutcome {
    let class_fqn = owner.fq_name().trim_end_matches('$').to_string();
    let owner_parent = ctx.scala.structural_parent_of(owner);
    let companion_fqn = format!("{class_fqn}$");
    let mut companions = ctx
        .support
        .fqn(&companion_fqn)
        .into_iter()
        .filter(|candidate| {
            candidate.is_class()
                && candidate.fq_name() == companion_fqn
                && candidate.source() == owner.source()
                && ctx.scala.structural_parent_of(candidate) == owner_parent
        })
        .collect::<Vec<_>>();
    sort_units(&mut companions);
    companions.dedup();
    if companions.len() > 1 {
        return no_definition(
            "ambiguous_scala_callable",
            format!("`{reference}` has multiple exact companion owners"),
        );
    }
    if let Some(companion) = companions.first() {
        let apply_fqn = format!("{companion_fqn}.apply");
        let apply_candidates = scala_filter_callable_units(
            ctx.scala,
            ctx.support
                .fqn(&apply_fqn)
                .into_iter()
                .filter(|unit| unit.is_function() && unit.fq_name() == apply_fqn)
                .filter(|unit| ctx.scala.structural_parent_of(unit).as_ref() == Some(companion))
                .collect(),
            call_shape,
            ScalaCallableSiteRole::Ordinary,
        );
        if !apply_candidates.is_empty() {
            return candidates_outcome(apply_candidates);
        }
    }

    let constructor_name = scala_constructor_member_name(&class_fqn);
    let constructor_fqn = format!("{class_fqn}.{constructor_name}");
    let constructors = scala_filter_callable_units(
        ctx.scala,
        ctx.support
            .fqn(&constructor_fqn)
            .into_iter()
            .filter(|unit| unit.is_function() && unit.fq_name() == constructor_fqn)
            .filter(|unit| ctx.scala.structural_parent_of(unit).as_ref() == Some(owner))
            .collect(),
        call_shape,
        ScalaCallableSiteRole::PrimaryConstruction,
    );
    if !constructors.is_empty() {
        return candidates_outcome(constructors);
    }
    no_definition(
        "no_applicable_scala_callable",
        format!(
            "`{reference}` has no indexed exact companion `apply` or primary constructor matching this call"
        ),
    )
}

fn scala_apply_or_constructor_outcome(
    scala: &ScalaAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    reference_file: &ProjectFile,
    owner_fqn: &str,
    reference: &str,
    call_shape: Option<&ScalaCallSiteShape>,
) -> DefinitionLookupOutcome {
    let class_fqn = owner_fqn.trim_end_matches('$');
    let apply_fqn = format!("{class_fqn}$.apply");
    let apply_units = support
        .fqn(&apply_fqn)
        .into_iter()
        .filter(|unit| unit.is_function() && unit.fq_name() == apply_fqn)
        .collect::<Vec<_>>();
    let same_file_apply_units = apply_units
        .iter()
        .filter(|unit| unit.source() == reference_file)
        .cloned()
        .collect::<Vec<_>>();
    let apply_candidates = scala_physical_callable_candidates(
        scala,
        scala_filter_callable_units(
            scala,
            if same_file_apply_units.is_empty() {
                apply_units
            } else {
                same_file_apply_units
            },
            call_shape,
            ScalaCallableSiteRole::Ordinary,
        ),
    );
    match apply_candidates {
        ScalaPhysicalCallableCandidates::Unique(candidates) => {
            return candidates_outcome(candidates);
        }
        ScalaPhysicalCallableCandidates::Ambiguous => {
            return no_definition(
                "ambiguous_scala_callable",
                format!("`{reference}` has multiple physical companion `apply` owners"),
            );
        }
        ScalaPhysicalCallableCandidates::NoCandidates => {}
    }

    let constructor_name = scala_constructor_member_name(class_fqn);
    let constructor_fqn = format!("{class_fqn}.{constructor_name}");
    let constructor_units = support
        .fqn(&constructor_fqn)
        .into_iter()
        .filter(|unit| unit.is_function() && unit.fq_name() == constructor_fqn)
        .collect::<Vec<_>>();
    let same_file_constructor_units = constructor_units
        .iter()
        .filter(|unit| unit.source() == reference_file)
        .cloned()
        .collect::<Vec<_>>();
    let constructor_candidates = scala_physical_callable_candidates(
        scala,
        scala_filter_callable_units(
            scala,
            if same_file_constructor_units.is_empty() {
                constructor_units
            } else {
                same_file_constructor_units
            },
            call_shape,
            ScalaCallableSiteRole::PrimaryConstruction,
        ),
    );
    match constructor_candidates {
        ScalaPhysicalCallableCandidates::Unique(candidates) => {
            return candidates_outcome(candidates);
        }
        ScalaPhysicalCallableCandidates::Ambiguous => {
            return no_definition(
                "ambiguous_scala_callable",
                format!("`{reference}` has multiple physical constructor owners"),
            );
        }
        ScalaPhysicalCallableCandidates::NoCandidates => {}
    }

    no_definition(
        "no_applicable_scala_callable",
        format!(
            "`{reference}` has no indexed companion `apply` or universal constructor matching this call"
        ),
    )
}

fn scala_type_lookup_node_fqn(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    root: Node<'_>,
    node: Node<'_>,
) -> Option<ScalaTypeLookupResolution> {
    let node_text = scala_node_text(node, ctx.source).trim();
    if matches!(node_text, "this" | "super") {
        return scala_receiver_type_fqn(ctx, resolver, root, node, node.start_byte()).map(|fqn| {
            ScalaTypeLookupResolution::Type {
                fqn,
                target_kind: TypeLookupTargetKind::ValueExpression,
            }
        });
    }

    if matches!(
        node.kind(),
        "type_identifier" | "stable_type_identifier" | "generic_type"
    ) && scala_is_type_position(node)
    {
        return scala_resolve_visible_type_node(ctx, resolver, node).map(|fqn| {
            ScalaTypeLookupResolution::Type {
                fqn,
                target_kind: TypeLookupTargetKind::TypeReference,
            }
        });
    }

    if node.kind() == "instance_expression" {
        return scala_constructed_type(ctx, node, resolver).map(|fqn| {
            ScalaTypeLookupResolution::Type {
                fqn,
                target_kind: TypeLookupTargetKind::ValueExpression,
            }
        });
    }
    if node.kind() == "call_expression" {
        let bindings = scala_bindings_before(ctx, resolver, root, node.start_byte());
        return scala_call_result_type(ctx, resolver, root, node, node.start_byte(), &bindings)
            .map(|fqn| ScalaTypeLookupResolution::Type {
                fqn,
                target_kind: TypeLookupTargetKind::ValueExpression,
            });
    }

    if let Some(parent) = node.parent() {
        if parent.kind() == "field_expression" && parent.child_by_field_name("value") == Some(node)
        {
            return scala_receiver_type_fqn(ctx, resolver, root, node, node.start_byte()).map(
                |fqn| ScalaTypeLookupResolution::Type {
                    fqn,
                    target_kind: TypeLookupTargetKind::ValueExpression,
                },
            );
        }
        if scala_is_callable_declaration_name(parent, node) {
            return Some(ScalaTypeLookupResolution::InappropriateSymbolContext);
        }
        if let Some(fqn) = scala_declaration_name_type_fqn(ctx, resolver, root, parent, node) {
            return Some(ScalaTypeLookupResolution::Type {
                fqn,
                target_kind: TypeLookupTargetKind::ValueExpression,
            });
        }
    }

    if !matches!(
        node.kind(),
        "identifier" | "operator_identifier" | "type_identifier"
    ) {
        return None;
    }

    let name = scala_node_text(node, ctx.source).trim();
    let bindings = scala_bindings_before(ctx, resolver, root, node.start_byte());
    precise_scala_binding(&bindings, name)
        .and_then(|binding| binding.receiver_type)
        .map(|fqn| ScalaTypeLookupResolution::Type {
            fqn,
            target_kind: TypeLookupTargetKind::ValueExpression,
        })
}

fn scala_declaration_name_type_fqn(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    root: Node<'_>,
    parent: Node<'_>,
    name: Node<'_>,
) -> Option<String> {
    match parent.kind() {
        "parameter" | "class_parameter" if parent.child_by_field_name("name") == Some(name) => {
            parent
                .child_by_field_name("type")
                .and_then(|type_node| scala_resolve_visible_type_node(ctx, resolver, type_node))
        }
        "val_definition" | "var_definition"
            if parent
                .child_by_field_name("pattern")
                .is_some_and(|pattern| {
                    pattern.start_byte() <= name.start_byte()
                        && name.end_byte() <= pattern.end_byte()
                }) =>
        {
            parent
                .child_by_field_name("type")
                .and_then(|type_node| scala_resolve_visible_type_node(ctx, resolver, type_node))
        }
        "function_definition" if parent.child_by_field_name("name") == Some(name) => parent
            .child_by_field_name("return_type")
            .and_then(|type_node| scala_resolve_visible_type_node(ctx, resolver, type_node)),
        _ => {
            let name_text = scala_node_text(name, ctx.source).trim();
            let bindings = scala_bindings_before(ctx, resolver, root, name.end_byte());
            precise_scala_binding(&bindings, name_text).and_then(|binding| binding.receiver_type)
        }
    }
}

fn scala_is_callable_declaration_name(parent: Node<'_>, name: Node<'_>) -> bool {
    parent.child_by_field_name("name") == Some(name)
        && matches!(parent.kind(), "function_definition")
}

pub(super) fn parse_scala_tree(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&crate::analyzer::scala::language::LANGUAGE.into())
        .ok()?;
    parser.parse(source, None)
}

enum ScalaReferenceNode<'tree> {
    Type(Node<'tree>),
    Constructor(Node<'tree>),
    Call(Node<'tree>),
    InfixCall(Node<'tree>),
    PostfixCall(Node<'tree>),
    Field(Node<'tree>),
    StableIdentifier(Node<'tree>),
    Identifier(Node<'tree>),
    /// A named argument `name = value` in a call `Callee(name = ..)`: `name`
    /// resolves to the callee type's member/parameter, not a name in scope.
    NamedArgument {
        call: Node<'tree>,
        name: Node<'tree>,
    },
}

/// A named-argument identifier (`a` in `Foo(a = 3)`): the LHS of an
/// `assignment_expression` directly inside a call's `arguments`.
fn scala_named_argument(node: Node<'_>) -> Option<ScalaReferenceNode<'_>> {
    if node.kind() != "identifier" {
        return None;
    }
    let assignment = node
        .parent()
        .filter(|parent| parent.kind() == "assignment_expression")?;
    let is_lhs = assignment
        .child_by_field_name("left")
        .or_else(|| assignment.named_child(0))
        == Some(node);
    if !is_lhs {
        return None;
    }
    let arguments = assignment
        .parent()
        .filter(|parent| parent.kind() == "arguments")?;
    let call = arguments
        .parent()
        .filter(|parent| parent.kind() == "call_expression")?;
    Some(ScalaReferenceNode::NamedArgument { call, name: node })
}

fn scala_reference_node(node: Node<'_>) -> Option<ScalaReferenceNode<'_>> {
    if let Some(named) = scala_named_argument(node) {
        return Some(named);
    }
    let mut current = node;
    while let Some(parent) = current.parent() {
        if parent.kind() == "field_expression"
            && parent.child_by_field_name("field") == Some(current)
        {
            current = parent;
            continue;
        }
        if parent.kind() == "call_expression"
            && parent.child_by_field_name("function") == Some(current)
        {
            current = parent;
            continue;
        }
        if parent.kind() == "generic_function"
            && parent.child_by_field_name("function") == Some(current)
        {
            current = parent;
            continue;
        }
        if parent.kind() == "infix_expression"
            && parent.child_by_field_name("operator") == Some(current)
        {
            current = parent;
            continue;
        }
        if parent.kind() == "postfix_expression"
            && scala_postfix_method_node(parent) == Some(current)
        {
            current = parent;
            continue;
        }
        if parent.kind() == "instance_expression"
            && parent.start_byte() <= current.start_byte()
            && parent.end_byte() >= current.end_byte()
        {
            current = parent;
            continue;
        }
        if matches!(
            parent.kind(),
            "stable_identifier"
                | "stable_type_identifier"
                | "generic_type"
                | "annotated_type"
                | "applied_constructor_type"
                | "projected_type"
        ) {
            current = parent;
            continue;
        }
        if parent.kind() == "stable_type_identifier"
            && parent.named_child(parent.named_child_count().saturating_sub(1)) == Some(current)
        {
            current = parent;
            continue;
        }
        if parent.kind() == "generic_type" && parent.child_by_field_name("type") == Some(current) {
            current = parent;
            continue;
        }
        break;
    }

    match current.kind() {
        "call_expression" => Some(ScalaReferenceNode::Call(current)),
        "infix_expression" => Some(ScalaReferenceNode::InfixCall(current)),
        "postfix_expression" => Some(ScalaReferenceNode::PostfixCall(current)),
        "instance_expression" => Some(ScalaReferenceNode::Constructor(current)),
        "generic_function" => scala_unapplied_generic_reference(current),
        "field_expression" => Some(ScalaReferenceNode::Field(current)),
        "stable_identifier" => Some(ScalaReferenceNode::StableIdentifier(current)),
        "type_identifier"
        | "stable_type_identifier"
        | "generic_type"
        | "annotated_type"
        | "applied_constructor_type"
        | "projected_type" => Some(ScalaReferenceNode::Type(current)),
        "identifier" | "operator_identifier" => Some(ScalaReferenceNode::Identifier(current)),
        _ => None,
    }
}

fn scala_unapplied_generic_reference(mut node: Node<'_>) -> Option<ScalaReferenceNode<'_>> {
    while node.kind() == "generic_function" {
        node = node.child_by_field_name("function")?;
    }
    match node.kind() {
        "call_expression" => Some(ScalaReferenceNode::Call(node)),
        "infix_expression" => Some(ScalaReferenceNode::InfixCall(node)),
        "postfix_expression" => Some(ScalaReferenceNode::PostfixCall(node)),
        "field_expression" => Some(ScalaReferenceNode::Field(node)),
        "stable_identifier" => Some(ScalaReferenceNode::StableIdentifier(node)),
        "identifier" | "operator_identifier" => Some(ScalaReferenceNode::Identifier(node)),
        _ => None,
    }
}

fn scala_is_declaration_name(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    parent.child_by_field_name("name") == Some(node)
        && matches!(
            parent.kind(),
            "class_definition"
                | "object_definition"
                | "trait_definition"
                | "enum_definition"
                | "type_definition"
                | "function_definition"
                | "parameter"
                | "val_definition"
                | "var_definition"
        )
}

fn scala_is_type_position(node: Node<'_>) -> bool {
    if scala_is_recovered_union_type_position(node) {
        return true;
    }
    let mut current = node;
    while let Some(parent) = current.parent() {
        if parent.child_by_field_name("type") == Some(current)
            || parent.child_by_field_name("return_type") == Some(current)
        {
            return true;
        }
        if matches!(
            parent.kind(),
            "generic_type" | "stable_type_identifier" | "infix_type"
        ) {
            current = parent;
            continue;
        }
        return false;
    }
    false
}

/// Recognize tree-sitter's recovery shape for an unparenthesized Scala 3
/// union in a `val`/`var` type annotation.
///
/// For `val value: Left | Right`, the grammar can expose the declaration's
/// pattern as `alternative_pattern(typed_pattern(value, Left), Right)` rather
/// than an `infix_type`. The trailing node is still parser-structured: it is a
/// direct alternative after a typed declaration pattern, not an arbitrary
/// source-text guess. Treat that node as the continuation of the declared
/// type so term namespace lookup cannot capture it.
fn scala_is_recovered_union_type_position(node: Node<'_>) -> bool {
    let Some(alternative) = node
        .parent()
        .filter(|parent| parent.kind() == "alternative_pattern")
    else {
        return false;
    };
    if alternative.named_child(0) == Some(node) {
        return false;
    }
    let Some(declaration) = alternative
        .parent()
        .filter(|parent| matches!(parent.kind(), "val_definition" | "var_definition"))
    else {
        return false;
    };
    declaration.child_by_field_name("pattern") == Some(alternative)
        && alternative.named_child(0).is_some_and(|typed| {
            typed.kind() == "typed_pattern" && typed.child_by_field_name("type").is_some()
        })
}

#[derive(Clone, Copy)]
struct ScalaLookupCtx<'a> {
    scala: &'a ScalaAnalyzer,
    analyzer: &'a dyn IAnalyzer,
    support: &'a dyn BoundedDefinitionLookup,
    file: &'a ProjectFile,
    source: &'a str,
    session: Option<&'a ResolutionSession>,
}

impl ScalaLookupCtx<'_> {
    fn scope_step(self) -> bool {
        self.session.is_none_or(ResolutionSession::scope_step)
    }
}

fn scala_smallest_named_node_covering<'tree>(
    session: Option<&ResolutionSession>,
    mut node: Node<'tree>,
    start: usize,
    end: usize,
) -> Option<Node<'tree>> {
    if !session.is_none_or(ResolutionSession::scope_step)
        || node.start_byte() > start
        || node.end_byte() < end
    {
        return None;
    }
    loop {
        let mut containing = None;
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if !session.is_none_or(ResolutionSession::scope_step) {
                return None;
            }
            if child.start_byte() <= start && child.end_byte() >= end {
                containing = Some(child);
                break;
            }
        }
        match containing {
            Some(child) => node = child,
            None => return Some(node),
        }
    }
}

fn scala_charge_ancestor_path(session: Option<&ResolutionSession>, mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent() {
        if !session.is_none_or(ResolutionSession::scope_step) {
            return false;
        }
        node = parent;
    }
    true
}

fn scala_lexical_context_at(
    session: Option<&ResolutionSession>,
    root: Node<'_>,
    source: &str,
    reference_node: Node<'_>,
    reference_byte: usize,
) -> Option<(Vec<String>, Vec<StructuredImportScope>)> {
    let Some(session) = session else {
        return Some((
            scala_package_prefixes_at(root, source, reference_byte),
            scala_lexical_scope_path_at(root, reference_byte),
        ));
    };
    let mut inspect = |_: Node<'_>| session.scope_step();
    let package_prefixes =
        scala_package_prefixes_at_checked(root, source, reference_byte, &mut inspect)?;
    let lexical_scopes =
        scala_lexical_scope_path_checked(reference_node, |_: Node<'_>| session.scope_step())?;
    Some((package_prefixes, lexical_scopes))
}

fn scala_call_site_shape(
    ctx: ScalaLookupCtx<'_>,
    root: Node<'_>,
    reference: Node<'_>,
) -> Option<ScalaCallSiteShape> {
    let shape = call_site_shape_for_reference(reference)?;
    let method_value_arity = applied_expression_for_reference(reference)
        .and_then(|expression| scala_forward_method_value_arity(ctx, root, expression));
    Some(shape.with_method_value_arity(method_value_arity))
}

fn scala_forward_method_value_arity(
    ctx: ScalaLookupCtx<'_>,
    _root: Node<'_>,
    expression: Node<'_>,
) -> Option<usize> {
    let arguments = expression
        .parent()
        .filter(|parent| parent.kind() == "arguments")?;
    let mut arguments_cursor = arguments.walk();
    let parameter_index = arguments
        .named_children(&mut arguments_cursor)
        .position(|argument| argument == expression)?;
    let call = arguments.parent().filter(|parent| {
        parent.kind() == "call_expression"
            && parent.child_by_field_name("arguments") == Some(arguments)
    })?;
    let mut parameter_list = 0usize;
    let mut function = call.child_by_field_name("function")?;
    while function.kind() == "call_expression" {
        parameter_list += 1;
        function = function.child_by_field_name("function")?;
    }
    if function.kind() == "generic_function" {
        function = function.child_by_field_name("function")?;
    }
    if !matches!(function.kind(), "identifier" | "operator_identifier") {
        return None;
    }
    let function_name = scala_node_text(function, ctx.source).trim();
    if function_name.is_empty() {
        return None;
    }
    let call_arities = call_arities_for_reference(function)?;
    let mut methods = Vec::new();
    if let Some(method) = resolve_in_enclosing_scopes(
        ctx.analyzer,
        ctx.file,
        function_name,
        function.start_byte(),
        CodeUnit::is_function,
    ) {
        methods.push(method);
    } else if let Some(owner) =
        scala_enclosing_class(ctx.analyzer, ctx.support, ctx.file, function.start_byte())
        && let ScalaExactMemberResolution::Found(candidates) =
            scala_exact_owner_member_candidate_units(ctx, &owner, function_name, false)
    {
        methods.extend(candidates);
    }
    methods.sort();
    methods.dedup();
    let mut resolved = None;
    let actual = ScalaCallSiteShape::ordinary(&call_arities);
    for method in methods {
        let alternatives = scala_forward_callable_alternatives(ctx.scala, ctx.support, &method);
        let mut method_arity = None;
        for alternative in alternatives.iter().filter(|alternative| {
            scala_callable_alternative_matches(
                alternative.role,
                &alternative.shape,
                Some(&actual),
                ScalaCallableSiteRole::Ordinary,
                true,
            )
        }) {
            let arity = alternative
                .parameter_function_shapes
                .get(parameter_list)
                .and_then(|parameters| parameters.get(parameter_index))
                .and_then(Option::as_ref)
                .map(|shape| shape.arity)?;
            if method_arity.is_some_and(|resolved| resolved != arity) {
                return None;
            }
            method_arity = Some(arity);
        }
        let arity = method_arity?;
        if resolved.is_some_and(|resolved| resolved != arity) {
            return None;
        }
        resolved = Some(arity);
    }
    resolved
}

fn resolve_scala_type(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    root: Node<'_>,
    node: Node<'_>,
) -> DefinitionLookupOutcome {
    let text = scala_node_text(node, ctx.source).trim();
    if text.is_empty() {
        return no_definition("no_reference_text", "Scala type reference is blank");
    }
    if !scala_is_type_position(node)
        && scala_lexical_binding_declares_name_before(root, ctx.source, text, node.start_byte())
    {
        return no_definition(
            "local_variable_reference",
            format!("`{text}` is a local Scala value"),
        );
    }
    let type_segments = scala_type_lookup_segments(node, ctx.source);
    if let Some(root_name) = type_segments.first()
        && root_name != text
    {
        let bindings = scala_bindings_before(ctx, resolver, root, node.start_byte());
        if bindings.is_shadowed(root_name) {
            return no_definition(
                "local_variable_reference",
                format!("`{root_name}` is a local Scala value"),
            );
        }
    }
    let local_import = scala_enclosing_type_definition_range(node).and_then(|declaration_range| {
        (!type_segments.is_empty()).then(|| {
            resolver.resolve_explicit_owner_segments_in_range(
                &type_segments,
                scala_type_node_owner_kind(node),
                Some(declaration_range),
            )
        })
    });
    match local_import {
        Some(ScalaNameResolution::Resolved(owner)) => {
            return candidates_outcome(vec![owner._declaration]);
        }
        Some(ScalaNameResolution::MissingExplicitImport) => {
            return boundary(format!(
                "`{text}` is bound by a local explicit Scala import whose declaration is not indexed in this workspace"
            ));
        }
        Some(ScalaNameResolution::Ambiguous) => {
            return no_definition(
                "ambiguous_scala_explicit_import",
                format!("Local Scala explicit imports expose multiple `{text}` types"),
            );
        }
        Some(ScalaNameResolution::Unresolved) | None => {}
    }
    match scala_exact_lexical_type_namespace(ctx, resolver, node) {
        ScalaTypeNamespaceResolution::Resolved(declaration) => {
            return candidates_outcome(vec![declaration]);
        }
        ScalaTypeNamespaceResolution::AuthoritativeMiss => {
            return no_definition(
                "local_type_binding",
                format!("`{text}` is a local Scala type binding without a stable indexed identity"),
            );
        }
        ScalaTypeNamespaceResolution::Ambiguous => {
            return no_definition(
                "ambiguous_scala_type",
                format!("`{text}` resolves to multiple exact Scala type declarations"),
            );
        }
        ScalaTypeNamespaceResolution::NoMatch => {}
    }
    if !type_segments.is_empty() {
        match resolver
            .resolve_explicit_owner_segments(&type_segments, scala_type_node_owner_kind(node))
        {
            ScalaNameResolution::Resolved(owner) => {
                return candidates_outcome(vec![owner._declaration]);
            }
            ScalaNameResolution::MissingExplicitImport => {
                return boundary(format!(
                    "`{text}` is bound by an explicit Scala import whose declaration is not indexed in this workspace"
                ));
            }
            ScalaNameResolution::Ambiguous => {
                return no_definition(
                    "ambiguous_scala_explicit_import",
                    format!("Scala explicit imports expose multiple `{text}` types"),
                );
            }
            ScalaNameResolution::Unresolved => {}
        }
    }
    match scala_exact_exported_qualified_type(ctx, resolver, node) {
        ScalaTypeNamespaceResolution::Resolved(declaration) => {
            return candidates_outcome(vec![declaration]);
        }
        ScalaTypeNamespaceResolution::AuthoritativeMiss => {
            return no_definition(
                "unresolved_scala_export",
                format!(
                    "`{text}` is exported by an indexed Scala owner, but its source type is unavailable"
                ),
            );
        }
        ScalaTypeNamespaceResolution::Ambiguous => {
            return no_definition(
                "ambiguous_scala_type",
                format!("`{text}` resolves through multiple Scala export targets"),
            );
        }
        ScalaTypeNamespaceResolution::NoMatch => {}
    }
    if let Some(intrinsic) = scala_compiler_intrinsic_type_reference(&type_segments) {
        if type_segments.len() == 1 {
            match resolver.resolve_intrinsic_shadow(intrinsic, ScalaOwnerKind::TypeNamespace) {
                ScalaNameResolution::Resolved(owner) => {
                    return scala_fqn_outcome(ctx.support, &owner.fqn, text);
                }
                ScalaNameResolution::MissingExplicitImport => {
                    return boundary(format!(
                        "`{intrinsic}` is bound by an explicit Scala import whose declaration is not indexed in this workspace"
                    ));
                }
                ScalaNameResolution::Ambiguous => {
                    return no_definition(
                        "ambiguous_scala_type",
                        format!("`{intrinsic}` resolves to multiple higher-precedence Scala types"),
                    );
                }
                ScalaNameResolution::Unresolved => {}
            }
        }
        return no_definition(
            "scala_compiler_intrinsic_type",
            format!(
                "`{intrinsic}` is a compiler-provided Scala lattice type without a physical source declaration"
            ),
        );
    }
    if let Some(fqn) = scala_resolve_visible_type_node_after_lexical_miss(ctx, resolver, node) {
        return scala_fqn_outcome(ctx.support, &fqn, text);
    }
    if scala_import_boundary_for_name(ctx.scala, ctx.support, ctx.file, scala_simple_name(text)) {
        return boundary(format!(
            "`{text}` appears to cross a Scala import boundary not indexed in this workspace"
        ));
    }
    no_definition(
        "no_indexed_definition",
        format!("`{text}` did not resolve to an indexed Scala type"),
    )
}

fn scala_enclosing_type_definition_range(mut node: Node<'_>) -> Option<(usize, usize)> {
    loop {
        if matches!(
            node.kind(),
            "class_definition" | "object_definition" | "trait_definition" | "enum_definition"
        ) {
            return Some((node.start_byte(), node.end_byte()));
        }
        node = node.parent()?;
    }
}

fn scala_compiler_intrinsic_type_reference(segments: &[String]) -> Option<&str> {
    let name = match segments {
        [name] => name.as_str(),
        [scala, name] if scala == "scala" => name.as_str(),
        [root, scala, name] if root == "_root_" && scala == "scala" => name.as_str(),
        _ => return None,
    };
    matches!(
        name,
        "Any" | "AnyRef" | "Nothing" | "Null" | "Singleton" | "Matchable"
    )
    .then_some(name)
}

/// Resolve a named argument (`Foo(a = 3)`, caret on `a`) to the callee type's
/// member `a` — case-class parameters are members (`Foo.a`).
fn resolve_scala_named_argument(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    call: Node<'_>,
    name_node: Node<'_>,
) -> DefinitionLookupOutcome {
    let arg_name = scala_node_text(name_node, ctx.source).trim();
    if arg_name.is_empty() {
        return no_definition("no_reference_text", "Scala named argument is blank");
    }
    let function = call
        .child_by_field_name("function")
        .filter(|function| matches!(function.kind(), "identifier" | "type_identifier"));
    if let Some(function) = function {
        match scala_exact_lexical_type_namespace(ctx, resolver, function) {
            ScalaTypeNamespaceResolution::Resolved(exact_owner) => {
                return match scala_exact_owner_member_candidate_units(
                    ctx,
                    &exact_owner,
                    arg_name,
                    false,
                ) {
                    ScalaExactMemberResolution::Found(candidates) => candidates_outcome(candidates),
                    ScalaExactMemberResolution::Ambiguous => no_definition(
                        "ambiguous_scala_named_argument",
                        format!(
                            "named argument `{arg_name}` has multiple declarations on the exact callee owner"
                        ),
                    ),
                    ScalaExactMemberResolution::NoMatch => no_definition(
                        "no_indexed_definition",
                        format!(
                            "named argument `{arg_name}` is not a member of `{}`",
                            exact_owner.fq_name()
                        ),
                    ),
                };
            }
            ScalaTypeNamespaceResolution::Ambiguous => {
                return no_definition(
                    "ambiguous_scala_named_argument_owner",
                    format!("named argument `{arg_name}` has an ambiguous lexical callee owner"),
                );
            }
            ScalaTypeNamespaceResolution::AuthoritativeMiss => {
                return no_definition(
                    "local_type_binding",
                    format!(
                        "named argument `{arg_name}` has a local callee type without indexed identity"
                    ),
                );
            }
            ScalaTypeNamespaceResolution::NoMatch => {}
        }
    }
    let owner_fqn = function
        .map(|function| scala_node_text(function, ctx.source).trim())
        .filter(|callee| !callee.is_empty())
        .and_then(|callee| resolver.resolve(callee));
    let Some(owner_fqn) = owner_fqn else {
        return no_definition(
            "no_indexed_definition",
            format!("named argument `{arg_name}` receiver could not be typed"),
        );
    };
    let candidates = scala_member_candidate_units(ctx, &owner_fqn, arg_name, false);
    if candidates.is_empty() {
        return no_definition(
            "no_indexed_definition",
            format!("named argument `{arg_name}` is not a member of `{owner_fqn}`"),
        );
    }
    candidates_outcome(candidates)
}

fn resolve_scala_call(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    root: Node<'_>,
    call: Node<'_>,
) -> DefinitionLookupOutcome {
    let Some(function) = call.child_by_field_name("function") else {
        return no_definition("no_function_name", "Scala call expression has no function");
    };
    let Some(function) = scala_direct_application_target(function) else {
        return no_definition(
            SCALA_UNSUPPORTED_CALL_TARGET_SHAPE,
            "Scala direct application chain has no structured terminal callable",
        );
    };
    let call_shape = scala_call_site_shape(ctx, root, function);
    match function.kind() {
        "instance_expression" => resolve_scala_constructor(ctx, resolver, function),
        "field_expression" => resolve_scala_field(ctx, resolver, root, function),
        "identifier" | "type_identifier" => {
            let name = scala_node_text(function, ctx.source).trim();
            if name.is_empty() {
                return no_definition("no_function_name", "Scala call name is blank");
            }
            if scala_lexical_binding_declares_name_before(
                root,
                ctx.source,
                name,
                function.start_byte(),
            ) {
                return no_definition(
                    "local_variable_reference",
                    format!("`{name}` is a local Scala value"),
                );
            }
            if let Some(fqn) = resolver.resolve_member(name) {
                let candidates = scala_filter_callable_units(
                    ctx.scala,
                    ctx.support.fqn(&fqn),
                    call_shape.as_ref(),
                    ScalaCallableSiteRole::Ordinary,
                );
                if !candidates.is_empty() {
                    return candidates_outcome(candidates);
                }
            }
            if let Some(unit) = resolve_in_enclosing_scopes(
                ctx.analyzer,
                ctx.file,
                name,
                function.start_byte(),
                |unit| unit.is_function(),
            ) && !ctx
                .scala
                .structural_parent_of(&unit)
                .is_some_and(|owner| owner.is_class())
                && scala_member_unit_applies(
                    ctx.scala,
                    &unit,
                    call_shape.as_ref(),
                    ScalaCallableSiteRole::Ordinary,
                    true,
                )
            {
                return candidates_outcome(vec![unit]);
            }
            if function.kind() == "identifier"
                && let Some(owner) = scala_enclosing_class(
                    ctx.analyzer,
                    ctx.support,
                    ctx.file,
                    function.start_byte(),
                )
                && owner.identifier() != name
            {
                match scala_exact_owner_typed_overload_resolution(
                    ctx,
                    resolver,
                    call,
                    &owner,
                    name,
                    call_shape.as_ref(),
                ) {
                    ScalaTypedOverloadResolution::Found(candidates) => {
                        return candidates_outcome(candidates);
                    }
                    ScalaTypedOverloadResolution::NoApplicable => {
                        return no_definition(
                            "no_applicable_scala_typed_overload",
                            format!(
                                "`{name}` has no overload applicable to the constructed argument type"
                            ),
                        );
                    }
                    ScalaTypedOverloadResolution::Ambiguous => {
                        return no_definition(
                            "ambiguous_scala_typed_overload",
                            format!(
                                "`{name}` overloads cannot be selected from exact argument type identity"
                            ),
                        );
                    }
                    ScalaTypedOverloadResolution::NotNeeded => {}
                }
                match scala_exact_owner_member_candidate_units(ctx, &owner, name, false) {
                    ScalaExactMemberResolution::Found(candidates) => {
                        let has_ordinary_member = candidates.iter().any(|unit| {
                            scala_unit_has_callable_role(
                                ctx.scala,
                                unit,
                                ScalaCallableRole::Ordinary,
                            )
                        });
                        let candidates = scala_filter_callable_units(
                            ctx.scala,
                            candidates,
                            call_shape.as_ref(),
                            ScalaCallableSiteRole::Ordinary,
                        );
                        if !candidates.is_empty() {
                            return candidates_outcome(candidates);
                        }
                        if has_ordinary_member {
                            return no_definition(
                                "no_applicable_scala_callable",
                                format!(
                                    "`{name}` has no enclosing member overload matching this call"
                                ),
                            );
                        }
                    }
                    ScalaExactMemberResolution::Ambiguous => {
                        return no_definition(
                            "ambiguous_scala_enclosing_member",
                            format!("`{name}` has multiple physical enclosing-owner definitions"),
                        );
                    }
                    ScalaExactMemberResolution::NoMatch => {
                        let mut lexical_owner = ctx.scala.structural_parent_of(&owner);
                        while let Some(candidate_owner) = lexical_owner {
                            lexical_owner = ctx.scala.structural_parent_of(&candidate_owner);
                            if !candidate_owner.is_class() {
                                continue;
                            }
                            match scala_exact_owner_member_candidate_units(
                                ctx,
                                &candidate_owner,
                                name,
                                false,
                            ) {
                                ScalaExactMemberResolution::Found(candidates) => {
                                    let has_ordinary_member = candidates.iter().any(|unit| {
                                        scala_unit_has_callable_role(
                                            ctx.scala,
                                            unit,
                                            ScalaCallableRole::Ordinary,
                                        )
                                    });
                                    let candidates = scala_filter_callable_units(
                                        ctx.scala,
                                        candidates,
                                        call_shape.as_ref(),
                                        ScalaCallableSiteRole::Ordinary,
                                    );
                                    if !candidates.is_empty() {
                                        return candidates_outcome(candidates);
                                    }
                                    if has_ordinary_member {
                                        return no_definition(
                                            "no_applicable_scala_callable",
                                            format!(
                                                "`{name}` has no lexically enclosing member overload matching this call"
                                            ),
                                        );
                                    }
                                }
                                ScalaExactMemberResolution::Ambiguous => {
                                    return no_definition(
                                        "ambiguous_scala_enclosing_member",
                                        format!(
                                            "`{name}` has multiple physical lexically enclosing definitions"
                                        ),
                                    );
                                }
                                ScalaExactMemberResolution::NoMatch => {}
                            }
                        }
                        let candidates = scala_filter_callable_units(
                            ctx.scala,
                            scala_source_ancestor_member_units(ctx, resolver, function, name),
                            call_shape.as_ref(),
                            ScalaCallableSiteRole::Ordinary,
                        );
                        if !candidates.is_empty() {
                            return candidates_outcome(candidates);
                        }
                    }
                }
            }
            match resolver.resolve_explicit_singleton(name) {
                ScalaNameResolution::Resolved(owner) => {
                    return scala_apply_or_constructor_outcome(
                        ctx.scala,
                        ctx.support,
                        ctx.file,
                        &owner.fqn,
                        name,
                        call_shape.as_ref(),
                    );
                }
                ScalaNameResolution::MissingExplicitImport => {
                    return boundary(format!(
                        "`{name}` is bound by an explicit Scala import whose declaration is not indexed in this workspace"
                    ));
                }
                ScalaNameResolution::Ambiguous => {
                    return no_definition(
                        "ambiguous_scala_explicit_import",
                        format!("Scala explicit imports expose multiple `{name}` objects"),
                    );
                }
                ScalaNameResolution::Unresolved => {}
            }
            if let Some(imported_member) =
                scala_wildcard_imported_member_outcome(ctx, name, call_shape.as_ref())
            {
                return imported_member;
            }
            match resolver.resolve_wildcard_singleton(name) {
                ScalaNameResolution::Resolved(owner) => {
                    return scala_apply_or_constructor_outcome(
                        ctx.scala,
                        ctx.support,
                        ctx.file,
                        &owner.fqn,
                        name,
                        call_shape.as_ref(),
                    );
                }
                ScalaNameResolution::Ambiguous => {
                    return no_definition(
                        "ambiguous_scala_wildcard_import",
                        format!("Scala wildcard imports expose multiple `{name}` objects"),
                    );
                }
                ScalaNameResolution::MissingExplicitImport | ScalaNameResolution::Unresolved => {}
            }
            if let Some(owner) = scala_resolve_visible_type_declaration(ctx, resolver, function)
                && owner.is_class()
                && !ctx.scala.is_type_alias(&owner)
            {
                return scala_exact_type_apply_or_constructor_outcome(
                    ctx,
                    &owner,
                    name,
                    call_shape.as_ref(),
                );
            }
            if let Some(owner_fqn) = resolver.resolve_singleton(name).or_else(|| {
                scala_resolve_visible_type_annotation(ctx, resolver, name, function.start_byte())
            }) {
                return scala_apply_or_constructor_outcome(
                    ctx.scala,
                    ctx.support,
                    ctx.file,
                    &owner_fqn,
                    name,
                    call_shape.as_ref(),
                );
            }
            if scala_import_boundary_for_name(ctx.scala, ctx.support, ctx.file, name) {
                return boundary(format!(
                    "`{name}` appears to cross a Scala import boundary not indexed in this workspace"
                ));
            }
            no_definition(
                "no_indexed_definition",
                format!("`{name}` did not resolve to an indexed Scala callable"),
            )
        }
        _ => no_definition(
            SCALA_UNSUPPORTED_CALL_TARGET_SHAPE,
            format!(
                "Scala `{}` call targets are not resolved by get_definition yet",
                function.kind()
            ),
        ),
    }
}

fn scala_direct_application_target(mut function: Node<'_>) -> Option<Node<'_>> {
    loop {
        function = match function.kind() {
            "call_expression" | "generic_function" => function.child_by_field_name("function")?,
            _ => return Some(function),
        };
    }
}

fn resolve_scala_infix_call(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    root: Node<'_>,
    call: Node<'_>,
) -> DefinitionLookupOutcome {
    let Some(operator) = call.child_by_field_name("operator") else {
        return no_definition("no_function_name", "Scala infix expression has no operator");
    };
    let name = scala_node_text(operator, ctx.source).trim();
    if name.is_empty() {
        return no_definition("no_function_name", "Scala infix operator is blank");
    }
    if scala_is_compound_infix_call(call) {
        return no_definition(
            SCALA_UNSUPPORTED_RECEIVER,
            format!(
                "compound Scala infix member `{name}` requires precedence-aware receiver reconstruction"
            ),
        );
    }
    let receiver_field = if name.ends_with(':') { "right" } else { "left" };
    let Some(receiver) = call.child_by_field_name(receiver_field) else {
        return no_definition(
            SCALA_UNSUPPORTED_RECEIVER,
            "Scala infix expression has no semantic receiver",
        );
    };
    let call_shape = call_site_shape_for_reference(operator);
    if let Some(owner) =
        scala_receiver_type_fqn(ctx, resolver, root, receiver, operator.start_byte())
    {
        let raw_candidates = scala_member_candidate_units(ctx, &owner, name, false);
        let candidates = scala_filter_callable_units(
            ctx.scala,
            raw_candidates.clone(),
            call_shape.as_ref(),
            ScalaCallableSiteRole::Ordinary,
        );
        if !candidates.is_empty() {
            return candidates_outcome(candidates);
        }
        if raw_candidates
            .iter()
            .any(|unit| scala_unit_has_callable_role(ctx.scala, unit, ScalaCallableRole::Ordinary))
        {
            return no_definition(
                "no_applicable_scala_callable",
                format!("`{name}` has an ordinary member tier, but no overload matches this call"),
            );
        }
        return scala_extension_candidates(ctx, resolver, name, Some(&owner), call_shape.as_ref());
    }
    let extension_candidates =
        scala_extension_candidate_units(ctx, resolver, name, None, call_shape.as_ref());
    if !extension_candidates.is_empty() {
        return candidates_outcome(extension_candidates);
    }
    no_definition(
        SCALA_UNSUPPORTED_RECEIVER,
        format!("receiver for Scala infix member `{name}` is not resolved"),
    )
}

fn scala_is_compound_infix_call(call: Node<'_>) -> bool {
    call.child_by_field_name("left")
        .is_some_and(|left| left.kind() == "infix_expression")
        || call.parent().is_some_and(|parent| {
            parent.kind() == "infix_expression" && parent.child_by_field_name("left") == Some(call)
        })
}

fn resolve_scala_postfix_call(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    root: Node<'_>,
    call: Node<'_>,
) -> DefinitionLookupOutcome {
    let Some(method) = scala_postfix_method_node(call) else {
        return no_definition("no_function_name", "Scala postfix expression has no method");
    };
    let Some(receiver) = scala_postfix_receiver_node(call, method) else {
        return no_definition(
            SCALA_UNSUPPORTED_RECEIVER,
            "Scala postfix expression has no receiver",
        );
    };
    let name = scala_node_text(method, ctx.source).trim();
    if name.is_empty() {
        return no_definition("no_function_name", "Scala postfix method is blank");
    }
    if let Some(owner) = scala_receiver_type_fqn(ctx, resolver, root, receiver, method.start_byte())
    {
        let raw_candidates = scala_member_candidate_units(ctx, &owner, name, false);
        let candidates = scala_filter_callable_units(
            ctx.scala,
            raw_candidates.clone(),
            None,
            ScalaCallableSiteRole::Ordinary,
        );
        if !candidates.is_empty() {
            return candidates_outcome(candidates);
        }
        if raw_candidates
            .iter()
            .any(|unit| scala_unit_has_callable_role(ctx.scala, unit, ScalaCallableRole::Ordinary))
        {
            return no_definition(
                "no_applicable_scala_callable",
                format!("`{name}` has an ordinary member tier, but no overload matches this call"),
            );
        }
        return scala_extension_candidates(ctx, resolver, name, Some(&owner), None);
    }
    let extension_candidates = scala_extension_candidate_units(ctx, resolver, name, None, None);
    if !extension_candidates.is_empty() {
        return candidates_outcome(extension_candidates);
    }
    no_definition(
        SCALA_UNSUPPORTED_RECEIVER,
        format!("receiver for Scala postfix member `{name}` is not resolved"),
    )
}

pub(super) fn scala_postfix_method_node(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    let mut method = None;
    for child in node.named_children(&mut cursor) {
        if matches!(child.kind(), "identifier" | "operator_identifier") {
            method = Some(child);
        }
    }
    method
}

fn scala_postfix_receiver_node<'tree>(
    node: Node<'tree>,
    method: Node<'tree>,
) -> Option<Node<'tree>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| child.end_byte() <= method.start_byte())
}

fn resolve_scala_constructor(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    constructor: Node<'_>,
) -> DefinitionLookupOutcome {
    let mut cursor = constructor.walk();
    let Some(type_node) = constructor
        .named_children(&mut cursor)
        .find(|child| !matches!(child.kind(), "arguments" | "template_body"))
    else {
        return no_definition(
            "no_indexed_definition",
            "Scala constructor call has no structured type node",
        );
    };
    let Some(exact_owner) = scala_resolve_visible_type_declaration(ctx, resolver, type_node) else {
        return no_definition(
            "no_indexed_definition",
            "Scala constructor call did not resolve to an indexed type",
        );
    };
    let owner_fqn = exact_owner.fq_name();
    let member = scala_constructor_member_name(&owner_fqn);
    let call_shape = call_site_shape_for_reference(type_node);
    if crate::analyzer::common::language_for_target(&exact_owner) == Language::Java {
        return resolve_java_constructor_from_scala(
            ctx,
            exact_owner,
            &owner_fqn,
            member,
            call_shape.as_ref(),
        );
    }
    let constructor_units = ctx
        .support
        .fqn(&format!("{owner_fqn}.{member}"))
        .into_iter()
        .filter(CodeUnit::is_function)
        .filter(|unit| ctx.scala.structural_parent_of(unit).as_ref() == Some(&exact_owner))
        .filter(|unit| {
            scala_unit_has_callable_role(ctx.scala, unit, ScalaCallableRole::PrimaryConstructor)
                || scala_unit_has_callable_role(
                    ctx.scala,
                    unit,
                    ScalaCallableRole::SecondaryConstructor,
                )
        })
        .collect::<Vec<_>>();
    let candidates = scala_physical_callable_candidates(
        ctx.scala,
        scala_filter_callable_units(
            ctx.scala,
            constructor_units.clone(),
            call_shape.as_ref(),
            ScalaCallableSiteRole::ExplicitConstruction,
        ),
    );
    match candidates {
        ScalaPhysicalCallableCandidates::Unique(candidates) => {
            return candidates_outcome(candidates);
        }
        ScalaPhysicalCallableCandidates::Ambiguous => {
            return no_definition(
                "ambiguous_scala_constructor",
                format!("`{member}` has multiple physical constructor owners"),
            );
        }
        ScalaPhysicalCallableCandidates::NoCandidates => {}
    }
    let owner_alternatives =
        scala_forward_callable_alternatives(ctx.scala, ctx.support, &exact_owner);
    let owner_matches = if owner_alternatives.is_empty() {
        scala_callable_alternative_matches(
            ScalaCallableRole::PrimaryConstructor,
            &[ScalaCallableParameterList::explicit(
                crate::analyzer::CallableArity::exact(0),
            )],
            call_shape.as_ref(),
            ScalaCallableSiteRole::ExplicitConstruction,
            false,
        )
    } else {
        owner_alternatives.iter().any(|alternative| {
            scala_callable_alternative_matches(
                alternative.role,
                &alternative.shape,
                call_shape.as_ref(),
                ScalaCallableSiteRole::ExplicitConstruction,
                false,
            )
        })
    };
    if owner_matches && !constructor_units.iter().any(CodeUnit::is_synthetic) {
        return candidates_outcome(vec![exact_owner]);
    }
    if !constructor_units.is_empty()
        && let Some(call_shape) = call_shape.as_ref()
    {
        let arities = call_shape
            .lists
            .iter()
            .map(|list| list.arity)
            .collect::<Vec<_>>();
        return no_definition(
            "scala_constructor_arity_mismatch",
            format!(
                "Scala constructor `{owner_fqn}` has no indexed overload accepting argument-list arities {arities:?}"
            ),
        );
    }
    no_definition(
        "no_applicable_scala_constructor",
        format!("`{member}` has no indexed primary or secondary constructor matching this call"),
    )
}

fn resolve_java_constructor_from_scala(
    ctx: ScalaLookupCtx<'_>,
    exact_owner: CodeUnit,
    owner_fqn: &str,
    member: &str,
    call_shape: Option<&ScalaCallSiteShape>,
) -> DefinitionLookupOutcome {
    let Some(arity) = call_shape.and_then(|shape| match shape.lists.as_slice() {
        [list] if list.kind == ScalaCallArgumentListKind::Ordinary => Some(list.arity),
        _ => None,
    }) else {
        return no_definition(
            "no_applicable_scala_constructor",
            format!("Java constructor `{owner_fqn}` requires one ordinary argument list"),
        );
    };
    let Some(java) = resolve_analyzer::<JavaAnalyzer>(ctx.analyzer) else {
        return no_definition(
            "no_indexed_definition",
            format!("Java analyzer is unavailable for constructor `{owner_fqn}`"),
        );
    };
    let callable_candidates = ctx
        .support
        .fqn_in_language(&format!("{owner_fqn}.{member}"), Language::Java)
        .into_iter()
        .filter(CodeUnit::is_function)
        .filter(|unit| !unit.is_synthetic())
        .collect::<Vec<_>>();
    let (constructors, owner_shape_accepts) =
        java.constructor_context(&exact_owner, callable_candidates, arity);
    let matching = constructors
        .iter()
        .filter(|unit| {
            ctx.analyzer
                .signature_metadata(unit)
                .into_iter()
                .find_map(|metadata| metadata.callable_arity())
                .unwrap_or_else(|| {
                    crate::analyzer::CallableArity::exact(java_signature_arity(unit.signature()))
                })
                .accepts(arity)
        })
        .cloned()
        .collect::<Vec<_>>();
    if !matching.is_empty() {
        return candidates_outcome(matching);
    }
    if owner_shape_accepts {
        return candidates_outcome(vec![exact_owner]);
    }
    no_definition(
        "no_applicable_scala_constructor",
        format!("Java constructor `{owner_fqn}` has no indexed overload accepting arity {arity}"),
    )
}

fn scala_constructor_member_name(owner_fqn: &str) -> &str {
    owner_fqn
        .trim_end_matches('$')
        .rsplit('.')
        .next()
        .unwrap_or(owner_fqn)
}

fn resolve_scala_field(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    root: Node<'_>,
    field: Node<'_>,
) -> DefinitionLookupOutcome {
    let Some(field_node) = field.child_by_field_name("field") else {
        return no_definition(
            "no_member_name",
            "Scala field expression has no member name",
        );
    };
    let member = scala_node_text(field_node, ctx.source).trim();
    let call_shape = scala_call_site_shape(ctx, root, field_node);
    let Some(receiver) = field.child_by_field_name("value") else {
        return no_definition(
            "no_member_receiver",
            "Scala field expression has no receiver",
        );
    };
    let bindings = matches!(receiver.kind(), "identifier" | "type_identifier")
        .then(|| scala_bindings_before(ctx, resolver, root, field.start_byte()));
    let owner = match bindings.as_ref() {
        Some(bindings) => scala_receiver_owner_with_bindings(ctx, resolver, receiver, bindings),
        None => scala_non_identifier_receiver_type_fqn(ctx, resolver, receiver)
            .map(ScalaReceiverOwner::Logical),
    };
    if let Some(owner) = owner {
        let owner_fqn = owner.fq_name();
        if let ScalaReceiverOwner::Exact(exact_owner) = &owner {
            match scala_exact_owner_member_candidate_units(ctx, exact_owner, member, false) {
                ScalaExactMemberResolution::Found(candidates) => {
                    let applicable = scala_filter_callable_units(
                        ctx.scala,
                        candidates,
                        call_shape.as_ref(),
                        ScalaCallableSiteRole::Ordinary,
                    );
                    if applicable.is_empty() {
                        let extensions = scala_extension_candidate_units(
                            ctx,
                            resolver,
                            member,
                            Some(&owner_fqn),
                            call_shape.as_ref(),
                        );
                        if !extensions.is_empty() {
                            return candidates_outcome(extensions);
                        }
                        return no_definition(
                            "no_applicable_scala_callable",
                            format!(
                                "`{member}` has no member matching this access on `{owner_fqn}`"
                            ),
                        );
                    }
                    return candidates_outcome(applicable);
                }
                ScalaExactMemberResolution::Ambiguous => {
                    return no_definition(
                        "ambiguous_scala_receiver_member",
                        format!(
                            "`{member}` has multiple member definitions in the exact receiver hierarchy of `{owner_fqn}`"
                        ),
                    );
                }
                ScalaExactMemberResolution::NoMatch => {
                    let extensions = scala_extension_candidate_units(
                        ctx,
                        resolver,
                        member,
                        Some(&owner_fqn),
                        call_shape.as_ref(),
                    );
                    if !extensions.is_empty() {
                        return candidates_outcome(extensions);
                    }
                    return no_definition(
                        SCALA_UNSUPPORTED_RECEIVER,
                        format!(
                            "exact Scala receiver `{owner_fqn}` has no indexed member `{member}`"
                        ),
                    );
                }
            }
        }
        let include_companion = bindings.as_ref().is_some_and(|bindings| {
            scala_receiver_allows_companion_lookup_with_bindings(
                ctx,
                resolver,
                root,
                receiver,
                field.start_byte(),
                &owner_fqn,
                bindings,
            )
        });
        let candidates = scala_applicable_member_candidate_units(
            ctx,
            &owner_fqn,
            member,
            include_companion,
            call_shape.as_ref(),
        );
        if !candidates.is_empty() {
            return candidates_outcome(candidates);
        }
        return scala_extension_candidates(
            ctx,
            resolver,
            member,
            Some(&owner_fqn),
            call_shape.as_ref(),
        );
    }
    let extension_candidates =
        scala_extension_candidate_units(ctx, resolver, member, None, call_shape.as_ref());
    if !extension_candidates.is_empty() {
        return candidates_outcome(extension_candidates);
    }
    no_definition(
        SCALA_UNSUPPORTED_RECEIVER,
        format!("receiver for Scala member `{member}` is not resolved"),
    )
}

fn scala_receiver_allows_companion_lookup_with_bindings(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    root: Node<'_>,
    receiver: Node<'_>,
    cutoff_start: usize,
    owner_fqn: &str,
    bindings: &LocalInferenceEngine<ScalaLocalBinding>,
) -> bool {
    if !matches!(receiver.kind(), "identifier" | "type_identifier") {
        return false;
    }
    let name = scala_node_text(receiver, ctx.source).trim();
    if name == "this" {
        return false;
    }
    if precise_scala_binding(bindings, name).is_some()
        || bindings.is_shadowed(name)
        || scala_lexical_binding_declares_name_before(root, ctx.source, name, cutoff_start)
        || scala_enclosing_class_parameter_type(ctx, receiver, name, resolver).is_some()
    {
        return false;
    }
    resolver
        .resolve(name)
        .is_some_and(|resolved| resolved == owner_fqn)
}

fn resolve_scala_stable_identifier(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    root: Node<'_>,
    identifier: Node<'_>,
) -> DefinitionLookupOutcome {
    let segments = scala_type_lookup_segments(identifier, ctx.source);
    let Some((member, owner_segments)) = segments.split_last() else {
        return resolve_scala_type(ctx, resolver, root, identifier);
    };
    if owner_segments.is_empty() {
        return resolve_scala_type(ctx, resolver, root, identifier);
    }
    if member.is_empty() || owner_segments.iter().any(String::is_empty) {
        return no_definition("no_reference_text", "Scala stable identifier is blank");
    }
    let text = scala_node_text(identifier, ctx.source).trim();
    let root_name = owner_segments.first().expect("non-empty stable owner path");
    let bindings = scala_bindings_before(ctx, resolver, root, identifier.start_byte());
    let bound_owner = precise_scala_binding(&bindings, root_name)
        .and_then(|binding| binding.receiver_type)
        .or_else(|| scala_enclosing_class_parameter_type(ctx, identifier, root_name, resolver));
    let owner = bound_owner
        .and_then(|owner| scala_resolve_stable_owner_tail(ctx.support, owner, &owner_segments[1..]))
        .or_else(|| {
            if bindings.is_shadowed(root_name) {
                return None;
            }
            if owner_segments.len() == 1 {
                return scala_resolve_visible_term_owner(
                    ctx, resolver, root, identifier, root_name,
                );
            }
            scala_resolve_enclosing_qualified_type(
                ctx,
                resolver,
                identifier,
                owner_segments,
                ScalaOwnerKind::SingletonObject,
            )
            .or_else(|| {
                match resolver
                    .resolve_owner_segments(owner_segments, ScalaOwnerKind::SingletonObject)
                {
                    ScalaNameResolution::Resolved(owner) => Some(owner.fqn),
                    ScalaNameResolution::MissingExplicitImport
                    | ScalaNameResolution::Ambiguous
                    | ScalaNameResolution::Unresolved => None,
                }
            })
        });
    if let Some(owner) = owner {
        let candidates = scala_stable_term_member_candidate_units(ctx, &owner, member);
        if !candidates.is_empty() {
            return candidates_outcome(candidates);
        }
        return scala_member_not_found(ctx, &owner, member);
    }
    if scala_import_boundary_for_name(ctx.scala, ctx.support, ctx.file, root_name) {
        return boundary(format!(
            "`{root_name}` appears to cross a Scala import boundary not indexed in this workspace"
        ));
    }
    no_definition(
        "no_indexed_definition",
        format!("`{text}` did not resolve to an indexed Scala definition"),
    )
}

fn scala_resolve_stable_owner_tail(
    support: &dyn BoundedDefinitionLookup,
    mut owner: String,
    tail: &[String],
) -> Option<String> {
    for segment in tail {
        let nested = format!("{owner}.{segment}$");
        if !support
            .fqn(&nested)
            .into_iter()
            .any(|unit| unit.is_class() && unit.fq_name() == nested)
        {
            return None;
        }
        owner = nested;
    }
    Some(owner)
}

fn scala_stable_term_member_candidate_units(
    ctx: ScalaLookupCtx<'_>,
    owner_fqn: &str,
    member: &str,
) -> Vec<CodeUnit> {
    let mut candidates =
        scala_stable_term_member_candidate_units_without_ancestors(ctx.support, owner_fqn, member);
    if !candidates.is_empty() {
        return candidates;
    }

    let mut matching_depth = None;
    for owner in ctx
        .support
        .fqn(owner_fqn)
        .into_iter()
        .filter(|unit| unit.is_class() && unit.fq_name() == owner_fqn)
    {
        for (ancestor, depth) in scala_ancestor_owners(ctx.scala, ctx.support, owner) {
            if matching_depth.is_some_and(|found| depth > found) {
                break;
            }
            let direct = scala_stable_term_member_candidate_units_without_ancestors(
                ctx.support,
                &ancestor.fq_name(),
                member,
            );
            if !direct.is_empty() {
                matching_depth = Some(depth);
                candidates.extend(direct);
            }
        }
    }
    sort_units(&mut candidates);
    candidates.dedup();
    candidates
}

fn scala_stable_term_member_candidate_units_without_ancestors(
    support: &dyn BoundedDefinitionLookup,
    owner_fqn: &str,
    member: &str,
) -> Vec<CodeUnit> {
    let singleton_fqn = format!("{owner_fqn}.{member}$");
    let mut candidates = support
        .fqn(&singleton_fqn)
        .into_iter()
        .filter(|unit| unit.is_class() && unit.fq_name() == singleton_fqn)
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        candidates = scala_direct_member_candidate_units(support, owner_fqn, member)
            .into_iter()
            .filter(|unit| unit.is_field() || unit.is_function())
            .collect();
    }
    sort_units(&mut candidates);
    candidates.dedup();
    candidates
}

fn scala_member_candidate_units(
    ctx: ScalaLookupCtx<'_>,
    owner_fqn: &str,
    member: &str,
    include_companion: bool,
) -> Vec<CodeUnit> {
    let candidates = scala_direct_member_candidate_units(ctx.support, owner_fqn, member);
    if !candidates.is_empty() {
        return candidates;
    }

    let inherited = scala_ancestor_member_candidate_units(ctx, owner_fqn, member);
    if !inherited.is_empty() {
        return inherited;
    }

    if include_companion && !owner_fqn.ends_with('$') {
        return scala_direct_member_candidate_units(ctx.support, &format!("{owner_fqn}$"), member);
    }

    Vec::new()
}

enum ScalaExactMemberResolution {
    Found(Vec<CodeUnit>),
    NoMatch,
    Ambiguous,
}

enum ScalaTypedOverloadResolution {
    NotNeeded,
    Found(Vec<CodeUnit>),
    NoApplicable,
    Ambiguous,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ScalaTypedCandidateMatch {
    Match,
    Mismatch,
    Unknown,
}

fn scala_explicit_local_member_import_outcome(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver<'_>,
    root: Node<'_>,
    reference: Node<'_>,
    visible_name: &str,
) -> Option<DefinitionLookupOutcome> {
    let bindings = scala_bindings_before(ctx, resolver, root, reference.start_byte());
    let mut matched_local_import = false;
    let mut candidates = Vec::new();
    for import in resolver
        .visible_imports()
        .filter(|import| !import.is_wildcard)
    {
        if import
            .identifier
            .as_deref()
            .is_none_or(|identifier| identifier != visible_name)
        {
            continue;
        }
        let Some(path) = import.path.as_ref() else {
            continue;
        };
        let Some((member, owner_path)) = path.segments.split_last() else {
            continue;
        };
        let Some(root_name) = owner_path.first() else {
            continue;
        };
        if !bindings.is_shadowed(root_name) {
            continue;
        }
        matched_local_import = true;
        let Some(binding) = precise_scala_binding(&bindings, root_name) else {
            continue;
        };
        let mut owners = if let Some(declaration) = binding.receiver_declaration {
            vec![declaration]
        } else if let Some(owner_fqn) = binding.receiver_type {
            ctx.support
                .fqn(&owner_fqn)
                .into_iter()
                .filter(|unit| unit.is_class() && unit.fq_name() == owner_fqn)
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        sort_units(&mut owners);
        owners.dedup();
        let [owner] = owners.as_slice() else {
            if owners.len() > 1 {
                return Some(no_definition(
                    "ambiguous_scala_local_import_owner",
                    format!("local import owner `{root_name}` has multiple physical definitions"),
                ));
            }
            continue;
        };
        let Some(owner) = scala_exact_nested_singleton_owner(ctx, owner, &owner_path[1..]) else {
            continue;
        };
        match scala_exact_owner_member_candidate_units(ctx, &owner, member, false) {
            ScalaExactMemberResolution::Found(found) => candidates.extend(found),
            ScalaExactMemberResolution::Ambiguous => {
                return Some(no_definition(
                    "ambiguous_scala_local_import_member",
                    format!("imported local member `{visible_name}` has multiple definitions"),
                ));
            }
            ScalaExactMemberResolution::NoMatch => {}
        }
    }
    sort_units(&mut candidates);
    candidates.dedup();
    if !candidates.is_empty() {
        Some(candidates_outcome(candidates))
    } else if matched_local_import {
        Some(boundary(format!(
            "`{visible_name}` is imported from a local Scala value whose exact member is unavailable"
        )))
    } else {
        None
    }
}

fn scala_exact_owner_typed_overload_resolution(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver<'_>,
    call: Node<'_>,
    owner: &CodeUnit,
    member: &str,
    call_shape: Option<&ScalaCallSiteShape>,
) -> ScalaTypedOverloadResolution {
    let Some(call_shape) = call_shape else {
        return ScalaTypedOverloadResolution::NotNeeded;
    };
    if call_shape.lists.len() != 1
        || call_shape.lists[0].kind != ScalaCallArgumentListKind::Ordinary
    {
        return ScalaTypedOverloadResolution::NotNeeded;
    }

    let mut levels = Vec::new();
    let mut level = vec![owner.clone()];
    let mut seen = HashSet::default();
    while !level.is_empty() {
        let mut candidates = Vec::new();
        let mut next = Vec::new();
        for current in level {
            if !seen.insert(current.clone()) {
                continue;
            }
            candidates.extend(scala_filter_callable_units(
                ctx.scala,
                scala_direct_member_candidate_units_for_owner(ctx, &current, member),
                Some(call_shape),
                ScalaCallableSiteRole::Ordinary,
            ));
            match scala_forward_direct_ancestor_resolution(ctx.scala, ctx.support, &current) {
                ScalaDirectAncestorResolution::Resolved(ancestors) => next.extend(ancestors),
                ScalaDirectAncestorResolution::Ambiguous => {
                    return ScalaTypedOverloadResolution::Ambiguous;
                }
            }
        }
        sort_units(&mut candidates);
        candidates.dedup();
        levels.push(candidates);
        level = next;
    }

    let callable_count = levels.iter().map(Vec::len).sum::<usize>();
    if callable_count < 2 {
        return ScalaTypedOverloadResolution::NotNeeded;
    }
    let Some(arguments) = scala_exact_constructed_call_arguments(ctx, resolver, call) else {
        return ScalaTypedOverloadResolution::Ambiguous;
    };

    for candidates in levels {
        let mut matching = Vec::new();
        let mut unknown = false;
        for candidate in candidates {
            match scala_callable_matches_constructed_arguments(
                ctx, &candidate, call_shape, &arguments,
            ) {
                ScalaTypedCandidateMatch::Match => matching.push(candidate),
                ScalaTypedCandidateMatch::Mismatch => {}
                ScalaTypedCandidateMatch::Unknown => unknown = true,
            }
        }
        if unknown {
            return ScalaTypedOverloadResolution::Ambiguous;
        }
        sort_units(&mut matching);
        matching.dedup();
        if !matching.is_empty() {
            let physical_owners = matching
                .iter()
                .filter_map(|unit| ctx.scala.structural_parent_of(unit))
                .collect::<HashSet<_>>();
            return if physical_owners.len() == 1 {
                ScalaTypedOverloadResolution::Found(matching)
            } else {
                ScalaTypedOverloadResolution::Ambiguous
            };
        }
    }
    ScalaTypedOverloadResolution::NoApplicable
}

fn scala_exact_constructed_call_arguments(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver<'_>,
    call: Node<'_>,
) -> Option<Vec<CodeUnit>> {
    let arguments = call.child_by_field_name("arguments")?;
    let mut cursor = arguments.walk();
    arguments
        .named_children(&mut cursor)
        .map(|argument| scala_exact_constructed_argument(ctx, resolver, argument))
        .collect()
}

fn scala_exact_constructed_argument(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver<'_>,
    node: Node<'_>,
) -> Option<CodeUnit> {
    let instance = if node.kind() == "instance_expression" {
        node
    } else if node.kind() == "call_expression" {
        node.child_by_field_name("function")
            .filter(|function| function.kind() == "instance_expression")?
    } else {
        return None;
    };
    let mut cursor = instance.walk();
    let type_node = instance.named_children(&mut cursor).find(|child| {
        matches!(
            child.kind(),
            "type_identifier"
                | "stable_type_identifier"
                | "generic_type"
                | "applied_constructor_type"
                | "projected_type"
                | "singleton_type"
                | "annotated_type"
        )
    })?;
    scala_resolve_visible_type_declaration(ctx, resolver, type_node)
        .filter(|declaration| declaration.is_class() && !ctx.scala.is_type_alias(declaration))
}

fn scala_callable_matches_constructed_arguments(
    ctx: ScalaLookupCtx<'_>,
    candidate: &CodeUnit,
    call_shape: &ScalaCallSiteShape,
    arguments: &[CodeUnit],
) -> ScalaTypedCandidateMatch {
    let alternatives = scala_forward_callable_alternatives(ctx.scala, ctx.support, candidate);
    if alternatives.is_empty() {
        return ScalaTypedCandidateMatch::Unknown;
    }
    let mut saw_unknown = false;
    for alternative in alternatives.iter().filter(|alternative| {
        scala_callable_alternative_is_candidate(
            alternative.role,
            &alternative.shape,
            call_shape,
            ScalaCallableSiteRole::Ordinary,
        )
    }) {
        let Some(parameter_list_index) = alternative
            .shape
            .iter()
            .position(|list| list.kind == ScalaParameterListKind::Explicit)
        else {
            saw_unknown = true;
            continue;
        };
        let Some(parameter_types) = alternative.parameter_types.get(parameter_list_index) else {
            saw_unknown = true;
            continue;
        };
        if parameter_types.len() != arguments.len() {
            continue;
        }
        let mut alternative_matches = true;
        for (actual, expected) in arguments.iter().zip(parameter_types) {
            let Some(expected) = expected else {
                saw_unknown = true;
                alternative_matches = false;
                break;
            };
            let relation = match expected {
                ScalaParameterTypeIdentity::Builtin(_) => ScalaTypedCandidateMatch::Mismatch,
                ScalaParameterTypeIdentity::Declaration(expected) => {
                    scala_exact_subtype_relation(ctx, actual, expected)
                }
            };
            match relation {
                ScalaTypedCandidateMatch::Match => {}
                ScalaTypedCandidateMatch::Mismatch => alternative_matches = false,
                ScalaTypedCandidateMatch::Unknown => {
                    saw_unknown = true;
                    alternative_matches = false;
                }
            }
            if !alternative_matches {
                break;
            }
        }
        if alternative_matches {
            return ScalaTypedCandidateMatch::Match;
        }
    }
    if saw_unknown {
        ScalaTypedCandidateMatch::Unknown
    } else {
        ScalaTypedCandidateMatch::Mismatch
    }
}

fn scala_exact_subtype_relation(
    ctx: ScalaLookupCtx<'_>,
    actual: &CodeUnit,
    expected: &CodeUnit,
) -> ScalaTypedCandidateMatch {
    let mut stack = vec![actual.clone()];
    let mut seen = HashSet::default();
    while let Some(current) = stack.pop() {
        if !seen.insert(current.clone()) {
            continue;
        }
        if current == *expected {
            return ScalaTypedCandidateMatch::Match;
        }
        match scala_forward_direct_ancestor_resolution(ctx.scala, ctx.support, &current) {
            ScalaDirectAncestorResolution::Resolved(ancestors) => stack.extend(ancestors),
            ScalaDirectAncestorResolution::Ambiguous => {
                return ScalaTypedCandidateMatch::Unknown;
            }
        }
    }
    ScalaTypedCandidateMatch::Mismatch
}

fn scala_exact_owner_member_candidate_units(
    ctx: ScalaLookupCtx<'_>,
    owner: &CodeUnit,
    member: &str,
    include_companion: bool,
) -> ScalaExactMemberResolution {
    let direct = scala_direct_member_candidate_units_for_owner(ctx, owner, member);
    if !direct.is_empty() {
        return ScalaExactMemberResolution::Found(direct);
    }

    let mut level = match scala_forward_direct_ancestor_resolution(ctx.scala, ctx.support, owner) {
        ScalaDirectAncestorResolution::Resolved(ancestors) => ancestors,
        ScalaDirectAncestorResolution::Ambiguous => {
            return ScalaExactMemberResolution::Ambiguous;
        }
    };
    let mut seen = HashSet::from_iter([owner.clone()]);
    while !level.is_empty() {
        let mut matches = Vec::new();
        let mut next = Vec::new();
        let mut next_is_ambiguous = false;
        for ancestor in level {
            if !seen.insert(ancestor.clone()) {
                continue;
            }
            matches.extend(scala_direct_member_candidate_units_for_owner(
                ctx, &ancestor, member,
            ));
            match scala_forward_direct_ancestor_resolution(ctx.scala, ctx.support, &ancestor) {
                ScalaDirectAncestorResolution::Resolved(ancestors) => next.extend(ancestors),
                ScalaDirectAncestorResolution::Ambiguous => next_is_ambiguous = true,
            }
        }
        sort_units(&mut matches);
        matches.dedup();
        if !matches.is_empty() {
            // Each ancestor path was already resolved to one exact physical
            // declaration. Distinct resolved traits at the same inheritance
            // depth are a legitimate Scala conflict, so definition lookup
            // returns every declaration and lets the client present the
            // alternatives. Name/import or duplicate-physical-owner
            // ambiguity is rejected earlier by the bounded ancestor resolver.
            return ScalaExactMemberResolution::Found(matches);
        }
        if next_is_ambiguous {
            return ScalaExactMemberResolution::Ambiguous;
        }
        level = next;
    }

    if include_companion && !owner.fq_name().ends_with('$') {
        let companion_fqn = format!("{}$", owner.fq_name());
        let companions = ctx
            .support
            .fqn(&companion_fqn)
            .into_iter()
            .filter(|candidate| {
                candidate.is_class()
                    && candidate.fq_name() == companion_fqn
                    && candidate.source() == owner.source()
            })
            .collect::<Vec<_>>();
        match companions.as_slice() {
            [companion] => {
                let candidates =
                    scala_direct_member_candidate_units_for_owner(ctx, companion, member);
                if !candidates.is_empty() {
                    return ScalaExactMemberResolution::Found(candidates);
                }
            }
            [_, _, ..] => return ScalaExactMemberResolution::Ambiguous,
            [] => {}
        }
    }

    ScalaExactMemberResolution::NoMatch
}

fn scala_direct_member_candidate_units_for_owner(
    ctx: ScalaLookupCtx<'_>,
    owner: &CodeUnit,
    member: &str,
) -> Vec<CodeUnit> {
    let exact_fqn = format!("{}.{member}", owner.fq_name());
    let mut candidates = ctx
        .support
        .fqn(&exact_fqn)
        .into_iter()
        .filter(|unit| unit.fq_name() == exact_fqn)
        .filter(|unit| ctx.scala.structural_parent_of(unit).as_ref() == Some(owner))
        .collect::<Vec<_>>();
    sort_units(&mut candidates);
    candidates.dedup();
    candidates
}

fn scala_applicable_member_candidate_units(
    ctx: ScalaLookupCtx<'_>,
    owner_fqn: &str,
    member: &str,
    include_companion: bool,
    call_shape: Option<&ScalaCallSiteShape>,
) -> Vec<CodeUnit> {
    let candidates = scala_member_candidate_units(ctx, owner_fqn, member, include_companion);
    scala_applicable_callable_candidate_units(ctx, candidates, call_shape)
}

fn scala_applicable_callable_candidate_units(
    ctx: ScalaLookupCtx<'_>,
    candidates: Vec<CodeUnit>,
    call_shape: Option<&ScalaCallSiteShape>,
) -> Vec<CodeUnit> {
    scala_filter_callable_units(
        ctx.scala,
        candidates,
        call_shape,
        ScalaCallableSiteRole::Ordinary,
    )
}

fn scala_forward_callable_type_identity(
    resolver: &ScalaNameResolver<'_>,
    path: &[String],
) -> Option<ScalaParameterTypeIdentity> {
    match resolver.resolve_owner_segments(path, ScalaOwnerKind::Class) {
        ScalaNameResolution::Resolved(owner) => {
            Some(ScalaParameterTypeIdentity::Declaration(owner._declaration))
        }
        ScalaNameResolution::Unresolved => {
            let [simple] = path else {
                return None;
            };
            scala_builtin_type_name(simple).map(ScalaParameterTypeIdentity::Builtin)
        }
        ScalaNameResolution::MissingExplicitImport | ScalaNameResolution::Ambiguous => None,
    }
}

/// Decode only the declaration source and exact ranges needed by this forward
/// request.  The inverse `ScalaProjectTypes` projection intentionally remains
/// a whole-workspace facility and must not be constructed from this path.
fn scala_forward_callable_alternatives(
    scala: &ScalaAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    target: &CodeUnit,
) -> Vec<ForwardScalaCallableAlternative> {
    let resolver = scala_name_resolver_for_unit(scala, support, target);
    scala_forward_callable_source_alternatives(scala, target)
        .iter()
        .map(|facts| ForwardScalaCallableAlternative {
            role: facts.role,
            shape: facts.shape.clone(),
            parameter_types: facts
                .parameter_type_paths
                .iter()
                .map(|parameters| {
                    parameters
                        .iter()
                        .map(|path| {
                            path.as_deref().and_then(|path| {
                                scala_forward_callable_type_identity(&resolver, path)
                            })
                        })
                        .collect()
                })
                .collect(),
            parameter_function_shapes: facts
                .parameter_function_arities
                .iter()
                .zip(&facts.parameter_function_type_paths)
                .map(|(arities, parameter_paths)| {
                    arities
                        .iter()
                        .zip(parameter_paths)
                        .map(|(arity, paths)| {
                            let arity = (*arity)?;
                            let parameter_types = paths.as_ref().and_then(|paths| {
                                paths
                                    .iter()
                                    .map(|path| {
                                        path.as_deref().and_then(|path| {
                                            scala_forward_callable_type_identity(&resolver, path)
                                        })
                                    })
                                    .collect::<Option<Vec<_>>>()
                            });
                            Some(ScalaFunctionParameterShape {
                                arity,
                                parameter_types,
                                parameter_types_authoritative: true,
                            })
                        })
                        .collect()
                })
                .collect(),
        })
        .collect()
}

fn scala_forward_callable_source_alternatives(
    scala: &ScalaAnalyzer,
    target: &CodeUnit,
) -> Vec<ScalaCallableSourceAlternative> {
    let Some(source) = scala.indexed_source(target.source()) else {
        return Vec::new();
    };
    let Some(source_facts) = scala_source_facts(&source) else {
        return Vec::new();
    };
    scala
        .ranges(target)
        .into_iter()
        .filter_map(|range| {
            source_facts
                .callable_alternatives_by_range
                .get(&(range.start_byte, range.end_byte))
                .cloned()
        })
        .collect()
}

fn scala_filter_callable_units(
    scala: &ScalaAnalyzer,
    candidates: Vec<CodeUnit>,
    call_shape: Option<&ScalaCallSiteShape>,
    site_role: ScalaCallableSiteRole,
) -> Vec<CodeUnit> {
    let callable_count = candidates
        .iter()
        .filter(|unit| unit.is_function())
        .map(|unit| {
            let alternatives = scala_forward_callable_source_alternatives(scala, unit);
            if let Some(call_shape) = call_shape {
                if !alternatives.is_empty() {
                    return alternatives
                        .iter()
                        .filter(|alternative| {
                            scala_callable_alternative_is_candidate(
                                alternative.role,
                                &alternative.shape,
                                call_shape,
                                site_role,
                            )
                        })
                        .count();
                }
                let fallback = method_signature_arity(scala, unit)
                    .map(crate::analyzer::CallableArity::exact)
                    .map(ScalaCallableParameterList::explicit)
                    .into_iter()
                    .collect::<Vec<_>>();
                return usize::from(scala_callable_alternative_is_candidate(
                    scala_fallback_callable_role(scala, unit),
                    &fallback,
                    call_shape,
                    site_role,
                ));
            }
            if alternatives.is_empty() {
                usize::from(site_role.accepts(scala_fallback_callable_role(scala, unit)))
            } else {
                alternatives
                    .iter()
                    .filter(|alternative| site_role.accepts(alternative.role))
                    .count()
            }
        })
        .sum::<usize>();
    let unique_callable = callable_count == 1;
    candidates
        .into_iter()
        .filter(|unit| {
            scala_member_unit_applies(scala, unit, call_shape, site_role, unique_callable)
        })
        .collect()
}

fn scala_member_candidate_applies(
    ctx: ScalaLookupCtx<'_>,
    unit: &CodeUnit,
    call_shape: Option<&ScalaCallSiteShape>,
    unique_callable: bool,
) -> bool {
    scala_member_unit_applies(
        ctx.scala,
        unit,
        call_shape,
        ScalaCallableSiteRole::Ordinary,
        unique_callable,
    )
}

fn scala_member_unit_applies(
    scala: &ScalaAnalyzer,
    unit: &CodeUnit,
    call_shape: Option<&ScalaCallSiteShape>,
    site_role: ScalaCallableSiteRole,
    unique_callable: bool,
) -> bool {
    if unit.is_field() {
        return true;
    }
    if !unit.is_function() {
        return false;
    }
    let alternatives = scala_forward_callable_source_alternatives(scala, unit);
    if !alternatives.is_empty() {
        return alternatives.iter().any(|alternative| {
            scala_callable_alternative_matches(
                alternative.role,
                &alternative.shape,
                call_shape,
                site_role,
                unique_callable,
            )
        });
    }
    let fallback = method_signature_arity(scala, unit)
        .map(crate::analyzer::CallableArity::exact)
        .map(ScalaCallableParameterList::explicit)
        .into_iter()
        .collect::<Vec<_>>();
    scala_callable_alternative_matches(
        scala_fallback_callable_role(scala, unit),
        &fallback,
        call_shape,
        site_role,
        unique_callable,
    )
}

fn scala_fallback_callable_role(scala: &ScalaAnalyzer, unit: &CodeUnit) -> ScalaCallableRole {
    if unit.is_synthetic() {
        ScalaCallableRole::PrimaryConstructor
    } else if scala
        .structural_parent_of(unit)
        .is_some_and(|owner| owner.identifier().trim_end_matches('$') == unit.identifier())
    {
        ScalaCallableRole::SecondaryConstructor
    } else {
        ScalaCallableRole::Ordinary
    }
}

/// Whether a physical callable represents only construction syntax.
///
/// A synthetic primary constructor shares the enclosing class's simple name,
/// and a `def this` can do the same. Neither declaration participates in bare
/// term lookup: an unapplied same-named identifier denotes an ordinary member
/// or companion object. Keep this decision tied to parser-recorded callable
/// roles so an ordinary same-named method remains eligible.
fn scala_constructor_only_callable(scala: &ScalaAnalyzer, unit: &CodeUnit) -> bool {
    if !unit.is_function() {
        return false;
    }
    let alternatives = scala_forward_callable_source_alternatives(scala, unit);
    if alternatives.is_empty() {
        return matches!(
            scala_fallback_callable_role(scala, unit),
            ScalaCallableRole::PrimaryConstructor | ScalaCallableRole::SecondaryConstructor
        );
    }
    alternatives.iter().all(|alternative| {
        matches!(
            alternative.role,
            ScalaCallableRole::PrimaryConstructor | ScalaCallableRole::SecondaryConstructor
        )
    })
}

enum ScalaPhysicalCallableCandidates {
    NoCandidates,
    Unique(Vec<CodeUnit>),
    Ambiguous,
}

fn scala_physical_callable_candidates(
    scala: &ScalaAnalyzer,
    candidates: Vec<CodeUnit>,
) -> ScalaPhysicalCallableCandidates {
    if candidates.is_empty() {
        return ScalaPhysicalCallableCandidates::NoCandidates;
    }
    let owners = candidates
        .iter()
        .filter_map(|candidate| scala.structural_parent_of(candidate))
        .collect::<HashSet<_>>();
    if owners.len() > 1 {
        ScalaPhysicalCallableCandidates::Ambiguous
    } else {
        ScalaPhysicalCallableCandidates::Unique(candidates)
    }
}

fn scala_unit_has_callable_role(
    scala: &ScalaAnalyzer,
    unit: &CodeUnit,
    role: ScalaCallableRole,
) -> bool {
    let alternatives = scala_forward_callable_source_alternatives(scala, unit);
    if alternatives.is_empty() {
        scala_fallback_callable_role(scala, unit) == role
    } else {
        alternatives
            .iter()
            .any(|alternative| alternative.role == role)
    }
}

fn scala_extension_candidates(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    member: &str,
    receiver_owner: Option<&str>,
    call_shape: Option<&ScalaCallSiteShape>,
) -> DefinitionLookupOutcome {
    let candidates =
        scala_extension_candidate_units(ctx, resolver, member, receiver_owner, call_shape);
    if !candidates.is_empty() {
        return candidates_outcome(candidates);
    }
    no_definition(
        SCALA_UNSUPPORTED_RECEIVER,
        format!("receiver for Scala extension member `{member}` is not resolved"),
    )
}

fn scala_extension_candidate_units(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    member: &str,
    receiver_owner: Option<&str>,
    call_shape: Option<&ScalaCallSiteShape>,
) -> Vec<CodeUnit> {
    let mut candidates = Vec::new();
    for method in resolver.visible_extension_methods(member) {
        if !scala_extension_receiver_matches(
            resolver,
            method.receiver_type.as_deref(),
            receiver_owner,
        ) {
            continue;
        }
        candidates.extend(ctx.support.fqn(&method.fqn));
    }
    candidates = scala_filter_callable_units(
        ctx.scala,
        candidates,
        call_shape,
        ScalaCallableSiteRole::Ordinary,
    );
    sort_units(&mut candidates);
    candidates.dedup();
    candidates
}

fn scala_extension_receiver_matches(
    resolver: &ScalaNameResolver,
    extension_receiver_type: Option<&str>,
    receiver_owner: Option<&str>,
) -> bool {
    scala_extension_receiver_matches_resolved(
        extension_receiver_type,
        receiver_owner,
        |type_text| resolver.resolve(type_text),
    )
}

fn scala_wildcard_imported_member_outcome(
    ctx: ScalaLookupCtx<'_>,
    member: &str,
    call_shape: Option<&ScalaCallSiteShape>,
) -> Option<DefinitionLookupOutcome> {
    let file_package = scala_package_name_of(ctx.scala, ctx.file).unwrap_or_default();
    let mut contributing_imports = 0_usize;
    let mut candidates = Vec::new();
    for import in ctx.scala.import_info_of(ctx.file) {
        if !import.is_wildcard {
            continue;
        }
        let Some(path) = scala_import_path(&import) else {
            continue;
        };
        // A relative wildcard base (`import Registry._` nested in a
        // template) resolves against its enclosing object/class/trait scopes
        // before the package, exactly like the import token itself (see
        // `scala_import_reference_outcome`). Without this, a member reached
        // only through such an enclosing-scope-qualified sibling (`Registry`
        // sitting beside the importing template rather than in the file's
        // package) was invisible here and fell through to the dishonest
        // `scala_import_boundary_for_name` diagnostic.
        let enclosing_owners = import
            .path
            .as_ref()
            .map(|structured_path| {
                scala_enclosing_template_owner_fq_names(
                    ctx.analyzer,
                    ctx.scala,
                    ctx.file,
                    structured_path.declaration_start_byte,
                )
            })
            .unwrap_or_default();
        let segments = import
            .path
            .as_ref()
            .map(|structured_path| structured_path.segments.as_slice())
            .unwrap_or(&[]);
        let import_candidates = scala_wildcard_imported_member_units(
            ctx.support,
            &path,
            &file_package,
            &enclosing_owners,
            segments,
            member,
        )
        .into_iter()
        .filter(|unit| !ctx.scala.is_type_alias(unit))
        .filter(|unit| scala_member_candidate_applies(ctx, unit, call_shape, false))
        .collect::<Vec<_>>();
        if !import_candidates.is_empty() {
            contributing_imports += 1;
            candidates.extend(import_candidates);
        }
        if contributing_imports > 1 {
            return Some(no_definition(
                "ambiguous_scala_wildcard_import",
                format!("Scala wildcard imports expose multiple `{member}` definitions"),
            ));
        }
    }
    sort_units(&mut candidates);
    candidates.dedup();
    if candidates.is_empty() {
        None
    } else {
        Some(candidates_outcome(candidates))
    }
}

fn scala_wildcard_imported_member_units(
    support: &dyn BoundedDefinitionLookup,
    path: &str,
    file_package: &str,
    enclosing_owners: &[String],
    segments: &[String],
    member: &str,
) -> Vec<CodeUnit> {
    let mut candidates = Vec::new();
    for imported_fqn in import_candidate_fq_names(path, file_package) {
        candidates.extend(
            support
                .fqn(&format!("{imported_fqn}.{member}"))
                .into_iter()
                .filter(|unit| unit.identifier() == member),
        );
    }
    for owner_fqn in import_candidate_owner_fq_names(path, file_package) {
        candidates.extend(
            support
                .fqn_direct_children(&owner_fqn)
                .into_iter()
                .filter(|unit| unit.identifier() == member),
        );
    }
    if !segments.is_empty() {
        for tier in scala_owner_qualified_import_candidate_tiers(enclosing_owners, segments) {
            for candidate in tier {
                candidates.extend(
                    support
                        .fqn(&format!("{candidate}.{member}"))
                        .into_iter()
                        .filter(|unit| unit.identifier() == member),
                );
                let owner_fqn = format!("{}$", candidate.trim_end_matches('$'));
                candidates.extend(
                    support
                        .fqn_direct_children(&owner_fqn)
                        .into_iter()
                        .filter(|unit| unit.identifier() == member),
                );
            }
        }
    }
    sort_units(&mut candidates);
    candidates.dedup();
    candidates
}

fn scala_ancestor_member_candidate_units(
    ctx: ScalaLookupCtx<'_>,
    owner_fqn: &str,
    member: &str,
) -> Vec<CodeUnit> {
    let owners = ctx
        .support
        .fqn(owner_fqn)
        .into_iter()
        .filter(|unit| unit.is_class() && unit.fq_name() == owner_fqn);
    let mut matching_depth = None;
    let mut matches = Vec::new();
    for owner in owners {
        for (ancestor, depth) in scala_ancestor_owners(ctx.scala, ctx.support, owner) {
            if matching_depth.is_some_and(|found| depth > found) {
                break;
            }
            let direct =
                scala_direct_member_candidate_units(ctx.support, &ancestor.fq_name(), member);
            if !direct.is_empty() {
                matching_depth = Some(depth);
                matches.extend(direct);
            }
        }
    }
    sort_units(&mut matches);
    matches.dedup();
    matches
}

fn scala_ancestor_owners(
    scala: &ScalaAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    owner: CodeUnit,
) -> Vec<(CodeUnit, usize)> {
    let mut queue = VecDeque::from([(owner.clone(), 0_usize)]);
    let mut discovered = HashSet::from_iter([owner.fq_name()]);
    let mut ancestors = Vec::new();
    while let Some((current, depth)) = queue.pop_front() {
        let ScalaDirectAncestorResolution::Resolved(direct) =
            scala_forward_direct_ancestor_resolution(scala, support, &current)
        else {
            break;
        };
        for ancestor in direct {
            if discovered.insert(ancestor.fq_name()) {
                let ancestor_depth = depth + 1;
                ancestors.push((ancestor.clone(), ancestor_depth));
                queue.push_back((ancestor, ancestor_depth));
            }
        }
    }
    ancestors
}

fn scala_forward_direct_ancestor_resolution(
    scala: &ScalaAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    owner: &CodeUnit,
) -> ScalaDirectAncestorResolution {
    let Some(facts) = scala.forward_owner_facts(owner) else {
        return ScalaDirectAncestorResolution::Resolved(Vec::new());
    };
    let resolver = scala_name_resolver_for_unit(scala, support, owner);
    let mut ancestors = Vec::new();
    for path in facts.supertype_lookup_paths {
        let identity = match resolver
            .resolve_explicit_owner_segments(path.segments(), ScalaOwnerKind::Class)
        {
            ScalaNameResolution::Resolved(identity) => identity,
            ScalaNameResolution::Ambiguous => return ScalaDirectAncestorResolution::Ambiguous,
            ScalaNameResolution::MissingExplicitImport => continue,
            ScalaNameResolution::Unresolved => {
                match resolver.resolve_lookup_path(&path, ScalaOwnerKind::Class) {
                    ScalaNameResolution::Resolved(identity) => identity,
                    ScalaNameResolution::Ambiguous
                        if !resolver.visible_imports().any(|import| import.is_wildcard) =>
                    {
                        let mut same_source = scala_nested_type_candidates(
                            owner.package_name().to_string(),
                            path.segments(),
                            false,
                        )
                        .into_iter()
                        .flat_map(|fqn| support.fqn(&fqn))
                        .filter(|unit| {
                            unit.is_class()
                                && unit.source() == owner.source()
                                && !unit.short_name().ends_with('$')
                        })
                        .collect::<Vec<_>>();
                        sort_units(&mut same_source);
                        same_source.dedup();
                        let [ancestor] = same_source.as_slice() else {
                            return ScalaDirectAncestorResolution::Ambiguous;
                        };
                        ancestors.push(ancestor.clone());
                        continue;
                    }
                    ScalaNameResolution::Ambiguous => {
                        return ScalaDirectAncestorResolution::Ambiguous;
                    }
                    ScalaNameResolution::MissingExplicitImport => continue,
                    ScalaNameResolution::Unresolved => {
                        return ScalaDirectAncestorResolution::Ambiguous;
                    }
                }
            }
        };
        ancestors.push(identity._declaration);
    }
    sort_units(&mut ancestors);
    ancestors.dedup();
    ScalaDirectAncestorResolution::Resolved(ancestors)
}

fn scala_direct_member_candidate_units(
    support: &dyn BoundedDefinitionLookup,
    owner_fqn: &str,
    member: &str,
) -> Vec<CodeUnit> {
    let exact_fqn = format!("{owner_fqn}.{member}");
    let mut candidates = support
        .fqn(&exact_fqn)
        .into_iter()
        .filter(|unit| unit.fq_name() == exact_fqn)
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        let scala_owner_exists = support
            .fqn(owner_fqn)
            .into_iter()
            .any(|unit| unit.is_class() && unit.fq_name() == owner_fqn);
        if !scala_owner_exists {
            candidates.extend(
                support
                    .fqn_in_language(&exact_fqn, Language::Java)
                    .into_iter()
                    .filter(|unit| unit.fq_name() == exact_fqn),
            );
        }
    }
    sort_units(&mut candidates);
    candidates.dedup();
    candidates
}

fn scala_source_ancestor_member_units(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    node: Node<'_>,
    member: &str,
) -> Vec<CodeUnit> {
    let Some(owner_node) = scala_enclosing_definition_node(node) else {
        return Vec::new();
    };
    let mut ancestor_types = Vec::new();
    scala_collect_extends_type_text(owner_node, ctx.source, &mut ancestor_types);
    for ancestor_type in ancestor_types {
        let Some(owner_fqn) = resolver.resolve(&ancestor_type) else {
            continue;
        };
        let candidates = scala_member_candidate_units(ctx, &owner_fqn, member, false);
        if !candidates.is_empty() {
            return candidates;
        }
    }
    Vec::new()
}

fn scala_enclosing_definition_node(mut node: Node<'_>) -> Option<Node<'_>> {
    while let Some(parent) = node.parent() {
        if matches!(
            parent.kind(),
            "class_definition" | "object_definition" | "trait_definition" | "enum_definition"
        ) {
            return Some(parent);
        }
        node = parent;
    }
    None
}

fn scala_collect_extends_type_text(node: Node<'_>, source: &str, out: &mut Vec<String>) {
    scala_collect_extends_type_text_inner(node, source, out, true);
}

fn scala_collect_extends_type_text_inner(
    node: Node<'_>,
    source: &str,
    out: &mut Vec<String>,
    is_root: bool,
) {
    if !is_root
        && matches!(
            node.kind(),
            "class_definition" | "object_definition" | "trait_definition" | "enum_definition"
        )
    {
        return;
    }
    let in_extends = node.kind() == "extends_clause";
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if in_extends
            && matches!(
                child.kind(),
                "type_identifier" | "stable_type_identifier" | "generic_type"
            )
        {
            let text = scala_node_text(child, source).trim();
            if !text.is_empty() {
                out.push(text.to_string());
            }
            continue;
        }
        scala_collect_extends_type_text_inner(child, source, out, false);
    }
}

fn scala_member_not_found(
    _ctx: ScalaLookupCtx<'_>,
    owner_fqn: &str,
    member: &str,
) -> DefinitionLookupOutcome {
    no_definition(
        SCALA_UNSUPPORTED_RECEIVER,
        format!(
            "receiver for Scala member `{member}` resolved to `{owner_fqn}`, but `{owner_fqn}.{member}` was not indexed"
        ),
    )
}

fn scala_receiver_type_fqn(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    root: Node<'_>,
    receiver: Node<'_>,
    cutoff_start: usize,
) -> Option<String> {
    if !matches!(receiver.kind(), "identifier" | "type_identifier") {
        return scala_non_identifier_receiver_type_fqn(ctx, resolver, receiver);
    }
    let bindings = scala_bindings_before(ctx, resolver, root, cutoff_start);
    scala_receiver_type_fqn_with_bindings(ctx, resolver, receiver, &bindings)
}

fn scala_receiver_type_fqn_with_bindings(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    receiver: Node<'_>,
    bindings: &LocalInferenceEngine<ScalaLocalBinding>,
) -> Option<String> {
    scala_receiver_owner_with_bindings(ctx, resolver, receiver, bindings)
        .map(|owner| owner.fq_name())
}

fn scala_receiver_owner_with_bindings(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    receiver: Node<'_>,
    bindings: &LocalInferenceEngine<ScalaLocalBinding>,
) -> Option<ScalaReceiverOwner> {
    if !matches!(receiver.kind(), "identifier" | "type_identifier") {
        return scala_non_identifier_receiver_type_fqn(ctx, resolver, receiver)
            .map(ScalaReceiverOwner::Logical);
    }
    let name = scala_node_text(receiver, ctx.source).trim();
    if matches!(name, "this" | "super") {
        return ClassRangeIndex::build(ctx.analyzer, ctx.file)
            .enclosing_unit(receiver.start_byte())
            .cloned()
            .map(ScalaReceiverOwner::Exact);
    }
    precise_scala_binding(bindings, name)
        .and_then(|binding| {
            binding
                .receiver_declaration
                .map(ScalaReceiverOwner::Exact)
                .or_else(|| binding.receiver_type.map(ScalaReceiverOwner::Logical))
        })
        .or_else(|| {
            scala_enclosing_class_parameter_type(ctx, receiver, name, resolver)
                .map(ScalaReceiverOwner::Logical)
                .or_else(|| {
                    if !bindings.is_shadowed(name)
                        && let Some(imported_member) = resolver.resolve_member(name)
                        && let Some(return_type) =
                            scala_imported_member_return_type(ctx, resolver, &imported_member)
                    {
                        return Some(ScalaReceiverOwner::Logical(return_type));
                    }
                    (!bindings.is_shadowed(name))
                        .then(|| {
                            scala_resolve_visible_term(ctx, resolver, receiver, name)
                                .or_else(|| resolver.resolve(name))
                                .map(ScalaReceiverOwner::Logical)
                        })
                        .flatten()
                })
        })
}

fn scala_non_identifier_receiver_type_fqn(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    receiver: Node<'_>,
) -> Option<String> {
    match receiver.kind() {
        // `new Foo().member` — the receiver is typed by the constructed class.
        "instance_expression" => scala_constructed_type(ctx, receiver, resolver),
        kind => scala_literal_type_name(kind).map(str::to_string),
    }
}

fn scala_imported_member_return_type(
    ctx: ScalaLookupCtx<'_>,
    _resolver: &ScalaNameResolver,
    member_fqn: &str,
) -> Option<String> {
    scala_coherent_function_return_type(ctx, ctx.support.fqn(member_fqn))
}

fn scala_signature_return_type(signature: &str) -> Option<&str> {
    let (_, after_colon) = signature.rsplit_once(':')?;
    let end = after_colon.find(['=', '{']).unwrap_or(after_colon.len());
    let return_type = after_colon[..end].trim();
    (!return_type.is_empty()).then_some(return_type)
}

fn scala_enclosing_class_parameter_type(
    ctx: ScalaLookupCtx<'_>,
    node: Node<'_>,
    name: &str,
    resolver: &ScalaNameResolver,
) -> Option<String> {
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == "class_definition" {
            let parameters = parent.child_by_field_name("class_parameters")?;
            let mut cursor = parameters.walk();
            for parameter in parameters.named_children(&mut cursor) {
                if !matches!(parameter.kind(), "parameter" | "class_parameter") {
                    continue;
                }
                let Some(param_name) = parameter.child_by_field_name("name") else {
                    continue;
                };
                if scala_node_text(param_name, ctx.source).trim() != name {
                    continue;
                }
                if scala_active_path_declares_name_after(
                    parent,
                    ctx.source,
                    name,
                    parameter.end_byte(),
                    node.start_byte(),
                ) {
                    return None;
                }
                return parameter.child_by_field_name("type").and_then(|type_node| {
                    scala_resolve_visible_type_node(ctx, resolver, type_node)
                });
            }
            return None;
        }
        current = parent.parent();
    }
    None
}

fn scala_active_path_declares_name_before(
    root: Node<'_>,
    source: &str,
    name: &str,
    cutoff_start: usize,
) -> bool {
    scala_active_path_declares_name_before_mode(root, source, name, cutoff_start, true)
}

fn scala_active_path_declares_name_before_in_session(
    session: Option<&ResolutionSession>,
    root: Node<'_>,
    source: &str,
    name: &str,
    cutoff_start: usize,
) -> Option<bool> {
    match session {
        Some(session) => scala_active_path_declares_name_before_bounded(
            session,
            root,
            source,
            name,
            cutoff_start,
        ),
        None => Some(scala_active_path_declares_name_before(
            root,
            source,
            name,
            cutoff_start,
        )),
    }
}

fn scala_active_path_declares_name_before_bounded(
    session: &ResolutionSession,
    root: Node<'_>,
    source: &str,
    name: &str,
    cutoff_start: usize,
) -> Option<bool> {
    if !session.scope_step() {
        return None;
    }
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.start_byte() >= cutoff_start {
            continue;
        }
        let enters_scope = SCALA_SCOPE_NODES.contains(&node.kind());
        let contains_cutoff = node.start_byte() <= cutoff_start && cutoff_start < node.end_byte();
        if enters_scope && !contains_cutoff {
            if node.kind() == "function_definition"
                && scala_node_declares_name_before_bounded(
                    session,
                    node,
                    source,
                    name,
                    0,
                    cutoff_start,
                )?
            {
                return Some(true);
            }
            continue;
        }

        if matches!(node.kind(), "class_definition" | "function_definition")
            && scala_parameters_declare_name_before_bounded(
                session,
                node,
                source,
                name,
                cutoff_start,
            )?
        {
            return Some(true);
        }
        match node.kind() {
            "function_definition" => {
                if scala_is_local_function_definition_bounded(session, node)?
                    && scala_node_declares_name_before_bounded(
                        session,
                        node,
                        source,
                        name,
                        0,
                        cutoff_start,
                    )?
                {
                    return Some(true);
                }
            }
            "case_clause" => {
                if let Some(pattern) = node.child_by_field_name("pattern") {
                    if !session.scope_step() {
                        return None;
                    }
                    if pattern.end_byte() <= cutoff_start
                        && scala_pattern_declares_name_bounded(session, pattern, source, name)?
                    {
                        return Some(true);
                    }
                }
            }
            "val_definition" | "var_definition"
                if !scala_is_direct_member_value_definition_bounded(session, node)?
                    && scala_node_declares_name_before_bounded(
                        session,
                        node,
                        source,
                        name,
                        0,
                        cutoff_start,
                    )? =>
            {
                return Some(true);
            }
            _ => {}
        }

        let mut cursor = node.walk();
        let mut children = Vec::new();
        for child in node.named_children(&mut cursor) {
            if !session.scope_step() {
                return None;
            }
            if child.start_byte() >= cutoff_start {
                break;
            }
            children.push(child);
        }
        children.reverse();
        stack.extend(children);
    }
    Some(false)
}

fn scala_lexical_binding_declares_name_before(
    root: Node<'_>,
    source: &str,
    name: &str,
    cutoff_start: usize,
) -> bool {
    scala_active_path_declares_name_before_mode(root, source, name, cutoff_start, false)
}

fn scala_active_path_declares_name_before_mode(
    root: Node<'_>,
    source: &str,
    name: &str,
    cutoff_start: usize,
    include_callable_names: bool,
) -> bool {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.start_byte() >= cutoff_start {
            continue;
        }
        let enters_scope = SCALA_SCOPE_NODES.contains(&node.kind());
        let contains_cutoff = node.start_byte() <= cutoff_start && cutoff_start < node.end_byte();
        if enters_scope && !contains_cutoff {
            if node.kind() == "function_definition"
                && (include_callable_names || scala_is_local_function_definition(node))
                && scala_node_declares_name_before(node, source, name, 0, cutoff_start)
            {
                return true;
            }
            continue;
        }

        match node.kind() {
            "class_definition" | "function_definition" => {
                if scala_parameters_declare_name_before(node, source, name, cutoff_start) {
                    return true;
                }
                if node.kind() == "function_definition"
                    && scala_is_local_function_definition(node)
                    && scala_node_declares_name_before(node, source, name, 0, cutoff_start)
                {
                    return true;
                }
            }
            "case_clause"
                if node.child_by_field_name("pattern").is_some_and(|pattern| {
                    pattern.end_byte() <= cutoff_start
                        && scala_pattern_binder_names(pattern, source).contains(&name)
                }) =>
            {
                return true;
            }
            "val_definition" | "var_definition"
                if !scala_is_direct_member_value_definition(node)
                    && scala_node_declares_name_before(node, source, name, 0, cutoff_start) =>
            {
                return true;
            }
            _ => {}
        }

        let mut cursor = node.walk();
        let mut children: Vec<_> = node
            .named_children(&mut cursor)
            .take_while(|child| child.start_byte() < cutoff_start)
            .collect();
        children.reverse();
        stack.extend(children);
    }
    false
}

fn scala_parameters_declare_name_before(
    node: Node<'_>,
    source: &str,
    name: &str,
    cutoff_start: usize,
) -> bool {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|child| matches!(child.kind(), "parameters" | "class_parameters"))
        .filter(|child| child.start_byte() < cutoff_start)
        .any(|child| scala_node_declares_name_before(child, source, name, 0, cutoff_start))
}

fn scala_parameters_declare_name_before_bounded(
    session: &ResolutionSession,
    node: Node<'_>,
    source: &str,
    name: &str,
    cutoff_start: usize,
) -> Option<bool> {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if !session.scope_step() {
            return None;
        }
        if matches!(child.kind(), "parameters" | "class_parameters")
            && child.start_byte() < cutoff_start
            && scala_node_declares_name_before_bounded(
                session,
                child,
                source,
                name,
                0,
                cutoff_start,
            )?
        {
            return Some(true);
        }
    }
    Some(false)
}

fn scala_active_path_declares_name_after(
    node: Node<'_>,
    source: &str,
    name: &str,
    lower_bound: usize,
    target_byte: usize,
) -> bool {
    if target_byte < node.start_byte() || node.end_byte() <= target_byte {
        return false;
    }

    let mut containing_child = None;
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.start_byte() <= target_byte && target_byte < child.end_byte() {
            containing_child = Some(child);
        }
        if child.start_byte() >= target_byte || child.end_byte() <= lower_bound {
            continue;
        }
        if scala_node_declares_name_before(child, source, name, lower_bound, target_byte) {
            return true;
        }
    }

    containing_child.is_some_and(|child| {
        scala_active_path_declares_name_after(child, source, name, lower_bound, target_byte)
    })
}

fn scala_node_declares_name_before(
    node: Node<'_>,
    source: &str,
    name: &str,
    lower_bound: usize,
    target_byte: usize,
) -> bool {
    match node.kind() {
        "parameter" | "class_parameter" => {
            node.child_by_field_name("name").is_some_and(|name_node| {
                lower_bound <= name_node.start_byte()
                    && name_node.start_byte() < target_byte
                    && scala_node_text(name_node, source).trim() == name
            })
        }
        "parameters" | "class_parameters" => {
            let mut cursor = node.walk();
            node.named_children(&mut cursor).any(|child| {
                scala_node_declares_name_before(child, source, name, lower_bound, target_byte)
            })
        }
        "val_definition" | "var_definition" => {
            if node.start_byte() >= target_byte {
                return false;
            }
            node.child_by_field_name("pattern").is_some_and(|pattern| {
                lower_bound <= pattern.start_byte()
                    && scala_pattern_binder_names(pattern, source).contains(&name)
            })
        }
        "enumerator" => {
            scala_enumerator_visible_pattern(node, target_byte).is_some_and(|pattern| {
                lower_bound <= pattern.start_byte()
                    && scala_pattern_binder_names(pattern, source).contains(&name)
            })
        }
        "function_definition" => node.child_by_field_name("name").is_some_and(|name_node| {
            lower_bound <= name_node.start_byte()
                && name_node.start_byte() < target_byte
                && scala_node_text(name_node, source).trim() == name
        }),
        _ => false,
    }
}

fn scala_node_declares_name_before_bounded(
    session: &ResolutionSession,
    node: Node<'_>,
    source: &str,
    name: &str,
    lower_bound: usize,
    target_byte: usize,
) -> Option<bool> {
    match node.kind() {
        "parameter" | "class_parameter" => {
            let Some(name_node) = node.child_by_field_name("name") else {
                return Some(false);
            };
            if !session.scope_step() {
                return None;
            }
            Some(
                lower_bound <= name_node.start_byte()
                    && name_node.start_byte() < target_byte
                    && scala_node_text(name_node, source).trim() == name,
            )
        }
        "parameters" | "class_parameters" => {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if !session.scope_step() {
                    return None;
                }
                if scala_node_declares_name_before_bounded(
                    session,
                    child,
                    source,
                    name,
                    lower_bound,
                    target_byte,
                )? {
                    return Some(true);
                }
            }
            Some(false)
        }
        "val_definition" | "var_definition" => {
            if node.start_byte() >= target_byte {
                return Some(false);
            }
            let Some(pattern) = node.child_by_field_name("pattern") else {
                return Some(false);
            };
            if !session.scope_step() {
                return None;
            }
            if lower_bound > pattern.start_byte() {
                return Some(false);
            }
            scala_pattern_declares_name_bounded(session, pattern, source, name)
        }
        "enumerator" => {
            let Some(pattern) =
                scala_enumerator_visible_pattern_bounded(session, node, target_byte)?
            else {
                return Some(false);
            };
            if lower_bound > pattern.start_byte() {
                return Some(false);
            }
            scala_pattern_declares_name_bounded(session, pattern, source, name)
        }
        "function_definition" => {
            let Some(name_node) = node.child_by_field_name("name") else {
                return Some(false);
            };
            if !session.scope_step() {
                return None;
            }
            Some(
                lower_bound <= name_node.start_byte()
                    && name_node.start_byte() < target_byte
                    && scala_node_text(name_node, source).trim() == name,
            )
        }
        _ => Some(false),
    }
}

fn scala_enumerator_visible_pattern(
    enumerator: Node<'_>,
    reference_byte: usize,
) -> Option<Node<'_>> {
    let pattern = enumerator
        .named_child(0)
        .filter(|child| child.kind() != "guard")?;
    enumerator
        .named_children(&mut enumerator.walk())
        .find(|child| child.start_byte() >= pattern.end_byte() && child.kind() != "guard")
        .filter(|expression| expression.end_byte() <= reference_byte)
        .map(|_| pattern)
}

fn scala_enumerator_visible_pattern_bounded<'tree>(
    session: &ResolutionSession,
    enumerator: Node<'tree>,
    reference_byte: usize,
) -> Option<Option<Node<'tree>>> {
    let Some(pattern) = enumerator.named_child(0) else {
        return Some(None);
    };
    if !session.scope_step() {
        return None;
    }
    if pattern.kind() == "guard" {
        return Some(None);
    }
    let mut cursor = enumerator.walk();
    for child in enumerator.named_children(&mut cursor) {
        if !session.scope_step() {
            return None;
        }
        if child.start_byte() >= pattern.end_byte() && child.kind() != "guard" {
            return Some((child.end_byte() <= reference_byte).then_some(pattern));
        }
    }
    Some(None)
}

fn scala_pattern_declares_name_bounded(
    session: &ResolutionSession,
    pattern: Node<'_>,
    source: &str,
    name: &str,
) -> Option<bool> {
    if !scala_charge_named_descendants(session, pattern) {
        return None;
    }
    Some(scala_pattern_binder_names(pattern, source).contains(&name))
}

fn scala_charge_named_descendants(session: &ResolutionSession, root: Node<'_>) -> bool {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if !session.scope_step() {
                return false;
            }
            stack.push(child);
        }
    }
    true
}

fn scala_is_direct_member_value_definition_bounded(
    session: &ResolutionSession,
    node: Node<'_>,
) -> Option<bool> {
    let mut current = node.parent();
    while let Some(ancestor) = current {
        if !session.scope_step() {
            return None;
        }
        match ancestor.kind() {
            "function_definition"
            | "block"
            | "block_expression"
            | "indented_block"
            | "case_clause"
            | "lambda_expression" => return Some(false),
            "class_definition" | "object_definition" | "trait_definition" | "enum_definition" => {
                return Some(true);
            }
            _ => current = ancestor.parent(),
        }
    }
    Some(false)
}

fn scala_is_local_function_definition_bounded(
    session: &ResolutionSession,
    node: Node<'_>,
) -> Option<bool> {
    let mut current = node.parent();
    while let Some(ancestor) = current {
        if !session.scope_step() {
            return None;
        }
        match ancestor.kind() {
            "function_definition"
            | "block"
            | "block_expression"
            | "indented_block"
            | "case_clause"
            | "lambda_expression" => return Some(true),
            "class_definition" | "object_definition" | "trait_definition" | "enum_definition" => {
                return Some(false);
            }
            _ => current = ancestor.parent(),
        }
    }
    Some(false)
}

fn scala_existing_package_type_fqn(
    support: &dyn BoundedDefinitionLookup,
    package: &str,
    type_text: &str,
) -> Option<String> {
    let fqn = scala_package_type_fqn(package, type_text)?;
    support
        .fqn(&fqn)
        .into_iter()
        .any(|unit| unit.is_class() && unit.fq_name() == fqn)
        .then_some(fqn)
}

fn scala_package_type_fqn(package: &str, type_text: &str) -> Option<String> {
    let simple = scala_simple_name(type_text);
    if simple.is_empty() || simple.contains('.') {
        return None;
    }
    if package.is_empty() {
        Some(simple.to_string())
    } else {
        Some(format!("{package}.{simple}"))
    }
}

fn scala_resolve_type_annotation(resolver: &ScalaNameResolver, type_text: &str) -> Option<String> {
    let trimmed = type_text.trim();
    if let Some(base_type) = trimmed.strip_suffix(".type") {
        return resolver.resolve_singleton(base_type);
    }
    let fqn = resolver
        .resolve(type_text)
        .or_else(|| scala_type_base_text(trimmed).and_then(|base| resolver.resolve(base)))?;
    Some(fqn.trim_end_matches('$').to_string())
}

fn scala_resolve_visible_type_annotation(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    type_text: &str,
    reference_byte: usize,
) -> Option<String> {
    if let Some(base) = type_text.trim().strip_suffix(".type") {
        return match resolver.resolve_owner(base, ScalaOwnerKind::SingletonObject) {
            ScalaNameResolution::Resolved(owner) => Some(owner.fqn),
            ScalaNameResolution::MissingExplicitImport
            | ScalaNameResolution::Ambiguous
            | ScalaNameResolution::Unresolved => None,
        };
    }
    let base = scala_type_base_text(type_text.trim()).unwrap_or(type_text);
    match resolver.resolve_owner(base, ScalaOwnerKind::Class) {
        ScalaNameResolution::Resolved(owner) => return Some(owner.fqn),
        ScalaNameResolution::MissingExplicitImport | ScalaNameResolution::Ambiguous => return None,
        ScalaNameResolution::Unresolved => {}
    }
    if scala_type_annotation_has_explicit_import(ctx, type_text) {
        return None;
    }
    scala_package_name_of(ctx.scala, ctx.file)
        .and_then(|package| scala_existing_package_type_fqn(ctx.support, &package, type_text))
        .or_else(|| scala_enclosing_type_fqn(ctx, type_text, reference_byte))
        .or_else(|| scala_builtin_type_name(type_text).map(str::to_string))
}

fn scala_resolve_visible_type_node(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    node: Node<'_>,
) -> Option<String> {
    let segments = scala_type_lookup_segments(node, ctx.source);
    if segments.is_empty() {
        return None;
    }
    match scala_exact_lexical_type_namespace(ctx, resolver, node) {
        ScalaTypeNamespaceResolution::Resolved(declaration) => {
            return Some(declaration.fq_name());
        }
        ScalaTypeNamespaceResolution::AuthoritativeMiss
        | ScalaTypeNamespaceResolution::Ambiguous => return None,
        ScalaTypeNamespaceResolution::NoMatch => {}
    }
    match scala_exact_exported_qualified_type(ctx, resolver, node) {
        ScalaTypeNamespaceResolution::Resolved(declaration) => {
            return Some(declaration.fq_name());
        }
        ScalaTypeNamespaceResolution::AuthoritativeMiss
        | ScalaTypeNamespaceResolution::Ambiguous => return None,
        ScalaTypeNamespaceResolution::NoMatch => {}
    }
    scala_resolve_visible_type_node_after_lexical_miss(ctx, resolver, node)
}

fn scala_resolve_visible_type_declaration(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver<'_>,
    node: Node<'_>,
) -> Option<CodeUnit> {
    match scala_exact_lexical_type_namespace(ctx, resolver, node) {
        ScalaTypeNamespaceResolution::Resolved(declaration) => return Some(declaration),
        ScalaTypeNamespaceResolution::AuthoritativeMiss
        | ScalaTypeNamespaceResolution::Ambiguous => return None,
        ScalaTypeNamespaceResolution::NoMatch => {}
    }
    match scala_exact_exported_qualified_type(ctx, resolver, node) {
        ScalaTypeNamespaceResolution::Resolved(declaration) => return Some(declaration),
        ScalaTypeNamespaceResolution::AuthoritativeMiss
        | ScalaTypeNamespaceResolution::Ambiguous => return None,
        ScalaTypeNamespaceResolution::NoMatch => {}
    }

    let segments = scala_type_lookup_segments(node, ctx.source);
    let kind = scala_type_node_owner_kind(node);
    if !segments.is_empty() {
        let package = scala_package_name_of(ctx.scala, ctx.file).unwrap_or_default();
        let mut same_file = scala_nested_type_candidates(package, &segments, false)
            .into_iter()
            .flat_map(|candidate| {
                let fqn = match kind {
                    ScalaOwnerKind::Class => candidate.trim_end_matches('$').to_string(),
                    ScalaOwnerKind::SingletonObject if candidate.ends_with('$') => candidate,
                    ScalaOwnerKind::SingletonObject => format!("{candidate}$"),
                    ScalaOwnerKind::TypeNamespace => candidate,
                };
                ctx.support.fqn(&fqn).into_iter().filter(move |unit| {
                    unit.fq_name() == fqn
                        && unit.source() == ctx.file
                        && (unit.is_class()
                            || (kind == ScalaOwnerKind::TypeNamespace
                                && ctx.scala.is_type_alias(unit)))
                })
            })
            .collect::<Vec<_>>();
        sort_units(&mut same_file);
        same_file.dedup();
        if let [declaration] = same_file.as_slice() {
            return Some(declaration.clone());
        }
        if same_file.len() > 1 {
            return None;
        }
    }

    match resolver.resolve_type_node(node, ctx.source, kind) {
        ScalaNameResolution::Resolved(owner) => Some(owner._declaration),
        ScalaNameResolution::MissingExplicitImport
        | ScalaNameResolution::Ambiguous
        | ScalaNameResolution::Unresolved => None,
    }
}

fn scala_resolve_visible_type_node_after_lexical_miss(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    node: Node<'_>,
) -> Option<String> {
    let segments = scala_type_lookup_segments(node, ctx.source);
    if segments.is_empty() {
        return None;
    }
    let kind = scala_type_node_owner_kind(node);
    let type_text = scala_node_text(node, ctx.source);
    if let Some(local) =
        scala_resolve_enclosing_qualified_type(ctx, resolver, node, &segments, kind)
    {
        return Some(local);
    }
    if !scala_type_annotation_has_explicit_import(ctx, type_text)
        && let Some(local) = scala_same_file_type_fqn(ctx, &segments, kind)
    {
        return Some(local);
    }
    match resolver.resolve_type_node(node, ctx.source, kind) {
        ScalaNameResolution::Resolved(owner) => Some(owner.fqn),
        ScalaNameResolution::MissingExplicitImport | ScalaNameResolution::Ambiguous => None,
        // A structured qualified path is authoritative. Falling back to its
        // terminal spelling would allow `java.lang.Long` or
        // `_root_.scala.Boolean` to bind an unrelated root-level fixture.
        ScalaNameResolution::Unresolved if segments.len() > 1 => None,
        ScalaNameResolution::Unresolved => scala_resolve_visible_type_annotation(
            ctx,
            resolver,
            scala_node_text(node, ctx.source),
            node.start_byte(),
        ),
    }
}

fn scala_exact_lexical_type_namespace(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver<'_>,
    node: Node<'_>,
) -> ScalaTypeNamespaceResolution {
    let lookup_node = scala_qualified_type_root(node);
    if scala_type_reference_is_singleton(lookup_node) {
        return ScalaTypeNamespaceResolution::NoMatch;
    }
    let segments = scala_type_lookup_segments(lookup_node, ctx.source);
    let Some(root_name) = segments.first() else {
        return ScalaTypeNamespaceResolution::NoMatch;
    };
    if let Some(binding) = scala_nearest_unindexed_type_binding(ctx.source, lookup_node, root_name)
    {
        return match binding {
            ScalaUnindexedTypeBinding::Authoritative => {
                ScalaTypeNamespaceResolution::AuthoritativeMiss
            }
            ScalaUnindexedTypeBinding::AnonymousRefinement(instance) => {
                if segments.len() > 1 {
                    ScalaTypeNamespaceResolution::AuthoritativeMiss
                } else {
                    scala_type_member_before_anonymous_refinement(
                        ctx,
                        resolver,
                        lookup_node,
                        instance,
                        root_name,
                    )
                }
            }
        };
    }
    let range = Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: node.start_position().row,
        end_line: node.end_position().row,
    };
    let mut owners = Vec::new();
    let mut current = ctx.analyzer.enclosing_code_unit(ctx.file, &range);
    while let Some(unit) = current {
        current = ctx.scala.structural_parent_of(&unit);
        if unit.is_class() {
            owners.push(unit);
        }
    }
    if segments.len() == 1
        && let Some(owner) = owners.iter().find(|owner| {
            !owner.short_name().ends_with('$') && owner.identifier() == root_name.as_str()
        })
    {
        // An enclosing class introduces its own exact type name before any
        // inherited type members. Resolve that parser-proven identity without
        // traversing incomplete ancestors (for example an unindexed
        // `Serializable` mixin), which cannot make the self type ambiguous.
        return ScalaTypeNamespaceResolution::Resolved(owner.clone());
    }
    if segments.len() > 1 {
        for owner in owners {
            let mut candidates =
                match scala_exact_owner_namespace_children(ctx, &owner, &segments[0]) {
                    ScalaExactMemberResolution::Found(candidates) => candidates,
                    ScalaExactMemberResolution::Ambiguous => {
                        return ScalaTypeNamespaceResolution::Ambiguous;
                    }
                    ScalaExactMemberResolution::NoMatch => continue,
                };
            for (index, segment) in segments[1..].iter().enumerate() {
                let terminal = index + 2 == segments.len();
                let mut next = candidates
                    .iter()
                    .flat_map(|candidate| {
                        scala_exact_direct_namespace_children(
                            ctx,
                            candidate,
                            segment,
                            terminal.then(|| scala_type_node_owner_kind(lookup_node)),
                        )
                    })
                    .collect::<Vec<_>>();
                sort_units(&mut next);
                next.dedup();
                if next.is_empty() {
                    // The lexical root is authoritative even when the selected
                    // child is absent; an imported or package-level namesake
                    // cannot replace it.
                    return ScalaTypeNamespaceResolution::AuthoritativeMiss;
                }
                candidates = next;
            }
            return match candidates.as_slice() {
                [declaration] => ScalaTypeNamespaceResolution::Resolved(declaration.clone()),
                [_, _, ..] => ScalaTypeNamespaceResolution::Ambiguous,
                [] => ScalaTypeNamespaceResolution::AuthoritativeMiss,
            };
        }
        return ScalaTypeNamespaceResolution::NoMatch;
    }
    let [name] = segments.as_slice() else {
        return ScalaTypeNamespaceResolution::NoMatch;
    };
    resolve_exact_lexical_type_namespace(
        owners,
        name,
        false,
        |owner, member| {
            ctx.support
                .fqn_direct_children(&owner.fq_name())
                .into_iter()
                .filter(|unit| unit.identifier() == member)
                .filter(|unit| unit.source() == owner.source())
                .filter(|unit| ctx.scala.structural_parent_of(unit).as_ref() == Some(owner))
                .filter(|unit| {
                    unit.is_class() && !unit.short_name().ends_with('$')
                        || ctx.scala.is_type_alias(unit)
                })
                .collect()
        },
        |owner| scala_forward_direct_ancestor_resolution(ctx.scala, ctx.support, owner),
    )
}

fn scala_type_member_before_anonymous_refinement(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver<'_>,
    lookup_node: Node<'_>,
    binding_instance: Node<'_>,
    name: &str,
) -> ScalaTypeNamespaceResolution {
    let mut current = Some(lookup_node);
    while let Some(node) = current {
        if node.kind() == "template_body" {
            let (owner, binding_tier) = if let Some(instance) =
                scala_anonymous_instance_for_template(node)
            {
                let Some(owner) = scala_exact_constructed_argument(ctx, resolver, instance) else {
                    return ScalaTypeNamespaceResolution::AuthoritativeMiss;
                };
                (owner, instance == binding_instance)
            } else {
                let Some(named_owner) = scala_named_template_owner_for_forward(node) else {
                    return ScalaTypeNamespaceResolution::AuthoritativeMiss;
                };
                let ranges = ClassRangeIndex::build(ctx.analyzer, ctx.file);
                let Some(owner) = ranges
                    .unit_for_exact_span(named_owner.start_byte(), named_owner.end_byte())
                    .cloned()
                else {
                    return ScalaTypeNamespaceResolution::AuthoritativeMiss;
                };
                (owner, false)
            };
            match resolve_exact_lexical_type_namespace(
                std::iter::once(owner),
                name,
                false,
                |owner, member| {
                    scala_exact_direct_namespace_children(
                        ctx,
                        owner,
                        member,
                        Some(ScalaOwnerKind::TypeNamespace),
                    )
                },
                |owner| scala_forward_direct_ancestor_resolution(ctx.scala, ctx.support, owner),
            ) {
                ScalaTypeNamespaceResolution::Resolved(member) => {
                    return ScalaTypeNamespaceResolution::Resolved(member);
                }
                ScalaTypeNamespaceResolution::Ambiguous
                | ScalaTypeNamespaceResolution::AuthoritativeMiss => {
                    return ScalaTypeNamespaceResolution::AuthoritativeMiss;
                }
                ScalaTypeNamespaceResolution::NoMatch if binding_tier => {
                    return ScalaTypeNamespaceResolution::AuthoritativeMiss;
                }
                ScalaTypeNamespaceResolution::NoMatch => {}
            }
        }
        current = node.parent();
    }
    ScalaTypeNamespaceResolution::AuthoritativeMiss
}

fn scala_named_template_owner_for_forward(mut template: Node<'_>) -> Option<Node<'_>> {
    while let Some(parent) = template.parent() {
        match parent.kind() {
            "class_definition" | "object_definition" | "trait_definition" | "enum_definition" => {
                return Some(parent);
            }
            "instance_expression" | "template_body" => return None,
            _ => template = parent,
        }
    }
    None
}

fn scala_exact_owner_namespace_children(
    ctx: ScalaLookupCtx<'_>,
    owner: &CodeUnit,
    name: &str,
) -> ScalaExactMemberResolution {
    let direct = scala_exact_direct_namespace_children(ctx, owner, name, None);
    if !direct.is_empty() {
        return ScalaExactMemberResolution::Found(direct);
    }

    let mut level = match scala_forward_direct_ancestor_resolution(ctx.scala, ctx.support, owner) {
        ScalaDirectAncestorResolution::Resolved(ancestors) => ancestors,
        ScalaDirectAncestorResolution::Ambiguous => {
            return ScalaExactMemberResolution::Ambiguous;
        }
    };
    let mut seen = HashSet::from_iter([owner.clone()]);
    while !level.is_empty() {
        let mut matches = Vec::new();
        let mut next = Vec::new();
        for ancestor in level {
            if !seen.insert(ancestor.clone()) {
                continue;
            }
            matches.extend(scala_exact_direct_namespace_children(
                ctx, &ancestor, name, None,
            ));
            match scala_forward_direct_ancestor_resolution(ctx.scala, ctx.support, &ancestor) {
                ScalaDirectAncestorResolution::Resolved(ancestors) => next.extend(ancestors),
                ScalaDirectAncestorResolution::Ambiguous => {
                    return ScalaExactMemberResolution::Ambiguous;
                }
            }
        }
        sort_units(&mut matches);
        matches.dedup();
        if !matches.is_empty() {
            return ScalaExactMemberResolution::Found(matches);
        }
        level = next;
    }
    ScalaExactMemberResolution::NoMatch
}

fn scala_exact_direct_namespace_children(
    ctx: ScalaLookupCtx<'_>,
    owner: &CodeUnit,
    name: &str,
    terminal_kind: Option<ScalaOwnerKind>,
) -> Vec<CodeUnit> {
    let mut candidates = ctx
        .support
        .fqn_direct_children(&owner.fq_name())
        .into_iter()
        .filter(|unit| unit.identifier().trim_end_matches('$') == name)
        .filter(|unit| unit.source() == owner.source())
        .filter(|unit| ctx.scala.structural_parent_of(unit).as_ref() == Some(owner))
        .filter(|unit| match terminal_kind {
            None => unit.is_class(),
            Some(ScalaOwnerKind::Class) => unit.is_class() && !unit.short_name().ends_with('$'),
            Some(ScalaOwnerKind::SingletonObject) => {
                unit.is_class() && unit.short_name().ends_with('$')
            }
            Some(ScalaOwnerKind::TypeNamespace) => {
                unit.is_class() && !unit.short_name().ends_with('$')
                    || ctx.scala.is_type_alias(unit)
            }
        })
        .collect::<Vec<_>>();
    sort_units(&mut candidates);
    candidates.dedup();
    candidates
}

fn scala_same_file_type_fqn(
    ctx: ScalaLookupCtx<'_>,
    segments: &[String],
    kind: ScalaOwnerKind,
) -> Option<String> {
    let package = scala_package_name_of(ctx.scala, ctx.file).unwrap_or_default();
    let candidates = scala_nested_type_candidates(package, segments, false);
    let mut matches = Vec::new();
    for candidate in candidates {
        let fqn = match kind {
            ScalaOwnerKind::Class => candidate.trim_end_matches('$').to_string(),
            ScalaOwnerKind::SingletonObject if candidate.ends_with('$') => candidate,
            ScalaOwnerKind::SingletonObject => format!("{candidate}$"),
            ScalaOwnerKind::TypeNamespace => candidate,
        };
        matches.extend(
            ctx.support
                .fqn(&fqn)
                .into_iter()
                .filter(|unit| {
                    unit.fq_name() == fqn
                        && unit.source() == ctx.file
                        && (unit.is_class()
                            || (kind == ScalaOwnerKind::TypeNamespace
                                && ctx.scala.is_type_alias(unit)))
                })
                .map(|unit| unit.fq_name()),
        );
    }
    matches.sort();
    matches.dedup();
    (matches.len() == 1).then(|| matches.remove(0))
}

fn scala_type_node_owner_kind(node: Node<'_>) -> ScalaOwnerKind {
    let mut current = Some(node);
    while let Some(node) = current {
        if node.kind() == "singleton_type" {
            return ScalaOwnerKind::SingletonObject;
        }
        current = node.parent().filter(|parent| {
            matches!(
                parent.kind(),
                "singleton_type" | "stable_type_identifier" | "generic_type"
            )
        });
    }
    ScalaOwnerKind::TypeNamespace
}

fn scala_resolve_enclosing_qualified_type(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    node: Node<'_>,
    type_segments: &[String],
    kind: ScalaOwnerKind,
) -> Option<String> {
    let mut owners = Vec::new();
    let mut current = node.parent();
    while let Some(parent) = current {
        if matches!(
            parent.kind(),
            "class_definition" | "object_definition" | "trait_definition" | "enum_definition"
        ) && let Some(name) = parent.child_by_field_name("name")
        {
            let name = scala_node_text(name, ctx.source).trim();
            if !name.is_empty() {
                owners.push(name.to_string());
            }
        }
        current = parent.parent();
    }
    owners.reverse();

    for prefix_len in (1..=owners.len()).rev() {
        let mut candidate = Vec::with_capacity(prefix_len + type_segments.len());
        candidate.extend(owners[..prefix_len].iter().cloned());
        candidate.extend(type_segments.iter().cloned());
        for package_prefix in resolver
            .package_prefixes
            .iter()
            .rev()
            .filter(|prefix| !prefix.is_empty())
        {
            match resolver.resolve_candidate_tier(
                scala_nested_type_candidates(package_prefix.clone(), &candidate, false),
                kind,
            ) {
                ScalaNameResolution::Resolved(owner) => return Some(owner.fqn),
                ScalaNameResolution::MissingExplicitImport | ScalaNameResolution::Ambiguous => {
                    return None;
                }
                ScalaNameResolution::Unresolved => {}
            }
        }
        if resolver.package_prefixes.iter().all(String::is_empty) {
            match resolver.resolve_candidate_tier(
                scala_nested_type_candidates(String::new(), &candidate, false),
                kind,
            ) {
                ScalaNameResolution::Resolved(owner) => return Some(owner.fqn),
                ScalaNameResolution::MissingExplicitImport | ScalaNameResolution::Ambiguous => {
                    return None;
                }
                ScalaNameResolution::Unresolved => {}
            }
        }
    }
    None
}

fn scala_resolve_receiver_type_annotation(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    type_text: &str,
    reference_byte: usize,
) -> Option<String> {
    scala_resolve_visible_type_annotation(ctx, resolver, type_text, reference_byte)
}

fn scala_enclosing_type_fqn(
    ctx: ScalaLookupCtx<'_>,
    type_text: &str,
    reference_byte: usize,
) -> Option<String> {
    let simple = scala_simple_name(type_text);
    if simple.is_empty() || simple.contains('.') {
        return None;
    }
    let owner = scala_enclosing_class(ctx.analyzer, ctx.support, ctx.file, reference_byte)?;
    let candidate = format!("{}.{simple}", owner.fq_name());
    ctx.analyzer
        .definitions(&candidate)
        .any(|unit| unit.is_class())
        .then_some(candidate)
}

fn scala_resolve_visible_term(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    node: Node<'_>,
    name: &str,
) -> Option<String> {
    if let Some(owner) =
        scala_enclosing_class(ctx.analyzer, ctx.support, ctx.file, node.start_byte())
        && owner.identifier().trim_end_matches('$') == name
    {
        let companion = format!("{}$", owner.fq_name().trim_end_matches('$'));
        if ctx
            .support
            .fqn(&companion)
            .into_iter()
            .any(|unit| unit.is_class() && unit.fq_name() == companion)
        {
            return Some(companion);
        }
    }
    if let Some(singleton) = scala_resolve_enclosing_qualified_type(
        ctx,
        resolver,
        node,
        &[name.to_string()],
        ScalaOwnerKind::SingletonObject,
    ) {
        return Some(singleton);
    }
    if let Some(singleton) = resolver.resolve_singleton(name) {
        return Some(singleton);
    }
    let owner = scala_resolve_visible_type_annotation(ctx, resolver, name, node.start_byte())?;
    if owner.ends_with('$') {
        return Some(owner);
    }
    let companion = format!("{owner}$");
    (!ctx.support.fqn(&companion).is_empty()).then_some(companion)
}

fn scala_resolve_visible_term_owner(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    root: Node<'_>,
    node: Node<'_>,
    name: &str,
) -> Option<String> {
    let bindings = scala_bindings_before(ctx, resolver, root, node.start_byte());
    if bindings.is_shadowed(name) {
        return precise_scala_binding(&bindings, name).and_then(|binding| binding.receiver_type);
    }
    scala_resolve_visible_term(ctx, resolver, node, name)
}

fn scala_type_annotation_has_explicit_import(ctx: ScalaLookupCtx<'_>, type_text: &str) -> bool {
    let simple = scala_simple_name(type_text);
    ctx.scala
        .import_info_of(ctx.file)
        .into_iter()
        .any(|import| {
            if import.is_wildcard {
                return false;
            }
            let Some(path) = scala_import_path(&import) else {
                return false;
            };
            let local_name = import
                .identifier
                .as_deref()
                .unwrap_or_else(|| path.rsplit('.').next().unwrap_or(path.as_str()));
            local_name == simple
        })
}

fn scala_type_base_text(type_text: &str) -> Option<&str> {
    let base = type_text
        .split(['[', '<'])
        .next()
        .unwrap_or(type_text)
        .trim();
    (!base.is_empty() && base != type_text.trim()).then_some(base)
}

fn scala_fqn_outcome(
    support: &dyn BoundedDefinitionLookup,
    fqn: &str,
    reference: &str,
) -> DefinitionLookupOutcome {
    let mut candidates = support.fqn(fqn);
    if candidates.is_empty() {
        candidates = support.fqn_in_language(fqn, Language::Java);
    }
    if candidates.is_empty() {
        no_definition(
            "no_indexed_definition",
            format!("`{reference}` resolved to `{fqn}`, but no indexed definition was found"),
        )
    } else {
        candidates_outcome(candidates)
    }
}

fn scala_enclosing_class(
    analyzer: &dyn IAnalyzer,
    _support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    byte: usize,
) -> Option<CodeUnit> {
    ClassRangeIndex::build(analyzer, file)
        .enclosing_unit(byte)
        .cloned()
}

fn scala_enclosing_member_shadows_bare_call(
    scala: &ScalaAnalyzer,
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    byte: usize,
    name: &str,
) -> bool {
    let Some(owner) = scala_enclosing_class(analyzer, support, file, byte) else {
        return false;
    };
    if owner.identifier().trim_end_matches('$') == name {
        return false;
    }
    let ctx = ScalaLookupCtx {
        scala,
        analyzer,
        support,
        file,
        source: "",
        session: None,
    };
    match scala_exact_owner_member_candidate_units(ctx, &owner, name, false) {
        ScalaExactMemberResolution::Found(candidates) => candidates.into_iter().any(|unit| {
            !unit.is_synthetic()
                && (unit.is_function() || scala_has_term_field_declaration(scala, &unit))
        }),
        ScalaExactMemberResolution::Ambiguous => true,
        ScalaExactMemberResolution::NoMatch => false,
    }
}

fn scala_has_term_field_declaration(scala: &ScalaAnalyzer, unit: &CodeUnit) -> bool {
    unit.is_field()
        && (!scala.is_type_alias(unit) || scala.signatures(unit).into_iter().nth(1).is_some())
}

fn scala_imported_member_shadows_bare_call(
    scala: &ScalaAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    name: &str,
    call_shape: Option<&ScalaCallSiteShape>,
) -> bool {
    let file_package = scala_package_name_of(scala, file).unwrap_or_default();
    for import in scala.import_info_of(file) {
        let Some(path) = scala_import_path(&import) else {
            continue;
        };
        if import.is_wildcard {
            let enclosing_owners = import
                .path
                .as_ref()
                .map(|structured_path| {
                    scala_enclosing_template_owner_fq_names(
                        scala,
                        scala,
                        file,
                        structured_path.declaration_start_byte,
                    )
                })
                .unwrap_or_default();
            let segments = import
                .path
                .as_ref()
                .map(|structured_path| structured_path.segments.as_slice())
                .unwrap_or(&[]);
            if scala_wildcard_imported_member_units(
                support,
                &path,
                &file_package,
                &enclosing_owners,
                segments,
                name,
            )
            .into_iter()
            .filter(|unit| !scala.is_type_alias(unit))
            .any(|unit| {
                scala_member_unit_applies(
                    scala,
                    &unit,
                    call_shape,
                    ScalaCallableSiteRole::Ordinary,
                    false,
                )
            }) {
                return true;
            }
            continue;
        }

        let local_name = import
            .identifier
            .as_deref()
            .unwrap_or_else(|| path.rsplit('.').next().unwrap_or(path.as_str()));
        if local_name != name {
            continue;
        }
        for candidate in import_candidate_fq_names(&path, &file_package) {
            let normalized = scala_normalized_fq_name(&candidate);
            if support
                .fqn(&candidate)
                .into_iter()
                .chain(support.fqn(&normalized))
                .chain(support.fqn(&format!("{candidate}$")))
                .any(|unit| (unit.is_function() || unit.is_field()) && !scala.is_type_alias(&unit))
            {
                return true;
            }
        }
    }
    false
}

const SCALA_SCOPE_NODES: &[&str] = &[
    "class_definition",
    "object_definition",
    "trait_definition",
    "enum_definition",
    "function_definition",
    "block",
    "indented_block",
    "case_clause",
    "lambda_expression",
];

fn scala_bindings_before(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    root: Node<'_>,
    cutoff_start: usize,
) -> LocalInferenceEngine<ScalaLocalBinding> {
    let mut bindings = LocalInferenceEngine::new(LocalInferenceConfig::default());
    scala_seed_active_path(ctx, resolver, root, cutoff_start, &mut bindings);
    bindings
}

fn scala_seed_active_path(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    node: Node<'_>,
    cutoff_start: usize,
    bindings: &mut LocalInferenceEngine<ScalaLocalBinding>,
) {
    let root = node;
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        if !ctx.scope_step() {
            return;
        }
        if node.start_byte() >= cutoff_start {
            continue;
        }
        let enters_scope = SCALA_SCOPE_NODES.contains(&node.kind());
        if enters_scope && !(node.start_byte() <= cutoff_start && cutoff_start < node.end_byte()) {
            if node.kind() == "function_definition"
                && scala_is_local_function_definition(node)
                && let Some(name) = node
                    .child_by_field_name("name")
                    .filter(|name| name.start_byte() < cutoff_start)
            {
                let name = scala_node_text(name, ctx.source).trim();
                if !name.is_empty() {
                    bindings.declare_shadow(name.to_string());
                }
            }
            continue;
        }
        if enters_scope {
            bindings.enter_scope();
        }
        match node.kind() {
            "class_definition" => {
                scala_seed_parameters(ctx, resolver, node, cutoff_start, bindings)
            }
            "function_definition" => {
                if scala_is_local_function_definition(node)
                    && let Some(name) = node.child_by_field_name("name")
                {
                    let name = scala_node_text(name, ctx.source).trim();
                    if !name.is_empty() {
                        bindings.declare_shadow(name.to_string());
                    }
                }
                scala_seed_parameters(ctx, resolver, node, cutoff_start, bindings);
            }
            "case_clause" => {
                if let Some(pattern) = node
                    .child_by_field_name("pattern")
                    .filter(|pattern| pattern.end_byte() <= cutoff_start)
                {
                    for name in scala_pattern_binder_names(pattern, ctx.source) {
                        bindings.declare_shadow(name.to_string());
                    }
                }
            }
            "enumerator" => {
                if let Some(pattern) = scala_enumerator_visible_pattern(node, cutoff_start) {
                    for name in scala_pattern_binder_names(pattern, ctx.source) {
                        bindings.declare_shadow(name.to_string());
                    }
                }
            }
            "val_definition" | "var_definition" if node.start_byte() < cutoff_start => {
                scala_seed_value_definition(ctx, resolver, root, node, cutoff_start, bindings)
            }
            "assignment_expression"
                if node.end_byte() <= cutoff_start && !is_scala_named_argument_assignment(node) =>
            {
                scala_refresh_assignment(ctx, resolver, root, node, bindings)
            }
            _ => {}
        }

        let mut cursor = node.walk();
        let mut children = Vec::new();
        for child in node.named_children(&mut cursor) {
            if !ctx.scope_step() {
                return;
            }
            if child.start_byte() >= cutoff_start {
                break;
            }
            children.push(child);
        }
        children.reverse();
        stack.extend(children);
    }
}

fn scala_refresh_assignment(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    root: Node<'_>,
    node: Node<'_>,
    bindings: &mut LocalInferenceEngine<ScalaLocalBinding>,
) {
    let (Some(left), Some(right)) = (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
    ) else {
        return;
    };
    if !matches!(left.kind(), "identifier" | "operator_identifier") {
        return;
    }
    let name = scala_node_text(left, ctx.source).trim();
    if name.is_empty() || !bindings.is_shadowed(name) {
        return;
    }
    let declaration_owner =
        precise_scala_binding(bindings, name).and_then(|binding| binding.declaration_owner);
    let receiver_type = scala_constructed_type(ctx, right, resolver)
        .or_else(|| {
            scala_call_result_type(ctx, resolver, root, right, right.start_byte(), bindings)
        })
        .or_else(|| {
            matches!(right.kind(), "identifier" | "operator_identifier")
                .then(|| {
                    precise_scala_binding(bindings, scala_node_text(right, ctx.source).trim())
                        .and_then(|binding| binding.receiver_type)
                })
                .flatten()
        });
    seed_scala_binding(name, receiver_type, declaration_owner, bindings);
}

fn scala_seed_parameters(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    node: Node<'_>,
    cutoff_start: usize,
    bindings: &mut LocalInferenceEngine<ScalaLocalBinding>,
) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if !ctx.scope_step() {
            return;
        }
        if !matches!(child.kind(), "parameters" | "class_parameters")
            || child.start_byte() >= cutoff_start
        {
            continue;
        }
        let mut inner = child.walk();
        for parameter in child.named_children(&mut inner) {
            if !ctx.scope_step() {
                return;
            }
            if matches!(parameter.kind(), "parameter" | "class_parameter")
                && parameter.start_byte() < cutoff_start
            {
                scala_seed_parameter(ctx, resolver, parameter, cutoff_start, bindings);
            }
        }
    }
}

fn scala_seed_parameter(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    parameter: Node<'_>,
    cutoff_start: usize,
    bindings: &mut LocalInferenceEngine<ScalaLocalBinding>,
) {
    let Some(name) = parameter.child_by_field_name("name") else {
        return;
    };
    if name.start_byte() >= cutoff_start {
        return;
    }
    let binding_name = scala_node_text(name, ctx.source).trim();
    if binding_name.is_empty() {
        return;
    }
    let type_node = parameter
        .child_by_field_name("type")
        .filter(|type_node| type_node.end_byte() <= cutoff_start);
    if let Some(declaration) = type_node
        .and_then(|type_node| scala_resolve_visible_type_declaration(ctx, resolver, type_node))
    {
        seed_scala_binding_with_receiver_declaration(binding_name, declaration, None, bindings);
        return;
    }
    let resolved = type_node.and_then(|type_node| {
        let type_text = scala_node_text(type_node, ctx.source);
        scala_resolve_receiver_type_annotation(ctx, resolver, type_text, type_node.start_byte())
    });
    scala_seed_typed(binding_name, resolved, false, bindings);
}

fn scala_seed_value_definition(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    root: Node<'_>,
    node: Node<'_>,
    cutoff_start: usize,
    bindings: &mut LocalInferenceEngine<ScalaLocalBinding>,
) {
    let resolved = node
        .child_by_field_name("type")
        .filter(|type_node| type_node.end_byte() <= cutoff_start)
        .and_then(|type_node| {
            scala_resolve_visible_type_declaration(ctx, resolver, type_node)
                .filter(|declaration| !ctx.scala.is_type_alias(declaration))
                .map(|declaration| declaration.fq_name())
                .or_else(|| {
                    scala_resolve_receiver_type_annotation(
                        ctx,
                        resolver,
                        scala_node_text(type_node, ctx.source),
                        type_node.start_byte(),
                    )
                })
        })
        .or_else(|| {
            node.child_by_field_name("value")
                .filter(|value| value.end_byte() <= cutoff_start)
                .and_then(|value| scala_constructed_type(ctx, value, resolver))
                .or_else(|| {
                    node.child_by_field_name("value")
                        .filter(|value| value.end_byte() <= cutoff_start)
                        .and_then(|value| {
                            // The active-path walk seeds definitions in source order, so
                            // `bindings` already is the exact prefix visible to this value.
                            // Rebuilding that prefix here recursively re-enters every earlier
                            // factory-valued definition and amplifies large files exponentially.
                            scala_call_result_type(
                                ctx,
                                resolver,
                                root,
                                value,
                                value.start_byte(),
                                bindings,
                            )
                        })
                })
                .or_else(|| {
                    scala_constructor_type_text(scala_node_text(node, ctx.source)).and_then(
                        |type_text| {
                            scala_resolve_visible_type_annotation(
                                ctx,
                                resolver,
                                type_text,
                                node.start_byte(),
                            )
                        },
                    )
                })
        });
    let Some(pattern) = node.child_by_field_name("pattern") else {
        return;
    };
    if pattern.start_byte() >= cutoff_start {
        return;
    }
    let declaration_owner = scala_is_direct_member_value_definition(node)
        .then(|| {
            ClassRangeIndex::build(ctx.analyzer, ctx.file)
                .enclosing_unit(node.start_byte())
                .cloned()
        })
        .flatten();
    for name in scala_pattern_binder_names(pattern, ctx.source) {
        seed_scala_binding(name, resolved.clone(), declaration_owner.clone(), bindings);
    }
}

fn scala_call_result_type(
    ctx: ScalaLookupCtx<'_>,
    resolver: &ScalaNameResolver,
    root: Node<'_>,
    value: Node<'_>,
    cutoff_start: usize,
    bindings: &LocalInferenceEngine<ScalaLocalBinding>,
) -> Option<String> {
    if value.kind() != "call_expression" {
        return None;
    }
    let function = value.child_by_field_name("function")?;
    match function.kind() {
        "field_expression" => {
            let receiver = function.child_by_field_name("value")?;
            let field = function.child_by_field_name("field")?;
            let member = scala_node_text(field, ctx.source).trim();
            if member.is_empty() {
                return None;
            }
            let owner = scala_receiver_type_fqn_with_bindings(ctx, resolver, receiver, bindings)?;
            let include_companion = scala_receiver_allows_companion_lookup_with_bindings(
                ctx,
                resolver,
                root,
                receiver,
                cutoff_start,
                &owner,
                bindings,
            );
            let call_shape = scala_call_site_shape(ctx, root, field);
            let candidates = scala_applicable_member_candidate_units(
                ctx,
                &owner,
                member,
                include_companion,
                call_shape.as_ref(),
            );
            scala_coherent_function_return_type(ctx, candidates)
        }
        "identifier" => {
            let name = scala_node_text(function, ctx.source).trim();
            if name.is_empty() {
                return None;
            }
            if let Some(member_fqn) = resolver.resolve_member(name) {
                let call_shape = scala_call_site_shape(ctx, root, function);
                let candidates = scala_applicable_callable_candidate_units(
                    ctx,
                    ctx.support.fqn(&member_fqn),
                    call_shape.as_ref(),
                );
                // An explicit/direct imported member is an authoritative tier.
                // If its applicable overloads do not have one coherent return
                // type, do not fall through to an enclosing same-name member.
                return scala_coherent_function_return_type(ctx, candidates);
            }
            if let Some(unit) = resolve_in_enclosing_scopes(
                ctx.analyzer,
                ctx.file,
                name,
                function.start_byte(),
                |unit| unit.is_function(),
            ) {
                let call_shape = scala_call_site_shape(ctx, root, function);
                let candidates = scala_applicable_callable_candidate_units(
                    ctx,
                    ctx.support.fqn(&unit.fq_name()),
                    call_shape.as_ref(),
                );
                return scala_coherent_function_return_type(ctx, candidates);
            }
            let owner =
                scala_enclosing_class(ctx.analyzer, ctx.support, ctx.file, function.start_byte())?;
            let call_shape = scala_call_site_shape(ctx, root, function);
            let ScalaExactMemberResolution::Found(candidates) =
                scala_exact_owner_member_candidate_units(ctx, &owner, name, false)
            else {
                return None;
            };
            let candidates =
                scala_applicable_callable_candidate_units(ctx, candidates, call_shape.as_ref());
            scala_coherent_function_return_type(ctx, candidates)
        }
        _ => None,
    }
}

fn scala_function_return_type(ctx: ScalaLookupCtx<'_>, unit: &CodeUnit) -> Option<String> {
    let signature = unit
        .signature()
        .map(str::to_string)
        .or_else(|| ctx.scala.signatures(unit).into_iter().next())?;
    let return_type = scala_signature_return_type(&signature)?;
    let resolver = scala_name_resolver_for_unit(ctx.scala, ctx.support, unit);
    scala_resolve_type_annotation(&resolver, return_type).or_else(|| {
        scala_package_type_fqn(unit.package_name(), return_type)
            .filter(|fqn| !ctx.support.fqn(fqn).is_empty())
    })
}

fn scala_coherent_function_return_type(
    ctx: ScalaLookupCtx<'_>,
    candidates: Vec<CodeUnit>,
) -> Option<String> {
    let mut resolved = None;
    let mut matched = false;
    for unit in candidates.into_iter().filter(CodeUnit::is_function) {
        let return_type = scala_function_return_type(ctx, &unit)?;
        if resolved
            .as_ref()
            .is_some_and(|current| current != &return_type)
        {
            return None;
        }
        resolved = Some(return_type);
        matched = true;
    }
    matched.then_some(resolved).flatten()
}

fn scala_constructed_type(
    ctx: ScalaLookupCtx<'_>,
    node: Node<'_>,
    resolver: &ScalaNameResolver,
) -> Option<String> {
    if node.kind() == "call_expression"
        && let Some(function) = node
            .child_by_field_name("function")
            .or_else(|| node.named_child(0))
    {
        return scala_constructed_type(ctx, function, resolver);
    }
    if !matches!(
        node.kind(),
        "instance_expression" | "generic_type" | "type_identifier" | "identifier"
    ) {
        return None;
    }
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| {
            matches!(
                child.kind(),
                "type_identifier"
                    | "stable_type_identifier"
                    | "generic_type"
                    | "applied_constructor_type"
                    | "projected_type"
                    | "singleton_type"
                    | "annotated_type"
            )
        })
        .or_else(|| {
            matches!(
                node.kind(),
                "type_identifier" | "generic_type" | "identifier"
            )
            .then_some(node)
        })
        .and_then(|type_node| scala_resolve_visible_type_node(ctx, resolver, type_node))
}

fn scala_constructor_type_text(value_text: &str) -> Option<&str> {
    let trimmed = value_text.trim_start();
    let value = if let Some(after_keyword) = trimmed
        .strip_prefix("val ")
        .or_else(|| trimmed.strip_prefix("var "))
    {
        after_keyword.split_once('=')?.1.trim_start()
    } else {
        trimmed
    };
    let value = value.strip_prefix("new ").unwrap_or(value).trim_start();
    let end = value
        .find(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '.'))
        .unwrap_or(value.len());
    if end == 0 {
        return None;
    }
    let type_text = &value[..end];
    let simple_name = type_text.rsplit('.').next().unwrap_or(type_text);
    simple_name
        .chars()
        .next()
        .is_some_and(|ch| ch.is_ascii_uppercase())
        .then_some(type_text)
}

fn scala_seed_typed(
    name: &str,
    resolved: Option<String>,
    _is_direct_member: bool,
    bindings: &mut LocalInferenceEngine<ScalaLocalBinding>,
) {
    seed_scala_binding(name, resolved, None, bindings);
}

fn scala_is_direct_member_definition(node: Node<'_>) -> bool {
    let mut current = node.parent();
    while let Some(ancestor) = current {
        match ancestor.kind() {
            "function_definition"
            | "block"
            | "block_expression"
            | "indented_block"
            | "case_clause"
            | "lambda_expression" => return false,
            "class_definition" | "object_definition" | "trait_definition" | "enum_definition" => {
                return true;
            }
            _ => current = ancestor.parent(),
        }
    }
    false
}

fn scala_is_direct_member_value_definition(node: Node<'_>) -> bool {
    scala_is_direct_member_definition(node)
}

fn scala_is_local_function_definition(node: Node<'_>) -> bool {
    let mut current = node.parent();
    while let Some(ancestor) = current {
        match ancestor.kind() {
            "function_definition"
            | "block"
            | "block_expression"
            | "indented_block"
            | "case_clause"
            | "lambda_expression" => return true,
            "class_definition" | "object_definition" | "trait_definition" | "enum_definition" => {
                return false;
            }
            _ => current = ancestor.parent(),
        }
    }
    false
}

fn scala_import_boundary_for_name(
    scala: &ScalaAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    name: &str,
) -> bool {
    let simple = scala_simple_name(name);
    for import in scala.import_info_of(file) {
        let Some(path) = scala_import_path(&import) else {
            continue;
        };
        if import.is_wildcard {
            if simple.chars().next().is_some_and(char::is_uppercase)
                && !scala_workspace_package_exists(support, &path)
            {
                return true;
            }
            continue;
        }
        let local_name = import
            .identifier
            .as_deref()
            .unwrap_or_else(|| path.rsplit('.').next().unwrap_or(path.as_str()));
        if local_name == simple && supportless_scala_import_target_missing(support, &path) {
            return true;
        }
    }
    false
}

fn supportless_scala_import_target_missing(
    support: &dyn BoundedDefinitionLookup,
    path: &str,
) -> bool {
    let normalized = path.replace("$.", ".").trim_end_matches('$').to_string();
    !support.fqn_exists(path) && !support.fqn_exists(&normalized)
}

fn scala_workspace_package_exists(support: &dyn BoundedDefinitionLookup, package: &str) -> bool {
    support.package_exists(package)
}

fn scala_simple_name(name: &str) -> &str {
    name.split(['[', '(', '{', '.', ' ', '<'])
        .next()
        .unwrap_or(name)
        .trim()
}

#[cfg(test)]
mod bounded_ast_tests {
    use super::*;
    use crate::analyzer::usages::receiver_analysis::{ReceiverAnalysisBudget, ReceiverBudgetLimit};
    use crate::analyzer::{
        AnalyzerConfig, Language, Project, Range, TestProject, WorkspaceAnalyzer,
    };
    use crate::path_utils::rel_path_string;
    use crate::test_support::AnalyzerFixture;
    use git2::{IndexAddOption, Repository, Signature};
    use std::sync::Arc;
    use tree_sitter::Parser;

    fn parse_scala(source: &str) -> Tree {
        let mut parser = Parser::new();
        parser
            .set_language(&crate::analyzer::scala::language::LANGUAGE.into())
            .expect("Scala grammar");
        parser.parse(source, None).expect("Scala tree")
    }

    #[test]
    fn bounded_lexical_context_scan_stops_at_scope_budget() {
        let source = r#"
package alpha.beta

object Demo {
  def use(): Unit = Factory()
}
"#;
        let tree = parse_scala(source);
        let root = tree.root_node();
        let start = source.find("Factory").expect("Factory reference");
        let reference =
            scala_smallest_named_node_covering(None, root, start, start + "Factory".len())
                .expect("reference node");
        let budget = ReceiverAnalysisBudget {
            max_scope_nodes: 2,
            ..ReceiverAnalysisBudget::default()
        };
        let session = ResolutionSession::bounded(budget, None);

        assert!(scala_lexical_context_at(Some(&session), root, source, reference, start).is_none());
        assert!(matches!(
            session.finish(()),
            BoundedResolution::Exceeded {
                limit: ReceiverBudgetLimit::ScopeNodes,
                work,
            } if work.scope_nodes == budget.max_scope_nodes
        ));
    }

    #[test]
    fn bounded_bare_apply_shadow_scan_stops_at_scope_budget() {
        let source = r#"
object Demo {
  def use(): Unit = {
    val first = 1
    val second = 2
    Factory()
  }
}
"#;
        let tree = parse_scala(source);
        let root = tree.root_node();
        let cutoff = source.find("Factory").expect("Factory reference");
        let budget = ReceiverAnalysisBudget {
            max_scope_nodes: 3,
            ..ReceiverAnalysisBudget::default()
        };
        let session = ResolutionSession::bounded(budget, None);

        assert_eq!(
            scala_active_path_declares_name_before_in_session(
                Some(&session),
                root,
                source,
                "Factory",
                cutoff,
            ),
            None
        );
        assert!(matches!(
            session.finish(()),
            BoundedResolution::Exceeded {
                limit: ReceiverBudgetLimit::ScopeNodes,
                work,
            } if work.scope_nodes == budget.max_scope_nodes
        ));
    }

    #[test]
    fn bounded_scala_full_lookup_observes_mid_walk_cancellation() {
        let mut source = String::from(
            r#"
class Service
object Factory {
  def makeService(): Service = new Service()
}
object Caller {
  def use(): Unit = {
"#,
        );
        for index in 0..96 {
            source.push_str(&format!("    val sibling{index} = {index}\n"));
        }
        source.push_str(
            r#"    Factory.makeService()
  }
}
"#,
        );
        let fixture =
            AnalyzerFixture::new_for_language(Language::Scala, &[("Receiver.scala", &source)]);
        let file = ProjectFile::new(fixture.project_root(), "Receiver.scala");
        let tree = parse_scala(&source);
        let start = source
            .find("Factory.makeService()")
            .expect("factory reference");
        let site = ResolvedReferenceSite {
            path: rel_path_string(&file),
            text: "Factory.makeService()".to_string(),
            range: Range {
                start_byte: start,
                end_byte: start + "Factory.makeService()".len(),
                start_line: 1,
                end_line: 1,
            },
            focus_start_byte: start,
            focus_end_byte: start + "Factory.makeService()".len(),
        };
        let scala =
            resolve_analyzer::<ScalaAnalyzer>(fixture.analyzer.analyzer()).expect("Scala analyzer");
        let cancellation = CancellationToken::new();
        let session =
            ResolutionSession::bounded(ReceiverAnalysisBudget::default(), Some(&cancellation));
        let provider = ScalaDefinitionProvider::new(scala, &session);
        let batch = bounded_scala_definition_context(scala, &file, &session);
        let walk = ScalaBoundedWalk::cancelling_after(&session, cancellation.clone(), 32);

        let resolution = bounded_scala_type_lookup_resolution(
            scala,
            &provider,
            &batch,
            &file,
            &source,
            tree.root_node(),
            &site,
            &walk,
        );
        let steps = walk.steps.get();
        let outcome = session.finish(resolution);

        assert_eq!(steps, 32, "cancellation must happen during the AST walk");
        assert!(
            matches!(
                outcome,
                BoundedResolution::Cancelled { work } if work.scope_nodes > 0
            ),
            "{outcome:#?}"
        );
    }

    #[test]
    fn bounded_scala_extension_lookup_keeps_budget_and_cancellation_terminal() {
        const SOURCE: &str = r#"
package app

trait Base
class Service extends Base

object Ops {
  extension (service: Base)
    def enhance(): Unit = ()
}

object Caller {
  import Ops.*

  def use(): Unit = {
    val service: Service = new Service()
    service.enhance()
  }
}
"#;
        let fixture =
            AnalyzerFixture::new_for_language(Language::Scala, &[("Receiver.scala", SOURCE)]);
        let file = ProjectFile::new(fixture.project_root(), "Receiver.scala");
        let tree = parse_scala(SOURCE);
        let start = SOURCE.rfind("enhance").expect("extension call");
        let site = ResolvedReferenceSite {
            path: rel_path_string(&file),
            text: "enhance".to_string(),
            range: Range {
                start_byte: start,
                end_byte: start + "enhance".len(),
                start_line: 1,
                end_line: 1,
            },
            focus_start_byte: start,
            focus_end_byte: start + "enhance".len(),
        };
        let complete = resolve_scala_bounded(
            fixture.analyzer.analyzer(),
            &file,
            SOURCE,
            Some(&tree),
            &site,
            ReceiverAnalysisBudget::default(),
            None,
        );
        let BoundedResolution::Complete { value, .. } = &complete else {
            panic!("bounded hierarchy extension lookup did not complete: {complete:#?}");
        };
        assert_eq!(
            value.status,
            DefinitionLookupStatus::Resolved,
            "{complete:#?}"
        );
        assert!(
            matches!(
                value.definitions.as_slice(),
                [definition] if definition.fq_name() == "app.Ops$.enhance"
            ),
            "{complete:#?}"
        );

        let budget = ReceiverAnalysisBudget::tiny();
        let exhausted = resolve_scala_bounded(
            fixture.analyzer.analyzer(),
            &file,
            SOURCE,
            Some(&tree),
            &site,
            budget,
            None,
        );
        assert!(
            matches!(
                exhausted,
                BoundedResolution::Exceeded {
                    limit: ReceiverBudgetLimit::ScopeNodes,
                    work,
                } if work.scope_nodes == budget.max_scope_nodes
            ),
            "{exhausted:#?}"
        );

        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let cancelled = resolve_scala_bounded(
            fixture.analyzer.analyzer(),
            &file,
            SOURCE,
            Some(&tree),
            &site,
            ReceiverAnalysisBudget::default(),
            Some(&cancellation),
        );
        assert!(
            matches!(cancelled, BoundedResolution::Cancelled { .. }),
            "{cancelled:#?}"
        );
    }

    #[test]
    fn cold_bounded_scala_hierarchy_uses_limited_supertype_projection() {
        const SOURCE: &str = r#"
package app

trait Base {
  def run(): Unit = ()
}

trait OtherBase {
  def run(): Unit = ()
}

class Child extends Base

object Caller {
  def use(): Unit = {
    val child: Child = new Child()
    child.run()
  }
}
"#;
        let _gc_guard = crate::analyzer::store::gc::set_min_interval_secs_for_test(i64::MAX);
        let temp = tempfile::tempdir().expect("temp dir");
        let root = temp.path().canonicalize().expect("canonical temp dir");
        let file = ProjectFile::new(root.clone(), "Hierarchy.scala");
        file.write(SOURCE).expect("write Scala hierarchy fixture");

        let repository = Repository::init(&root).expect("git repository");
        let mut config = repository.config().expect("git config");
        config
            .set_str("user.name", "Bifrost Test")
            .expect("git user name");
        config
            .set_str("user.email", "bifrost@example.com")
            .expect("git user email");
        let mut index = repository.index().expect("git index");
        index
            .add_all(["*"], IndexAddOption::DEFAULT, None)
            .expect("stage Scala fixture");
        index.write().expect("write git index");
        let tree_id = index.write_tree().expect("write git tree");
        let git_tree = repository.find_tree(tree_id).expect("git tree");
        let signature =
            Signature::now("Bifrost Test", "bifrost@example.com").expect("git signature");
        repository
            .commit(Some("HEAD"), &signature, &signature, "init", &git_tree, &[])
            .expect("commit Scala fixture");

        let project: Arc<dyn Project> = Arc::new(TestProject::new(root.clone(), Language::Scala));
        let cold =
            WorkspaceAnalyzer::build_persisted(Arc::clone(&project), AnalyzerConfig::default())
                .expect("cold persisted Scala analyzer");
        drop(cold);
        let warm = WorkspaceAnalyzer::build_persisted(project, AnalyzerConfig::default())
            .expect("warm persisted Scala analyzer");
        let analyzer = warm.analyzer();
        analyzer.reset_candidate_hydration_count_for_test();
        let scala = resolve_analyzer::<ScalaAnalyzer>(analyzer).expect("warm Scala analyzer");
        let tree = parse_scala(SOURCE);
        let start = SOURCE.rfind("run").expect("inherited member call");
        let site = ResolvedReferenceSite {
            path: rel_path_string(&file),
            text: "run".to_string(),
            range: Range {
                start_byte: start,
                end_byte: start + "run".len(),
                start_line: 1,
                end_line: 1,
            },
            focus_start_byte: start,
            focus_end_byte: start + "run".len(),
        };

        let outcome = resolve_scala_bounded(
            analyzer,
            &file,
            SOURCE,
            Some(&tree),
            &site,
            ReceiverAnalysisBudget::default(),
            None,
        );
        let BoundedResolution::Complete { value, .. } = &outcome else {
            panic!("cold bounded Scala hierarchy did not complete: {outcome:#?}");
        };
        assert_eq!(
            value.status,
            DefinitionLookupStatus::Resolved,
            "{outcome:#?}"
        );
        assert!(
            matches!(
                value.definitions.as_slice(),
                [definition] if definition.fq_name() == "app.Base.run"
            ),
            "{outcome:#?}"
        );
        assert!(
            value
                .definitions
                .iter()
                .all(|definition| definition.fq_name() != "app.OtherBase.run"),
            "NULL-key fallback must retain owner-qualified short-name discrimination: {outcome:#?}"
        );
        assert_eq!(
            scala.full_hydration_count_for_test(),
            0,
            "bounded hierarchy lookup must not point-hydrate cold file state"
        );
        assert_eq!(
            scala.bulk_hydration_count_for_test(),
            0,
            "bounded hierarchy lookup must not bulk-hydrate cold file state"
        );
    }
}
