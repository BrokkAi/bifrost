//! The facts that make a Java single-type import of a JDK type safe from every
//! missing dependency jar (#10470).
//!
//! A jar can change what a simple name means only by putting a type, or a
//! binding that obscures a type, in scope. `UnshadowedScope::check` runs every
//! condition under which that is impossible for one simple name at one use
//! site, and a value of it is the proof that the checks ran: it has one
//! constructor. The reduced gap rule of the ladder
//! (`JvmExternalDeclarations::resolve_explicit_import_in_unshadowed_scope`)
//! takes one by value.
//!
//! Platform overrides are an assumption, not a check. A build can put jar
//! classes into a `java.*` package outside the class-loader rule with
//! `--patch-module`, `--upgrade-module-path`, `-Xbootclasspath/p|a` or an
//! endorsed-standards directory. The check refuses when the Maven build model
//! shows one. Gradle compile options are not in the model, so a project that
//! has both a missing jar and a Gradle-only override can get a complete
//! `java.*` answer the override falsifies. Every fully built project already
//! carries that exposure, and #10492 owns the general fix; when it models
//! overrides, `check` must consult that model.

use crate::analyzer::java::JavaAnalyzer;
use crate::analyzer::java::imports::{JavaTypeResolution, TypeNameOutcome};
use crate::analyzer::jvm::external::{
    ExplicitImportHit, JvmExternalDeclarations, JvmExternalType, JvmVisibility, LazyExternal,
    QueryGapRecorder, is_external_inheritable_by_package,
};
use brokk_bifrost_analysis::analyzer::{ProjectFile, QueryToken, Range};
use brokk_bifrost_core::analyzer::CodeUnitIndex;
use brokk_bifrost_core::analyzer::capabilities::TypeHierarchyProvider;
use brokk_bifrost_core::analyzer::common::node_source_text_trimmed as java_node_text;
use brokk_bifrost_core::analyzer::definition_lookup::sort_units;
use brokk_bifrost_core::analyzer::model::{CodeUnit, ImportInfo, Language, SignatureMetadata};
use brokk_bifrost_core::analyzer::structural::resolution::{DeclaredVisibility, PrecedenceTier};
use brokk_bifrost_core::hash::{HashMap, HashSet};
use brokk_bifrost_jvm::java::graph::return_type::java_type_name_components;
use brokk_bifrost_jvm::java::graph_support::JavaSource;
use brokk_bifrost_jvm::java::graph_support::{
    JavaTypeName, java_declared_type_parameters, java_same_file_candidates,
    java_source_class_by_fqn, java_type_parameter_in_scope, java_type_parameter_name_node,
    resolve_java_lexical_type_name,
};
use brokk_bifrost_jvm::java::imports::{non_static_import_path, static_import_path};
use std::sync::Arc;
use tree_sitter::Node;

/// The most distinct types one closure walk visits before it refuses. A
/// supertype hierarchy this wide is not worth proving; refusing records every
/// gap, which is the answer before this rule existed.
const MAX_CLOSURE_TYPES: usize = 256;

/// Where a simple name is written: the raw syntax facts `UnshadowedScope::check`
/// reads. The node is the name's own occurrence, so the enclosing
/// declarations, type parameters and anonymous class bodies are read from it.
#[derive(Clone, Copy)]
pub(crate) struct UseSite<'a> {
    pub(crate) token: QueryToken<'a>,
    pub(crate) source: &'a str,
    pub(crate) node: Node<'a>,
}

/// The class declarations that enclose the byte `start` of `file`, innermost
/// first. Empty when no declaration covers it.
pub(crate) fn enclosing_class_units_at(
    java: &JavaAnalyzer,
    file: &ProjectFile,
    start: usize,
) -> Vec<CodeUnit> {
    use brokk_bifrost_analysis::analyzer::Range;
    let Some(start) = java.enclosing_code_unit(
        file,
        &Range {
            start_byte: start,
            end_byte: start.saturating_add(1),
            start_line: 0,
            end_line: 0,
        },
    ) else {
        return Vec::new();
    };
    brokk_bifrost_core::analyzer::usages::common::enclosing_owner_chain(start, |unit| {
        java.parent_of(unit)
    })
    .filter(CodeUnit::is_class)
    .collect()
}

/// Proof that nothing in scope at a use site can shadow or obscure one simple
/// name, so a single-type import of a JDK type in an unshadowable package binds
/// it whatever a missing jar holds. `UnshadowedScope::check` is the only
/// constructor.
#[derive(Debug)]
pub(crate) struct UnshadowedScope {
    simple_name: String,
}

impl UnshadowedScope {
    pub(crate) fn simple_name(&self) -> &str {
        &self.simple_name
    }

    /// Runs every condition and returns a value only when all hold:
    ///
    /// * the build model shows no platform override;
    /// * exactly one distinct canonical name is bound to `simple_name` by the
    ///   file's non-static single-type imports, and no single-static-import
    ///   names it (it could bind a member type or a field that obscures the
    ///   type);
    /// * no class or method type parameter in scope has the name (JLS 6.4.1);
    /// * every supertype in the closure of every enclosing type declaration
    ///   resolves to workspace source or to a JDK-pack type in an unshadowable
    ///   package, the implicit supertype counted, and no type in that closure
    ///   declares or inherits a member type with the name. Anonymous classes
    ///   (whose supertype is the named type) and enum constant bodies (whose
    ///   supertype is the enum) are enclosing declarations. A supertype found
    ///   in a present dependency jar is not enough: the same fully qualified
    ///   name in a missing jar earlier on the classpath could supply a
    ///   different definition;
    /// * every static-import-on-demand names a workspace type whose own closure
    ///   meets the same rule. A static-import-on-demand of a JDK type refuses,
    ///   because no lookup here proves that type and its supertypes declare no
    ///   member of that name.
    ///
    /// Static fields are not part of this check: it guards type-name lookups,
    /// and a field never shadows a type name. A name that is an expression
    /// qualifier is decided as a variable before the ladder runs.
    pub(crate) fn check(
        java: &JavaAnalyzer,
        packs: Option<
            Arc<brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay>,
        >,
        selected_jdk_artifact_sha256: Option<&str>,
        external: &JvmExternalDeclarations<'_>,
        file: &ProjectFile,
        site: &UseSite<'_>,
        simple_name: &str,
    ) -> Option<Self> {
        ScopeCheck {
            java,
            packs,
            selected_jdk_artifact_sha256,
            external,
            file,
            site,
            simple_name,
        }
        .holds()
        .then(|| Self {
            simple_name: simple_name.to_owned(),
        })
    }
}

/// Whether no scope, import or enclosing type at `site` can bind `simple_name`
/// except Java's implicit `java.lang.*` on-demand import (JLS 6.4.1, 7.3).
///
/// This is a scoping fact, not a lookup: it does not resolve the name, so it
/// needs no JDK declaration. It holds when
///
/// * the build model shows no platform override;
/// * no class or method type parameter in scope has the name;
/// * the file has no import naming the simple name and no on-demand import,
///   static or not, because an on-demand package or type could supply it and
///   nothing here proves the package lacks it;
/// * the external surface carries no gap, so no missing dependency can supply
///   the name through the same package;
/// * every supertype in the closure of every enclosing type declaration is
///   inspectable and none declares or inherits a member type with the name
///   (the closure rule of [`UnshadowedScope::check`]). A JDK supertype needs
///   the JDK pack, so without one this refuses, which fails closed.
///
/// The caller must have read the same-package and single-type tiers of the
/// type ladder as unbound; this function covers the rest.
pub(crate) fn names_only_through_implicit_java_lang(
    java: &JavaAnalyzer,
    packs: Option<
        Arc<brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay>,
    >,
    selected_jdk_artifact_sha256: Option<&str>,
    external: &JvmExternalDeclarations<'_>,
    file: &ProjectFile,
    site: &UseSite<'_>,
    simple_name: &str,
) -> bool {
    ScopeCheck {
        java,
        packs,
        selected_jdk_artifact_sha256,
        external,
        file,
        site,
        simple_name,
    }
    .implicit_java_lang_only()
}

struct ScopeCheck<'a, 'q> {
    java: &'a JavaAnalyzer,
    packs: Option<
        Arc<brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay>,
    >,
    selected_jdk_artifact_sha256: Option<&'a str>,
    external: &'a JvmExternalDeclarations<'a>,
    file: &'a ProjectFile,
    site: &'a UseSite<'q>,
    simple_name: &'a str,
}

/// One type reached while walking the supertype closure.
enum ClosureMember {
    Workspace(CodeUnit),
    /// A JDK-pack type in an unshadowable package. It is a leaf: the pack's
    /// owner surface already holds its ancestors' members.
    Jdk(String),
}

impl ScopeCheck<'_, '_> {
    fn holds(&self) -> bool {
        if self.external.override_possible() {
            return false;
        }
        if java_type_parameter_in_scope(self.site.node, self.site.source, self.simple_name)
            .is_some()
        {
            return false;
        }
        let mut static_on_demand = Vec::new();
        let mut canonical_names = Vec::<String>::new();
        for import in self.java.inner.import_info_of(self.site.token, self.file) {
            if import.is_wildcard {
                if let Some(path) = static_import_path(&import) {
                    static_on_demand.push(path.render_segments("."));
                }
                continue;
            }
            if import.identifier.as_deref() != Some(self.simple_name) {
                continue;
            }
            if let Some(path) = non_static_import_path(&import) {
                let canonical = path.render_segments(".");
                if !canonical_names.contains(&canonical) {
                    canonical_names.push(canonical);
                }
            } else if static_import_path(&import).is_some() {
                return false;
            }
        }
        if canonical_names.len() != 1 {
            return false;
        }
        let mut seeds = Vec::new();
        for owner in &static_on_demand {
            match java_source_class_by_fqn(self.java, self.site.token, owner) {
                Some(unit) => seeds.push(ClosureMember::Workspace(unit)),
                None => return false,
            }
        }
        let Some(enclosing) = self.enclosing_seeds() else {
            return false;
        };
        seeds.extend(enclosing);
        matches!(self.read_closure(seeds), ClosureReading::Clear)
    }

    fn implicit_java_lang_only(&self) -> bool {
        if self.external.override_possible()
            || !self.external.carries_no_gaps()
            || java_type_parameter_in_scope(self.site.node, self.site.source, self.simple_name)
                .is_some()
        {
            return false;
        }
        let names_it = |import: &brokk_bifrost_core::analyzer::model::ImportInfo| {
            import.is_wildcard || import.identifier.as_deref() == Some(self.simple_name)
        };
        if self
            .java
            .inner
            .import_info_of(self.site.token, self.file)
            .iter()
            .any(names_it)
        {
            return false;
        }
        self.enclosing_seeds()
            .is_some_and(|seeds| matches!(self.read_closure(seeds), ClosureReading::Clear))
    }

    /// The enclosing type declarations of the use site, innermost first, with
    /// the implicit supertype of each already checked. `None` means a
    /// declaration could not be read, which refuses.
    fn enclosing_seeds(&self) -> Option<Vec<ClosureMember>> {
        let mut seeds = Vec::new();
        let mut declarations = Vec::new();
        let mut child = self.site.node;
        let mut ancestor = self.site.node.parent();
        while let Some(node) = ancestor {
            match node.kind() {
                "class_declaration"
                | "interface_declaration"
                | "enum_declaration"
                | "record_declaration"
                | "annotation_type_declaration" => {
                    declarations.push(node);
                }
                "object_creation_expression" if child.kind() == "class_body" => {
                    // An anonymous class: its supertype is the named type, and
                    // the type is resolved in the scope outside the body.
                    if node.child_by_field_name("object").is_some() {
                        return None;
                    }
                    let components = java_type_name_components(
                        node.child_by_field_name("type")?,
                        self.site.source,
                    )?;
                    seeds.push(self.supertype_member(
                        self.file,
                        &JavaTypeName::from_components(components)?,
                    )?);
                }
                _ => {}
            }
            child = node;
            ancestor = node.parent();
        }
        let units = self.enclosing_class_units();
        if units.len() != declarations.len() {
            return None;
        }
        for (declaration, unit) in declarations.into_iter().zip(units) {
            let implicit = implicit_class_supertype(declaration.kind());
            if let Some(implicit) = implicit
                && !self
                    .external
                    .jdk_owner_has_no_member_type(implicit, self.simple_name)
            {
                return None;
            }
            seeds.push(ClosureMember::Workspace(unit));
        }
        Some(seeds)
    }

    fn enclosing_class_units(&self) -> Vec<CodeUnit> {
        enclosing_class_units_at(self.java, self.file, self.site.node.start_byte())
    }

    /// The closure member a written supertype name denotes in `file`'s scope,
    /// or `None` when it is neither workspace source nor an unshadowable JDK
    /// type, which includes a type that only a missing or present dependency
    /// jar could supply.
    fn supertype_member(&self, file: &ProjectFile, name: &JavaTypeName) -> Option<ClosureMember> {
        let token = self.site.token;
        match self.java.resolve_type_name_at(
            token,
            self.packs.clone(),
            file,
            name,
            self.selected_jdk_artifact_sha256,
            None,
        )? {
            JavaTypeResolution::Source(unit) => Some(ClosureMember::Workspace(unit)),
            JavaTypeResolution::External(hit) => hit
                .is_unshadowable_jdk()
                .then(|| ClosureMember::Jdk(hit.fqn().to_owned())),
        }
    }

    /// Walks the supertype closure of `worklist` and reports what it finds
    /// about member types named like the use site's simple name.
    fn read_closure(&self, worklist: Vec<ClosureMember>) -> ClosureReading {
        read_member_type_closure(
            self.java,
            self.packs.clone(),
            self.selected_jdk_artifact_sha256,
            &LazyExternal::Ready(self.external),
            self.site,
            self.simple_name,
            worklist,
        )
    }
}

fn implicit_class_supertype(kind: &str) -> Option<&'static str> {
    match kind {
        "enum_declaration" => Some("java.lang.Enum"),
        "record_declaration" => Some("java.lang.Record"),
        "annotation_type_declaration" => Some("java.lang.annotation.Annotation"),
        _ => None,
    }
}

// Match java_direct_ancestors' source edge resolution, without acquiring an
// external index for an edge that is already settled in workspace source.
fn source_supertype(
    java: &JavaAnalyzer,
    token: QueryToken<'_>,
    unit: &CodeUnit,
    raw: &str,
) -> Option<CodeUnit> {
    resolve_java_lexical_type_name(java, unit, raw)
        .or_else(|| java.resolve_imported_type_name(token, unit.source(), raw))
}

// The conservative scope proof uses a ready surface. Keep its traversal
// separate from visibility-aware positive member resolution.
fn read_member_type_closure(
    java: &JavaAnalyzer,
    packs: Option<
        Arc<brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay>,
    >,
    selected_jdk_artifact_sha256: Option<&str>,
    external: &LazyExternal<'_>,
    site: &UseSite<'_>,
    simple_name: &str,
    mut worklist: Vec<ClosureMember>,
) -> ClosureReading {
    let mut visited = brokk_bifrost_core::hash::HashSet::<String>::default();
    while let Some(member) = worklist.pop() {
        if visited.len() > MAX_CLOSURE_TYPES {
            return ClosureReading::Uninspectable;
        }
        match member {
            ClosureMember::Jdk(fqn) => {
                if !external
                    .get()
                    .jdk_owner_has_no_member_type(&fqn, simple_name)
                {
                    return ClosureReading::Uninspectable;
                }
            }
            ClosureMember::Workspace(unit) => {
                if !visited.insert(unit.fq_name()) {
                    continue;
                }
                let member_type = format!("{}.{}", unit.fq_name(), simple_name);
                if java
                    .forward_definition_fqn(&member_type)
                    .iter()
                    .any(CodeUnit::is_class)
                {
                    return ClosureReading::Declares;
                }
                for raw in JavaSource::raw_supertypes_of(java, &unit) {
                    let supertype = source_supertype(java, site.token, &unit, &raw)
                        .map(ClosureMember::Workspace)
                        .or_else(|| {
                            ScopeCheck {
                                java,
                                packs: packs.clone(),
                                selected_jdk_artifact_sha256,
                                external: external.get(),
                                file: unit.source(),
                                site,
                                simple_name,
                            }
                            .supertype_member(
                                unit.source(),
                                &JavaTypeName::from_normalized_spelling(&raw)?,
                            )
                        });
                    match supertype {
                        Some(supertype) => worklist.push(supertype),
                        None => return ClosureReading::Uninspectable,
                    }
                }
            }
        }
    }
    ClosureReading::Clear
}

/// What a walk of a supertype closure found out about one member type name.
enum ClosureReading {
    /// Every type in the closure is inspectable and none declares the name.
    Clear,
    /// A workspace type in the closure declares a member type with the name.
    Declares,
    /// A type in the closure could not be inspected, or the walk was too wide.
    Uninspectable,
}

pub(crate) fn implicit_supertype_at_site(
    java: &JavaAnalyzer,
    unit: &CodeUnit,
    site: Option<(&ProjectFile, Node<'_>)>,
) -> Option<&'static str> {
    let (file, site_node) = site?;
    if unit.source() != file {
        return None;
    }
    let ranges = java.ranges(unit);
    let mut ancestor = Some(site_node);
    while let Some(node) = ancestor {
        if let Some(implicit) = implicit_class_supertype(node.kind())
            && ranges.iter().any(|range| {
                range.start_byte == node.start_byte() && range.end_byte == node.end_byte()
            })
        {
            return Some(implicit);
        }
        ancestor = node.parent();
    }
    None
}

/// The direct supertypes of a Java declaration that are not workspace source:
/// the ones the external surface resolves, and the written spellings nothing
/// resolves (no workspace type, no import target, no external declaration).
#[derive(Debug, Default)]
pub(crate) struct DirectExternalSupertypes {
    pub(crate) resolved: Vec<JvmExternalType>,
    pub(crate) unresolved: Vec<String>,
}

/// A written supertype nothing resolves, found while reading the member types
/// `declaration` inherits. It may declare a member type that shadows an
/// import, so a lookup that binds past it is incomplete, never refused
/// (#14293).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OpenSupertype {
    pub(crate) declaration: CodeUnit,
    pub(crate) supertype: String,
}

impl OpenSupertype {
    /// The gap a lookup that binds past this supertype reports.
    pub(crate) fn gap(&self, name: &str) -> String {
        format!(
            "jvm.member_type.inherited_unresolved: {name} in {} (supertype {} is unresolved and may declare a member type {name})",
            self.declaration.fq_name(),
            self.supertype
        )
    }
}

/// Shared helper: resolves the non-source direct supertypes of `unit` lazily
/// through `external`. A spelling nothing binds is reported as unresolved; a
/// stopped lookup (an ambiguous or shadowed name) fails closed (`Err(())`).
pub(crate) fn resolve_java_direct_external_supertypes(
    java: &JavaAnalyzer,
    token: QueryToken<'_>,
    packs: Option<
        Arc<brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay>,
    >,
    selected_jdk_artifact_sha256: Option<&str>,
    unit: &CodeUnit,
    implicit_supertype: Option<&str>,
) -> Result<DirectExternalSupertypes, ()> {
    if unit.source().language() != Language::Java {
        return Ok(DirectExternalSupertypes::default());
    }
    let mut raw_supertypes = JavaSource::raw_supertypes_of(java, unit);
    if let Some(implicit) = implicit_supertype
        && !raw_supertypes.iter().any(|s| s == implicit)
    {
        raw_supertypes.push(implicit.to_owned());
    }
    let mut supertypes = DirectExternalSupertypes::default();
    for raw in raw_supertypes {
        if source_supertype(java, token, unit, &raw).is_some() {
            continue;
        }
        // Edge did not resolve to workspace source: resolve through external surface.
        let Some(type_name) = JavaTypeName::from_normalized_spelling(raw.trim()) else {
            return Err(());
        };
        match java.resolve_type_name_outcome_at(
            token,
            packs.clone(),
            unit.source(),
            &type_name,
            selected_jdk_artifact_sha256,
            None,
        ) {
            TypeNameOutcome::Resolved(JavaTypeResolution::External(hit)) => {
                supertypes.resolved.push(hit.into_type());
            }
            TypeNameOutcome::Resolved(JavaTypeResolution::Source(_)) => {}
            TypeNameOutcome::Unbound | TypeNameOutcome::BoundMiss => {
                supertypes.unresolved.push(raw);
            }
            TypeNameOutcome::Stopped => return Err(()),
        }
    }
    Ok(supertypes)
}

/// Shared helper: walks `roots` and their external supertypes lazily through
/// `external` to find inherited member types named `simple_name` (JLS 8.5).
pub(crate) fn inherited_external_member_types_with_lazy(
    java: &JavaAnalyzer,
    external: &LazyExternal<'_>,
    roots: &[JvmExternalType],
    subtype_package: &str,
    simple_name: &str,
) -> Result<Vec<JvmExternalType>, ()> {
    if roots.is_empty() {
        return Ok(Vec::new());
    }
    let recorder = QueryGapRecorder::new(java);
    external.get().inherited_member_types_of_supertypes(
        &recorder,
        roots,
        subtype_package,
        simple_name,
    )
}

/// Shared helper: direct external supertype FQNs of `fqn` via `external`.
pub(crate) fn external_supertypes_with_lazy(
    java: &JavaAnalyzer,
    external: &LazyExternal<'_>,
    fqn: &str,
) -> Result<Vec<String>, ()> {
    let recorder = QueryGapRecorder::new(java);
    external.get().direct_supertypes_of(&recorder, fqn)
}

/// Shared lookup view for Java workspace member-type inheritance and lexical
/// enclosing-class scoping (JLS 6.3, 6.4.1, 6.6.1, 8.5).
pub(crate) trait WorkspaceMemberTypeEnv {
    fn is_live(&self) -> bool;
    fn charge_step(&self) -> bool;
    fn package_name_of_file(&self, file: &ProjectFile) -> String;
    fn raw_supertypes_of(&self, unit: &CodeUnit) -> Vec<String>;
    fn forward_classes_by_fqn(&self, fqn: &str) -> Vec<CodeUnit>;
    fn parent_of_unit(&self, unit: &CodeUnit) -> Option<CodeUnit>;
    fn enclosing_class_units_at(&self, file: &ProjectFile, byte: usize) -> Vec<CodeUnit>;
    fn unit_ranges(&self, unit: &CodeUnit) -> Vec<Range>;
    fn signature_metadata_of(&self, unit: &CodeUnit) -> Vec<SignatureMetadata>;
    fn import_infos_of(&self, file: &ProjectFile) -> Vec<ImportInfo>;
    fn resolve_type_name_candidates_in_file(
        &self,
        file: &ProjectFile,
        normalized: &str,
    ) -> Vec<CodeUnit>;
    fn direct_hierarchy_ancestors(&self, unit: &CodeUnit) -> Result<Vec<CodeUnit>, ()>;
    fn direct_external_supertypes(&self, unit: &CodeUnit) -> Result<DirectExternalSupertypes, ()>;
    fn inherited_external_member_types(
        &self,
        roots: &[JvmExternalType],
        subtype_package: &str,
        simple_name: &str,
    ) -> Result<Vec<JvmExternalType>, ()>;
    fn external_supertypes(&self, _fqn: &str) -> Result<Vec<String>, ()> {
        Ok(Vec::new())
    }
}

pub(crate) struct JavaAnalyzerMemberTypeEnv<'a, 'q, 'x> {
    pub(crate) java: &'a JavaAnalyzer,
    pub(crate) token: QueryToken<'q>,
    pub(crate) packs: Option<
        Arc<brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay>,
    >,
    pub(crate) selected_jdk_artifact_sha256: Option<&'a str>,
    pub(crate) external: &'a LazyExternal<'x>,
    pub(crate) site: Option<(&'a ProjectFile, &'a UseSite<'q>)>,
}

impl WorkspaceMemberTypeEnv for JavaAnalyzerMemberTypeEnv<'_, '_, '_> {
    fn is_live(&self) -> bool {
        true
    }

    fn charge_step(&self) -> bool {
        true
    }

    fn package_name_of_file(&self, file: &ProjectFile) -> String {
        self.java.package_name_of(file).unwrap_or_default()
    }

    fn raw_supertypes_of(&self, unit: &CodeUnit) -> Vec<String> {
        let mut raw = JavaSource::raw_supertypes_of(self.java, unit);
        // Reaching this hook means the contextual resolver has passed the
        // header, type-parameter and own-member tiers. Reading this enclosing
        // declaration's parent tier includes its implicit external root.
        if let Some(implicit) = implicit_supertype_at_site(
            self.java,
            unit,
            self.site.map(|(file, site)| (file, site.node)),
        ) {
            self.external.get();
            if !raw.iter().any(|s| s == implicit) {
                raw.push(implicit.to_owned());
            }
        }
        raw
    }

    fn forward_classes_by_fqn(&self, fqn: &str) -> Vec<CodeUnit> {
        self.java
            .forward_definition_fqn(fqn)
            .into_iter()
            .filter(CodeUnit::is_class)
            .collect()
    }

    fn parent_of_unit(&self, unit: &CodeUnit) -> Option<CodeUnit> {
        self.java.parent_of(unit)
    }

    fn enclosing_class_units_at(&self, file: &ProjectFile, byte: usize) -> Vec<CodeUnit> {
        enclosing_class_units_at(self.java, file, byte)
    }

    fn unit_ranges(&self, unit: &CodeUnit) -> Vec<Range> {
        self.java.ranges(unit)
    }

    fn signature_metadata_of(&self, unit: &CodeUnit) -> Vec<SignatureMetadata> {
        self.java.signature_metadata(unit)
    }

    fn import_infos_of(&self, file: &ProjectFile) -> Vec<ImportInfo> {
        self.java.inner.import_info_of(self.token, file)
    }

    fn resolve_type_name_candidates_in_file(
        &self,
        file: &ProjectFile,
        normalized: &str,
    ) -> Vec<CodeUnit> {
        self.java
            .resolve_type_name_candidates_in_file(self.token, file, normalized)
    }

    fn direct_hierarchy_ancestors(&self, unit: &CodeUnit) -> Result<Vec<CodeUnit>, ()> {
        let ancestors = if unit.source().language() == Language::Java {
            self.java.legacy_direct_ancestors(unit)
        } else {
            TypeHierarchyProvider::get_direct_ancestors(self.java, unit)
        };
        if !ancestors.is_complete() {
            return Err(());
        }
        Ok(ancestors.edges)
    }

    fn direct_external_supertypes(&self, unit: &CodeUnit) -> Result<DirectExternalSupertypes, ()> {
        resolve_java_direct_external_supertypes(
            self.java,
            self.token,
            self.packs.clone(),
            self.selected_jdk_artifact_sha256,
            unit,
            implicit_supertype_at_site(
                self.java,
                unit,
                self.site.map(|(file, site)| (file, site.node)),
            ),
        )
    }

    fn inherited_external_member_types(
        &self,
        roots: &[JvmExternalType],
        subtype_package: &str,
        simple_name: &str,
    ) -> Result<Vec<JvmExternalType>, ()> {
        inherited_external_member_types_with_lazy(
            self.java,
            self.external,
            roots,
            subtype_package,
            simple_name,
        )
    }

    fn external_supertypes(&self, fqn: &str) -> Result<Vec<String>, ()> {
        external_supertypes_with_lazy(self.java, self.external, fqn)
    }
}

/// Outcome of resolving one `.Member` segment on a known workspace owner type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MemberTypeStep {
    Resolved(CodeUnit),
    ResolvedExternal(JvmExternalType),
    Ambiguous(Vec<CodeUnit>),
    AmbiguousResolutions(Vec<JavaTypeResolution>),
    Incomplete(CodeUnit),
    Missing,
}

/// Outcome of contextual Java type lookup (local classes, enclosing declared
/// and inherited workspace member types, and type-parameter shadowing) before
/// file-level imports, same-package types, and on-demand imports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum JavaContextualTypeOutcome {
    Resolved {
        unit: CodeUnit,
        tier: PrecedenceTier,
    },
    ResolvedExternal {
        external: JvmExternalType,
        tier: PrecedenceTier,
    },
    Ambiguous(Vec<CodeUnit>),
    AmbiguousExternal(Vec<JavaTypeResolution>),
    Incomplete(CodeUnit),
    /// No contextual tier binds the name, but an enclosing declaration has a
    /// supertype nothing resolves, which may declare a member type of that
    /// name. The caller binds through the file-level tiers and reports the
    /// answer as incomplete (#14293).
    OpenSupertype(OpenSupertype),
    MissingMemberOfBoundPrefix,
    ShadowedByTypeParameter,
    Unbound,
}

/// What the enclosing declarations of a use site say about a simple name before
/// any import is consulted on `TypeLadder`.
pub(crate) enum EnclosingMemberType {
    /// No enclosing declaration or type parameter binds the simple name.
    None,
    /// A class or callable type parameter in scope shadows the name (JLS 6.4.1).
    ShadowedByTypeParameter,
    /// A unique declared or inherited member type binds the name.
    Resolved(JavaTypeResolution),
    /// Two or more distinct member types bind the name (compile error).
    Ambiguous(Vec<JavaTypeResolution>),
    /// A supertype hierarchy could not be read completely.
    Incomplete { enclosing: String },
    /// Nothing visible binds the name, but a supertype nothing resolves may.
    OpenSupertype(OpenSupertype),
}

fn owned_member_types<E: WorkspaceMemberTypeEnv>(
    env: &E,
    owner: &CodeUnit,
    simple_name: &str,
) -> Vec<CodeUnit> {
    assert!(!simple_name.is_empty());
    let child_fqn = format!("{}.{simple_name}", owner.fq_name());
    let mut owned = java_same_file_candidates(
        env.forward_classes_by_fqn(&child_fqn)
            .into_iter()
            .filter(|unit| unit.fq_name() == child_fqn)
            .collect(),
        owner.source(),
    );
    sort_units(&mut owned);
    owned.dedup();
    owned
}

fn declared_type_visibility<E: WorkspaceMemberTypeEnv>(
    env: &E,
    member: &CodeUnit,
) -> Result<DeclaredVisibility, CodeUnit> {
    let alternatives = env.signature_metadata_of(member);
    if member.source().language() != Language::Java {
        let Some(first) = alternatives
            .first()
            .and_then(SignatureMetadata::callable_declared_visibility)
        else {
            return Ok(DeclaredVisibility::Public);
        };
        if alternatives
            .iter()
            .any(|alt| alt.callable_declared_visibility() != Some(first))
        {
            return Err(member.clone());
        }
        return Ok(first);
    }
    let Some(visibility) = alternatives
        .first()
        .and_then(SignatureMetadata::callable_declared_visibility)
    else {
        return Err(member.clone());
    };
    if alternatives
        .iter()
        .any(|alt| alt.callable_declared_visibility() != Some(visibility))
    {
        return Err(member.clone());
    }
    match visibility {
        DeclaredVisibility::Public
        | DeclaredVisibility::Protected
        | DeclaredVisibility::PackagePrivate
        | DeclaredVisibility::Private => Ok(visibility),
        DeclaredVisibility::Internal
        | DeclaredVisibility::CrateOrModule
        | DeclaredVisibility::ProtectedInternal
        | DeclaredVisibility::PrivateProtected
        | DeclaredVisibility::Unknown => Err(member.clone()),
    }
}

fn is_inheritable_by_subtype<E: WorkspaceMemberTypeEnv>(
    env: &E,
    member: &CodeUnit,
    subtype: &CodeUnit,
) -> Result<bool, CodeUnit> {
    match declared_type_visibility(env, member)? {
        DeclaredVisibility::Public
        | DeclaredVisibility::Protected
        | DeclaredVisibility::Internal
        | DeclaredVisibility::ProtectedInternal => Ok(true),
        DeclaredVisibility::PackagePrivate | DeclaredVisibility::CrateOrModule => {
            Ok(member.package_name() == subtype.package_name())
        }
        DeclaredVisibility::Private | DeclaredVisibility::PrivateProtected => Ok(false),
        DeclaredVisibility::Unknown => Err(member.clone()),
    }
}

fn has_clashing_explicit_type_imports<E: WorkspaceMemberTypeEnv>(
    env: &E,
    file: &ProjectFile,
    head: &str,
) -> bool {
    let mut canonical_names = Vec::<String>::new();
    let mut static_targets = Vec::<String>::new();
    for import in env.import_infos_of(file) {
        if import.is_wildcard || import.identifier.as_deref() != Some(head) {
            continue;
        }
        if let Some(path) = non_static_import_path(&import) {
            let canonical = path.render_segments(".");
            if !canonical_names.contains(&canonical) {
                canonical_names.push(canonical);
            }
        } else if let Some(path) = static_import_path(&import) {
            let canonical = path.render_segments(".");
            if !static_targets.contains(&canonical) {
                static_targets.push(canonical);
            }
        }
    }
    if canonical_names.len() >= 2 {
        return true;
    }
    if canonical_names.len() + static_targets.len() < 2 {
        return false;
    }
    let mut distinct_targets = Vec::<String>::new();
    for canonical in &canonical_names {
        if !distinct_targets.contains(canonical) {
            distinct_targets.push(canonical.clone());
        }
    }
    for static_path in &static_targets {
        if !env.forward_classes_by_fqn(static_path).is_empty()
            && !distinct_targets.contains(static_path)
        {
            distinct_targets.push(static_path.clone());
        }
    }
    distinct_targets.len() >= 2
}

struct DirectSupertypes {
    workspace: Vec<CodeUnit>,
    external: Vec<JvmExternalType>,
    /// Written supertypes nothing resolves.
    unresolved: Vec<String>,
}

/// Direct supertypes of `unit`, failing closed with `Err(unit)` when the
/// supertype edge set is incomplete, stopped, or obscured by an ambiguous
/// workspace supertype spelling. A spelling nothing resolves is returned in
/// `unresolved`; [`closed_direct_supertypes`] refuses it.
fn direct_supertypes<E: WorkspaceMemberTypeEnv>(
    env: &E,
    unit: &CodeUnit,
) -> Result<DirectSupertypes, CodeUnit> {
    if !env.is_live() || !env.charge_step() {
        return Err(unit.clone());
    }
    if unit.source().language() != Language::Java {
        let workspace = env
            .direct_hierarchy_ancestors(unit)
            .map_err(|()| unit.clone())?;
        return Ok(DirectSupertypes {
            workspace,
            external: Vec::new(),
            unresolved: Vec::new(),
        });
    }
    let raw_supertypes = env.raw_supertypes_of(unit);
    if raw_supertypes.is_empty() {
        return Ok(DirectSupertypes {
            workspace: Vec::new(),
            external: Vec::new(),
            unresolved: Vec::new(),
        });
    }
    for raw in &raw_supertypes {
        if !env.charge_step() {
            return Err(unit.clone());
        }
        let Some(type_name) = JavaTypeName::from_normalized_spelling(raw.trim()) else {
            return Err(unit.clone());
        };
        let head = type_name.first();
        if type_name.rest().is_empty() {
            let mut resolved_lexically = false;
            let mut enclosing = env.parent_of_unit(unit).filter(|u| !u.is_module());
            while let Some(current) = enclosing {
                if !env.charge_step() {
                    return Err(unit.clone());
                }
                if current.is_class() {
                    let fqn = format!("{}.{head}", current.fq_name());
                    let candidates = java_same_file_candidates(
                        env.forward_classes_by_fqn(&fqn)
                            .into_iter()
                            .filter(|u| u.fq_name() == fqn)
                            .collect(),
                        unit.source(),
                    );
                    if candidates.len() > 1 {
                        return Err(unit.clone());
                    }
                    if candidates.len() == 1 {
                        resolved_lexically = true;
                        break;
                    }
                }
                enclosing = env.parent_of_unit(&current).filter(|u| !u.is_module());
            }
            if resolved_lexically {
                continue;
            }
        } else {
            let rendered = type_name.render();
            let direct = java_same_file_candidates(
                env.forward_classes_by_fqn(&rendered)
                    .into_iter()
                    .filter(|u| u.fq_name() == rendered)
                    .collect(),
                unit.source(),
            );
            if direct.len() > 1 {
                return Err(unit.clone());
            }
            if direct.len() == 1 {
                continue;
            }
            if env
                .resolve_type_name_candidates_in_file(unit.source(), head)
                .len()
                > 1
            {
                return Err(unit.clone());
            }
        }
        if has_clashing_explicit_type_imports(env, unit.source(), head) {
            return Err(unit.clone());
        }
        if env
            .resolve_type_name_candidates_in_file(unit.source(), &type_name.render())
            .len()
            > 1
        {
            return Err(unit.clone());
        }
    }
    let workspace = env
        .direct_hierarchy_ancestors(unit)
        .map_err(|()| unit.clone())?;
    let external = env
        .direct_external_supertypes(unit)
        .map_err(|()| unit.clone())?;
    if !env.is_live() {
        return Err(unit.clone());
    }
    Ok(DirectSupertypes {
        workspace,
        external: external.resolved,
        unresolved: external.unresolved,
    })
}

/// [`direct_supertypes`] for a subtype question, which a supertype nothing
/// resolves leaves open: it fails closed with `Err(unit)`.
fn closed_direct_supertypes<E: WorkspaceMemberTypeEnv>(
    env: &E,
    unit: &CodeUnit,
) -> Result<DirectSupertypes, CodeUnit> {
    let direct = direct_supertypes(env, unit)?;
    if !direct.unresolved.is_empty() {
        return Err(unit.clone());
    }
    Ok(direct)
}

#[derive(Debug, Clone)]
pub(crate) enum InheritedCandidate {
    Workspace(CodeUnit),
    External(JvmExternalType),
}

impl InheritedCandidate {
    fn into_resolution(self) -> JavaTypeResolution {
        match self {
            Self::Workspace(unit) => JavaTypeResolution::Source(unit),
            Self::External(ext) => JavaTypeResolution::External(ExplicitImportHit::Ordinary(ext)),
        }
    }
}

/// The member types a declaration inherits under one simple name, and the
/// first supertype nothing resolves on the way, which may hide another.
struct InheritedMemberTypes {
    candidates: Vec<InheritedCandidate>,
    open: Option<OpenSupertype>,
}

/// Iterative post-order computation of member types named `simple_name` that
/// `root_owner` inherits from its workspace and external supertypes (JLS 8.5).
/// A supertype nothing resolves does not stop the walk: the candidates the
/// readable supertypes declare are returned with the first such supertype in
/// `open`, and the caller decides what the gap costs.
///
/// A supertype `P` that declares its own member type `simple_name` hides all
/// member types of that name from `P`'s own supertypes (even when `P`'s
/// declaration is `private`), and `root_owner` inherits `P`'s declaration iff
/// it is inheritable by `root_owner`. One declaration inherited along multiple
/// diamond paths is deduplicated to one candidate; two distinct declarations
/// remain distinct so callers report a compile-error ambiguity.
fn inherited_member_types_of<E: WorkspaceMemberTypeEnv>(
    env: &E,
    root_owner: &CodeUnit,
    simple_name: &str,
) -> Result<InheritedMemberTypes, CodeUnit> {
    assert!(!simple_name.is_empty());
    enum Frame {
        Enter(CodeUnit),
        Combine {
            unit: CodeUnit,
            workspace_ancestors: Vec<CodeUnit>,
            external_ancestors: Vec<JvmExternalType>,
        },
    }

    let direct = direct_supertypes(env, root_owner)?;
    let mut open = direct.unresolved.first().map(|supertype| OpenSupertype {
        declaration: root_owner.clone(),
        supertype: supertype.clone(),
    });
    if direct.workspace.is_empty() && direct.external.is_empty() {
        return Ok(InheritedMemberTypes {
            candidates: Vec::new(),
            open,
        });
    }

    let mut memo = HashMap::<CodeUnit, Vec<InheritedCandidate>>::default();
    let mut active = HashSet::<CodeUnit>::default();
    let mut visited = HashSet::<CodeUnit>::default();
    visited.insert(root_owner.clone());
    // The root is being computed: a supertype edge that reaches back to it is
    // a cycle, detected at the combine below.
    active.insert(root_owner.clone());

    let mut stack = Vec::<Frame>::new();
    let workspace_direct = direct.workspace;
    stack.push(Frame::Combine {
        unit: root_owner.clone(),
        workspace_ancestors: workspace_direct.clone(),
        external_ancestors: direct.external,
    });
    for ancestor in workspace_direct.into_iter().rev() {
        stack.push(Frame::Enter(ancestor));
    }

    while let Some(frame) = stack.pop() {
        if !env.is_live() || !env.charge_step() {
            return Err(root_owner.clone());
        }
        match frame {
            Frame::Enter(unit) => {
                if memo.contains_key(&unit) || active.contains(&unit) {
                    continue;
                }
                if visited.insert(unit.clone()) && visited.len() > MAX_CLOSURE_TYPES {
                    return Err(unit);
                }
                let own = owned_member_types(env, &unit, simple_name);
                if !own.is_empty() {
                    for candidate in &own {
                        let _ = declared_type_visibility(env, candidate)?;
                    }
                    memo.insert(
                        unit,
                        own.into_iter().map(InheritedCandidate::Workspace).collect(),
                    );
                    continue;
                }
                let ancestors = direct_supertypes(env, &unit)?;
                if open.is_none()
                    && let Some(supertype) = ancestors.unresolved.first()
                {
                    open = Some(OpenSupertype {
                        declaration: unit.clone(),
                        supertype: supertype.clone(),
                    });
                }
                active.insert(unit.clone());
                let workspace_ancestors = ancestors.workspace;
                stack.push(Frame::Combine {
                    unit,
                    workspace_ancestors: workspace_ancestors.clone(),
                    external_ancestors: ancestors.external,
                });
                for ancestor in workspace_ancestors.into_iter().rev() {
                    if !memo.contains_key(&ancestor) && !active.contains(&ancestor) {
                        stack.push(Frame::Enter(ancestor));
                    }
                }
            }
            Frame::Combine {
                unit,
                workspace_ancestors,
                external_ancestors,
            } => {
                active.remove(&unit);
                let mut inherited_ws = Vec::new();
                let mut inherited_ext = Vec::new();
                for ancestor in &workspace_ancestors {
                    let Some(visible_on_ancestor) = memo.get(ancestor) else {
                        // The post-order walk memoizes every ancestor before
                        // the unit that needs it; a miss means the ancestor is
                        // still being computed, so the edge closes a cycle
                        // (`A extends B`, `B extends A`, or `S extends S`).
                        // The hierarchy is ill-formed (JLS 8.1.4) and no
                        // inheritance answer through it is established: fail
                        // closed.
                        return Err(ancestor.clone());
                    };
                    for candidate in visible_on_ancestor {
                        match candidate {
                            InheritedCandidate::Workspace(ws) => {
                                if is_inheritable_by_subtype(env, ws, &unit)? {
                                    inherited_ws.push(ws.clone());
                                }
                            }
                            InheritedCandidate::External(ext) => {
                                if is_external_inheritable_by_package(ext, unit.package_name()) {
                                    inherited_ext.push(ext.clone());
                                }
                            }
                        }
                    }
                }
                if !external_ancestors.is_empty() {
                    let direct_ext = env
                        .inherited_external_member_types(
                            &external_ancestors,
                            unit.package_name(),
                            simple_name,
                        )
                        .map_err(|()| unit.clone())?;
                    inherited_ext.extend(direct_ext);
                }
                sort_units(&mut inherited_ws);
                inherited_ws.dedup();
                inherited_ext.sort_by(|left, right| left.fqn().cmp(right.fqn()));
                inherited_ext.dedup_by(|left, right| left.fqn() == right.fqn());
                // JLS 8.5 and 6.4.1: a member type declared in a more specific
                // supertype hides a same-named declaration from a less specific
                // one, even when the hidden declaration also reaches this class
                // along another supertype path that never passes through the
                // hider. Apply hiding across both workspace and external owners.
                let mut combined = inherited_ws
                    .into_iter()
                    .map(InheritedCandidate::Workspace)
                    .collect::<Vec<_>>();
                combined.extend(inherited_ext.into_iter().map(InheritedCandidate::External));
                if combined.len() > 1 {
                    let mut hidden = HashSet::default();
                    for (index, candidate) in combined.iter().enumerate() {
                        let Some(owner) = candidate_owner(env, candidate) else {
                            continue;
                        };
                        for (other_index, other) in combined.iter().enumerate() {
                            if other_index == index {
                                continue;
                            }
                            let Some(other_owner) = candidate_owner(env, other) else {
                                continue;
                            };
                            if owner != other_owner
                                && is_candidate_owner_subtype(env, &other_owner, &owner, &unit)?
                            {
                                hidden.insert(index);
                                break;
                            }
                        }
                    }
                    if !hidden.is_empty() {
                        combined = combined
                            .into_iter()
                            .enumerate()
                            .filter(|(index, _)| !hidden.contains(index))
                            .map(|(_, candidate)| candidate)
                            .collect();
                    }
                }
                memo.insert(unit, combined);
            }
        }
    }

    Ok(InheritedMemberTypes {
        candidates: memo.remove(root_owner).unwrap_or_default(),
        open,
    })
}

#[derive(Clone, PartialEq, Eq)]
enum CandidateOwner {
    Workspace(CodeUnit),
    External(String),
}

fn candidate_owner<E: WorkspaceMemberTypeEnv>(
    env: &E,
    candidate: &InheritedCandidate,
) -> Option<CandidateOwner> {
    match candidate {
        InheritedCandidate::Workspace(unit) => env
            .parent_of_unit(unit)
            .filter(|u| u.is_class())
            .map(CandidateOwner::Workspace),
        InheritedCandidate::External(ext) => ext
            .fqn()
            .rsplit_once('.')
            .map(|(owner_fqn, _)| CandidateOwner::External(owner_fqn.to_owned())),
    }
}

fn is_candidate_owner_subtype<E: WorkspaceMemberTypeEnv>(
    env: &E,
    sub: &CandidateOwner,
    sup: &CandidateOwner,
    blame_unit: &CodeUnit,
) -> Result<bool, CodeUnit> {
    match (sub, sup) {
        (CandidateOwner::Workspace(sub_u), CandidateOwner::Workspace(sup_u)) => {
            is_subtype_or_equal(env, sub_u, sup_u)
        }
        (CandidateOwner::External(sub_fqn), CandidateOwner::External(sup_fqn)) => {
            is_external_subtype_or_equal(env, sub_fqn, sup_fqn).map_err(|()| blame_unit.clone())
        }
        (CandidateOwner::Workspace(sub_u), CandidateOwner::External(sup_fqn)) => {
            is_workspace_subtype_of_external(env, sub_u, sup_fqn)
        }
        (CandidateOwner::External(_), CandidateOwner::Workspace(_)) => Ok(false),
    }
}

fn is_external_subtype_or_equal<E: WorkspaceMemberTypeEnv>(
    env: &E,
    sub_fqn: &str,
    sup_fqn: &str,
) -> Result<bool, ()> {
    if sub_fqn == sup_fqn {
        return Ok(true);
    }
    const MAX_EXTERNAL_CLOSURE: usize = 256;
    let mut visited = HashSet::<String>::default();
    let mut worklist = vec![sub_fqn.to_owned()];
    while let Some(curr) = worklist.pop() {
        if curr == sup_fqn {
            return Ok(true);
        }
        if !visited.insert(curr.clone()) {
            continue;
        }
        if visited.len() > MAX_EXTERNAL_CLOSURE {
            return Err(());
        }
        for super_fqn in env.external_supertypes(&curr)? {
            if super_fqn == sup_fqn {
                return Ok(true);
            }
            worklist.push(super_fqn);
        }
    }
    Ok(false)
}

fn is_workspace_subtype_of_external<E: WorkspaceMemberTypeEnv>(
    env: &E,
    unit: &CodeUnit,
    ext_fqn: &str,
) -> Result<bool, CodeUnit> {
    let mut visited = HashSet::default();
    let mut worklist = vec![unit.clone()];
    while let Some(curr) = worklist.pop() {
        if !visited.insert(curr.clone()) {
            continue;
        }
        if visited.len() > MAX_CLOSURE_TYPES || !env.is_live() || !env.charge_step() {
            return Err(curr);
        }
        let DirectSupertypes {
            workspace: ws_ancestors,
            external: ext_ancestors,
            ..
        } = closed_direct_supertypes(env, &curr)?;
        for ext in ext_ancestors {
            if is_external_subtype_or_equal(env, ext.fqn(), ext_fqn).map_err(|()| curr.clone())? {
                return Ok(true);
            }
        }
        worklist.extend(ws_ancestors);
    }
    Ok(false)
}

fn top_level_class<E: WorkspaceMemberTypeEnv>(env: &E, unit: &CodeUnit) -> Option<CodeUnit> {
    let mut top = unit.is_class().then(|| unit.clone());
    let mut current = env.parent_of_unit(unit);
    let mut steps = 0usize;
    while let Some(parent) = current {
        steps += 1;
        if steps > MAX_CLOSURE_TYPES || !env.charge_step() {
            break;
        }
        if parent.is_module() {
            break;
        }
        if parent.is_class() {
            top = Some(parent.clone());
        }
        current = env.parent_of_unit(&parent);
    }
    top
}

fn is_subtype_or_equal<E: WorkspaceMemberTypeEnv>(
    env: &E,
    candidate: &CodeUnit,
    target_super: &CodeUnit,
) -> Result<bool, CodeUnit> {
    if candidate == target_super {
        return Ok(true);
    }
    let mut visited = HashSet::<CodeUnit>::default();
    let mut worklist = vec![candidate.clone()];
    while let Some(current) = worklist.pop() {
        if !visited.insert(current.clone()) {
            continue;
        }
        if visited.len() > MAX_CLOSURE_TYPES {
            return Err(current);
        }
        for ancestor in closed_direct_supertypes(env, &current)?.workspace {
            if &ancestor == target_super {
                return Ok(true);
            }
            if !visited.contains(&ancestor) {
                worklist.push(ancestor);
            }
        }
    }
    Ok(false)
}

fn is_member_type_accessible_at<E: WorkspaceMemberTypeEnv>(
    env: &E,
    member: &CodeUnit,
    access_package: &str,
    site_enclosing_classes: &[CodeUnit],
) -> Result<bool, CodeUnit> {
    match declared_type_visibility(env, member)? {
        DeclaredVisibility::Public
        | DeclaredVisibility::Internal
        | DeclaredVisibility::ProtectedInternal => Ok(true),
        DeclaredVisibility::PackagePrivate | DeclaredVisibility::CrateOrModule => {
            Ok(member.package_name() == access_package)
        }
        DeclaredVisibility::Protected => {
            if member.package_name() == access_package {
                return Ok(true);
            }
            let Some(declaring_class) = env.parent_of_unit(member).filter(CodeUnit::is_class)
            else {
                return Ok(false);
            };
            for enclosing in site_enclosing_classes {
                if is_subtype_or_equal(env, enclosing, &declaring_class)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        DeclaredVisibility::Private | DeclaredVisibility::PrivateProtected => {
            let Some(member_top) = top_level_class(env, member) else {
                return Err(member.clone());
            };
            Ok(site_enclosing_classes.iter().any(|enclosing| {
                top_level_class(env, enclosing).is_some_and(|site_top| site_top == member_top)
            }))
        }
        DeclaredVisibility::Unknown => Err(member.clone()),
    }
}

fn is_external_member_type_accessible_at<E: WorkspaceMemberTypeEnv>(
    env: &E,
    member: &JvmExternalType,
    access_package: &str,
    site_enclosing_classes: &[CodeUnit],
) -> Result<bool, CodeUnit> {
    match member.visibility() {
        JvmVisibility::Public => Ok(true),
        JvmVisibility::PackagePrivate => Ok(member.package_name() == access_package),
        JvmVisibility::Private => Ok(false),
        JvmVisibility::Protected => {
            if member.package_name() == access_package {
                return Ok(true);
            }
            let Some((declaring_fqn, _)) = member.fqn().rsplit_once('.') else {
                return Ok(false);
            };
            for enclosing in site_enclosing_classes {
                if is_workspace_subtype_of_external(env, enclosing, declaring_fqn)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
    }
}

/// Resolve `owner.<member_name>` against `owner`'s declared and inherited
/// workspace member types, enforcing JLS 8.5 hiding and JLS 6.6.1 accessibility.
pub(crate) fn resolve_accessible_member_types_of_owner<E: WorkspaceMemberTypeEnv>(
    env: &E,
    owner: &CodeUnit,
    member_name: &str,
    access_file: &ProjectFile,
    site_enclosing_classes: &[CodeUnit],
) -> MemberTypeStep {
    if member_name.is_empty() {
        return MemberTypeStep::Missing;
    }
    let access_package = env.package_name_of_file(access_file);
    let own = owned_member_types(env, owner, member_name);
    if !own.is_empty() {
        let mut accessible = Vec::new();
        for candidate in own {
            match is_member_type_accessible_at(
                env,
                &candidate,
                &access_package,
                site_enclosing_classes,
            ) {
                Ok(true) => accessible.push(candidate),
                Ok(false) => {}
                Err(blame) => return MemberTypeStep::Incomplete(blame),
            }
        }
        return match accessible.len() {
            0 => MemberTypeStep::Missing,
            1 => MemberTypeStep::Resolved(accessible.remove(0)),
            _ => MemberTypeStep::Ambiguous(accessible),
        };
    }
    // A qualified member type read through an owner with a supertype nothing
    // resolves stays refused: the hidden member may be the one named.
    let inherited = match inherited_member_types_of(env, owner, member_name) {
        Ok(InheritedMemberTypes {
            candidates,
            open: None,
        }) => candidates,
        Ok(InheritedMemberTypes {
            open: Some(open), ..
        }) => return MemberTypeStep::Incomplete(open.declaration),
        Err(blame) => return MemberTypeStep::Incomplete(blame),
    };
    if inherited.is_empty() {
        return MemberTypeStep::Missing;
    }
    let mut accessible_ws = Vec::new();
    let mut accessible_ext = Vec::new();
    for candidate in inherited {
        match candidate {
            InheritedCandidate::Workspace(unit) => {
                match is_member_type_accessible_at(
                    env,
                    &unit,
                    &access_package,
                    site_enclosing_classes,
                ) {
                    Ok(true) => accessible_ws.push(unit),
                    Ok(false) => {}
                    Err(blame) => return MemberTypeStep::Incomplete(blame),
                }
            }
            InheritedCandidate::External(ext) => {
                match is_external_member_type_accessible_at(
                    env,
                    &ext,
                    &access_package,
                    site_enclosing_classes,
                ) {
                    Ok(true) => accessible_ext.push(ext),
                    Ok(false) => {}
                    Err(blame) => return MemberTypeStep::Incomplete(blame),
                }
            }
        }
    }
    let total = accessible_ws.len() + accessible_ext.len();
    match (total, accessible_ws.len(), accessible_ext.len()) {
        (0, _, _) => MemberTypeStep::Missing,
        (1, 1, 0) => MemberTypeStep::Resolved(accessible_ws.remove(0)),
        (1, 0, 1) => MemberTypeStep::ResolvedExternal(accessible_ext.remove(0)),
        (_, _, 0) => MemberTypeStep::Ambiguous(accessible_ws),
        _ => {
            let mut resolutions = accessible_ws
                .into_iter()
                .map(JavaTypeResolution::Source)
                .collect::<Vec<_>>();
            resolutions.extend(
                accessible_ext
                    .into_iter()
                    .map(|ext| JavaTypeResolution::External(ExplicitImportHit::Ordinary(ext))),
            );
            MemberTypeStep::AmbiguousResolutions(resolutions)
        }
    }
}

#[derive(Clone, Copy)]
struct AstTypeScope {
    in_member_scope: bool,
    callable_type_param_inside: bool,
    declares_type_param: bool,
}

struct AstTypeScopes {
    scopes: HashMap<(usize, usize), AstTypeScope>,
    trailing_callable_type_param: bool,
}

fn node_declares_type_param(declaration: Node<'_>, source: &str, target_name: &str) -> bool {
    java_declared_type_parameters(declaration)
        .into_iter()
        .filter_map(java_type_parameter_name_node)
        .any(|name_node| java_node_text(name_node, source) == target_name)
}

fn collect_ast_type_scopes(site_node: Node<'_>, source: &str, target_name: &str) -> AstTypeScopes {
    let mut scopes = HashMap::default();
    let mut callable_type_param_pending = false;
    let mut child = site_node;
    let mut current = site_node.parent();
    while let Some(node) = current {
        match node.kind() {
            "method_declaration"
            | "constructor_declaration"
            | "compact_constructor_declaration" => {
                let in_modifiers_or_name = node
                    .child_by_field_name("modifiers")
                    .is_some_and(|m| m.id() == child.id())
                    || node
                        .child_by_field_name("name")
                        .is_some_and(|n| n.id() == child.id());
                if !in_modifiers_or_name && node_declares_type_param(node, source, target_name) {
                    callable_type_param_pending = true;
                }
            }
            "class_declaration"
            | "interface_declaration"
            | "enum_declaration"
            | "record_declaration"
            | "annotation_type_declaration" => {
                let in_body = node
                    .child_by_field_name("body")
                    .is_some_and(|body| body.id() == child.id());
                let in_modifiers_or_name = node
                    .child_by_field_name("modifiers")
                    .is_some_and(|m| m.id() == child.id())
                    || node
                        .child_by_field_name("name")
                        .is_some_and(|n| n.id() == child.id());
                scopes.insert(
                    (node.start_byte(), node.end_byte()),
                    AstTypeScope {
                        // The record component list, like a class's own
                        // extends/implements clause, is outside the class body
                        // where inherited member types are in scope (JLS 8.5).
                        in_member_scope: in_body,
                        callable_type_param_inside: callable_type_param_pending,
                        declares_type_param: !in_modifiers_or_name
                            && node_declares_type_param(node, source, target_name),
                    },
                );
                callable_type_param_pending = false;
            }
            "object_creation_expression" if child.kind() == "class_body" => {
                scopes.insert(
                    (child.start_byte(), child.end_byte()),
                    AstTypeScope {
                        in_member_scope: true,
                        callable_type_param_inside: callable_type_param_pending,
                        declares_type_param: false,
                    },
                );
                callable_type_param_pending = false;
            }
            "enum_constant"
                if node
                    .child_by_field_name("body")
                    .is_some_and(|body| body.id() == child.id()) =>
            {
                scopes.insert(
                    (child.start_byte(), child.end_byte()),
                    AstTypeScope {
                        in_member_scope: true,
                        callable_type_param_inside: callable_type_param_pending,
                        declares_type_param: false,
                    },
                );
                callable_type_param_pending = false;
            }
            _ => {}
        }
        child = node;
        current = node.parent();
    }
    AstTypeScopes {
        scopes,
        trailing_callable_type_param: callable_type_param_pending,
    }
}

fn enclosing_classes_from_seed<E: WorkspaceMemberTypeEnv>(
    env: &E,
    seed: Option<CodeUnit>,
) -> Vec<CodeUnit> {
    let mut classes = Vec::new();
    let mut current = seed;
    let mut steps = 0usize;
    while let Some(unit) = current {
        steps += 1;
        if steps > MAX_CLOSURE_TYPES || !env.charge_step() {
            break;
        }
        if unit.is_module() {
            break;
        }
        if unit.is_class() {
            classes.push(unit.clone());
        }
        current = env.parent_of_unit(&unit);
    }
    classes
}

fn fold_external_member_type_segments<E: WorkspaceMemberTypeEnv>(
    env: &E,
    head_ext: JvmExternalType,
    rest: &[String],
    access_file: &ProjectFile,
    site_enclosing_classes: &[CodeUnit],
    head_tier: PrecedenceTier,
) -> JavaContextualTypeOutcome {
    let access_package = env.package_name_of_file(access_file);
    let mut current = head_ext;
    let last_idx = rest.len().saturating_sub(1);
    for (idx, segment) in rest.iter().enumerate() {
        let Ok(mut candidates) = env.inherited_external_member_types(
            std::slice::from_ref(&current),
            current.package_name(),
            segment,
        ) else {
            return match site_enclosing_classes.first() {
                Some(blame) => JavaContextualTypeOutcome::Incomplete(blame.clone()),
                None => JavaContextualTypeOutcome::MissingMemberOfBoundPrefix,
            };
        };
        if candidates.len() > 1 {
            let mut hidden = HashSet::default();
            for (i, cand) in candidates.iter().enumerate() {
                let Some((owner_fqn, _)) = cand.fqn().rsplit_once('.') else {
                    continue;
                };
                for (j, other) in candidates.iter().enumerate() {
                    if i == j {
                        continue;
                    }
                    let Some((other_fqn, _)) = other.fqn().rsplit_once('.') else {
                        continue;
                    };
                    if owner_fqn != other_fqn
                        && match is_external_subtype_or_equal(env, other_fqn, owner_fqn) {
                            Ok(true) => true,
                            Ok(false) => false,
                            Err(()) => {
                                return match site_enclosing_classes.first() {
                                    Some(blame) => {
                                        JavaContextualTypeOutcome::Incomplete(blame.clone())
                                    }
                                    None => JavaContextualTypeOutcome::MissingMemberOfBoundPrefix,
                                };
                            }
                        }
                    {
                        hidden.insert(i);
                        break;
                    }
                }
            }
            if !hidden.is_empty() {
                candidates = candidates
                    .into_iter()
                    .enumerate()
                    .filter(|(i, _)| !hidden.contains(i))
                    .map(|(_, cand)| cand)
                    .collect();
            }
        }
        let mut accessible = Vec::new();
        for cand in candidates {
            match is_external_member_type_accessible_at(
                env,
                &cand,
                &access_package,
                site_enclosing_classes,
            ) {
                Ok(true) => accessible.push(cand),
                Ok(false) => {}
                Err(blame) => return JavaContextualTypeOutcome::Incomplete(blame),
            }
        }
        match accessible.len() {
            0 => return JavaContextualTypeOutcome::MissingMemberOfBoundPrefix,
            1 => current = accessible.remove(0),
            _ => {
                if idx == last_idx {
                    return JavaContextualTypeOutcome::AmbiguousExternal(
                        accessible
                            .into_iter()
                            .map(|ext| {
                                JavaTypeResolution::External(ExplicitImportHit::Ordinary(ext))
                            })
                            .collect(),
                    );
                }
                return JavaContextualTypeOutcome::MissingMemberOfBoundPrefix;
            }
        }
    }
    JavaContextualTypeOutcome::ResolvedExternal {
        external: current,
        tier: head_tier,
    }
}

fn fold_member_type_segments<E: WorkspaceMemberTypeEnv>(
    env: &E,
    head_unit: CodeUnit,
    rest: &[String],
    access_file: &ProjectFile,
    site_enclosing_classes: &[CodeUnit],
    head_tier: PrecedenceTier,
) -> JavaContextualTypeOutcome {
    let mut current = head_unit;
    let last_idx = rest.len().saturating_sub(1);
    for (idx, segment) in rest.iter().enumerate() {
        match resolve_accessible_member_types_of_owner(
            env,
            &current,
            segment,
            access_file,
            site_enclosing_classes,
        ) {
            MemberTypeStep::Resolved(next) => current = next,
            MemberTypeStep::ResolvedExternal(ext) => {
                return fold_external_member_type_segments(
                    env,
                    ext,
                    &rest[idx + 1..],
                    access_file,
                    site_enclosing_classes,
                    head_tier,
                );
            }
            MemberTypeStep::Ambiguous(units) => {
                // Only the terminal segment can surface candidate peers; an
                // intermediate ambiguous owner cannot project a further member.
                if idx == last_idx {
                    return JavaContextualTypeOutcome::Ambiguous(units);
                }
                return JavaContextualTypeOutcome::MissingMemberOfBoundPrefix;
            }
            MemberTypeStep::AmbiguousResolutions(resolutions) => {
                if idx == last_idx {
                    return JavaContextualTypeOutcome::AmbiguousExternal(resolutions);
                }
                return JavaContextualTypeOutcome::MissingMemberOfBoundPrefix;
            }
            MemberTypeStep::Incomplete(blame) => {
                return JavaContextualTypeOutcome::Incomplete(blame);
            }
            MemberTypeStep::Missing => {
                return JavaContextualTypeOutcome::MissingMemberOfBoundPrefix;
            }
        }
    }
    JavaContextualTypeOutcome::Resolved {
        unit: current,
        tier: head_tier,
    }
}

/// Resolve `normalized` against method-local classes (`local_type` for `head`),
/// enclosing declared member types, type parameters in scope, and workspace
/// inherited member types in Java's innermost-outward order (JLS 6.3, 6.4.1, 8.5).
///
/// An enclosing declaration with a supertype nothing resolves leaves the
/// answer open. When no tier binds the name, the outcome is
/// [`JavaContextualTypeOutcome::OpenSupertype`], so the caller can bind
/// through the file-level tiers and report the doubt. When an outer tier does
/// bind it, the hidden member could shadow that binding as well, so the
/// outcome stays `Incomplete`.
pub(crate) fn resolve_contextual_java_type<E: WorkspaceMemberTypeEnv>(
    env: &E,
    file: &ProjectFile,
    normalized: &str,
    site: Option<(&str, Node<'_>)>,
    seed_owner: Option<CodeUnit>,
    local_type: Option<CodeUnit>,
) -> JavaContextualTypeOutcome {
    let mut open = None;
    let outcome = scan_contextual_java_type(
        env, file, normalized, site, seed_owner, local_type, &mut open,
    );
    match (open, outcome) {
        (None, outcome) => outcome,
        (Some(open), JavaContextualTypeOutcome::Unbound) => {
            JavaContextualTypeOutcome::OpenSupertype(open)
        }
        (Some(_), outcome @ JavaContextualTypeOutcome::Incomplete(_)) => outcome,
        (Some(open), _) => JavaContextualTypeOutcome::Incomplete(open.declaration),
    }
}

fn scan_contextual_java_type<E: WorkspaceMemberTypeEnv>(
    env: &E,
    file: &ProjectFile,
    normalized: &str,
    site: Option<(&str, Node<'_>)>,
    seed_owner: Option<CodeUnit>,
    local_type: Option<CodeUnit>,
    open: &mut Option<OpenSupertype>,
) -> JavaContextualTypeOutcome {
    let Some(type_name) = JavaTypeName::from_normalized_spelling(normalized) else {
        return JavaContextualTypeOutcome::Unbound;
    };
    let head = type_name.first();
    let rest = type_name.rest();

    let (enclosing_classes, ast_scopes) = match site {
        Some((source, site_node)) => (
            env.enclosing_class_units_at(file, site_node.start_byte()),
            Some(collect_ast_type_scopes(site_node, source, head)),
        ),
        None => (enclosing_classes_from_seed(env, seed_owner), None),
    };

    if let Some(local_unit) = local_type {
        if rest.is_empty() {
            return JavaContextualTypeOutcome::Resolved {
                unit: local_unit,
                tier: PrecedenceTier::LexicalBinding,
            };
        }
        return fold_member_type_segments(
            env,
            local_unit,
            rest,
            file,
            &enclosing_classes,
            PrecedenceTier::LexicalBinding,
        );
    }

    for enclosing in &enclosing_classes {
        if !env.is_live() || !env.charge_step() {
            return JavaContextualTypeOutcome::Incomplete(enclosing.clone());
        }
        let scope_info = ast_scopes.as_ref().and_then(|ast| {
            env.unit_ranges(enclosing)
                .first()
                .and_then(|range| ast.scopes.get(&(range.start_byte, range.end_byte)).copied())
        });
        if let Some(info) = scope_info {
            if info.callable_type_param_inside {
                return if rest.is_empty() {
                    JavaContextualTypeOutcome::ShadowedByTypeParameter
                } else {
                    JavaContextualTypeOutcome::MissingMemberOfBoundPrefix
                };
            }
            if !info.in_member_scope {
                if info.declares_type_param {
                    return if rest.is_empty() {
                        JavaContextualTypeOutcome::ShadowedByTypeParameter
                    } else {
                        JavaContextualTypeOutcome::MissingMemberOfBoundPrefix
                    };
                }
                continue;
            }
        }

        let owned = owned_member_types(env, enclosing, head);
        if owned.len() == 1 {
            let head_unit = owned.into_iter().next().expect("checked singleton");
            if rest.is_empty() {
                return JavaContextualTypeOutcome::Resolved {
                    unit: head_unit,
                    tier: PrecedenceTier::OwnMember,
                };
            }
            return fold_member_type_segments(
                env,
                head_unit,
                rest,
                file,
                &enclosing_classes,
                PrecedenceTier::OwnMember,
            );
        }
        if owned.len() > 1 {
            return if rest.is_empty() {
                JavaContextualTypeOutcome::Ambiguous(owned)
            } else {
                JavaContextualTypeOutcome::MissingMemberOfBoundPrefix
            };
        }

        if scope_info.is_some_and(|info| info.declares_type_param) {
            return if rest.is_empty() {
                JavaContextualTypeOutcome::ShadowedByTypeParameter
            } else {
                JavaContextualTypeOutcome::MissingMemberOfBoundPrefix
            };
        }

        let inherited = match inherited_member_types_of(env, enclosing, head) {
            Ok(InheritedMemberTypes {
                candidates,
                open: Some(found),
            }) => {
                // A readable supertype binds the name, and the unresolved one
                // may bind it too: refuse rather than pick.
                if !candidates.is_empty() {
                    return JavaContextualTypeOutcome::Incomplete(found.declaration);
                }
                open.get_or_insert(found);
                continue;
            }
            Ok(InheritedMemberTypes {
                candidates,
                open: None,
            }) => Ok(candidates),
            Err(blame) => Err(blame),
        };
        match inherited {
            Ok(mut inherited) if inherited.len() == 1 => match inherited.remove(0) {
                InheritedCandidate::Workspace(head_unit) => {
                    if rest.is_empty() {
                        return JavaContextualTypeOutcome::Resolved {
                            unit: head_unit,
                            tier: PrecedenceTier::InheritedMember,
                        };
                    }
                    return fold_member_type_segments(
                        env,
                        head_unit,
                        rest,
                        file,
                        &enclosing_classes,
                        PrecedenceTier::InheritedMember,
                    );
                }
                InheritedCandidate::External(head_ext) => {
                    if rest.is_empty() {
                        return JavaContextualTypeOutcome::ResolvedExternal {
                            external: head_ext,
                            tier: PrecedenceTier::InheritedMember,
                        };
                    }
                    return fold_external_member_type_segments(
                        env,
                        head_ext,
                        rest,
                        file,
                        &enclosing_classes,
                        PrecedenceTier::InheritedMember,
                    );
                }
            },
            Ok(inherited) if inherited.len() > 1 => {
                if !rest.is_empty() {
                    return JavaContextualTypeOutcome::MissingMemberOfBoundPrefix;
                }
                if inherited
                    .iter()
                    .all(|candidate| matches!(candidate, InheritedCandidate::Workspace(_)))
                {
                    let units = inherited
                        .into_iter()
                        .filter_map(|candidate| match candidate {
                            InheritedCandidate::Workspace(unit) => Some(unit),
                            InheritedCandidate::External(_) => None,
                        })
                        .collect();
                    return JavaContextualTypeOutcome::Ambiguous(units);
                }
                return JavaContextualTypeOutcome::AmbiguousExternal(
                    inherited
                        .into_iter()
                        .map(InheritedCandidate::into_resolution)
                        .collect(),
                );
            }
            Ok(_) => {}
            Err(blame) => return JavaContextualTypeOutcome::Incomplete(blame),
        }
    }

    if ast_scopes
        .as_ref()
        .is_some_and(|ast| ast.trailing_callable_type_param)
    {
        return if rest.is_empty() {
            JavaContextualTypeOutcome::ShadowedByTypeParameter
        } else {
            JavaContextualTypeOutcome::MissingMemberOfBoundPrefix
        };
    }

    JavaContextualTypeOutcome::Unbound
}

/// The member type, declared or inherited, that the enclosing declarations of
/// `site` bind to `simple_name`. An unreadable or ambiguous supertype hierarchy
/// stops as `Incomplete`; a supertype nothing resolves, when nothing visible
/// binds the name, is `OpenSupertype`.
pub(crate) fn enclosing_member_type(
    java: &JavaAnalyzer,
    packs: Option<
        Arc<brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay>,
    >,
    selected_jdk_artifact_sha256: Option<&str>,
    external: &LazyExternal<'_>,
    file: &ProjectFile,
    site: &UseSite<'_>,
    simple_name: &str,
) -> EnclosingMemberType {
    let env = JavaAnalyzerMemberTypeEnv {
        java,
        token: site.token,
        packs,
        selected_jdk_artifact_sha256,
        external,
        site: Some((file, site)),
    };
    match resolve_contextual_java_type(
        &env,
        file,
        simple_name,
        Some((site.source, site.node)),
        None,
        None,
    ) {
        JavaContextualTypeOutcome::Resolved { unit, .. } => {
            EnclosingMemberType::Resolved(JavaTypeResolution::Source(unit))
        }
        JavaContextualTypeOutcome::ResolvedExternal { external, .. } => {
            EnclosingMemberType::Resolved(JavaTypeResolution::External(
                ExplicitImportHit::Ordinary(external),
            ))
        }
        JavaContextualTypeOutcome::Ambiguous(units) => EnclosingMemberType::Ambiguous(
            units.into_iter().map(JavaTypeResolution::Source).collect(),
        ),
        JavaContextualTypeOutcome::AmbiguousExternal(resolutions) => {
            EnclosingMemberType::Ambiguous(resolutions)
        }
        JavaContextualTypeOutcome::Incomplete(blame) => EnclosingMemberType::Incomplete {
            enclosing: blame.fq_name(),
        },
        JavaContextualTypeOutcome::OpenSupertype(open) => EnclosingMemberType::OpenSupertype(open),
        JavaContextualTypeOutcome::ShadowedByTypeParameter
        | JavaContextualTypeOutcome::MissingMemberOfBoundPrefix => {
            EnclosingMemberType::ShadowedByTypeParameter
        }
        JavaContextualTypeOutcome::Unbound => EnclosingMemberType::None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inline_project::InlineTestProject;
    use brokk_bifrost_analysis::analyzer::{AnalyzerQueryScope, QueryScope};
    use brokk_bifrost_test_macros::hardwon;

    struct MissingMemberVisibilityEnv<'a, 'q, 'x> {
        inner: JavaAnalyzerMemberTypeEnv<'a, 'q, 'x>,
        strip_visibility_fqn: &'a str,
    }

    impl WorkspaceMemberTypeEnv for MissingMemberVisibilityEnv<'_, '_, '_> {
        fn is_live(&self) -> bool {
            self.inner.is_live()
        }

        fn charge_step(&self) -> bool {
            self.inner.charge_step()
        }

        fn package_name_of_file(&self, file: &ProjectFile) -> String {
            self.inner.package_name_of_file(file)
        }

        fn raw_supertypes_of(&self, unit: &CodeUnit) -> Vec<String> {
            self.inner.raw_supertypes_of(unit)
        }

        fn forward_classes_by_fqn(&self, fqn: &str) -> Vec<CodeUnit> {
            self.inner.forward_classes_by_fqn(fqn)
        }

        fn parent_of_unit(&self, unit: &CodeUnit) -> Option<CodeUnit> {
            self.inner.parent_of_unit(unit)
        }

        fn enclosing_class_units_at(&self, file: &ProjectFile, byte: usize) -> Vec<CodeUnit> {
            self.inner.enclosing_class_units_at(file, byte)
        }

        fn unit_ranges(&self, unit: &CodeUnit) -> Vec<Range> {
            self.inner.unit_ranges(unit)
        }

        fn signature_metadata_of(&self, unit: &CodeUnit) -> Vec<SignatureMetadata> {
            if unit.fq_name() == self.strip_visibility_fqn {
                return Vec::new();
            }
            self.inner.signature_metadata_of(unit)
        }

        fn import_infos_of(&self, file: &ProjectFile) -> Vec<ImportInfo> {
            self.inner.import_infos_of(file)
        }

        fn resolve_type_name_candidates_in_file(
            &self,
            file: &ProjectFile,
            normalized: &str,
        ) -> Vec<CodeUnit> {
            self.inner
                .resolve_type_name_candidates_in_file(file, normalized)
        }

        fn direct_hierarchy_ancestors(&self, unit: &CodeUnit) -> Result<Vec<CodeUnit>, ()> {
            self.inner.direct_hierarchy_ancestors(unit)
        }

        fn direct_external_supertypes(
            &self,
            unit: &CodeUnit,
        ) -> Result<DirectExternalSupertypes, ()> {
            self.inner.direct_external_supertypes(unit)
        }

        fn inherited_external_member_types(
            &self,
            roots: &[JvmExternalType],
            subtype_package: &str,
            simple_name: &str,
        ) -> Result<Vec<JvmExternalType>, ()> {
            self.inner
                .inherited_external_member_types(roots, subtype_package, simple_name)
        }

        fn external_supertypes(&self, fqn: &str) -> Result<Vec<String>, ()> {
            self.inner.external_supertypes(fqn)
        }
    }

    #[test]
    #[hardwon(
        "#10858: Missing member-type visibility metadata fails closed as Incomplete instead of falling through to imports."
    )]
    fn missing_member_type_visibility_metadata_stops_as_incomplete() {
        let app_source = "package app;\nimport org.acme.Files;\nclass App extends p.Base {\n    Files field;\n}\n";
        let project = InlineTestProject::with_language(Language::Java)
            .file(
                "p/Base.java",
                "package p;\npublic class Base { public static class Files {} }\n",
            )
            .file(
                "org/acme/Files.java",
                "package org.acme;\npublic class Files {}\n",
            )
            .file("app/App.java", app_source)
            .build();
        let java = JavaAnalyzer::new_with_config(project.project_dyn(), Default::default());
        let file = project.file("app/App.java");
        let scope = AnalyzerQueryScope::new(&java);
        let parsed =
            brokk_bifrost_jvm::java::declarations::parse_tree(app_source).expect("parse App.java");
        let start = app_source.find("Files field").expect("field needle");
        let site_node = parsed
            .root_node()
            .named_descendant_for_byte_range(start, start + "Files".len())
            .expect("Files type node");
        let external = LazyExternal::deferred(|| java.external_declarations(None));
        let env = MissingMemberVisibilityEnv {
            inner: JavaAnalyzerMemberTypeEnv {
                java: &java,
                token: scope.token(),
                packs: None,
                selected_jdk_artifact_sha256: None,
                external: &external,
                site: None,
            },
            strip_visibility_fqn: "p.Base.Files",
        };
        let outcome = resolve_contextual_java_type(
            &env,
            &file,
            "Files",
            Some((app_source, site_node)),
            None,
            None,
        );
        match outcome {
            JavaContextualTypeOutcome::Incomplete(blame) => {
                assert_eq!(blame.fq_name(), "p.Base.Files");
            }
            other => panic!("expected Incomplete(p.Base.Files), got {other:?}"),
        }
    }
}
