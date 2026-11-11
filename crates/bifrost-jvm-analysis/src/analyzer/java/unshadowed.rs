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
use crate::analyzer::java::imports::JavaTypeResolution;
use crate::analyzer::jvm::external::JvmExternalDeclarations;
use brokk_bifrost_analysis::analyzer::{ProjectFile, QueryToken};
use brokk_bifrost_core::analyzer::CodeUnitIndex;
use brokk_bifrost_core::analyzer::model::CodeUnit;
use brokk_bifrost_jvm::java::graph::return_type::java_type_name_components;
use brokk_bifrost_jvm::java::graph_support::JavaSource;
use brokk_bifrost_jvm::java::graph_support::{
    JavaTypeName, java_source_class_by_fqn, java_type_parameter_in_scope,
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
        if self.external.platform_override_visible() {
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
            let implicit = match declaration.kind() {
                "enum_declaration" => Some("java.lang.Enum"),
                "record_declaration" => Some("java.lang.Record"),
                "annotation_type_declaration" => Some("java.lang.annotation.Annotation"),
                _ => None,
            };
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
        use brokk_bifrost_analysis::analyzer::Range;
        let Some(start) = self.java.enclosing_code_unit(
            self.file,
            &Range {
                start_byte: self.site.node.start_byte(),
                end_byte: self.site.node.start_byte().saturating_add(1),
                start_line: 0,
                end_line: 0,
            },
        ) else {
            return Vec::new();
        };
        brokk_bifrost_core::analyzer::usages::common::enclosing_owner_chain(start, |unit| {
            self.java.parent_of(unit)
        })
        .filter(CodeUnit::is_class)
        .collect()
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
    fn read_closure(&self, mut worklist: Vec<ClosureMember>) -> ClosureReading {
        let mut visited = brokk_bifrost_core::hash::HashSet::<String>::default();
        while let Some(member) = worklist.pop() {
            if visited.len() > MAX_CLOSURE_TYPES {
                return ClosureReading::Uninspectable;
            }
            match member {
                ClosureMember::Jdk(fqn) => {
                    if !self
                        .external
                        .jdk_owner_has_no_member_type(&fqn, self.simple_name)
                    {
                        return ClosureReading::Uninspectable;
                    }
                }
                ClosureMember::Workspace(unit) => {
                    if !visited.insert(unit.fq_name()) {
                        continue;
                    }
                    let member_type = format!("{}.{}", unit.fq_name(), self.simple_name);
                    if self
                        .java
                        .forward_definition_fqn(&member_type)
                        .iter()
                        .any(CodeUnit::is_class)
                    {
                        return ClosureReading::Declares;
                    }
                    for raw in JavaSource::raw_supertypes_of(self.java, &unit) {
                        let supertype = resolve_java_lexical_type_name(self.java, &unit, &raw)
                            .or_else(|| {
                                self.java.resolve_imported_type_name(
                                    self.site.token,
                                    unit.source(),
                                    &raw,
                                )
                            })
                            .map(ClosureMember::Workspace)
                            .or_else(|| {
                                self.supertype_member(
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

/// What the enclosing declarations of a use site say about a simple name before
/// any import is consulted.
pub(crate) enum EnclosingMemberType {
    /// No enclosing declaration declares or inherits a member type of that name
    /// that the ladder can see.
    None,
    /// An enclosing type declares it, and it is the innermost scope that binds
    /// the name.
    Declared(CodeUnit),
    /// A supertype of an enclosing type declares it. The inherited member-type
    /// tier is not active, so the ladder cannot name the type, and a lower
    /// tier's answer would be wrong.
    Inherited { enclosing: String },
}

/// The member type, declared or inherited, that the enclosing declarations of
/// `site` bind to `simple_name`. An enclosing type that cannot be inspected
/// (it extends a type from a dependency jar) answers `None`: it only might
/// declare a competing binding, which the best-effort target tolerates and the
/// gap marks.
pub(crate) fn enclosing_member_type(
    java: &JavaAnalyzer,
    packs: Option<
        Arc<brokk_bifrost_analysis::analyzer::semantic_model::overlay::SemanticModelOverlay>,
    >,
    selected_jdk_artifact_sha256: Option<&str>,
    external: &JvmExternalDeclarations<'_>,
    file: &ProjectFile,
    site: &UseSite<'_>,
    simple_name: &str,
) -> EnclosingMemberType {
    let check = ScopeCheck {
        java,
        packs,
        selected_jdk_artifact_sha256,
        external,
        file,
        site,
        simple_name,
    };
    for enclosing in check.enclosing_class_units() {
        let own = format!("{}.{simple_name}", enclosing.fq_name());
        if let Some(declared) = java
            .forward_definition_fqn(&own)
            .into_iter()
            .find(CodeUnit::is_class)
        {
            return EnclosingMemberType::Declared(declared);
        }
        let supertypes = JavaSource::raw_supertypes_of(java, &enclosing)
            .iter()
            .filter_map(|raw| {
                resolve_java_lexical_type_name(java, &enclosing, raw)
                    .or_else(|| java.resolve_imported_type_name(site.token, file, raw))
            })
            .map(ClosureMember::Workspace)
            .collect::<Vec<_>>();
        if let ClosureReading::Declares = check.read_closure(supertypes) {
            return EnclosingMemberType::Inherited {
                enclosing: enclosing.fq_name(),
            };
        }
    }
    EnclosingMemberType::None
}
