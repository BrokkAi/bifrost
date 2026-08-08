//! Kotlin definition navigation (issue #1238).
//!
//! Answers "the token at this location refers to which declaration?" for
//! Kotlin source. Every fact comes from the pinned Kotlin tree-sitter syntax
//! tree (`crates/bifrost-analysis/vendor/tree-sitter-kotlin`) or from the
//! analyzer's indexed declarations; nothing is recovered by scanning source
//! text.
//!
//! # What the grammar gives us
//!
//! The vendored Kotlin grammar is field-poor: only `function_declaration` and
//! `property_declaration` carry a `receiver` field, so "the callee of this
//! call" and "the member of this navigation" are read positionally from named
//! children rather than by field name. The shapes this module matches:
//!
//! - a call is `call_expression` = callee expression, then `call_suffix`
//!   (holding `value_arguments` and/or a trailing `annotated_lambda`);
//! - a member access is `navigation_expression` = receiver expression, then
//!   `navigation_suffix` whose named child is the member `simple_identifier`
//!   (`.` and `?.` produce the same shape; `!!` wraps the receiver in
//!   `postfix_expression`);
//! - a type reference is `user_type`, whose `type_identifier` children are the
//!   dotted segments (`lib.Base` is one `user_type` with two children);
//! - an import is `import_header` = `identifier` (one `simple_identifier` per
//!   segment), optional `import_alias`, optional `wildcard_import`.
//!
//! The positional reads themselves live in [`brokk_bifrost_jvm::kotlin::syntax`],
//! shared with the usage graphs (issue #1239) so the two cannot drift apart
//! about what a syntax shape means.
//!
//! # How a name becomes a declaration
//!
//! Name precedence is not reimplemented here. [`brokk_bifrost_jvm::kotlin::types`]
//! owns Kotlin's ladder (enclosing scopes, then explicit imports, then the
//! file's package, then star imports, then default imports) as
//! [`resolve_kotlin_type_name`], parameterised over a "does this
//! fully-qualified name exist" predicate. This module supplies a predicate
//! backed by [`BoundedDefinitionLookup`], which is realm-aware: in a mixed
//! Java/Kotlin/Scala workspace a Kotlin file resolves a Java type declared next
//! door. Calling `KotlinAnalyzer::resolve_type_name_in_file` instead would
//! bypass `MultiAnalyzer`'s realm widening and silently lose those answers.

use super::*;
use crate::analyzer::kotlin::KotlinAnalyzer;
use crate::analyzer::semantic_model::{
    SemanticModelOverlay, SemanticModelSymbol, SemanticModelSymbolKind, TypeRef,
};
use crate::analyzer::structural::{
    HierarchyRelation, MemberDispatchTier, PrecedenceTier, RejectionReason,
};
use crate::analyzer::tree_walk::{first_named_child_of_kind, named_children};
use crate::analyzer::usages::common::language_for_target;
use crate::analyzer::usages::target_kind::TypeLookupTargetKind;
use crate::analyzer::{BoundedDefinitionLookup, ForwardQueryProvider, SignatureMetadata};
use brokk_bifrost_jvm::kotlin::declarations::kotlin_package_name;
use brokk_bifrost_jvm::kotlin::syntax::{
    kotlin_call_arity, kotlin_call_with_callee, kotlin_callee, kotlin_declaration_node,
    kotlin_enclosing_import_header, kotlin_is_declaration_name, kotlin_is_expression_kind,
    kotlin_named_argument_label,
};
use brokk_bifrost_jvm::kotlin::types::{KotlinNameScope, KotlinTypeName, resolve_kotlin_type_name};
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

/// How many levels of ancestor scope a name lookup inherits.
///
/// Matches `MAX_INHERITED_SCOPE_DEPTH` in [`brokk_bifrost_jvm::kotlin::types`]:
/// inherited nested types are rare and deep chains rarer, and a small cap keeps
/// a cyclic hierarchy from turning one lookup into an unbounded traversal.
const MAX_INHERITED_SCOPE_DEPTH: usize = 4;
const KOTLIN_PACKAGE_MARKER: &str = "bifrost:kotlin-package";

/// The declaration lookup a bounded Kotlin request resolves against.
///
/// Every query is charged to the request's session, so a receiver query over a
/// large workspace reports exhaustion instead of quietly performing the
/// unbounded navigation lookup.
///
/// Cross-language answers are deliberately not served. A Kotlin file in a JVM
/// realm can name a Java or Scala declaration, but materialising another
/// language's index speculatively is exactly the unbounded work this path
/// exists to avoid, so an absent cross-language candidate is a resolution
/// boundary rather than budget exhaustion — the same stance the Scala and Ruby
/// bounded providers take.
pub(crate) struct KotlinDefinitionProvider<'a> {
    kotlin: &'a KotlinAnalyzer,
    session: &'a ResolutionSession,
}

impl<'a> KotlinDefinitionProvider<'a> {
    pub(crate) fn new(kotlin: &'a KotlinAnalyzer, session: &'a ResolutionSession) -> Self {
        Self { kotlin, session }
    }
}

impl BoundedDefinitionLookup for KotlinDefinitionProvider<'_> {
    fn fqn(&self, fqn: &str) -> Vec<CodeUnit> {
        let mut units = self
            .session
            .query_rows(|| self.kotlin.forward_definition_fqn(fqn));
        sort_units(&mut units);
        units.dedup();
        units
    }

    fn fqn_in_language(&self, fqn: &str, language: Language) -> Vec<CodeUnit> {
        if language == Language::Kotlin {
            self.fqn(fqn)
        } else {
            Vec::new()
        }
    }

    fn file_identifier(&self, file: &ProjectFile, ident: &str) -> Vec<CodeUnit> {
        let mut units = self
            .session
            .query_rows(|| self.kotlin.forward_file_identifier(file, ident));
        sort_units(&mut units);
        units.dedup();
        units
    }

    fn fqn_direct_children(&self, fqn: &str) -> Vec<CodeUnit> {
        let mut children = Vec::new();
        for owner in self.fqn(fqn) {
            children.extend(
                self.session
                    .query_rows(|| self.kotlin.forward_direct_children(&owner)),
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
            .query(|| self.kotlin.forward_package_exists(package))
            .unwrap_or(false)
    }

    fn package_exists_in_language(&self, package: &str, language: Language) -> bool {
        language == Language::Kotlin && self.package_exists(package)
    }

    fn fqn_prefix_exists(&self, prefix: &str) -> bool {
        self.session
            .query(|| self.kotlin.forward_fqn_prefix_exists(prefix))
            .unwrap_or(false)
    }
}

pub(super) fn parse_kotlin_tree(source: &str) -> Option<Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&crate::analyzer::kotlin::language::LANGUAGE.into())
        .ok()?;
    parser.parse(source.as_bytes(), None)
}

pub(crate) fn resolve_kotlin(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
) -> DefinitionLookupOutcome {
    resolve_kotlin_in_session(
        analyzer,
        support,
        &ResolutionSession::unbounded(),
        file,
        source,
        tree,
        site,
    )
}

/// Bounded Kotlin definition resolution for the receiver-query path (#1242).
///
/// The resolver itself is the same one navigation uses; only the session
/// differs, so a bounded receiver query and a `get_definition` request cannot
/// disagree about what a Kotlin reference denotes.
pub(crate) fn resolve_kotlin_bounded(
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
    budget: ReceiverAnalysisBudget,
    cancellation: Option<&CancellationToken>,
) -> BoundedResolution<DefinitionLookupOutcome> {
    let session = ResolutionSession::bounded(budget, cancellation);
    let Some(kotlin) = resolve_analyzer::<KotlinAnalyzer>(analyzer) else {
        return session.finish(no_definition(
            "kotlin_analyzer_unavailable",
            "Kotlin analyzer is unavailable",
        ));
    };
    let support = KotlinDefinitionProvider::new(kotlin, &session);
    let outcome = resolve_kotlin_in_session(analyzer, &support, &session, file, source, tree, site);
    session.finish(outcome)
}

#[allow(clippy::too_many_arguments)]
fn resolve_kotlin_in_session(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    session: &ResolutionSession,
    file: &ProjectFile,
    source: &str,
    tree: Option<&Tree>,
    site: &ResolvedReferenceSite,
) -> DefinitionLookupOutcome {
    let Some(tree) = tree else {
        return no_definition("kotlin_parse_failed", "Kotlin source could not be parsed");
    };
    let root = tree.root_node();
    let Some(node) = smallest_named_node_covering(root, site.focus_start_byte, site.focus_end_byte)
    else {
        return no_definition(
            "no_indexed_definition",
            format!(
                "`{}` did not resolve to an indexed Kotlin definition",
                site.text
            ),
        );
    };

    let ctx = KotlinCtx::new(analyzer, support, session, file, source, root, site);

    if let Some(header) = kotlin_enclosing_import_header(node) {
        return kotlin_import_reference_outcome(&ctx, header, node);
    }
    if kotlin_is_declaration_name(node) {
        return no_definition(
            "declaration_site",
            format!(
                "`{}` is a Kotlin declaration name, not a reference",
                site.text
            ),
        );
    }

    match node.kind() {
        "type_identifier" => kotlin_type_reference_outcome(&ctx, node),
        "simple_identifier" => kotlin_identifier_reference_outcome(&ctx, node),
        kind => no_definition(
            "unsupported_kotlin_reference_shape",
            format!(
                "`{}` is a Kotlin `{kind}` reference shape that get_definition does not resolve yet",
                site.text
            ),
        ),
    }
}

/// Route a focused `simple_identifier` to the resolver for the shape it sits in.
///
/// `simple_identifier` is Kotlin's most overloaded node: it spells callees,
/// members, named-argument labels, and bare value references alike. The parent
/// node is what distinguishes them.
fn kotlin_identifier_reference_outcome(
    ctx: &KotlinCtx<'_>,
    node: Node<'_>,
) -> DefinitionLookupOutcome {
    let name = ctx.text(node);
    if name.is_empty() {
        return no_definition("no_reference_text", "Kotlin reference is blank");
    }
    let Some(parent) = node.parent() else {
        return kotlin_bare_value_outcome(ctx, node, name);
    };

    if parent.kind() == "value_argument" && kotlin_named_argument_label(parent, node) {
        return kotlin_named_argument_outcome(ctx, parent, name);
    }
    if let Some(call) = kotlin_call_with_callee(node) {
        return kotlin_bare_call_outcome(ctx, node, name, Some(kotlin_call_arity(call)));
    }
    if parent.kind() == "callable_reference" {
        // `::topLevel` names a callable without applying it, so no arity is
        // proven and every overload of the name is a legitimate answer.
        return kotlin_bare_call_outcome(ctx, node, name, None);
    }
    if parent.kind() == "navigation_suffix" {
        return kotlin_member_outcome(ctx, parent, name);
    }
    kotlin_bare_value_outcome(ctx, node, name)
}

/// Everything a Kotlin resolver step needs about the request it is serving.
///
/// The package name and imports are read once per request: both are file-wide
/// facts, and every name lookup in the request consults them.
struct KotlinCtx<'a> {
    analyzer: &'a dyn IAnalyzer,
    support: &'a dyn BoundedDefinitionLookup,
    /// Work accounting for this request. An unbounded session charges nothing,
    /// so the ordinary navigation path is unchanged; a bounded one — the
    /// receiver-query path of issue #1242 — charges every index query, syntax
    /// read, and hierarchy expansion this resolver performs, so exhaustion is
    /// reported rather than silently answered around.
    session: &'a ResolutionSession,
    file: &'a ProjectFile,
    source: &'a str,
    site: &'a ResolvedReferenceSite,
    overlay: Option<Arc<SemanticModelOverlay>>,
    /// Parsed syntax of the files this request has had to look inside, keyed by
    /// file. Resolving a reference regularly needs a fact that lives in another
    /// file's *syntax* rather than in its index — whether a nested object is a
    /// `companion_object`, what a parameter is called, what type a property
    /// declares — and re-reading and re-parsing the same file for each of those
    /// questions would be quadratic in a chained expression.
    file_syntax: RefCell<HashMap<ProjectFile, Option<Rc<KotlinFileSyntax>>>>,
    /// Package name and imports per file. A declaration's own file decides what
    /// its spelled types mean, so resolving the return type of a function in
    /// another file needs *that* file's scope, not the requesting file's.
    file_facts: RefCell<HashMap<ProjectFile, Rc<KotlinFileFacts>>>,
}

/// The file-level half of a Kotlin name scope.
struct KotlinFileFacts {
    package_name: String,
    imports: Vec<ImportInfo>,
}

/// A complete Kotlin name scope, owned so it can be built for any file.
///
/// [`KotlinNameScope`] borrows its file-level parts, which a per-file cache
/// cannot hand out; this owns them and lends a `KotlinNameScope` on demand.
struct KotlinScope {
    facts: Rc<KotlinFileFacts>,
    owners: Vec<String>,
}

impl KotlinScope {
    fn as_name_scope(&self) -> KotlinNameScope<'_> {
        KotlinNameScope {
            package_name: &self.facts.package_name,
            imports: &self.facts.imports,
            scope_owners: self.owners.clone(),
        }
    }
}

/// One file's source together with its parse, owned so a caller can hold nodes
/// borrowed from the tree for as long as it holds the `Rc`.
struct KotlinFileSyntax {
    source: String,
    tree: Tree,
}

impl<'a> KotlinCtx<'a> {
    fn new(
        analyzer: &'a dyn IAnalyzer,
        support: &'a dyn BoundedDefinitionLookup,
        session: &'a ResolutionSession,
        file: &'a ProjectFile,
        source: &'a str,
        root: Node<'_>,
        site: &'a ResolvedReferenceSite,
    ) -> Self {
        // The package comes from the syntax tree rather than from an indexed
        // declaration: a file whose only content is a reference, or whose
        // declarations were dropped by parse recovery, still has a package
        // header, and the same-package tier of the ladder needs it.
        let facts = Rc::new(KotlinFileFacts {
            package_name: kotlin_package_name(root, source),
            imports: session.query_rows(|| {
                analyzer
                    .import_analysis_provider()
                    .map(|provider| provider.import_info_of(file))
                    .unwrap_or_default()
            }),
        });
        let mut file_facts = HashMap::default();
        file_facts.insert(file.clone(), facts);
        Self {
            analyzer,
            support,
            session,
            file,
            source,
            site,
            overlay: analyzer.semantic_model_overlay(),
            file_syntax: RefCell::new(HashMap::default()),
            file_facts: RefCell::new(file_facts),
        }
    }

    /// One declaration's ranges, charged to this request.
    fn ranges(&self, unit: &CodeUnit) -> Vec<Range> {
        self.session.query_rows(|| self.analyzer.ranges(unit))
    }

    /// One declaration's published signature metadata, charged to this request.
    fn signature_metadata(&self, unit: &CodeUnit) -> Vec<SignatureMetadata> {
        self.session
            .query_rows(|| self.analyzer.signature_metadata(unit))
    }

    fn parent_of(&self, unit: &CodeUnit) -> Option<CodeUnit> {
        self.session
            .query_optional(|| self.analyzer.parent_of(unit))
    }

    fn enclosing_code_unit(&self, file: &ProjectFile, range: &Range) -> Option<CodeUnit> {
        self.session
            .query_optional(|| self.analyzer.enclosing_code_unit(file, range))
    }

    /// One hierarchy expansion step, charged against the summary budget so a
    /// deep or cyclic hierarchy exhausts a separate limit from syntax work.
    fn direct_ancestors(&self, unit: &CodeUnit) -> Vec<CodeUnit> {
        self.session.summary_rows(|| {
            self.analyzer
                .type_hierarchy_provider()
                .map(|provider| provider.get_direct_ancestors(unit))
                .unwrap_or_default()
        })
    }

    fn raw_supertypes(&self, unit: &CodeUnit) -> Vec<String> {
        let Some(kotlin) = resolve_analyzer::<KotlinAnalyzer>(self.analyzer) else {
            return Vec::new();
        };
        self.session
            .query_limited_rows(|limit| kotlin.raw_supertypes_limited(unit, limit))
    }

    fn imports_of(&self, file: &ProjectFile) -> Vec<ImportInfo> {
        self.session.query_rows(|| {
            self.analyzer
                .import_analysis_provider()
                .map(|provider| provider.import_info_of(file))
                .unwrap_or_default()
        })
    }

    /// A `KotlinCtx` over another file's syntax, sharing this request's
    /// analyzer, lookup, and work accounting.
    fn declaring_ctx<'declaring>(
        &'declaring self,
        file: &'declaring ProjectFile,
        source: &'declaring str,
    ) -> KotlinCtx<'declaring> {
        KotlinCtx {
            analyzer: self.analyzer,
            support: self.support,
            session: self.session,
            file,
            source,
            site: self.site,
            overlay: self.overlay.clone(),
            file_syntax: RefCell::new(HashMap::default()),
            file_facts: RefCell::new(HashMap::default()),
        }
    }

    /// The scope a *declaration* is written in, built entirely from the index.
    ///
    /// The package comes from the declaration's own identity, the imports from
    /// the import index, and the enclosing owners from the declaration ranges —
    /// so unlike [`Self::scope_in`], nothing here reads or parses the declaring
    /// file. That is what makes the published-facts path of
    /// [`Self::declared_type_of`] a genuine saving rather than a reordering: the
    /// spelled type still has to be resolved in the file that wrote it, and this
    /// is how that file's scope is obtained without opening it.
    fn declaration_scope(&self, unit: &CodeUnit) -> Option<KotlinScope> {
        let byte = self.ranges(unit).into_iter().min()?.start_byte;
        Some(KotlinScope {
            facts: self.indexed_file_facts(unit),
            owners: self.scope_owners_at(unit.source(), byte),
        })
    }

    /// The package and imports of `unit`'s file, taken from the index.
    ///
    /// Seeds the same cache [`Self::file_facts`] reads, because the two produce
    /// the same answer: a Kotlin `CodeUnit` records the package of the file that
    /// declared it, which is exactly what parsing that file's package header
    /// would report.
    fn indexed_file_facts(&self, unit: &CodeUnit) -> Rc<KotlinFileFacts> {
        let file = unit.source();
        if let Some(cached) = self.file_facts.borrow().get(file) {
            return Rc::clone(cached);
        }
        let facts = Rc::new(KotlinFileFacts {
            package_name: unit.package_name().to_string(),
            imports: self.imports_of(file),
        });
        self.file_facts
            .borrow_mut()
            .insert(file.clone(), Rc::clone(&facts));
        facts
    }

    /// The package and imports of `file`.
    fn file_facts(&self, file: &ProjectFile) -> Rc<KotlinFileFacts> {
        if let Some(cached) = self.file_facts.borrow().get(file) {
            return Rc::clone(cached);
        }
        let package_name = self
            .file_syntax(file)
            .map(|syntax| kotlin_package_name(syntax.tree.root_node(), &syntax.source))
            .unwrap_or_default();
        let facts = Rc::new(KotlinFileFacts {
            package_name,
            imports: self.imports_of(file),
        });
        self.file_facts
            .borrow_mut()
            .insert(file.clone(), Rc::clone(&facts));
        facts
    }

    /// The parsed syntax of `file`, read from the analyzer's indexed content so
    /// the answer matches the generation the declaration ranges came from.
    fn file_syntax(&self, file: &ProjectFile) -> Option<Rc<KotlinFileSyntax>> {
        if let Some(cached) = self.file_syntax.borrow().get(file) {
            return cached.clone();
        }
        // Reading and parsing another file is the most expensive step this
        // resolver takes, so it is charged before it happens rather than after.
        let syntax = self
            .session
            .query_optional(|| {
                self.analyzer
                    .indexed_source(file)
                    .or_else(|| self.analyzer.project().read_source(file).ok())
            })
            .and_then(|source| {
                let tree = parse_kotlin_tree(&source)?;
                Some(Rc::new(KotlinFileSyntax { source, tree }))
            });
        self.file_syntax
            .borrow_mut()
            .insert(file.clone(), syntax.clone());
        syntax
    }

    /// The syntax node a declaration was indexed from.
    ///
    /// Declaration ranges are recorded against the file's own bytes, so the
    /// smallest named node covering the range is the declaration itself. This
    /// is how a resolver asks a *structural* question about a declaration in
    /// another file — is this object a companion, what is this parameter
    /// called, what type does this property declare — without inventing a
    /// second, text-based model of Kotlin.
    fn declaration_syntax(&self, unit: &CodeUnit) -> Option<(Rc<KotlinFileSyntax>, Range)> {
        let range = self.ranges(unit).into_iter().min()?;
        let syntax = self.file_syntax(unit.source())?;
        Some((syntax, range))
    }

    fn text(&self, node: Node<'_>) -> &'a str {
        node.utf8_text(self.source.as_bytes()).unwrap_or_default()
    }

    /// The names visible at `byte` of the requesting file.
    fn scope_at(&self, byte: usize) -> KotlinScope {
        self.scope_in(self.file, byte)
    }

    /// The names visible at `byte` of `file`: that file's package and imports,
    /// plus the declarations enclosing the position and the scopes they inherit.
    fn scope_in(&self, file: &ProjectFile, byte: usize) -> KotlinScope {
        KotlinScope {
            facts: self.file_facts(file),
            owners: self.scope_owners_at(file, byte),
        }
    }

    /// Resolve a spelled Kotlin name to the fully-qualified name it denotes.
    fn resolve_name(&self, spelled: &str, scope: &KotlinScope) -> KotlinTypeName {
        resolve_kotlin_type_name(spelled, &scope.as_name_scope(), |candidate| {
            self.type_exists(candidate)
        })
    }

    /// The type declaration a spelled name denotes in `scope`, if exactly one
    /// indexed declaration answers to it.
    fn resolve_type_unit(&self, spelled: &str, scope: &KotlinScope) -> Option<CodeUnit> {
        let fqn = self.resolve_name(spelled, scope).resolved()?;
        let mut units = self.types_named(&fqn);
        (units.len() == 1).then(|| units.remove(0))
    }

    fn types_named(&self, fqn: &str) -> Vec<CodeUnit> {
        self.support
            .fqn_in_any_language(fqn)
            .into_iter()
            .filter(|unit| unit.is_class() && !unit.is_synthetic())
            .collect()
    }

    fn type_exists(&self, fqn: &str) -> bool {
        !self.types_named(fqn).is_empty() || !self.model_types_named(fqn).is_empty()
    }

    fn model_symbols_named(
        &self,
        fqn: &str,
        accepts: impl Fn(SemanticModelSymbolKind) -> bool,
    ) -> Vec<&SemanticModelSymbol> {
        let Some(overlay) = &self.overlay else {
            return Vec::new();
        };
        self.session
            .query_rows(|| overlay.symbols_named(fqn).records)
            .into_iter()
            .filter(|symbol| {
                symbol.language == "kotlin" && symbol.externally_visible() && accepts(symbol.kind)
            })
            .collect()
    }

    fn model_types_named(&self, fqn: &str) -> Vec<&SemanticModelSymbol> {
        self.model_symbols_named(fqn, |kind| {
            matches!(
                kind,
                SemanticModelSymbolKind::Class
                    | SemanticModelSymbolKind::Annotation
                    | SemanticModelSymbolKind::Interface
                    | SemanticModelSymbolKind::Enum
                    | SemanticModelSymbolKind::Module
                    | SemanticModelSymbolKind::TypeAlias
            )
        })
        .into_iter()
        .filter(|symbol| {
            !symbol
                .aliases
                .iter()
                .any(|alias| alias == KOTLIN_PACKAGE_MARKER)
        })
        .collect()
    }

    fn model_package_exists(&self, fqn: &str) -> bool {
        self.model_symbols_named(fqn, |kind| kind == SemanticModelSymbolKind::Module)
            .iter()
            .any(|symbol| {
                symbol
                    .aliases
                    .iter()
                    .any(|alias| alias == KOTLIN_PACKAGE_MARKER)
            })
    }

    fn model_type_available(&self, fqn: &str) -> bool {
        self.types_named(fqn).is_empty() && !self.model_types_named(fqn).is_empty()
    }

    fn model_callables_named(&self, fqn: &str, arity: Option<usize>) -> Vec<&SemanticModelSymbol> {
        self.model_symbols_named(fqn, |kind| {
            matches!(
                kind,
                SemanticModelSymbolKind::Constructor
                    | SemanticModelSymbolKind::Method
                    | SemanticModelSymbolKind::Function
            )
        })
        .into_iter()
        .filter(|symbol| {
            arity.is_none_or(|arity| {
                symbol
                    .structured_signature
                    .as_ref()
                    .is_none_or(|signature| {
                        let required = signature
                            .parameters
                            .iter()
                            .filter(|parameter| !parameter.optional && !parameter.variadic)
                            .count();
                        required <= arity
                            && (signature
                                .parameters
                                .iter()
                                .any(|parameter| parameter.variadic)
                                || arity <= signature.parameters.len())
                    })
            })
        })
        .collect()
    }

    fn model_values_named(&self, fqn: &str) -> Vec<&SemanticModelSymbol> {
        self.model_symbols_named(fqn, |kind| {
            matches!(
                kind,
                SemanticModelSymbolKind::Property
                    | SemanticModelSymbolKind::Field
                    | SemanticModelSymbolKind::Constant
                    | SemanticModelSymbolKind::Module
            )
        })
        .into_iter()
        .filter(|symbol| {
            !symbol
                .aliases
                .iter()
                .any(|alias| alias == KOTLIN_PACKAGE_MARKER)
        })
        .collect()
    }

    fn model_members_named(&self, fqn: &str, arity: Option<usize>) -> Vec<&SemanticModelSymbol> {
        let callables = self.model_callables_named(fqn, arity);
        if arity.is_some() || !callables.is_empty() {
            callables
        } else {
            self.model_values_named(fqn)
        }
    }

    fn model_owner_and_ancestors(&self, owner: &str) -> Vec<&SemanticModelSymbol> {
        let types = self.model_types_named(owner);
        if types.len() != 1 || types[0].provenance.ambiguous {
            return types;
        }
        let mut result = vec![types[0]];
        if let Some(overlay) = &self.overlay {
            result.extend(
                self.session
                    .summary_rows(|| overlay.ancestors_of(types[0]).records),
            );
        }
        result
    }

    fn model_extension_candidates(
        &self,
        owner: &str,
        member: &str,
        arity: Option<usize>,
        site_byte: usize,
    ) -> Vec<&SemanticModelSymbol> {
        let conforming = self
            .model_owner_and_ancestors(owner)
            .into_iter()
            .map(|symbol| symbol.qualified_name.as_str())
            .collect::<Vec<_>>();
        let scope = self.scope_at(site_byte);
        let resolution = resolve_kotlin_type_name(member, &scope.as_name_scope(), |candidate| {
            self.model_callables_named(candidate, arity)
                .iter()
                .any(|symbol| model_extension_symbol_matches(symbol, &conforming))
        });
        let Some(fqn) = resolution.resolved() else {
            return Vec::new();
        };
        self.model_callables_named(&fqn, arity)
            .into_iter()
            .filter(|symbol| model_extension_symbol_matches(symbol, &conforming))
            .collect()
    }

    fn model_extension_candidates_for_conforming(
        &self,
        conforming: &[String],
        member: &str,
        arity: Option<usize>,
        site_byte: usize,
    ) -> Vec<&SemanticModelSymbol> {
        let conforming = conforming.iter().map(String::as_str).collect::<Vec<_>>();
        let scope = self.scope_at(site_byte);
        let resolution = resolve_kotlin_type_name(member, &scope.as_name_scope(), |candidate| {
            self.model_callables_named(candidate, arity)
                .iter()
                .any(|symbol| model_extension_symbol_matches(symbol, &conforming))
        });
        let Some(fqn) = resolution.resolved() else {
            return Vec::new();
        };
        self.model_callables_named(&fqn, arity)
            .into_iter()
            .filter(|symbol| model_extension_symbol_matches(symbol, &conforming))
            .collect()
    }

    fn authored_receiver_model_names(&self, receiver: &KotlinReceiver) -> Vec<String> {
        let mut names = Vec::new();
        let mut frontier = vec![receiver.owner.clone()];
        for _ in 0..MAX_MEMBER_HIERARCHY_DEPTH {
            let mut next = Vec::new();
            for unit in &frontier {
                let owner = unit.fq_name();
                if !names.contains(&owner) {
                    names.push(owner);
                }
                let Some(range) = self.ranges(unit).into_iter().min() else {
                    continue;
                };
                let scope = self.scope_in(unit.source(), range.start_byte);
                for spelled in self.raw_supertypes(unit) {
                    let Some(fqn) = self.resolve_name(&spelled, &scope).resolved() else {
                        continue;
                    };
                    if !names.contains(&fqn) {
                        names.push(fqn.clone());
                    }
                    for modeled in self.model_owner_and_ancestors(&fqn) {
                        let modeled_name = modeled.qualified_name.clone();
                        if !names.contains(&modeled_name) {
                            names.push(modeled_name);
                        }
                    }
                }
                next.extend(self.direct_ancestors(unit));
            }
            if next.is_empty() {
                break;
            }
            frontier = next;
        }
        names
    }

    fn model_members_for_conforming(
        &self,
        conforming: &[String],
        static_qualifier: bool,
        member: &str,
        arity: Option<usize>,
        site_byte: usize,
    ) -> Vec<&SemanticModelSymbol> {
        for (index, owner) in conforming.iter().enumerate() {
            let direct = self.model_members_named(&format!("{owner}.{member}"), arity);
            if !direct.is_empty() {
                return direct;
            }
            if static_qualifier && index == 0 {
                let companion =
                    self.model_members_named(&format!("{owner}.Companion.{member}"), arity);
                if !companion.is_empty() {
                    return companion;
                }
            }
        }
        self.model_extension_candidates_for_conforming(conforming, member, arity, site_byte)
    }

    fn model_members_for_receiver(
        &self,
        owner: &str,
        static_qualifier: bool,
        member: &str,
        arity: Option<usize>,
        site_byte: usize,
    ) -> Vec<&SemanticModelSymbol> {
        for modeled_owner in self.model_owner_and_ancestors(owner) {
            let inherited_owner = &modeled_owner.qualified_name;
            let direct = self.model_members_named(&format!("{inherited_owner}.{member}"), arity);
            if !direct.is_empty() {
                return direct;
            }
            if static_qualifier && inherited_owner == owner {
                let companion =
                    self.model_members_named(&format!("{owner}.Companion.{member}"), arity);
                if !companion.is_empty() {
                    return companion;
                }
            }
        }
        self.model_extension_candidates(owner, member, arity, site_byte)
    }

    fn model_outcome(
        &self,
        records: Vec<&SemanticModelSymbol>,
        subject: &str,
    ) -> DefinitionLookupOutcome {
        if records.is_empty() {
            return no_definition(
                "no_indexed_definition",
                format!("`{subject}` is not indexed as a Kotlin model definition"),
            );
        }
        if records.iter().any(|record| record.provenance.ambiguous) {
            // no candidates: the conflicting records are semantic-model symbols,
            // not indexed code units, so none can be offered as a target.
            return ambiguous_without_candidates(format!(
                "`{subject}` matches conflicting active Kotlin model declarations"
            ));
        }
        let target = if records.len() == 1 {
            records[0].id.clone()
        } else {
            records[0].qualified_name.clone()
        };
        let mut reference = self.site.clone();
        reference.text = target;
        DefinitionLookupOutcome {
            status: DefinitionLookupStatus::Resolved,
            reference: Some(reference),
            definitions: Vec::new(),
            lexical_definition: None,
            diagnostics: Vec::new(),
        }
    }

    /// Ordinary callables declared at `fqn`.
    ///
    /// Synthetic units are excluded: Kotlin's constructors are synthetic
    /// `Owner.Owner` callables, and a call spelled without a receiver reaches
    /// them through the type tier, never by looking up a function of that name.
    fn callables_named(&self, fqn: &str) -> Vec<CodeUnit> {
        self.support
            .fqn_in_any_language(fqn)
            .into_iter()
            .filter(|unit| unit.is_function() && !unit.is_synthetic())
            .collect()
    }

    fn callable_exists(&self, fqn: &str, arity: Option<usize>) -> bool {
        let authored = self.callables_named(fqn);
        if !authored.is_empty() {
            return authored
                .iter()
                .any(|unit| arity.is_none_or(|arity| self.accepts_arity(unit, arity)));
        }
        !self.model_callables_named(fqn, arity).is_empty()
    }

    /// Declarations at `fqn` that a bare name can denote as a value: a
    /// property, an enum entry, an object, or a class used as a qualifier.
    fn values_named(&self, fqn: &str) -> Vec<CodeUnit> {
        self.support
            .fqn_in_any_language(fqn)
            .into_iter()
            .filter(|unit| {
                !unit.is_synthetic() && (unit.is_field() || unit.is_class() || unit.is_function())
            })
            .collect()
    }

    /// Whether `unit`'s recorded arity admits a call passing `arity` arguments.
    ///
    /// A callable with no recorded arity is treated as accepting the call:
    /// missing metadata is an absence of evidence, and using it to reject a
    /// candidate would turn a gap in indexing into a confident wrong answer.
    fn accepts_arity(&self, unit: &CodeUnit, arity: usize) -> bool {
        let metadata = self.signature_metadata(unit);
        if metadata.is_empty() {
            return true;
        }
        metadata.iter().any(|entry| {
            entry
                .callable_arity()
                .is_none_or(|callable| callable.accepts(arity))
        })
    }

    /// Whether `unit` declares a parameter spelled `label`.
    ///
    /// The parameter's name is read from the declaring file's syntax at the byte
    /// range the indexer recorded for it, so a parameter written
    /// `vararg names: List<String> = emptyList()` yields `names` structurally
    /// rather than by picking the label apart.
    fn declares_parameter(&self, unit: &CodeUnit, label: &str) -> bool {
        let Some(syntax) = self.file_syntax(unit.source()) else {
            return false;
        };
        self.signature_metadata(unit)
            .iter()
            .flat_map(|entry| entry.parameters().to_vec())
            .any(|parameter| {
                kotlin_declaration_node(
                    syntax.tree.root_node(),
                    &Range {
                        start_byte: parameter.start_byte(),
                        end_byte: parameter.end_byte(),
                        start_line: 0,
                        end_line: 0,
                    },
                )
                .and_then(|node| first_named_child_of_kind(node, "simple_identifier"))
                .and_then(|name| name.utf8_text(syntax.source.as_bytes()).ok())
                .is_some_and(|name| name == label)
            })
    }

    /// The companion objects declared directly inside `owner_fqn`.
    ///
    /// Kotlin lets a class's own body, and its subclasses, name companion
    /// members without qualification, so a companion is a scope in its own
    /// right. Companion-ness is read from the declaration's syntax
    /// (`companion_object` versus `object_declaration`) because the two are
    /// indistinguishable in the index: both are nested classes.
    fn companion_objects(&self, owner_fqn: &str) -> Vec<CodeUnit> {
        self.support
            .fqn_direct_children(owner_fqn)
            .into_iter()
            .filter(|unit| unit.is_class() && self.is_companion_object(unit))
            .collect()
    }

    /// Declarations at `fqn` that can answer a member reference, before the call
    /// shape is considered.
    fn member_declarations(&self, fqn: &str) -> Vec<CodeUnit> {
        self.support
            .fqn_in_any_language(fqn)
            .into_iter()
            .filter(|unit| !unit.is_synthetic() && (unit.is_function() || unit.is_field()))
            .collect()
    }

    /// Whether a member declaration can answer a call of `arity`. A property is
    /// never rejected on a call shape: what it holds decides that, not the
    /// property's own declaration.
    fn member_accepts_arity(&self, unit: &CodeUnit, arity: Option<usize>) -> bool {
        arity.is_none_or(|arity| !unit.is_function() || self.accepts_arity(unit, arity))
    }

    /// The innermost class-like declaration enclosing `byte` in the requesting
    /// file.
    fn enclosing_class_at(&self, byte: usize) -> Option<CodeUnit> {
        let start = self.enclosing_code_unit(
            self.file,
            &Range {
                start_byte: byte,
                end_byte: byte.saturating_add(1),
                start_line: 0,
                end_line: 0,
            },
        )?;
        let mut current = Some(start);
        while let Some(unit) = current {
            if unit.is_class() {
                return Some(unit);
            }
            current = self.parent_of(&unit);
        }
        None
    }

    /// The type a declaration carries: a property's or parameter's written
    /// type, an enum entry's own enum, or a function's declared return type.
    ///
    /// Read from the declaring file's syntax and resolved in *that* file's
    /// scope, because a spelled type means whatever the file that wrote it says
    /// it means.
    fn declared_type_of(&self, unit: &CodeUnit, depth: usize) -> Option<CodeUnit> {
        // The index publishes what a Kotlin declaration wrote (issue #1345), so
        // the case that matters — a written type, which is what a receiver chain
        // needs at every link — costs a lookup rather than a parse of the
        // declaring file. The syntax path below stays for what the index cannot
        // publish: an unwritten type inferred from an initializer, an enum
        // entry's own enum, and a declaration parse recovery dropped entirely.
        if let Some(resolved) = self.published_declared_type_of(unit) {
            return Some(resolved);
        }

        let (syntax, range) = self.declaration_syntax(unit)?;
        let node = kotlin_declaration_node(syntax.tree.root_node(), &range)?;
        // An enum entry has no written type: it is an instance of its own enum.
        if node.kind() == "enum_entry" {
            return self.parent_of(unit).filter(CodeUnit::is_class);
        }

        let declaring = self.declaring_ctx(unit.source(), &syntax.source);
        let type_node = match node.kind() {
            "property_declaration" => named_children(node)
                .into_iter()
                .find(|child| child.kind() == "variable_declaration")
                .and_then(|variable| {
                    named_children(variable)
                        .into_iter()
                        .find_map(|child| kotlin_type_node_spelling(&declaring, child))
                }),
            "function_declaration" => kotlin_declared_return_type_spelling(&declaring, node),
            _ => named_children(node)
                .into_iter()
                .find_map(|child| kotlin_type_node_spelling(&declaring, child)),
        };
        if let Some(spelled) = type_node {
            let scope = declaring.scope_in(unit.source(), range.start_byte);
            if let Some(resolved) = declaring.resolve_type_unit(&spelled, &scope) {
                return Some(resolved);
            }
        }
        if node.kind() != "property_declaration" {
            return None;
        }
        // A property with no written type is only typed when its initializer
        // proves one.
        let initializer = named_children(node)
            .into_iter()
            .rev()
            .find(|child| kotlin_is_expression_kind(child.kind()))?;
        kotlin_expression_type(&declaring, initializer, depth + 1)
    }

    /// The type `unit` declares, read from the published index rather than from
    /// the declaring file's syntax.
    ///
    /// Restricted to Kotlin declarations. In a JVM realm a member lookup can
    /// return a Java or Scala unit, and several of those languages publish a
    /// return type of their own — resolving one of *those* spellings through
    /// Kotlin's name ladder would answer a Kotlin question with another
    /// language's syntax.
    fn published_declared_type_of(&self, unit: &CodeUnit) -> Option<CodeUnit> {
        if language_for_target(unit) != Language::Kotlin {
            return None;
        }
        let spelled = self
            .signature_metadata(unit)
            .into_iter()
            .find_map(|entry| entry.return_type_text().map(str::to_string))?;
        let scope = self.declaration_scope(unit)?;
        self.resolve_type_unit(&spelled, &scope)
    }

    /// The type an extension function extends, or `None` when the callable is
    /// not an extension.
    fn extension_receiver_unit(&self, unit: &CodeUnit) -> Option<CodeUnit> {
        // Extension conformance is checked once per candidate, so a member
        // lookup considering several same-named extensions used to re-parse
        // several declaring files to decide which applied. The published
        // receiver (issue #1345) answers both halves of that question from the
        // index: which candidates are extensions at all, and what each extends.
        if language_for_target(unit) == Language::Kotlin {
            let metadata = self.signature_metadata(unit);
            if let Some(spelled) = metadata
                .iter()
                .find_map(|entry| entry.extension_receiver_type())
            {
                let spelled = spelled.to_string();
                let scope = self.declaration_scope(unit)?;
                return self.resolve_type_unit(&spelled, &scope);
            }
            if !metadata.is_empty() {
                // Every indexed Kotlin callable and property carries metadata,
                // so metadata that records no receiver is positive evidence that
                // the declaration is not an extension — not a gap to go and
                // re-read the file about.
                return None;
            }
        }

        let (syntax, range) = self.declaration_syntax(unit)?;
        let node = kotlin_declaration_node(syntax.tree.root_node(), &range)?;
        let receiver = node.child_by_field_name("receiver")?;
        let declaring = self.declaring_ctx(unit.source(), &syntax.source);
        let spelled = kotlin_type_node_spelling(&declaring, receiver)?;
        let scope = declaring.scope_in(unit.source(), range.start_byte);
        declaring.resolve_type_unit(&spelled, &scope)
    }

    /// Whether `subtype` is `supertype` or inherits from it.
    fn type_conforms_to(&self, subtype: &CodeUnit, supertype: &CodeUnit) -> bool {
        if subtype.fq_name() == supertype.fq_name() {
            return true;
        }
        let target = supertype.fq_name();
        let mut seen = Vec::new();
        let mut frontier = vec![subtype.clone()];
        for _ in 0..MAX_MEMBER_HIERARCHY_DEPTH {
            let mut next = Vec::new();
            for unit in &frontier {
                for ancestor in self.direct_ancestors(unit) {
                    let fqn = ancestor.fq_name();
                    if fqn == target {
                        return true;
                    }
                    if seen.contains(&fqn) {
                        continue;
                    }
                    seen.push(fqn);
                    next.push(ancestor);
                }
            }
            if next.is_empty() {
                return false;
            }
            frontier = next;
        }
        false
    }

    /// Whether `unit` is a `companion object`.
    ///
    /// Read from the published `SignatureMetadata` marker (issue #1239,
    /// milestone 3), which the Kotlin declaration walk sets from the very
    /// `companion_object` node kind this used to re-read. Navigation and the
    /// usage graphs consult the same published fact, so they cannot disagree
    /// about which objects are companions.
    fn is_companion_object(&self, unit: &CodeUnit) -> bool {
        crate::analyzer::usages::kotlin_graph::is_companion_object(self.analyzer, unit)
    }

    /// The declarations enclosing `byte`, innermost first, followed by the
    /// scopes they inherit.
    ///
    /// A Kotlin class can name its own nested types unqualified, and the nested
    /// types its supertypes declare, so both belong in the scope tier of the
    /// ladder. Ancestors are expanded through the analyzer's hierarchy
    /// provider, which is realm-aware: a Kotlin class extending a Java class in
    /// the same workspace inherits that class's scope too.
    fn scope_owners_at(&self, file: &ProjectFile, byte: usize) -> Vec<String> {
        let Some(start) = self.enclosing_code_unit(
            file,
            &Range {
                start_byte: byte,
                end_byte: byte.saturating_add(1),
                start_line: 0,
                end_line: 0,
            },
        ) else {
            return Vec::new();
        };

        let mut lexical = Vec::new();
        let mut current = Some(start);
        while let Some(unit) = current {
            current = self.parent_of(&unit);
            lexical.push(unit);
        }

        let mut owners: Vec<String> = Vec::new();
        for unit in &lexical {
            let fqn = unit.fq_name();
            if owners.contains(&fqn) {
                continue;
            }
            owners.extend(
                self.companion_objects(&fqn)
                    .into_iter()
                    .map(|unit| unit.fq_name()),
            );
            owners.push(fqn);
        }

        let mut frontier = lexical;
        for _ in 0..MAX_INHERITED_SCOPE_DEPTH {
            let mut next = Vec::new();
            for unit in &frontier {
                for ancestor in self.direct_ancestors(unit) {
                    let fqn = ancestor.fq_name();
                    if owners.contains(&fqn) {
                        continue;
                    }
                    owners.extend(
                        self.companion_objects(&fqn)
                            .into_iter()
                            .map(|unit| unit.fq_name()),
                    );
                    owners.push(fqn);
                    next.push(ancestor);
                }
            }
            if next.is_empty() {
                break;
            }
            frontier = next;
        }
        owners
    }
}

/// Resolve a focus inside `import a.b.C`, `import a.b.C as D`, or `import a.b.*`.
///
/// Focusing segment *k* of the dotted path means the prefix `0..=k`: putting
/// the cursor on `b` in `import a.b.C` asks about `a.b`, not about `a.b.C`.
/// Focusing the alias asks about the whole path, which is what makes an aliased
/// import navigable from its local name.
fn kotlin_import_reference_outcome(
    ctx: &KotlinCtx<'_>,
    header: Node<'_>,
    focus: Node<'_>,
) -> DefinitionLookupOutcome {
    let Some(path) = first_named_child_of_kind(header, "identifier") else {
        return no_definition(
            "no_reference_text",
            "Kotlin import has no qualified path to resolve",
        );
    };
    let segments = named_children(path)
        .into_iter()
        .filter(|child| child.kind() == "simple_identifier")
        .collect::<Vec<_>>();
    if segments.is_empty() {
        return no_definition(
            "no_reference_text",
            "Kotlin import has no qualified path to resolve",
        );
    }

    // A focus on a path segment asks about the prefix ending there; anything
    // else in the header (the alias, the star, the header itself) asks about
    // the whole path.
    let last = segments
        .iter()
        .position(|segment| segment.id() == focus.id())
        .unwrap_or(segments.len() - 1);
    let candidate = segments[..=last]
        .iter()
        .map(|segment| ctx.text(*segment))
        .collect::<Vec<_>>()
        .join(".");

    let mut units = ctx
        .support
        .fqn_in_any_language(&candidate)
        .into_iter()
        .filter(|unit| !unit.is_synthetic())
        .collect::<Vec<_>>();
    if !units.is_empty() {
        sort_units(&mut units);
        units.dedup();
        return candidates_outcome(units);
    }
    if ctx.model_package_exists(&candidate) {
        return no_definition(
            "package_reference",
            format!("`{candidate}` names a package, which has no declaration to navigate to"),
        );
    }
    let modeled = ctx.model_symbols_named(&candidate, |kind| {
        matches!(
            kind,
            SemanticModelSymbolKind::Class
                | SemanticModelSymbolKind::Annotation
                | SemanticModelSymbolKind::Interface
                | SemanticModelSymbolKind::Enum
                | SemanticModelSymbolKind::Module
                | SemanticModelSymbolKind::TypeAlias
                | SemanticModelSymbolKind::Constructor
                | SemanticModelSymbolKind::Method
                | SemanticModelSymbolKind::Function
                | SemanticModelSymbolKind::Field
                | SemanticModelSymbolKind::Property
                | SemanticModelSymbolKind::Constant
        )
    });
    if !modeled.is_empty() {
        return ctx.model_outcome(modeled, &candidate);
    }
    if ctx.support.package_exists_in_any_language(&candidate) {
        return no_definition(
            "package_reference",
            format!("`{candidate}` names a package, which has no declaration to navigate to"),
        );
    }
    no_definition(
        "no_indexed_definition",
        format!("`{candidate}` is not indexed as a Kotlin definition"),
    )
}

/// Resolve a focus on a `type_identifier`: a type annotation, a supertype, an
/// annotation name, a receiver type, or a type argument.
fn kotlin_type_reference_outcome(ctx: &KotlinCtx<'_>, node: Node<'_>) -> DefinitionLookupOutcome {
    let spelled = kotlin_type_spelling_through(ctx, node);
    if spelled.is_empty() {
        return no_definition("no_reference_text", "Kotlin type reference is blank");
    }
    let scope = ctx.scope_at(node.start_byte());
    match ctx.resolve_name(&spelled, &scope) {
        KotlinTypeName::Resolved(fqn) => {
            let units = ctx.types_named(&fqn);
            if !units.is_empty() {
                return candidates_outcome(units);
            }
            ctx.model_outcome(ctx.model_types_named(&fqn), &fqn)
        }
        KotlinTypeName::Ambiguous => no_definition(
            "ambiguous_kotlin_type",
            format!("`{spelled}` is bound to different owners by more than one Kotlin star import"),
        ),
        KotlinTypeName::Unresolved => {
            if ctx.support.package_exists_in_any_language(&spelled) {
                return no_definition(
                    "package_reference",
                    format!("`{spelled}` names a package, which has no declaration to navigate to"),
                );
            }
            no_definition(
                "no_indexed_definition",
                format!("`{spelled}` is not indexed as a Kotlin type"),
            )
        }
    }
}

/// The dotted name a focused `type_identifier` spells, up to and including
/// itself.
///
/// A dotted type is one `user_type` node with one `type_identifier` child per
/// segment, so focusing `Outer` in `Outer.Inner` asks about `Outer` while
/// focusing `Inner` asks about `Outer.Inner`. Joining the children's own text
/// is a structural read of the tree, not a re-parse of the source.
fn kotlin_type_spelling_through(ctx: &KotlinCtx<'_>, node: Node<'_>) -> String {
    let Some(parent) = node.parent().filter(|parent| parent.kind() == "user_type") else {
        return ctx.text(node).to_string();
    };
    let segments = named_children(parent)
        .into_iter()
        .filter(|child| child.kind() == "type_identifier")
        .collect::<Vec<_>>();
    let last = segments
        .iter()
        .position(|segment| segment.id() == node.id())
        .unwrap_or(segments.len().saturating_sub(1));
    segments[..=last]
        .iter()
        .map(|segment| ctx.text(*segment))
        .collect::<Vec<_>>()
        .join(".")
}

// ---------------------------------------------------------------------------
// Calls, constructors, and named arguments.
// ---------------------------------------------------------------------------

/// Resolve `name(...)` where `name` is spelled without a receiver.
///
/// Functions are tried before constructors because a Kotlin function may share
/// a class's spelling, and a call that matches a function is a call of that
/// function. Both tiers run through the same precedence ladder, so an import
/// shadows a same-package declaration for callables exactly as it does for
/// types.
///
/// Arity participates in the ladder rather than filtering its result. Kotlin
/// picks the overload that can accept the call even when a nearer scope
/// declares the same name with a different shape: inside a subclass that
/// declares `run(Int)`, the call `run(1) { … }` means the inherited
/// `run(Int, () -> Unit)`. Filtering afterwards could not express that, because
/// the ladder would already have stopped at the nearer scope. When no scope has
/// a callable that accepts the call, the ladder runs again ignoring arity: an
/// arity mismatch means the recorded metadata is incomplete, not that the
/// declaration does not exist.
fn kotlin_bare_call_outcome(
    ctx: &KotlinCtx<'_>,
    node: Node<'_>,
    name: &str,
    arity: Option<usize>,
) -> DefinitionLookupOutcome {
    let scope = ctx.scope_at(node.start_byte());
    for required_arity in [arity, None] {
        match resolve_kotlin_type_name(name, &scope.as_name_scope(), |candidate| {
            ctx.callable_exists(candidate, required_arity)
        }) {
            KotlinTypeName::Resolved(fqn) => {
                let authored = ctx.callables_named(&fqn);
                if !authored.is_empty() {
                    return kotlin_callable_outcome(authored, &fqn);
                }
                return ctx.model_outcome(ctx.model_callables_named(&fqn, required_arity), &fqn);
            }
            KotlinTypeName::Ambiguous => {
                return no_definition(
                    "ambiguous_kotlin_type",
                    format!(
                        "`{name}` is bound to different owners by more than one Kotlin star import"
                    ),
                );
            }
            KotlinTypeName::Unresolved => {}
        }
        if required_arity.is_none() {
            break;
        }
    }

    match ctx.resolve_name(name, &scope) {
        KotlinTypeName::Resolved(type_fqn) => kotlin_constructor_outcome(ctx, &type_fqn),
        KotlinTypeName::Ambiguous => no_definition(
            "ambiguous_kotlin_type",
            format!("`{name}` is bound to different owners by more than one Kotlin star import"),
        ),
        KotlinTypeName::Unresolved => no_definition(
            "no_indexed_definition",
            format!("`{name}` is not indexed as a Kotlin callable or type"),
        ),
    }
}

/// The declarations a constructor call `Type(...)` names.
///
/// Kotlin indexes a primary constructor as a synthetic `Owner.Owner` callable,
/// but only when it declares parameters: `class Base` has no constructor
/// declaration at all, and the class itself is then the only physical thing the
/// call can point at.
fn kotlin_constructor_outcome(ctx: &KotlinCtx<'_>, type_fqn: &str) -> DefinitionLookupOutcome {
    let simple = type_fqn.rsplit('.').next().unwrap_or(type_fqn);
    let constructors = ctx
        .support
        .fqn_in_any_language(&format!("{type_fqn}.{simple}"))
        .into_iter()
        .filter(CodeUnit::is_function)
        .collect::<Vec<_>>();
    if !constructors.is_empty() {
        return candidates_outcome(constructors);
    }
    let types = ctx.types_named(type_fqn);
    if !types.is_empty() {
        return candidates_outcome(types);
    }
    let modeled_constructors = ctx.model_callables_named(&format!("{type_fqn}.{simple}"), None);
    if !modeled_constructors.is_empty() {
        return ctx.model_outcome(modeled_constructors, type_fqn);
    }
    ctx.model_outcome(ctx.model_types_named(type_fqn), type_fqn)
}

fn kotlin_callable_outcome(candidates: Vec<CodeUnit>, subject: &str) -> DefinitionLookupOutcome {
    if candidates.is_empty() {
        return no_definition(
            "no_indexed_definition",
            format!("`{subject}` is not indexed as a Kotlin callable"),
        );
    }
    candidates_outcome(candidates)
}

/// Resolve a bare name used as a value: a property, an object, an enum entry,
/// or a class named as a qualifier.
fn kotlin_bare_value_outcome(
    ctx: &KotlinCtx<'_>,
    node: Node<'_>,
    name: &str,
) -> DefinitionLookupOutcome {
    let scope = ctx.scope_at(node.start_byte());
    match resolve_kotlin_type_name(name, &scope.as_name_scope(), |candidate| {
        !ctx.values_named(candidate).is_empty() || !ctx.model_values_named(candidate).is_empty()
    }) {
        KotlinTypeName::Resolved(fqn) => {
            let authored = ctx.values_named(&fqn);
            if !authored.is_empty() {
                candidates_outcome(authored)
            } else {
                ctx.model_outcome(ctx.model_values_named(&fqn), &fqn)
            }
        }
        KotlinTypeName::Ambiguous => no_definition(
            "ambiguous_kotlin_type",
            format!("`{name}` is bound to different owners by more than one Kotlin star import"),
        ),
        KotlinTypeName::Unresolved => no_definition(
            "no_indexed_definition",
            format!("`{name}` is not indexed as a Kotlin definition"),
        ),
    }
}

/// Resolve the label of a named argument to the callable that declares a
/// parameter of that name.
///
/// Kotlin parameters are not indexed as declarations, and the lexical-definition
/// channel can only address the file the request was made in, so the callable is
/// the finest identity that is correct across files. Proving the parameter
/// exists is what keeps this honest: a label that no candidate declares abstains
/// rather than pointing at a callable it does not belong to.
fn kotlin_named_argument_outcome(
    ctx: &KotlinCtx<'_>,
    argument: Node<'_>,
    label: &str,
) -> DefinitionLookupOutcome {
    let Some(call) = kotlin_enclosing_call(argument) else {
        return no_definition(
            "no_named_argument_owner",
            format!("named argument `{label}` has no enclosing Kotlin call"),
        );
    };
    let Some(callee) = kotlin_callee(call) else {
        return no_definition(
            "no_named_argument_owner",
            format!("named argument `{label}` has no resolvable callee"),
        );
    };
    if callee.kind() != "simple_identifier" {
        return no_definition(
            "no_named_argument_owner",
            format!(
                "named argument `{label}` has a Kotlin `{}` callee that get_definition does not resolve yet",
                callee.kind()
            ),
        );
    }
    let owner =
        kotlin_bare_call_outcome(ctx, callee, ctx.text(callee), Some(kotlin_call_arity(call)));
    if owner.definitions.is_empty() {
        return no_definition(
            "no_named_argument_owner",
            format!("named argument `{label}` has an unresolved Kotlin callee"),
        );
    }
    let declaring = owner
        .definitions
        .into_iter()
        .filter(|unit| ctx.declares_parameter(unit, label))
        .collect::<Vec<_>>();
    if declaring.is_empty() {
        return no_definition(
            "unknown_named_argument",
            format!("no resolved Kotlin callable declares a parameter named `{label}`"),
        );
    }
    candidates_outcome(declaring)
}

/// The `call_expression` or `constructor_invocation` an argument belongs to.
fn kotlin_enclosing_call(argument: Node<'_>) -> Option<Node<'_>> {
    let mut current = argument.parent();
    while let Some(node) = current {
        match node.kind() {
            "call_expression" | "constructor_invocation" => return Some(node),
            "value_arguments" | "call_suffix" | "value_argument" => current = node.parent(),
            _ => return None,
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Member access: typing a receiver, then finding the member on that type.
// ---------------------------------------------------------------------------

/// How many receiver hops a chained expression is followed for.
///
/// `a.b().c().d` needs three; a cap keeps a pathological or cyclic chain from
/// turning one request into an unbounded walk, and an exceeded cap abstains
/// rather than guessing.
const MAX_RECEIVER_DEPTH: usize = 8;

/// How many levels of supertype a member lookup walks.
const MAX_MEMBER_HIERARCHY_DEPTH: usize = 8;

/// A typed receiver: the declaration the member must be looked up on, and
/// whether it was named as a type rather than produced as a value.
///
/// The distinction matters because Kotlin exposes a class's companion members
/// through the class name (`Factory.create()`) but not through an instance of
/// it, so only a static qualifier may search the companion.
struct KotlinReceiver {
    owner: CodeUnit,
    static_qualifier: bool,
}

/// Resolve the member of `a.member` / `a?.member` / `a!!.member`.
fn kotlin_member_outcome(
    ctx: &KotlinCtx<'_>,
    suffix: Node<'_>,
    member: &str,
) -> DefinitionLookupOutcome {
    let Some(navigation) = suffix
        .parent()
        .filter(|parent| parent.kind() == "navigation_expression")
    else {
        return no_definition(
            "unsupported_kotlin_reference_shape",
            format!("`{member}` is a Kotlin member access with no receiver expression"),
        );
    };
    let Some(receiver_node) = named_children(navigation).into_iter().next() else {
        return no_definition(
            "unsupported_kotlin_reference_shape",
            format!("`{member}` is a Kotlin member access with no receiver expression"),
        );
    };
    // A member access is a call only when the navigation is itself the callee
    // of a call; `a.b` as a value proves no arity.
    let arity = navigation
        .parent()
        .filter(|parent| parent.kind() == "call_expression")
        .filter(|call| kotlin_callee(*call).is_some_and(|callee| callee.id() == navigation.id()))
        .map(kotlin_call_arity);

    let authored_receiver = kotlin_receiver(ctx, receiver_node, 0);
    if let Some(receiver) = authored_receiver.as_ref() {
        let candidates =
            kotlin_member_candidates(ctx, receiver, member, arity, suffix.start_byte());
        if !candidates.is_empty() {
            return candidates_outcome(candidates);
        }
        let conforming = ctx.authored_receiver_model_names(receiver);
        for required_arity in [arity, None] {
            let modeled = ctx.model_members_for_conforming(
                &conforming,
                receiver.static_qualifier,
                member,
                required_arity,
                suffix.start_byte(),
            );
            if !modeled.is_empty() {
                return ctx.model_outcome(modeled, member);
            }
            if required_arity.is_none() {
                break;
            }
        }
    }
    if let Some((owner, static_qualifier)) = kotlin_model_receiver(ctx, receiver_node, 0) {
        for required_arity in [arity, None] {
            let modeled = ctx.model_members_for_receiver(
                &owner,
                static_qualifier,
                member,
                required_arity,
                suffix.start_byte(),
            );
            if !modeled.is_empty() {
                return ctx.model_outcome(modeled, member);
            }
            if required_arity.is_none() {
                break;
            }
        }
        return no_definition(
            "no_indexed_definition",
            format!("`{member}` is not a member of `{owner}` or anything it inherits"),
        );
    }
    if let Some(receiver) = authored_receiver {
        return no_definition(
            "no_indexed_definition",
            format!(
                "`{member}` is not a member of `{}` or anything it inherits",
                receiver.owner.fq_name()
            ),
        );
    }
    no_definition(
        "receiver_type_unknown",
        format!(
            "the receiver of `{member}` is a Kotlin `{}` expression whose type is not proven",
            receiver_node.kind()
        ),
    )
}

fn nominal_type_name(reference: &TypeRef) -> Option<&str> {
    match reference {
        TypeRef::Named { name, .. } => Some(name),
        _ => None,
    }
}

fn model_extension_receiver_matches(reference: &TypeRef, conforming: &[&str]) -> bool {
    match reference {
        TypeRef::Named { name, .. } => name == "kotlin.Any" || conforming.contains(&name.as_str()),
        TypeRef::TypeParameter { .. } => true,
        _ => false,
    }
}

fn model_extension_symbol_matches(symbol: &SemanticModelSymbol, conforming: &[&str]) -> bool {
    symbol
        .extension_receiver
        .as_ref()
        .is_some_and(|receiver| model_extension_receiver_matches(receiver, conforming))
        && symbol
            .extension_receiver_constraints
            .iter()
            .all(|constraint| model_extension_receiver_matches(constraint, conforming))
}

fn kotlin_model_receiver(
    ctx: &KotlinCtx<'_>,
    node: Node<'_>,
    depth: usize,
) -> Option<(String, bool)> {
    if depth > MAX_RECEIVER_DEPTH {
        return None;
    }
    match node.kind() {
        "postfix_expression" | "parenthesized_expression" => {
            kotlin_model_receiver(ctx, named_children(node).into_iter().next()?, depth + 1)
        }
        "as_expression" => {
            let asserted = named_children(node).into_iter().next_back()?;
            let spelled = kotlin_type_node_spelling(ctx, asserted)?;
            let fqn = ctx
                .resolve_name(&spelled, &ctx.scope_at(node.start_byte()))
                .resolved()?;
            ctx.model_type_available(&fqn).then_some((fqn, false))
        }
        "simple_identifier" => {
            let name = ctx.text(node);
            if let Some(binding) = kotlin_local_binding(node, ctx.source, name)
                && let Some(spelled) = kotlin_declared_type_spelling(ctx, binding)
            {
                let fqn = ctx
                    .resolve_name(&spelled, &ctx.scope_at(binding.start_byte()))
                    .resolved()?;
                if ctx.model_type_available(&fqn) {
                    return Some((fqn, false));
                }
            }
            let fqn = ctx
                .resolve_name(name, &ctx.scope_at(node.start_byte()))
                .resolved()?;
            ctx.model_type_available(&fqn).then_some((fqn, true))
        }
        "call_expression" => {
            let callee = kotlin_callee(node)?;
            let scope = ctx.scope_at(callee.start_byte());
            let arity = Some(kotlin_call_arity(node));
            if callee.kind() == "navigation_expression" {
                let children = named_children(callee);
                let receiver = children.first().copied()?;
                let suffix = children.last().copied()?;
                let member_node = named_children(suffix).into_iter().last()?;
                let records = if let Some((owner, static_qualifier)) =
                    kotlin_model_receiver(ctx, receiver, depth + 1)
                {
                    ctx.model_members_for_receiver(
                        &owner,
                        static_qualifier,
                        ctx.text(member_node),
                        arity,
                        callee.start_byte(),
                    )
                } else {
                    let authored = kotlin_receiver(ctx, receiver, depth + 1)?;
                    let conforming = ctx.authored_receiver_model_names(&authored);
                    ctx.model_members_for_conforming(
                        &conforming,
                        authored.static_qualifier,
                        ctx.text(member_node),
                        arity,
                        callee.start_byte(),
                    )
                };
                return model_return_receiver(ctx, &scope, records);
            }
            if callee.kind() != "simple_identifier" {
                return None;
            }
            let callable =
                resolve_kotlin_type_name(ctx.text(callee), &scope.as_name_scope(), |candidate| {
                    !ctx.model_callables_named(candidate, arity).is_empty()
                })
                .resolved();
            if let Some(callable) = callable {
                let records = ctx.model_callables_named(&callable, arity);
                if let Some(receiver) = model_return_receiver(ctx, &scope, records) {
                    return Some(receiver);
                }
            }
            let fqn = ctx.resolve_name(ctx.text(callee), &scope).resolved()?;
            ctx.model_type_available(&fqn).then_some((fqn, false))
        }
        _ => None,
    }
}

fn model_return_receiver(
    ctx: &KotlinCtx<'_>,
    scope: &KotlinScope,
    records: Vec<&SemanticModelSymbol>,
) -> Option<(String, bool)> {
    if records.len() != 1 || records[0].provenance.ambiguous {
        return None;
    }
    let returned = records[0]
        .structured_signature
        .as_ref()?
        .returns
        .as_ref()
        .and_then(nominal_type_name)?;
    let fqn = ctx.resolve_name(returned, scope).resolved()?;
    ctx.model_type_available(&fqn).then_some((fqn, false))
}

/// Members named `member` reachable through `receiver`.
///
/// The search order is Kotlin's: the receiver's own members, the companion when
/// the receiver was named as a type, then supertypes breadth-first, then
/// extension functions visible at the reference site. Arity steers the search
/// the same way it steers a bare call, with an arity-blind second pass so a
/// missing arity record cannot turn a present declaration into "not found".
fn kotlin_member_candidates(
    ctx: &KotlinCtx<'_>,
    receiver: &KotlinReceiver,
    member: &str,
    arity: Option<usize>,
    site_byte: usize,
) -> Vec<CodeUnit> {
    use brokk_bifrost_core::analyzer::structural::callable::ApplicabilityVerdict;

    let mut member_trace = trace::recording().then(KotlinMemberTrace::default);
    for required_arity in [arity, None] {
        let mut seen = Vec::new();
        let mut frontier = vec![receiver.owner.clone()];
        for level in 0..MAX_MEMBER_HIERARCHY_DEPTH {
            let mut next = Vec::new();
            for owner in &frontier {
                let owner_fqn = owner.fq_name();
                if seen.contains(&owner_fqn) {
                    continue;
                }
                seen.push(owner_fqn.clone());

                let mut owners = vec![owner.clone()];
                if receiver.static_qualifier {
                    let companions = ctx.companion_objects(&owner_fqn);
                    if let Some(state) = member_trace.as_mut() {
                        state.record_companions(owner, &companions);
                    }
                    owners.extend(companions);
                }
                for scope in owners {
                    let mut found = Vec::new();
                    let mut inapplicable = Vec::new();
                    for unit in ctx.member_declarations(&format!("{}.{member}", scope.fq_name())) {
                        if ctx.member_accepts_arity(&unit, required_arity) {
                            found.push(unit);
                        } else if member_trace.is_some() {
                            // Computed by the walk and discarded on the call
                            // shape alone: a row, not a silence (#1477 rule 5).
                            inapplicable.push(unit);
                        }
                    }
                    if let Some(state) = member_trace.as_mut() {
                        state.record_found(&found, &scope, level);
                        state.record_found(&inapplicable, &scope, level);
                        state.record_inapplicable(&receiver.owner, &inapplicable);
                    }
                    if !found.is_empty() {
                        if let Some(state) = member_trace.as_ref() {
                            state.stage_selection(
                                &receiver.owner,
                                &found,
                                if required_arity.is_some() {
                                    ApplicabilityVerdict::Applicable
                                } else {
                                    ApplicabilityVerdict::Unknown
                                },
                            );
                        }
                        return found;
                    }
                }

                let expanded = ctx.direct_ancestors(owner);
                if let Some(state) = member_trace.as_mut() {
                    state.record_supertypes(owner, &expanded);
                }
                next.extend(expanded);
            }
            if next.is_empty() {
                break;
            }
            frontier = next;
        }

        let extensions =
            kotlin_extension_candidates(ctx, receiver, member, required_arity, site_byte);
        if !extensions.is_empty() {
            return extensions;
        }
        if required_arity.is_none() {
            break;
        }
    }
    Vec::new()
}

/// Where the Kotlin member walk found each candidate, recorded as the walk ran.
///
/// `depth` is the length of the route back to the receiver's own type, so a
/// companion find counts the promotion edge that reached it; `level` is the
/// breadth-first hierarchy level of the class the walk was inspecting, which is
/// what Kotlin's own precedence ladder orders by. The two differ only for a
/// companion, and keeping both is what lets the row state an exact route
/// without claiming a companion member is inherited.
struct KotlinMemberFind {
    owner: CodeUnit,
    depth: usize,
    level: usize,
    dispatch_tier: MemberDispatchTier,
}

/// The per-candidate attribution the Kotlin member walk records while it runs
/// (#1477), built only when a trace is being recorded.
///
/// The walk decides nothing from it. Every entry is a fact the walk already
/// held: which scope each candidate was found in, at which breadth-first level,
/// and through which first-discovery edges that scope was reached.
///
/// Two honest limits are stated here rather than guessed around. The walk
/// expands ancestors through `get_direct_ancestors`, which reports
/// undifferentiated supertypes, so a Kotlin superclass hop and an interface hop
/// are the same edge to this walk and both are recorded as
/// [`HierarchyRelation::Supertype`] with the `inherited_or_promoted` bucket --
/// a `trait_or_interface` claim would be a distinction the provider never made.
/// And a companion is reached by promotion out of the class that declares it,
/// which is the edge [`HierarchyRelation::Embedded`] names: the nested
/// declaration's members answer references qualified by the enclosing type.
#[derive(Default)]
struct KotlinMemberTrace {
    /// First-discovery supertype parent of each ancestor the walk expanded.
    parents: HashMap<CodeUnit, CodeUnit>,
    /// Companion object -> the class whose companions the walk expanded.
    companion_of: HashMap<CodeUnit, CodeUnit>,
    found: HashMap<CodeUnit, KotlinMemberFind>,
}

impl KotlinMemberTrace {
    fn record_supertypes(&mut self, owner: &CodeUnit, ancestors: &[CodeUnit]) {
        for ancestor in ancestors {
            self.parents
                .entry(ancestor.clone())
                .or_insert_with(|| owner.clone());
        }
    }

    fn record_companions(&mut self, owner: &CodeUnit, companions: &[CodeUnit]) {
        for companion in companions {
            self.companion_of
                .entry(companion.clone())
                .or_insert_with(|| owner.clone());
        }
    }

    /// Attribute every candidate the walk just read out of `scope`, which sits
    /// at breadth-first hierarchy `level`.
    fn record_found(&mut self, candidates: &[CodeUnit], scope: &CodeUnit, level: usize) {
        let companion = self.companion_of.contains_key(scope);
        let dispatch_tier = if companion {
            MemberDispatchTier::StaticOrCompanion
        } else if level == 0 {
            MemberDispatchTier::InherentOrDirect
        } else {
            MemberDispatchTier::InheritedOrPromoted
        };
        let depth = level + usize::from(companion);
        for candidate in candidates {
            self.found
                .entry(candidate.clone())
                .or_insert_with(|| KotlinMemberFind {
                    owner: scope.clone(),
                    depth,
                    level,
                    dispatch_tier,
                });
        }
    }

    /// The exact route from `base` to the scope `candidate` was found in, as the
    /// first-discovery edges the walk actually took.
    fn route(&self, base: &CodeUnit, candidate: &CodeUnit) -> Vec<trace::HierarchyHopRecord> {
        let Some(find) = self.found.get(candidate) else {
            return Vec::new();
        };
        let mut reversed: Vec<(CodeUnit, CodeUnit, HierarchyRelation)> = Vec::new();
        let mut current = find.owner.clone();
        while &current != base {
            let step = if let Some(class) = self.companion_of.get(&current) {
                (class.clone(), HierarchyRelation::Embedded)
            } else if let Some(parent) = self.parents.get(&current) {
                (parent.clone(), HierarchyRelation::Supertype)
            } else {
                break;
            };
            reversed.push((step.0.clone(), current, step.1));
            current = step.0;
        }
        debug_assert_eq!(
            reversed.len(),
            find.depth,
            "the first-discovery route must be exactly the recorded depth"
        );
        reversed.reverse();
        reversed
            .into_iter()
            .enumerate()
            .map(|(hop, (from, to, relation))| trace::HierarchyHopRecord {
                hop,
                from,
                to,
                relation,
            })
            .collect()
    }

    fn enrichment(
        &self,
        base: &CodeUnit,
        candidate: &CodeUnit,
        applicability: brokk_bifrost_core::analyzer::structural::callable::ApplicabilityVerdict,
    ) -> Option<trace::MemberEnrichment> {
        let find = self.found.get(candidate)?;
        Some(trace::MemberEnrichment {
            owner: find.owner.clone(),
            hierarchy_depth: find.depth,
            dispatch_tier: find.dispatch_tier,
            applicability,
            route: self.route(base, candidate),
        })
    }

    /// Kotlin's precedence ladder for a member find, which follows the
    /// hierarchy level: a companion of the receiver's own type is that type's
    /// own member, not an inherited one.
    fn precedence_tier(&self, candidate: &CodeUnit) -> Option<PrecedenceTier> {
        self.found.get(candidate).map(|find| {
            if find.level == 0 {
                PrecedenceTier::OwnMember
            } else {
                PrecedenceTier::InheritedMember
            }
        })
    }

    /// Record the candidates this scope computed and then discarded because
    /// they cannot accept the call's argument list. The structured story of an
    /// argument-list mismatch belongs to the callable axis (#1478), so the
    /// rejection reason defers to it.
    fn record_inapplicable(&self, base: &CodeUnit, losers: &[CodeUnit]) {
        use brokk_bifrost_core::analyzer::structural::callable::ApplicabilityVerdict;

        for loser in losers {
            let mut row = trace::TraceCandidate::rejected(
                trace::TraceCandidateRef::Unit(loser.clone()),
                self.precedence_tier(loser),
                RejectionReason::CallableApplicabilityDeferred,
            );
            if let Some(enrichment) =
                self.enrichment(base, loser, ApplicabilityVerdict::Inapplicable)
            {
                row = row.with_member(enrichment);
            }
            trace::record(row);
        }
    }

    /// Stage attribution for the candidates the walk is about to return, for
    /// the outcome constructor the caller reaches next.
    fn stage_selection(
        &self,
        base: &CodeUnit,
        winners: &[CodeUnit],
        applicability: brokk_bifrost_core::analyzer::structural::callable::ApplicabilityVerdict,
    ) {
        if let Some(tier) = winners
            .iter()
            .filter_map(|unit| self.precedence_tier(unit))
            .min()
        {
            trace::stage_tier(tier, winners.iter().map(|unit| unit.fq_name()).collect());
        }
        trace::stage_member_context(
            winners
                .iter()
                .filter_map(|unit| {
                    self.enrichment(base, unit, applicability)
                        .map(|enrichment| (unit.fq_name(), enrichment))
                })
                .collect(),
        );
    }
}

/// Extension functions named `member` that are in scope at the reference and
/// whose declared receiver type is the receiver's type or one of its supertypes.
///
/// Visibility runs through the ordinary name-resolution ladder, so an extension
/// is found exactly when Kotlin would find it: declared in an enclosing scope,
/// imported, declared in the same package, or star-imported.
fn kotlin_extension_candidates(
    ctx: &KotlinCtx<'_>,
    receiver: &KotlinReceiver,
    member: &str,
    arity: Option<usize>,
    site_byte: usize,
) -> Vec<CodeUnit> {
    use brokk_bifrost_core::analyzer::structural::callable::ApplicabilityVerdict;

    let scope = ctx.scope_at(site_byte);
    // The declared receiver each admitted extension conformed to, kept from the
    // very check that admitted it. Re-reading it afterwards would spend session
    // budget a recording run must not spend.
    let admitted = |unit: &CodeUnit| -> Option<CodeUnit> {
        if !arity.is_none_or(|arity| ctx.accepts_arity(unit, arity)) {
            return None;
        }
        let declared = ctx.extension_receiver_unit(unit)?;
        ctx.type_conforms_to(&receiver.owner, &declared)
            .then_some(declared)
    };
    let resolution = resolve_kotlin_type_name(member, &scope.as_name_scope(), |candidate| {
        ctx.callables_named(candidate)
            .iter()
            .any(|unit| admitted(unit).is_some())
    });
    let Some(fqn) = resolution.resolved() else {
        return Vec::new();
    };
    let matched: Vec<(CodeUnit, CodeUnit)> = ctx
        .callables_named(&fqn)
        .into_iter()
        .filter_map(|unit| admitted(&unit).map(|declared| (unit, declared)))
        .collect();
    if trace::recording() && !matched.is_empty() {
        // An extension is admitted by conformance, and conformance is a yes/no
        // question: `type_conforms_to` walks the hierarchy without metering the
        // distance it walked. So only an extension declared directly on the
        // receiver's own type has a route this seam holds -- depth zero, no
        // hops. An extension of a supertype stays unattributed rather than
        // being given a depth the walk never counted.
        trace::stage_member_context(
            matched
                .iter()
                .filter(|(_, declared)| declared.fq_name() == receiver.owner.fq_name())
                .map(|(unit, declared)| {
                    (
                        unit.fq_name(),
                        trace::MemberEnrichment {
                            owner: declared.clone(),
                            hierarchy_depth: 0,
                            dispatch_tier: MemberDispatchTier::Extension,
                            applicability: if arity.is_some() {
                                ApplicabilityVerdict::Applicable
                            } else {
                                ApplicabilityVerdict::Unknown
                            },
                            route: Vec::new(),
                        },
                    )
                })
                .collect(),
        );
    }
    matched.into_iter().map(|(unit, _)| unit).collect()
}

/// Type the expression a member is selected from.
fn kotlin_receiver(ctx: &KotlinCtx<'_>, node: Node<'_>, depth: usize) -> Option<KotlinReceiver> {
    if depth > MAX_RECEIVER_DEPTH {
        return None;
    }
    match node.kind() {
        // `a!!.b` and `(a).b` select from the same thing `a` does.
        "postfix_expression" | "parenthesized_expression" => {
            kotlin_receiver(ctx, named_children(node).into_iter().next()?, depth + 1)
        }
        "this_expression" => Some(KotlinReceiver {
            owner: kotlin_this_owner(ctx, node)?,
            static_qualifier: false,
        }),
        "super_expression" => Some(KotlinReceiver {
            owner: kotlin_super_owner(ctx, node)?,
            static_qualifier: false,
        }),
        "as_expression" => {
            let asserted = named_children(node).into_iter().next_back()?;
            Some(KotlinReceiver {
                owner: ctx.resolve_type_unit(
                    &kotlin_type_node_spelling(ctx, asserted)?,
                    &ctx.scope_at(node.start_byte()),
                )?,
                static_qualifier: false,
            })
        }
        "simple_identifier" => kotlin_identifier_receiver(ctx, node, depth),
        "call_expression" | "navigation_expression" => Some(KotlinReceiver {
            owner: kotlin_expression_type(ctx, node, depth)?,
            static_qualifier: false,
        }),
        _ => None,
    }
}

/// Type a bare name used as a receiver: a local binding, a property in scope,
/// or a type named as a static qualifier.
fn kotlin_identifier_receiver(
    ctx: &KotlinCtx<'_>,
    node: Node<'_>,
    depth: usize,
) -> Option<KotlinReceiver> {
    let name = ctx.text(node);
    if let Some(binding) = kotlin_local_binding(node, ctx.source, name) {
        return Some(KotlinReceiver {
            owner: kotlin_binding_type(ctx, binding, depth)?,
            static_qualifier: false,
        });
    }

    let scope = ctx.scope_at(node.start_byte());
    if let Some(owner) = ctx.resolve_type_unit(name, &scope) {
        return Some(KotlinReceiver {
            owner,
            static_qualifier: true,
        });
    }

    // A property of an enclosing declaration, or a top-level/imported one.
    let fqn = resolve_kotlin_type_name(name, &scope.as_name_scope(), |candidate| {
        ctx.support
            .fqn_in_any_language(candidate)
            .iter()
            .any(CodeUnit::is_field)
    })
    .resolved()?;
    let property = ctx
        .support
        .fqn_in_any_language(&fqn)
        .into_iter()
        .find(CodeUnit::is_field)?;
    Some(KotlinReceiver {
        owner: ctx.declared_type_of(&property, depth)?,
        static_qualifier: false,
    })
}

/// The class a `this` expression denotes.
///
/// A label (`this@Outer`) picks the named enclosing declaration; an unlabelled
/// `this` is the innermost one.
fn kotlin_this_owner(ctx: &KotlinCtx<'_>, node: Node<'_>) -> Option<CodeUnit> {
    let label = first_named_child_of_kind(node, "label").map(|label| {
        ctx.text(label)
            .trim_start_matches('@')
            .trim_end_matches('@')
            .to_string()
    });
    // Inside an extension, an unlabelled `this` is the extension receiver, and
    // it shadows the enclosing class instance a member extension also has.
    // Only `this@Owner` reaches that dispatch receiver.
    if label.is_none()
        && let Some(receiver) = kotlin_enclosing_extension_receiver(node)
        && let Some(spelled) = kotlin_type_node_spelling(ctx, receiver)
    {
        let scope = ctx.scope_at(receiver.start_byte());
        return ctx.resolve_type_unit(&spelled, &scope);
    }
    let mut current = ctx.enclosing_class_at(node.start_byte());
    while let Some(unit) = current {
        match label.as_deref() {
            Some(label) if unit.identifier() != label => {
                current = ctx.parent_of(&unit).filter(CodeUnit::is_class);
            }
            _ => return Some(unit),
        }
    }
    None
}

/// The `receiver` type node of the callable that owns `node`, when that
/// callable is an extension.
///
/// The walk stops at any syntax that opens a receiver scope of its own: a
/// lambda may or may not rebind `this` depending on the parameter type it is
/// passed to, which is a whole-program fact, so an enclosing extension is not
/// claimed through one.
fn kotlin_enclosing_extension_receiver<'tree>(node: Node<'tree>) -> Option<Node<'tree>> {
    let mut current = node.parent();
    while let Some(parent) = current {
        match parent.kind() {
            "function_declaration" | "property_declaration" => {
                return parent.child_by_field_name("receiver");
            }
            "lambda_literal"
            | "anonymous_function"
            | "class_declaration"
            | "object_declaration"
            | "companion_object"
            | "object_literal"
            | "secondary_constructor"
            | "anonymous_initializer" => return None,
            _ => {}
        }
        current = parent.parent();
    }
    None
}

/// The class a `super` expression denotes: the first direct ancestor of the
/// enclosing class, or the named one in `super<Base>`.
fn kotlin_super_owner(ctx: &KotlinCtx<'_>, node: Node<'_>) -> Option<CodeUnit> {
    let enclosing = ctx.enclosing_class_at(node.start_byte())?;
    let named = first_named_child_of_kind(node, "user_type")
        .and_then(|user_type| kotlin_type_node_spelling(ctx, user_type));
    let ancestors = ctx.direct_ancestors(&enclosing);
    match named {
        Some(named) => ancestors
            .into_iter()
            .find(|ancestor| ancestor.identifier() == named || ancestor.fq_name() == named),
        None => ancestors.into_iter().next(),
    }
}

/// The type an expression evaluates to, as an indexed declaration.
fn kotlin_expression_type(ctx: &KotlinCtx<'_>, node: Node<'_>, depth: usize) -> Option<CodeUnit> {
    if depth > MAX_RECEIVER_DEPTH {
        return None;
    }
    match node.kind() {
        "postfix_expression" | "parenthesized_expression" => {
            kotlin_expression_type(ctx, named_children(node).into_iter().next()?, depth + 1)
        }
        "call_expression" => {
            let callee = kotlin_callee(node)?;
            let target = kotlin_call_target(ctx, node, callee, depth)?;
            // A constructor call evaluates to the class it constructs; any
            // other call evaluates to its declared return type.
            if target.is_class() {
                return Some(target);
            }
            ctx.declared_type_of(&target, depth)
        }
        "navigation_expression" => {
            let suffix = named_children(node)
                .into_iter()
                .find(|child| child.kind() == "navigation_suffix")?;
            let member = first_named_child_of_kind(suffix, "simple_identifier")?;
            let receiver =
                kotlin_receiver(ctx, named_children(node).into_iter().next()?, depth + 1)?;
            let target = kotlin_member_candidates(
                ctx,
                &receiver,
                ctx.text(member),
                None,
                suffix.start_byte(),
            )
            .into_iter()
            .next()?;
            ctx.declared_type_of(&target, depth)
        }
        "simple_identifier" => kotlin_receiver(ctx, node, depth + 1).map(|receiver| receiver.owner),
        "as_expression" => {
            let asserted = named_children(node).into_iter().next_back()?;
            ctx.resolve_type_unit(
                &kotlin_type_node_spelling(ctx, asserted)?,
                &ctx.scope_at(node.start_byte()),
            )
        }
        "object_literal" => None,
        _ => None,
    }
}

/// The single declaration a call resolves to, when it resolves to exactly one.
fn kotlin_call_target(
    ctx: &KotlinCtx<'_>,
    call: Node<'_>,
    callee: Node<'_>,
    depth: usize,
) -> Option<CodeUnit> {
    let outcome = match callee.kind() {
        "simple_identifier" => {
            kotlin_bare_call_outcome(ctx, callee, ctx.text(callee), Some(kotlin_call_arity(call)))
        }
        "navigation_expression" => {
            let suffix = named_children(callee)
                .into_iter()
                .find(|child| child.kind() == "navigation_suffix")?;
            let member = first_named_child_of_kind(suffix, "simple_identifier")?;
            let receiver =
                kotlin_receiver(ctx, named_children(callee).into_iter().next()?, depth + 1)?;
            return kotlin_member_candidates(
                ctx,
                &receiver,
                ctx.text(member),
                Some(kotlin_call_arity(call)),
                suffix.start_byte(),
            )
            .into_iter()
            .next();
        }
        _ => return None,
    };
    let mut definitions = outcome.definitions;
    (definitions.len() == 1).then(|| definitions.remove(0))
}

/// The declaration a `variable_declaration`, `parameter`, or `class_parameter`
/// node binds a type to.
fn kotlin_binding_type(ctx: &KotlinCtx<'_>, binding: Node<'_>, depth: usize) -> Option<CodeUnit> {
    let scope = ctx.scope_at(binding.start_byte());
    if let Some(spelled) = kotlin_declared_type_spelling(ctx, binding)
        && let Some(unit) = ctx.resolve_type_unit(&spelled, &scope)
    {
        return Some(unit);
    }
    // No written type: the initializer of the enclosing property is the only
    // other proof. Kotlin's full inference is not modelled, so anything that is
    // not a call or a cast stays unknown rather than being guessed.
    let property = binding
        .parent()
        .filter(|parent| parent.kind() == "property_declaration")?;
    let initializer = named_children(property)
        .into_iter()
        .rev()
        .find(|child| kotlin_is_expression_kind(child.kind()))?;
    kotlin_expression_type(ctx, initializer, depth + 1)
}

/// The `variable_declaration`, `parameter`, or `class_parameter` node that binds
/// `name` at `node`, searching enclosing scopes innermost first.
///
/// Only bindings that begin before the reference are considered, which is what
/// keeps a later same-named local from answering for an earlier reference.
fn kotlin_local_binding<'tree>(node: Node<'tree>, source: &str, name: &str) -> Option<Node<'tree>> {
    let reference_start = node.start_byte();
    let mut current = node.parent();
    while let Some(scope) = current {
        let mut stack = named_children(scope);
        while let Some(candidate) = stack.pop() {
            if candidate.start_byte() > reference_start {
                continue;
            }
            match candidate.kind() {
                "variable_declaration" | "parameter" | "class_parameter" => {
                    if kotlin_binding_name(candidate, source) == Some(name) {
                        return Some(candidate);
                    }
                }
                // Do not descend into a nested declaration: its locals are not
                // in scope here, and a same-named one there must not answer.
                "class_declaration"
                | "object_declaration"
                | "companion_object"
                | "function_declaration" => continue,
                _ => stack.extend(named_children(candidate)),
            }
        }
        current = scope.parent();
    }
    None
}

fn kotlin_binding_name<'a>(binding: Node<'_>, source: &'a str) -> Option<&'a str> {
    first_named_child_of_kind(binding, "simple_identifier")?
        .utf8_text(source.as_bytes())
        .ok()
}

/// The return type a function declaration writes, if it wrote one.
///
/// The grammar gives the return type no field, but it is the only bare type
/// node among a `function_declaration`'s children: the parameters live inside
/// `function_value_parameters` and the receiver behind the `receiver` field.
fn kotlin_declared_return_type_spelling(ctx: &KotlinCtx<'_>, node: Node<'_>) -> Option<String> {
    let receiver = node.child_by_field_name("receiver").map(|node| node.id());
    named_children(node)
        .into_iter()
        .filter(|child| Some(child.id()) != receiver)
        .find_map(|child| kotlin_type_node_spelling(ctx, child))
}

/// The dotted name a type node spells, or `None` for a shape that names no
/// nominal type (a function type, a star projection).
fn kotlin_type_node_spelling(ctx: &KotlinCtx<'_>, node: Node<'_>) -> Option<String> {
    match node.kind() {
        "user_type" => {
            let segments = named_children(node)
                .into_iter()
                .filter(|child| child.kind() == "type_identifier")
                .map(|child| ctx.text(child))
                .collect::<Vec<_>>();
            (!segments.is_empty()).then(|| segments.join("."))
        }
        "nullable_type" | "not_nullable_type" | "parenthesized_type" | "receiver_type"
        | "type_projection" => named_children(node)
            .into_iter()
            .find_map(|child| kotlin_type_node_spelling(ctx, child)),
        _ => None,
    }
}

/// The type written on a binding, if it was written at all.
fn kotlin_declared_type_spelling(ctx: &KotlinCtx<'_>, binding: Node<'_>) -> Option<String> {
    named_children(binding)
        .into_iter()
        .find_map(|child| kotlin_type_node_spelling(ctx, child))
}

// ---------------------------------------------------------------------------
// Type lookup: what type does the expression at this location have?
// ---------------------------------------------------------------------------

/// What `get_type_by_location` found at a Kotlin location.
pub(crate) enum KotlinTypeLookupResolution {
    Type {
        fqn: String,
        target_kind: TypeLookupTargetKind,
    },
    /// The location names a callable, which has no type in the sense the caller
    /// is asking about. Distinguished from "no type found" so the caller can say
    /// why rather than implying the lookup failed.
    InappropriateSymbolContext,
}

pub(crate) fn kotlin_type_lookup_resolution(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    site: &ResolvedReferenceSite,
) -> Option<KotlinTypeLookupResolution> {
    kotlin_type_lookup_resolution_in_session(
        analyzer,
        support,
        &ResolutionSession::unbounded(),
        file,
        source,
        root,
        site,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn kotlin_type_lookup_resolution_in_session(
    analyzer: &dyn IAnalyzer,
    support: &dyn BoundedDefinitionLookup,
    session: &ResolutionSession,
    file: &ProjectFile,
    source: &str,
    root: Node<'_>,
    site: &ResolvedReferenceSite,
) -> Option<KotlinTypeLookupResolution> {
    let node = smallest_named_node_covering(root, site.focus_start_byte, site.focus_end_byte)?;
    let ctx = KotlinCtx::new(analyzer, support, session, file, source, root, site);

    if node.kind() == "type_identifier" {
        if kotlin_enclosing_import_header(node).is_some() {
            return None;
        }
        let spelled = kotlin_type_spelling_through(&ctx, node);
        let scope = ctx.scope_at(node.start_byte());
        let fqn = ctx.resolve_name(&spelled, &scope).resolved()?;
        return Some(KotlinTypeLookupResolution::Type {
            fqn,
            target_kind: TypeLookupTargetKind::TypeReference,
        });
    }

    // A site covering a whole expression — a construction, a call, a chained
    // selection — types through the same expression typer receiver resolution
    // uses. Kotlin has no `new`, so `Service()` is an ordinary `call_expression`
    // and this is the only place a construction can answer with the class it
    // builds.
    if node.kind() != "simple_identifier" && kotlin_is_expression_kind(node.kind()) {
        let unit = kotlin_expression_type(&ctx, node, 0)?;
        return Some(KotlinTypeLookupResolution::Type {
            fqn: unit.fq_name(),
            target_kind: TypeLookupTargetKind::ValueExpression,
        });
    }

    if node.kind() != "simple_identifier" || kotlin_enclosing_import_header(node).is_some() {
        return None;
    }

    let parent = node.parent()?;
    // A callable's own name is not a typed expression.
    if parent.kind() == "function_declaration"
        && first_named_child_of_kind(parent, "simple_identifier")
            .is_some_and(|name| name.id() == node.id())
    {
        return Some(KotlinTypeLookupResolution::InappropriateSymbolContext);
    }

    // The name a binding introduces has the binding's type.
    let unit = if matches!(
        parent.kind(),
        "variable_declaration" | "parameter" | "class_parameter"
    ) && first_named_child_of_kind(parent, "simple_identifier")
        .is_some_and(|name| name.id() == node.id())
    {
        kotlin_binding_type(&ctx, parent, 0)?
    } else if parent.kind() == "navigation_suffix" {
        let navigation = parent.parent()?;
        let receiver = kotlin_receiver(&ctx, named_children(navigation).into_iter().next()?, 0)?;
        let member =
            kotlin_member_candidates(&ctx, &receiver, ctx.text(node), None, parent.start_byte())
                .into_iter()
                .next()?;
        ctx.declared_type_of(&member, 0)?
    } else {
        kotlin_receiver(&ctx, node, 0)?.owner
    };

    Some(KotlinTypeLookupResolution::Type {
        fqn: unit.fq_name(),
        target_kind: TypeLookupTargetKind::ValueExpression,
    })
}

/// Whether `node` is the callee token of a Kotlin call, which is what
/// signature help anchors a call site on.
pub(super) fn kotlin_call_reference_candidate(node: Node<'_>) -> bool {
    if let Some(parent) = node.parent()
        && parent.kind() == "navigation_suffix"
        && let Some(navigation) = parent.parent()
    {
        return navigation
            .parent()
            .filter(|call| call.kind() == "call_expression")
            .and_then(kotlin_callee)
            .is_some_and(|callee| callee.id() == navigation.id());
    }
    if kotlin_call_with_callee(node).is_some() {
        return true;
    }
    // `Base(...)` in a supertype list is spelled as a `constructor_invocation`
    // over a `user_type` rather than as a call expression.
    node.parent()
        .filter(|parent| parent.kind() == "user_type")
        .and_then(|user_type| user_type.parent())
        .is_some_and(|parent| parent.kind() == "constructor_invocation")
}
