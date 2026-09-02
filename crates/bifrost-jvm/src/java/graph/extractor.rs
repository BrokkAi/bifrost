use super::JavaGraphSource;
use super::hits;
use super::resolver::{
    ReceiverTargetMatch, TargetKind, TargetSpec, argument_list_arity,
    bare_field_context_matches_target, bare_method_context_matches_target,
    constructor_method_reference_receiver, has_proven_static_import, infer_type_from_value,
    is_declaration_name, is_ignored_type_context, is_module_type_reference,
    is_record_pattern_type_reference, java_method_signatures_match, nested_type_for_owner,
    node_text, receiver_matches_target, receiver_type_matches_target, resolve_field_access_type,
    resolve_field_access_type_segments, resolve_non_nested_type_from_node, resolve_type_from_node,
    resolve_type_segments, same_owner_context, seed_class_binding,
};
use super::return_type::{
    FileReturnCache, MethodAnonymousReturnCache, MethodReturnCache, java_type_name_components,
};
use crate::java::graph_support::{
    JavaSource, java_switch_selector_expression, resolve_java_usage_type_components_in,
};
use crate::java::structural::expression_name_node;
use brokk_bifrost_core::CancellationToken;
use brokk_bifrost_core::analyzer::model::{CodeUnit, ProjectFile};
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_core::analyzer::tree_walk::{TreeWalkAction, walk_tree_iterative};
use brokk_bifrost_core::analyzer::usages::inverted_edges::ClassRangeIndex;
use brokk_bifrost_core::analyzer::usages::local_inference::{
    LocalInferenceConfig, LocalInferenceEngine, SymbolResolution,
};
use brokk_bifrost_core::analyzer::usages::model::UsageHit;
use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisOutcome;
use brokk_bifrost_core::hash::HashMap;
use brokk_bifrost_core::text_utils::compute_line_starts;
use std::cell::RefCell;
use std::collections::BTreeSet;
use tree_sitter::{Node, Parser, Tree};

/// Identifies one resolved call shape: the fully qualified name of the type the
/// call is dispatched on, the called method's name, and the argument count that
/// selects the overload.
#[derive(PartialEq, Eq, Hash)]
pub struct MethodCallReturnCacheKey {
    pub owner_fqn: String,
    pub method_name: String,
    pub arity: usize,
}

pub struct ScanState<'a> {
    pub max_usages: usize,
    pub hits: &'a mut BTreeSet<UsageHit>,
    pub unproven_hits: &'a mut BTreeSet<UsageHit>,
    pub raw_match_count: &'a mut usize,
    pub limit_exceeded: &'a mut bool,
}

/// The exact reason a per-file evidence build cannot be published.
///
/// A complete zero-hit scan is represented by [`JavaFileUsageEvidence`] with
/// empty hit sets. It must not be confused with one of these omissions: an
/// omission means that the scan could not establish an exact answer for the
/// file and is therefore not cacheable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JavaFileEvidenceOmission {
    SourceRead,
    ParserSetup,
    Parse,
    StoreProvider,
    ClassRange,
    RelationalFrontier,
    UnavailableCapability,
    InternalSafetyCap,
}

/// Immutable, uncapped semantic evidence for one Java file and one target
/// specification.
///
/// `UsageHit` owns its source snippet and enclosing declaration, so this value
/// remains valid after the parser and request-local relational frontier are
/// dropped. The two sets intentionally retain proven and unproven rows
/// separately; request-level budgets and projections are applied by the
/// analysis layer after this value is acquired.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JavaFileUsageEvidence {
    pub hits: BTreeSet<UsageHit>,
    pub unproven_hits: BTreeSet<UsageHit>,
    pub raw_match_count: usize,
}

impl JavaFileUsageEvidence {
    pub fn empty() -> Self {
        Self {
            hits: BTreeSet::new(),
            unproven_hits: BTreeSet::new(),
            raw_match_count: 0,
        }
    }
}

/// Result of one uncapped Java file evidence build.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JavaFileEvidenceBuildOutcome {
    Complete(JavaFileUsageEvidence),
    Omitted(JavaFileEvidenceOmission),
    Cancelled,
}

/// Parser-backed immutable inputs shared by every semantic operation in one
/// evidence build. In particular, source text, its tree, line starts, and
/// class ranges are prepared once and never rebuilt during the scan.
pub struct PreparedJavaFile {
    source: String,
    tree: Tree,
    line_starts: Vec<usize>,
    class_ranges: ClassRangeIndex,
    target_present: bool,
}

pub struct ReturnTypeCaches<'a> {
    pub method_return: &'a MethodReturnCache,
    pub method_anonymous_return: &'a MethodAnonymousReturnCache,
    pub file_return: &'a FileReturnCache,
}

/// Query-scoped owner of the return-type caches.
///
/// One usage query scans many files, and a referenced file's return facts are
/// the same for every scanned file in that query. The owner lives beside the
/// query's file loop so `build_java_file_return_facts` parses each referenced
/// file once per query, not once per scanned file.
#[derive(Default)]
pub struct OwnedReturnTypeCaches {
    method_return: MethodReturnCache,
    method_anonymous_return: MethodAnonymousReturnCache,
    file_return: FileReturnCache,
}

impl OwnedReturnTypeCaches {
    pub fn caches(&self) -> ReturnTypeCaches<'_> {
        ReturnTypeCaches {
            method_return: &self.method_return,
            method_anonymous_return: &self.method_anonymous_return,
            file_return: &self.file_return,
        }
    }
}

pub struct ScanCtx<'a> {
    pub java: &'a dyn JavaSource,
    pub graph: &'a JavaGraphSource<'a>,
    pub file: &'a ProjectFile,
    pub source: &'a str,
    pub root: Node<'a>,
    pub line_starts: &'a [usize],
    pub spec: &'a TargetSpec,
    pub bindings: &'a mut LocalInferenceEngine<String>,
    pub hits: &'a mut BTreeSet<UsageHit>,
    pub unproven_hits: &'a mut BTreeSet<UsageHit>,
    pub raw_match_count: &'a mut usize,
    pub max_usages: usize,
    pub limit_exceeded: &'a mut bool,
    pub class_ranges: ClassRangeIndex,
    pub method_call_return_cache:
        RefCell<HashMap<MethodCallReturnCacheKey, ReceiverAnalysisOutcome<String>>>,
    pub receiver_target_match_cache: RefCell<HashMap<String, ReceiverTargetMatch>>,
    pub method_return_cache: &'a MethodReturnCache,
    pub method_anonymous_return_cache: &'a MethodAnonymousReturnCache,
    pub file_return_cache: &'a FileReturnCache,
    pub enclosing_cache: HashMap<(usize, usize), hits::EnclosingContext>,
    class_scope_depths: Vec<usize>,
}

impl ScanCtx<'_> {
    /// Resolve a spelled type name through Java's own import and package tiers,
    /// against the *realm-aware* declaration index.
    ///
    /// Java, Scala, and Kotlin share one JVM candidate space (#1237), so a Java
    /// file can name a Kotlin or Scala class declared next door through an
    /// ordinary import. `JavaAnalyzer::resolve_usage_type_name` searches the
    /// Java-only index and would resolve that name to nothing, silently losing
    /// the reference. Only the universe of declarations widens here — Java's
    /// visibility rules are unchanged, so a class in another package still needs
    /// an import (#1239 milestone 4).
    pub fn resolve_realm_type_components(&self, components: &[String]) -> Option<CodeUnit> {
        resolve_java_usage_type_components_in(
            self.java,
            self.graph.token,
            self.graph.relational_definitions,
            self.file,
            components,
        )
    }
}

pub fn scan_file(
    java: &dyn JavaSource,
    _token: QueryToken<'_>,
    graph: &JavaGraphSource<'_>,
    file: &ProjectFile,
    spec: &TargetSpec,
    return_caches: &ReturnTypeCaches<'_>,
    state: &mut ScanState<'_>,
) {
    if *state.limit_exceeded {
        return;
    }
    let Ok(source) = file.read_to_string() else {
        return;
    };
    let Ok(prepared) = prepare_file(graph, file, spec, source) else {
        return;
    };
    scan_prepared_file(java, graph, file, spec, return_caches, &prepared, state);
}

/// Build exact, uncapped evidence for one Java file.
///
/// This is the adapter seam used by analysis-side cache acquisition. The
/// scan deliberately uses the existing graph resolver and frontier-backed
/// questions, but it never receives a request hit limit. A limit trip is
/// therefore an internal safety failure and cannot become a cacheable value.
pub fn scan_file_evidence(
    java: &dyn JavaSource,
    _token: QueryToken<'_>,
    graph: &JavaGraphSource<'_>,
    file: &ProjectFile,
    spec: &TargetSpec,
    return_caches: &ReturnTypeCaches<'_>,
    cancellation: &CancellationToken,
) -> JavaFileEvidenceBuildOutcome {
    if cancellation.is_cancelled() {
        return JavaFileEvidenceBuildOutcome::Cancelled;
    }
    if graph.hierarchy.is_none() {
        return JavaFileEvidenceBuildOutcome::Omitted(
            JavaFileEvidenceOmission::UnavailableCapability,
        );
    }
    // Cacheable evidence must be built from the analyzer generation's exact
    // source, not a later filesystem read that can race the snapshot key.
    // Read the live file only to distinguish an unavailable source from an
    // unavailable indexed provider; never use it as evidence here.
    let source = match graph.index.indexed_source(file) {
        Some(source) => source,
        None => {
            let omission = if file.read_to_string().is_ok() {
                JavaFileEvidenceOmission::StoreProvider
            } else {
                JavaFileEvidenceOmission::SourceRead
            };
            return JavaFileEvidenceBuildOutcome::Omitted(omission);
        }
    };
    let prepared = match prepare_file(graph, file, spec, source) {
        Ok(prepared) => prepared,
        Err(omission) => return JavaFileEvidenceBuildOutcome::Omitted(omission),
    };
    if cancellation.is_cancelled() {
        return JavaFileEvidenceBuildOutcome::Cancelled;
    }

    let mut hits = BTreeSet::new();
    let mut unproven_hits = BTreeSet::new();
    let mut raw_match_count = 0usize;
    let mut limit_exceeded = false;
    let mut state = ScanState {
        // Evidence must include every hit. Keeping this at usize::MAX means
        // the request-level maximum cannot truncate or poison publication.
        max_usages: usize::MAX,
        hits: &mut hits,
        unproven_hits: &mut unproven_hits,
        raw_match_count: &mut raw_match_count,
        limit_exceeded: &mut limit_exceeded,
    };
    scan_prepared_file(
        java,
        graph,
        file,
        spec,
        return_caches,
        &prepared,
        &mut state,
    );
    if cancellation.is_cancelled() {
        return JavaFileEvidenceBuildOutcome::Cancelled;
    }
    if limit_exceeded {
        return JavaFileEvidenceBuildOutcome::Omitted(JavaFileEvidenceOmission::InternalSafetyCap);
    }
    JavaFileEvidenceBuildOutcome::Complete(JavaFileUsageEvidence {
        hits,
        unproven_hits,
        raw_match_count,
    })
}

fn prepare_file(
    graph: &JavaGraphSource<'_>,
    file: &ProjectFile,
    spec: &TargetSpec,
    source: String,
) -> Result<PreparedJavaFile, JavaFileEvidenceOmission> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_java::LANGUAGE.into())
        .map_err(|_| JavaFileEvidenceOmission::ParserSetup)?;
    let tree = parser
        .parse(source.as_str(), None)
        .ok_or(JavaFileEvidenceOmission::Parse)?;
    let line_starts = compute_line_starts(&source);
    let target_present =
        tree_contains_target_terminal(tree.root_node(), &source, &spec.member_name);
    let class_ranges = if target_present {
        build_class_ranges(graph.index, file)?
    } else {
        ClassRangeIndex::from_class_spans(std::iter::empty())
    };
    Ok(PreparedJavaFile {
        source,
        tree,
        line_starts,
        class_ranges,
        target_present,
    })
}

fn build_class_ranges(
    index: &dyn brokk_bifrost_core::analyzer::CodeUnitIndex,
    file: &ProjectFile,
) -> Result<ClassRangeIndex, JavaFileEvidenceOmission> {
    let mut spans = Vec::new();
    for unit in index
        .declarations(file)
        .into_iter()
        .filter(CodeUnit::is_class)
    {
        let ranges = index.ranges(&unit);
        if ranges.is_empty() {
            return Err(JavaFileEvidenceOmission::ClassRange);
        }
        spans.extend(ranges.into_iter().map(|range| (unit.clone(), range)));
    }
    Ok(ClassRangeIndex::from_class_spans(spans))
}

fn scan_prepared_file(
    java: &dyn JavaSource,
    graph: &JavaGraphSource<'_>,
    file: &ProjectFile,
    spec: &TargetSpec,
    return_caches: &ReturnTypeCaches<'_>,
    prepared: &PreparedJavaFile,
    state: &mut ScanState<'_>,
) {
    if !prepared.target_present {
        return;
    }
    let token = graph.token;
    let mut bindings = LocalInferenceEngine::new(LocalInferenceConfig::default());
    seed_class_binding(java, token, graph, file, spec, &mut bindings);
    let mut ctx = ScanCtx {
        java,
        graph,
        file,
        source: &prepared.source,
        root: prepared.tree.root_node(),
        line_starts: &prepared.line_starts,
        spec,
        bindings: &mut bindings,
        hits: state.hits,
        unproven_hits: state.unproven_hits,
        raw_match_count: state.raw_match_count,
        max_usages: state.max_usages,
        limit_exceeded: state.limit_exceeded,
        class_ranges: prepared.class_ranges.clone(),
        method_call_return_cache: RefCell::new(HashMap::default()),
        receiver_target_match_cache: RefCell::new(HashMap::default()),
        method_return_cache: return_caches.method_return,
        method_anonymous_return_cache: return_caches.method_anonymous_return,
        file_return_cache: return_caches.file_return,
        enclosing_cache: HashMap::default(),
        class_scope_depths: Vec::new(),
    };
    scan_node(prepared.tree.root_node(), token, &mut ctx);
}

/// Whether this parsed file contains the target's terminal symbol at all.
///
/// A path-scoped query receives ranked files, not occurrence candidates. Most
/// of those files cannot mention the requested declaration. Building local
/// type inference for them asks relational definition questions about every
/// unrelated declaration in the file before the semantic hit checks reject
/// them. The Java grammar represents every type, method, field, constructor,
/// and import terminal that the scanner can match as an `identifier` or
/// `type_identifier`, so this AST pass is an exact necessary condition. The
/// semantic scan still proves identity for every file that passes it.
fn tree_contains_target_terminal(root: Node<'_>, source: &str, target: &str) -> bool {
    let mut found = false;
    walk_tree_iterative(
        root,
        &mut found,
        |node, found| {
            if matches!(node.kind(), "identifier" | "type_identifier")
                && node_text(node, source) == target
            {
                *found = true;
                TreeWalkAction::Stop
            } else {
                TreeWalkAction::Descend
            }
        },
        |_| {},
    );
    found
}

fn scan_node(node: Node<'_>, token: QueryToken<'_>, ctx: &mut ScanCtx<'_>) {
    if *ctx.limit_exceeded {
        return;
    }
    if node.kind() == "try_with_resources_statement" {
        scan_try_with_resources(node, token, ctx);
        return;
    }
    let enters_class_scope = is_java_type_body(node.kind());
    let enters_scope = enters_class_scope
        || matches!(
            node.kind(),
            "method_declaration"
                | "constructor_declaration"
                | "compact_constructor_declaration"
                | "block"
                | "lambda_expression"
                | "catch_clause"
                | "enhanced_for_statement"
                | "for_statement"
        );

    if enters_scope {
        ctx.bindings.enter_scope();
        if enters_class_scope {
            ctx.class_scope_depths.push(ctx.bindings.scope_depth());
        }
        seed_declarations(node, token, ctx);
    } else {
        seed_inline_declarations(node, token, ctx);
    }

    if node.kind() == "import_declaration" {
        maybe_record_import_hit(node, token, ctx);
    } else {
        maybe_record_hit(node, token, ctx);
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        scan_node(child, token, ctx);
        if *ctx.limit_exceeded {
            break;
        }
    }

    if enters_class_scope {
        ctx.class_scope_depths.pop();
    }
    if enters_scope {
        ctx.bindings.exit_scope();
    }
}

/// Whether a node is the body of a Java type declaration, and so the scope its
/// members are declared in.
///
/// tree-sitter-java gives each declaration form its own body node. Treating
/// only `class_body` as a member scope left an enum's, an interface's and an
/// annotation's fields declared in whatever scope happened to be open around
/// them, which is what hid a bare implicit-this read of an enum-body field:
/// the field's own declaration counted as a shadowing local (#2156).
fn is_java_type_body(kind: &str) -> bool {
    matches!(
        kind,
        "class_body" | "enum_body" | "interface_body" | "annotation_type_body"
    )
}

fn scan_try_with_resources(node: Node<'_>, token: QueryToken<'_>, ctx: &mut ScanCtx<'_>) {
    ctx.bindings.enter_scope();
    if let Some(resources) = node.child_by_field_name("resources") {
        let mut cursor = resources.walk();
        for resource in resources.named_children(&mut cursor) {
            scan_node(resource, token, ctx);
            if *ctx.limit_exceeded {
                break;
            }
            if resource.kind() == "resource" {
                seed_typed_binding(resource, token, ctx);
            }
        }
    }
    if !*ctx.limit_exceeded
        && let Some(body) = node.child_by_field_name("body")
    {
        scan_node(body, token, ctx);
    }
    ctx.bindings.exit_scope();

    if *ctx.limit_exceeded {
        return;
    }
    let resources = node.child_by_field_name("resources");
    let body = node.child_by_field_name("body");
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if Some(child) == resources || Some(child) == body {
            continue;
        }
        scan_node(child, token, ctx);
        if *ctx.limit_exceeded {
            break;
        }
    }
}

fn seed_declarations(node: Node<'_>, token: QueryToken<'_>, ctx: &mut ScanCtx<'_>) {
    match node.kind() {
        "method_declaration" | "constructor_declaration" | "compact_constructor_declaration" => {
            if let Some(parameters) = node.child_by_field_name("parameters") {
                let mut cursor = parameters.walk();
                for child in parameters.named_children(&mut cursor) {
                    if child.kind() == "formal_parameter" {
                        seed_typed_binding(child, token, ctx);
                    }
                }
            }
        }
        "catch_clause" => {
            if let Some(parameter) = node.child_by_field_name("parameter") {
                seed_typed_binding(parameter, token, ctx);
            }
        }
        "enhanced_for_statement" => {
            if let Some(name) = node.child_by_field_name("name") {
                ctx.bindings.declare_shadow(node_text(name, ctx.source));
            }
        }
        _ => {}
    }
}

fn seed_inline_declarations(node: Node<'_>, token: QueryToken<'_>, ctx: &mut ScanCtx<'_>) {
    match node.kind() {
        "local_variable_declaration" | "field_declaration" => {
            seed_variable_declaration(node, token, ctx)
        }
        "formal_parameter" => seed_typed_binding(node, token, ctx),
        _ => {}
    }
}

fn seed_variable_declaration(node: Node<'_>, token: QueryToken<'_>, ctx: &mut ScanCtx<'_>) {
    let Some(type_node) = node.child_by_field_name("type") else {
        return;
    };
    let mut resolved_type = (ctx.spec.kind != TargetKind::Type)
        .then(|| resolve_type_from_node(type_node, token, ctx))
        .flatten();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() != "variable_declarator" {
            continue;
        }
        let Some(name) = child.child_by_field_name("name") else {
            continue;
        };
        let binding_name = node_text(name, ctx.source);
        if binding_name.is_empty() {
            continue;
        }

        if ctx.spec.kind != TargetKind::Type
            && resolved_type.is_none()
            && let Some(value) = child.child_by_field_name("value")
        {
            resolved_type = infer_type_from_value(value, token, ctx);
        }

        // Record the type this declaration resolved to, whatever it is. Only a
        // type target skips the resolution entirely, so that a value binding
        // never answers a type name. Keeping the type even when it is not the
        // target's own owner is what lets a receiver chain such as
        // `config.mode` type its intermediate step (#2162); no consumer of a
        // field target's bindings distinguishes an unresolved receiver from an
        // incompatible one, so nothing is claimed that was not claimed before.
        match resolved_type.as_ref() {
            Some(resolved) => ctx
                .bindings
                .seed_symbol(binding_name.to_string(), resolved.fq_name()),
            None => ctx.bindings.declare_shadow(binding_name.to_string()),
        }
    }
}

fn seed_typed_binding(node: Node<'_>, token: QueryToken<'_>, ctx: &mut ScanCtx<'_>) {
    let Some(name) = node.child_by_field_name("name") else {
        return;
    };
    let binding_name = node_text(name, ctx.source);
    if binding_name.is_empty() {
        return;
    }
    if ctx.spec.kind == TargetKind::Type {
        ctx.bindings.declare_shadow(binding_name.to_string());
        return;
    }
    match node
        .child_by_field_name("type")
        .and_then(|type_node| resolve_type_from_node(type_node, token, ctx))
    {
        Some(resolved) => ctx
            .bindings
            .seed_symbol(binding_name.to_string(), resolved.fq_name()),
        None => ctx.bindings.declare_shadow(binding_name.to_string()),
    }
}

fn maybe_record_hit(node: Node<'_>, token: QueryToken<'_>, ctx: &mut ScanCtx<'_>) {
    match ctx.spec.kind {
        TargetKind::Type => maybe_record_type_hit(node, token, ctx),
        TargetKind::Constructor => maybe_record_constructor_hit(node, token, ctx),
        TargetKind::Method => maybe_record_method_hit(node, token, ctx),
        TargetKind::Field => maybe_record_field_hit(node, token, ctx),
    }
}

fn maybe_record_type_hit(node: Node<'_>, token: QueryToken<'_>, ctx: &mut ScanCtx<'_>) {
    if node.kind() == "method_reference" {
        if let Some(receiver) = node.named_child(0) {
            record_selector_type_segments(receiver, token, ctx);
        }
        return;
    }
    if node.kind() == "field_access" {
        record_selector_type_segments(node, token, ctx);
        return;
    }
    if maybe_record_static_qualifier_type_hit(node, token, ctx) {
        return;
    }
    let Some(type_node) = type_reference_node(node) else {
        return;
    };
    // A scoped parent records each of its semantic type segments with exact
    // token ranges, so visiting a child separately would only duplicate it.
    if type_node.parent().is_some_and(|parent| {
        matches!(
            parent.kind(),
            "scoped_type_identifier" | "scoped_identifier"
        )
    }) {
        return;
    }
    if !tree_contains_target_terminal(type_node, ctx.source, &ctx.spec.member_name) {
        return;
    }
    if is_ignored_type_context(type_node) {
        return;
    }
    for (resolved, segment) in resolve_type_segments(
        type_node,
        ctx.source,
        |candidate| resolve_non_nested_type_from_node(candidate, token, ctx),
        |owner, name| nested_type_for_owner(owner, name, ctx),
    ) {
        if resolved.fq_name() == ctx.spec.owner.fq_name() {
            hits::push_hit(segment, ctx);
        }
    }
}

fn record_selector_type_segments(node: Node<'_>, token: QueryToken<'_>, ctx: &mut ScanCtx<'_>) {
    if !tree_contains_target_terminal(node, ctx.source, &ctx.spec.member_name) {
        return;
    }
    let segments = match node.kind() {
        "field_access" => resolve_field_access_type_segments(
            node,
            ctx.source,
            |base| Ok(resolve_selector_root_type(base, token, ctx)),
            |qualified| ctx.resolve_realm_type_components(qualified),
            |owner, name| nested_type_for_owner(owner, name, ctx),
        ),
        "identifier"
        | "type_identifier"
        | "scoped_identifier"
        | "scoped_type_identifier"
        | "generic_type" => resolve_type_segments(
            node,
            ctx.source,
            |candidate| resolve_selector_root_type(candidate, token, ctx),
            |owner, name| nested_type_for_owner(owner, name, ctx),
        ),
        _ => Vec::new(),
    };
    for (resolved, segment) in segments {
        if resolved.fq_name() == ctx.spec.owner.fq_name() {
            hits::push_hit(segment, ctx);
        }
    }
}

fn resolve_selector_root_type(
    node: Node<'_>,
    token: QueryToken<'_>,
    ctx: &ScanCtx<'_>,
) -> Option<CodeUnit> {
    let name = node_text(node, ctx.source);
    let direct = || {
        java_type_name_components(node, ctx.source)
            .and_then(|components| ctx.resolve_realm_type_components(&components))
            .or_else(|| resolve_non_nested_type_from_node(node, token, ctx))
    };
    match ctx.bindings.resolve_symbol(name) {
        SymbolResolution::Precise(_) => direct(),
        SymbolResolution::Ambiguous => None,
        SymbolResolution::Unknown if ctx.bindings.is_shadowed(name) => None,
        SymbolResolution::Unknown => direct(),
    }
}

fn maybe_record_static_qualifier_type_hit(
    node: Node<'_>,
    token: QueryToken<'_>,
    ctx: &mut ScanCtx<'_>,
) -> bool {
    if node.kind() != "identifier" || !is_member_access_object(node) {
        return false;
    }
    let text = node_text(node, ctx.source);
    if text != ctx.spec.member_name {
        return false;
    }
    match ctx.bindings.resolve_symbol(text) {
        SymbolResolution::Precise(targets)
            if targets
                .iter()
                .any(|target| target == &ctx.spec.target.fq_name()) =>
        {
            hits::push_hit(node, ctx);
            true
        }
        SymbolResolution::Unknown if ctx.bindings.is_shadowed(text) => true,
        SymbolResolution::Unknown => {
            if resolve_type_from_node(node, token, ctx)
                .is_some_and(|resolved| resolved == ctx.spec.target)
            {
                hits::push_hit(node, ctx);
            } else {
                hits::push_unproven_hit(node, ctx);
            }
            true
        }
        SymbolResolution::Ambiguous | SymbolResolution::Precise(_) => true,
    }
}

fn is_member_access_object(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        matches!(parent.kind(), "method_invocation" | "field_access")
            && parent.child_by_field_name("object") == Some(node)
    })
}

fn maybe_record_import_hit(node: Node<'_>, token: QueryToken<'_>, ctx: &mut ScanCtx<'_>) {
    let Some(path) = node.named_child(0) else {
        return;
    };
    match ctx.spec.kind {
        TargetKind::Type => {
            if node_text(path, ctx.source) == ctx.spec.owner.fq_name() {
                hits::push_import_hit(path, ctx);
                return;
            }
        }
        TargetKind::Field | TargetKind::Method => {
            if node_text(path, ctx.source)
                == format!("{}.{}", ctx.spec.owner.fq_name(), ctx.spec.member_name)
            {
                if let Some(member) = expression_name_node(path) {
                    hits::push_import_hit(member, ctx);
                } else {
                    hits::push_import_hit(path, ctx);
                }
                return;
            }
        }
        TargetKind::Constructor => return,
    }

    if ctx.spec.kind != TargetKind::Type {
        return;
    }
    walk_tree_iterative(
        node,
        ctx,
        |current, ctx| {
            if matches!(
                current.kind(),
                "type_identifier" | "scoped_type_identifier" | "scoped_identifier" | "identifier"
            ) && type_terminal_name_matches(current, ctx)
                && resolve_type_from_node(current, token, ctx)
                    .is_some_and(|resolved| resolved.fq_name() == ctx.spec.owner.fq_name())
            {
                hits::push_import_hit(current, ctx);
                return TreeWalkAction::Skip;
            }
            TreeWalkAction::Descend
        },
        |_| {},
    );
}

fn maybe_record_constructor_hit(node: Node<'_>, token: QueryToken<'_>, ctx: &mut ScanCtx<'_>) {
    if let Some(receiver) = constructor_method_reference_receiver(node) {
        maybe_record_constructor_method_reference(node, token, receiver, ctx);
        return;
    }
    if node.kind() != "object_creation_expression" {
        return;
    }
    let Some(type_node) = node.child_by_field_name("type") else {
        return;
    };
    if !type_terminal_name_matches(type_node, ctx) {
        return;
    }
    let Some(resolved) = resolve_type_from_node(type_node, token, ctx) else {
        return;
    };
    if resolved.fq_name() != ctx.spec.owner.fq_name() {
        return;
    }
    if !callable_arity_matches_target(node, ctx) {
        return;
    }
    hits::push_hit(node, ctx);
}

fn maybe_record_constructor_method_reference(
    node: Node<'_>,
    token: QueryToken<'_>,
    receiver: Node<'_>,
    ctx: &mut ScanCtx<'_>,
) {
    let Some(owner) = resolve_type_from_node(receiver, token, ctx) else {
        return;
    };
    if owner != ctx.spec.owner {
        return;
    }
    let candidates = ctx
        .graph
        .structural_members(owner.fq(), owner.identifier())
        .into_iter()
        .filter(|candidate| candidate.is_function() && !candidate.is_synthetic())
        .collect::<Vec<_>>();
    let matching = candidates
        .iter()
        .filter(|candidate| ctx.spec.targets.contains(*candidate))
        .count();
    if matching == 0 {
        return;
    }
    if matching == candidates.len() {
        hits::push_hit(node, ctx);
    } else {
        hits::push_unproven_hit(node, ctx);
    }
}

fn type_terminal_name_matches(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    expression_name_node(node)
        .is_some_and(|name| node_text(name, ctx.source) == ctx.spec.member_name)
}

fn maybe_record_method_hit(node: Node<'_>, token: QueryToken<'_>, ctx: &mut ScanCtx<'_>) {
    if is_declaration_name(node) {
        maybe_record_method_declaration_hit(node, ctx);
        return;
    }
    if node.kind() == "method_reference" {
        maybe_record_method_reference_hit(node, token, ctx);
        return;
    }
    if node.kind() != "method_invocation" {
        return;
    }
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    if node_text(name_node, ctx.source) != ctx.spec.member_name {
        return;
    }
    if !callable_arity_matches_target(node, ctx) {
        return;
    }

    // Track whether a matched receiver is a same-owner receiver (`this`,
    // implicit-this, or the owner type itself) so the hit is classified as a
    // same-owner site rather than an external usage (#1014 facet B).
    let (receiver_match, same_owner) = if let Some(object) = node.child_by_field_name("object") {
        let outcome = receiver_matches_target(object, token, ctx);
        let same_owner = outcome == ReceiverTargetMatch::Matched
            && method_receiver_object_is_same_owner(object, token, ctx);
        (outcome, same_owner)
    } else if bare_method_context_matches_target(node, token, ctx) {
        // An unqualified call resolving to the enclosing type is an implicit-this
        // (or inherited) receiver on the current instance.
        (ReceiverTargetMatch::Matched, true)
    } else if has_proven_static_import(token, ctx) {
        // A static import resolves to another type's static member, not the owner.
        (ReceiverTargetMatch::Matched, false)
    } else {
        (ReceiverTargetMatch::Unresolved, false)
    };
    match receiver_match {
        ReceiverTargetMatch::Matched if same_owner => hits::push_self_receiver_hit(name_node, ctx),
        ReceiverTargetMatch::Matched => hits::push_hit(name_node, ctx),
        ReceiverTargetMatch::Unresolved => hits::push_unproven_hit(name_node, ctx),
        ReceiverTargetMatch::Incompatible => {}
    }
}

/// Whether a *matched* method-invocation receiver `object` is a same-owner
/// receiver: the current instance (`this`) or the owner type itself for a static
/// call from within that type (`Owner.staticMethod()` inside `Owner`). A call
/// through a different variable of the same type, or `super`, stays external.
fn method_receiver_object_is_same_owner(
    object: Node<'_>,
    token: QueryToken<'_>,
    ctx: &mut ScanCtx<'_>,
) -> bool {
    match object.kind() {
        "this" => true,
        "super" => false,
        "identifier" | "type_identifier" | "scoped_type_identifier" | "generic_type" => {
            // Own-type static call: the receiver resolves to a type, and the
            // enclosing declaration is owned by that same type. A binding to a
            // local/parameter value is not a type receiver, so only treat it as
            // same-owner when it is not a shadowed value binding.
            let name = node_text(object, ctx.source);
            if !name.is_empty() && ctx.bindings.is_shadowed(name) {
                return false;
            }
            match resolve_type_from_node(object, token, ctx) {
                Some(receiver_type) => {
                    receiver_type.fq_name() == ctx.spec.owner.fq_name()
                        && same_owner_context(object, ctx)
                }
                None => false,
            }
        }
        _ => false,
    }
}

fn maybe_record_method_reference_hit(node: Node<'_>, token: QueryToken<'_>, ctx: &mut ScanCtx<'_>) {
    let Some((receiver, member)) = method_reference_parts(node) else {
        return;
    };
    if node_text(member, ctx.source) != ctx.spec.member_name {
        return;
    }
    match method_reference_target_resolution(receiver, token, ctx) {
        MethodReferenceTargetResolution::NotTarget => {}
        MethodReferenceTargetResolution::Proven => hits::push_hit(member, ctx),
        MethodReferenceTargetResolution::Unproven => hits::push_unproven_hit(member, ctx),
    }
}

enum MethodReferenceTargetResolution {
    NotTarget,
    Proven,
    Unproven,
}

fn method_reference_parts(node: Node<'_>) -> Option<(Node<'_>, Node<'_>)> {
    let mut cursor = node.walk();
    let children: Vec<_> = node.named_children(&mut cursor).collect();
    let (member, rest) = children.split_last()?;
    let receiver = rest.last().copied()?;
    Some((receiver, *member))
}

fn method_reference_target_resolution(
    receiver: Node<'_>,
    token: QueryToken<'_>,
    ctx: &mut ScanCtx<'_>,
) -> MethodReferenceTargetResolution {
    let owners = method_reference_owner_fq_names(receiver, token, ctx);
    let receiver_matches = owners
        .iter()
        .filter_map(|owner| ctx.graph.index.definitions(owner).next())
        .map(|owner| receiver_type_matches_target(&owner, token, ctx))
        .collect::<Vec<_>>();
    if receiver_matches
        .iter()
        .all(|outcome| *outcome == ReceiverTargetMatch::Incompatible)
        && !receiver_matches.is_empty()
    {
        return MethodReferenceTargetResolution::NotTarget;
    }
    if !receiver_matches.contains(&ReceiverTargetMatch::Matched) {
        return MethodReferenceTargetResolution::Unproven;
    }
    let mut candidates = Vec::new();
    for owner in &owners {
        candidates.extend(method_reference_candidates_for_owner(owner, token, ctx));
    }
    let matching = candidates
        .iter()
        .filter(|candidate| ctx.spec.targets.contains(*candidate))
        .count();
    if matching == 0 {
        return MethodReferenceTargetResolution::NotTarget;
    }
    if matching == 1 && candidates.len() == 1 && owners.len() == 1 {
        MethodReferenceTargetResolution::Proven
    } else {
        MethodReferenceTargetResolution::Unproven
    }
}

fn method_reference_owner_fq_names(
    receiver: Node<'_>,
    token: QueryToken<'_>,
    ctx: &mut ScanCtx<'_>,
) -> Vec<String> {
    match receiver.kind() {
        "this" | "super" => ctx
            .class_ranges
            .enclosing(receiver.start_byte())
            .map(|owner| vec![owner.to_string()])
            .unwrap_or_default(),
        "identifier" => ctx
            .bindings
            .resolve_symbol(node_text(receiver, ctx.source))
            .as_precise()
            .map(|targets| targets.iter().cloned().collect())
            .unwrap_or_else(|| {
                resolve_type_from_node(receiver, token, ctx)
                    .map(|unit| vec![unit.fq_name()])
                    .unwrap_or_default()
            }),
        "field_access" => resolve_field_access_type(
            receiver,
            ctx.source,
            |base| {
                let name = node_text(base, ctx.source);
                if ctx.bindings.is_shadowed(name) {
                    Err(())
                } else {
                    Ok(resolve_type_from_node(base, token, ctx))
                }
            },
            |qualified| ctx.resolve_realm_type_components(qualified),
            |owner, name| nested_type_for_owner(owner, name, ctx),
        )
        .map(|owner| vec![owner.fq_name()])
        .unwrap_or_default(),
        _ => resolve_type_from_node(receiver, token, ctx)
            .map(|unit| vec![unit.fq_name()])
            .unwrap_or_default(),
    }
}

fn method_reference_candidates_for_owner(
    owner_fq_name: &str,
    _token: QueryToken<'_>,
    ctx: &ScanCtx<'_>,
) -> Vec<CodeUnit> {
    let Some(owner) = ctx.graph.index.definitions(owner_fq_name).next() else {
        return Vec::new();
    };
    let mut candidates = ctx
        .graph
        .structural_members(owner.fq(), &ctx.spec.member_name)
        .into_iter()
        .filter(CodeUnit::is_function)
        .collect::<Vec<_>>();
    let Some(provider) = ctx.graph.hierarchy else {
        return candidates;
    };
    for ancestor in provider.get_ancestors(&owner) {
        candidates.extend(
            ctx.graph
                .structural_members(ancestor.fq(), &ctx.spec.member_name)
                .into_iter()
                .filter(CodeUnit::is_function),
        );
    }
    candidates.sort();
    candidates.dedup();
    candidates
}

fn maybe_record_method_declaration_hit(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    if node_text(node, ctx.source) != ctx.spec.member_name {
        return;
    }
    let Some(declaration) = node.parent() else {
        return;
    };
    if declaration.kind() != "method_declaration" {
        return;
    }
    let context = hits::enclosing_context(declaration, ctx);
    let Some(enclosing) = context.enclosing.as_ref() else {
        return;
    };
    let Some(owner) = context.owner.as_ref() else {
        return;
    };
    if owner.fq_name() == ctx.spec.owner.fq_name() {
        return;
    }
    if !enclosing.is_function()
        || !java_method_signatures_match(ctx.java, &ctx.spec.target, enclosing)
    {
        return;
    }
    let Some(hierarchy) = ctx.graph.hierarchy else {
        return;
    };
    let candidate_overrides_target = hierarchy
        .get_ancestors(owner)
        .iter()
        .any(|ancestor| ancestor == &ctx.spec.owner);
    let target_overrides_candidate = hierarchy
        .get_ancestors(&ctx.spec.owner)
        .iter()
        .any(|ancestor| ancestor == owner);
    if candidate_overrides_target || target_overrides_candidate {
        hits::push_override_declaration_hit(node, ctx);
    }
}

fn maybe_record_field_hit(node: Node<'_>, token: QueryToken<'_>, ctx: &mut ScanCtx<'_>) {
    if node.kind() == "field_access" {
        let Some(field_node) = node.child_by_field_name("field") else {
            return;
        };
        if node_text(field_node, ctx.source) != ctx.spec.member_name {
            return;
        }
        if let Some(object) = node.child_by_field_name("object") {
            match receiver_matches_target(object, token, ctx) {
                ReceiverTargetMatch::Matched => hits::push_hit(field_node, ctx),
                ReceiverTargetMatch::Unresolved | ReceiverTargetMatch::Incompatible => {
                    hits::push_unproven_hit(field_node, ctx)
                }
            }
        }
        return;
    }

    if node.kind() != "identifier" || node_text(node, ctx.source) != ctx.spec.member_name {
        return;
    }
    if is_declaration_name(node) {
        return;
    }
    // The `field` of a `field_access` is a qualified name: it binds in the
    // receiver's type, which the arm above proves. Reading it a second time as
    // a simple name would let the *enclosing* class answer for it, and claim
    // `other.count` as a read of the enclosing class's own `count`.
    if node
        .parent()
        .is_some_and(|parent| parent.child_by_field_name("field") == Some(node))
    {
        return;
    }
    // A case label written as a simple name binds in the switch selector's
    // type, not in the lexical scope around the switch (JLS 14.11), so the
    // enclosing-owner test below can never see it: the label's owner is the
    // selector's enum, which is not the class the switch is written in. Typing
    // the selector is the same question the forward lookup asks (#2043). A
    // selector that does not type to the target owner falls through to the
    // ordinary rule, which is what keeps a constant-variable label on an
    // `int` or `String` switch resolving exactly as before.
    if node
        .parent()
        .is_some_and(|parent| parent.kind() == "switch_label")
        && let Some(selector) = java_switch_selector_expression(node)
        && receiver_matches_target(selector, token, ctx) == ReceiverTargetMatch::Matched
    {
        hits::push_hit(node, ctx);
        return;
    }
    let same_owner = same_owner_context(node, ctx);
    let shadowed = ctx.class_scope_depths.last().map_or_else(
        || ctx.bindings.is_shadowed(ctx.spec.member_name.as_str()),
        |depth| {
            if !same_owner {
                return ctx
                    .bindings
                    .is_shadowed_at_or_below_scope(*depth, ctx.spec.member_name.as_str());
            }
            ctx.bindings
                .is_shadowed_below_scope(*depth, ctx.spec.member_name.as_str())
        },
    );
    if !shadowed
        && (bare_field_context_matches_target(node, token, ctx)
            || has_proven_static_import(token, ctx))
    {
        hits::push_hit(node, ctx);
    }
}

fn type_reference_node(node: Node<'_>) -> Option<Node<'_>> {
    match node.kind() {
        "type_identifier" | "scoped_type_identifier" | "generic_type" => Some(node),
        "identifier" | "scoped_identifier" if is_record_pattern_type_reference(node) => Some(node),
        "identifier" | "scoped_identifier" if is_module_type_reference(node) => Some(node),
        "annotation" | "marker_annotation" => node.child_by_field_name("name"),
        _ => None,
    }
}

fn callable_arity_matches_target(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    let Some(expected_arities) = ctx.spec.callable_arities.as_ref() else {
        return true;
    };
    let actual = argument_list_arity(node);
    expected_arities.iter().any(|arity| arity.accepts(actual))
}
