use brokk_bifrost_core::analyzer::common::language_for_file;
use brokk_bifrost_core::analyzer::model::ImportInfo;
use brokk_bifrost_core::analyzer::usages::common::{SNIPPET_CONTEXT_LINES, usage_hit};
use brokk_bifrost_core::analyzer::usages::model::UsageHit;
use brokk_bifrost_core::analyzer::{CodeUnit, CodeUnitIndex, Language, ProjectFile, Range};
use brokk_bifrost_core::cancellation::CancellationToken;
use brokk_bifrost_core::hash::{HashMap, HashSet};
use brokk_bifrost_core::text_utils::{
    compute_line_starts, find_line_index_for_offset, snippet_around_line,
};
use std::collections::BTreeSet;
use tree_sitter::{Node, Parser};

use crate::java::graph::extractor::ScanState;
use crate::java::graph::resolver::{TargetKind, TargetSpec};
use crate::scala::graph::syntax::{
    ScalaPackageContextIndex, call_site_shape_for_reference, has_ancestor_kind,
    is_declaration_name, is_identifier_node, is_type_like_reference, member_qualifier_node,
    node_text, scala_definition_binder_names, scala_import_path,
};
use crate::scala::graph_support::ScalaSource;
use crate::scala::wildcard_imports::scala_import_path_candidates;

pub fn scan_scala_files_for_java_target(
    owners: &dyn CodeUnitIndex,
    scala: &dyn ScalaSource,
    candidate_files: &HashSet<ProjectFile>,
    spec: &TargetSpec,
    state: &mut ScanState<'_>,
    cancellation: Option<&CancellationToken>,
) {
    if *state.limit_exceeded {
        return;
    }

    for file in candidate_files
        .iter()
        .filter(|file| language_for_file(file) == Language::Scala)
    {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            break;
        }
        scan_scala_file(owners, scala, file, spec, state);
        if *state.limit_exceeded || cancellation.is_some_and(CancellationToken::is_cancelled) {
            break;
        }
    }
}

fn scan_scala_file(
    owners: &dyn CodeUnitIndex,
    scala: &dyn ScalaSource,
    file: &ProjectFile,
    spec: &TargetSpec,
    state: &mut ScanState<'_>,
) {
    if *state.limit_exceeded {
        return;
    }
    if file.is_binary().unwrap_or(true) {
        return;
    }
    let Ok(source) = file.read_to_string() else {
        return;
    };
    if source.is_empty() {
        return;
    }

    let target_name = spec.owner.identifier();
    let target_fq_name = spec.owner.fq_name();
    if !source.contains(target_name) && !source.contains(&target_fq_name) {
        return;
    }

    let mut parser = Parser::new();
    if parser
        .set_language(&crate::scala::language::LANGUAGE.into())
        .is_err()
    {
        return;
    }
    let Some(tree) = parser.parse(source.as_str(), None) else {
        return;
    };

    let line_starts = compute_line_starts(&source);
    let imports = scala.import_info_of(file);
    let package = scala_file_package(scala, file);
    let visibility = Visibility::for_file(&imports, package.as_deref(), spec);
    let bindings = QualifierBindings::for_file(&imports);
    let packages = ScalaPackageContextIndex::new(tree.root_node(), &source);
    let mut ctx = ScalaJavaScanCtx {
        owners,
        scala,
        file,
        source: &source,
        line_starts: &line_starts,
        spec,
        visibility,
        bindings,
        packages,
        type_shadow_scopes: vec![HashSet::default()],
        term_shadow_scopes: vec![HashSet::default()],
        max_usages: state.max_usages,
        hits: state.hits,
        raw_match_count: state.raw_match_count,
        limit_exceeded: state.limit_exceeded,
    };
    scan_node(tree.root_node(), &mut ctx);
}

struct Visibility {
    visible_type_names: HashSet<String>,
}

impl Visibility {
    fn for_file(imports: &[ImportInfo], package: Option<&str>, spec: &TargetSpec) -> Self {
        let target_package = spec.owner.package_name();
        let target_name = spec.owner.identifier();
        let target_fq_name = spec.owner.fq_name();
        let mut visible_type_names = HashSet::default();

        if is_top_level_type(&spec.owner) && package == Some(target_package) {
            visible_type_names.insert(target_name.to_string());
        }

        for import in imports {
            let Some(path) = scala_import_path(import) else {
                continue;
            };
            if import.is_wildcard {
                if path == target_package {
                    visible_type_names.insert(target_name.to_string());
                }
                continue;
            }
            if path == target_fq_name {
                visible_type_names.insert(
                    import
                        .identifier
                        .as_deref()
                        .unwrap_or(target_name)
                        .to_string(),
                );
            }
        }

        Self { visible_type_names }
    }

    fn contains(&self, name: &str) -> bool {
        self.visible_type_names.contains(name)
    }
}

/// What a qualified name written in this file can denote. Scala reaches a Java
/// declaration through a written prefix that is neither the target's package
/// nor its owner's own spelling: `common.FeatureValue` after
/// `import com.linkedin.feathr.common`, `pm.Exception` after
/// `import ...msg.{PersistenceMessages => pm}`, `Outer.Inner.newBuilder` after
/// `import ...Outer`. Comparing the written prefix directly against the target
/// owner leaves every one of those sites unrecorded (#1855), so expand the
/// prefix through this file's imports and package first.
struct QualifierBindings {
    /// The name an import binds in this file, and the fully qualified paths
    /// that name denotes. The import states nothing about whether the last
    /// segment is a package or a type, and neither reading needs to be
    /// singled out here.
    bound: HashMap<String, Vec<String>>,
    /// Namespaces a leading name may hang off without being bound by name: the
    /// path of a wildcard import. The package clauses in scope at the site are
    /// the other such namespace, and they are read per site.
    open_prefixes: Vec<String>,
}

impl QualifierBindings {
    fn for_file(imports: &[ImportInfo]) -> Self {
        let mut bound: HashMap<String, Vec<String>> = HashMap::default();
        let mut open_prefixes = Vec::new();
        for import in imports {
            let Some(path) = scala_import_path(import) else {
                continue;
            };
            let lexical_prefixes = import
                .path
                .as_ref()
                .map(|path| path.lexical_prefixes.as_slice())
                .unwrap_or_default();
            let candidates = scala_import_path_candidates(&path, lexical_prefixes);
            if import.is_wildcard {
                open_prefixes.extend(candidates);
                continue;
            }
            let Some(name) = import.identifier.as_deref() else {
                continue;
            };
            bound
                .entry(name.to_string())
                .or_default()
                .extend(candidates);
        }
        Self {
            bound,
            open_prefixes,
        }
    }

    fn binds(&self, name: &str) -> bool {
        self.bound.contains_key(name)
    }

    /// The fully qualified paths that `segments`, written where
    /// `package_prefixes` are the package clauses in scope, can denote.
    fn denoted_paths(&self, segments: &[String], package_prefixes: &[String]) -> Vec<String> {
        let Some((head, rest)) = segments.split_first() else {
            return Vec::new();
        };
        let written = segments.join(".");
        let rest = rest.join(".");
        let mut paths = vec![written.clone()];
        if let Some(bound) = self.bound.get(head) {
            paths.extend(bound.iter().map(|base| join_qualified(base, &rest)));
        }
        paths.extend(
            self.open_prefixes
                .iter()
                .chain(package_prefixes)
                .map(|prefix| join_qualified(prefix, &written)),
        );
        paths
    }
}

fn join_qualified(prefix: &str, rest: &str) -> String {
    if prefix.is_empty() {
        return rest.to_string();
    }
    if rest.is_empty() {
        return prefix.to_string();
    }
    format!("{prefix}.{rest}")
}

struct ScalaJavaScanCtx<'a, 'state> {
    owners: &'a dyn CodeUnitIndex,
    scala: &'a dyn ScalaSource,
    file: &'a ProjectFile,
    source: &'a str,
    line_starts: &'a [usize],
    spec: &'a TargetSpec,
    visibility: Visibility,
    bindings: QualifierBindings,
    packages: ScalaPackageContextIndex,
    type_shadow_scopes: Vec<HashSet<String>>,
    term_shadow_scopes: Vec<HashSet<String>>,
    max_usages: usize,
    hits: &'state mut BTreeSet<UsageHit>,
    raw_match_count: &'state mut usize,
    limit_exceeded: &'state mut bool,
}

fn scan_node(node: Node<'_>, ctx: &mut ScalaJavaScanCtx<'_, '_>) {
    if *ctx.limit_exceeded {
        return;
    }
    seed_type_shadow(node, ctx);
    seed_term_shadow(node, ctx);
    let enters_scope = enters_local_scope(node);
    if enters_scope {
        ctx.type_shadow_scopes.push(HashSet::default());
        ctx.term_shadow_scopes.push(HashSet::default());
    }
    if is_identifier_node(node) {
        match ctx.spec.kind {
            TargetKind::Type => maybe_record_java_type_hit(node, ctx),
            TargetKind::Method => maybe_record_java_static_method_hit(node, ctx),
            TargetKind::Field => maybe_record_java_static_field_hit(node, ctx),
            TargetKind::Constructor => maybe_record_java_constructor_hit(node, ctx),
        }
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        scan_node(child, ctx);
        if *ctx.limit_exceeded {
            break;
        }
    }
    if enters_scope {
        ctx.type_shadow_scopes.pop();
        ctx.term_shadow_scopes.pop();
    }
}

fn maybe_record_java_type_hit(node: Node<'_>, ctx: &mut ScalaJavaScanCtx<'_, '_>) {
    if has_ancestor_kind(node, "import_declaration") {
        if java_type_import_owner_matches_target(node, ctx) {
            push_scala_hit(node, ctx);
        }
        return;
    }
    if is_declaration_name(node) {
        return;
    }

    let text = node_text(node, ctx.source).trim_end_matches('$');
    if text.is_empty() {
        return;
    }

    let proven = match written_qualifier_segments(node, ctx.source) {
        // A written prefix is the whole proof: it has to expand to the path the
        // target's own name is written after. A name that is visible under some
        // other prefix is a different type.
        Some(qualifier) => {
            text == ctx.spec.owner.identifier()
                && qualifier_denotes_target_owner(node, &qualifier, ctx)
        }
        // A bare name proves the target when this file's imports or package
        // make it visible, under its own spelling or under an import rename,
        // and it stands in a type position or leads a qualified path. The
        // leading segment is how an import rename of a Java outer class is
        // written before its nested member: `pm` in `pm.State`.
        None => {
            ctx.visibility.contains(text)
                && !is_type_shadowed(ctx, text)
                && (is_type_like_reference(node, ctx.source)
                    || (is_leading_path_segment(node) && !is_term_shadowed(ctx, text)))
        }
    };

    if proven {
        push_scala_hit(node, ctx);
    }
}

/// Whether this identifier spells the target's owner type at this site: the
/// written path denotes the owner, or the simple name is visible in this file
/// and unshadowed. The syntactic *position* is not part of this answer -- each
/// caller states the position it accepts.
fn scala_name_denotes_target_owner(node: Node<'_>, ctx: &ScalaJavaScanCtx<'_, '_>) -> bool {
    let text = node_text(node, ctx.source).trim_end_matches('$');
    if text.is_empty() {
        return false;
    }
    match written_qualifier_segments(node, ctx.source) {
        Some(qualifier) => {
            text == ctx.spec.owner.identifier()
                && qualifier_denotes_target_owner(node, &qualifier, ctx)
        }
        None => ctx.visibility.contains(text) && !is_type_shadowed(ctx, text),
    }
}

/// The path segments written before `node`, or `None` when the name stands
/// alone or its prefix is not a plain dotted path. Tree-sitter spells the three
/// Scala positions of a qualified name with three node kinds --
/// `field_expression` for the expression `pm.Exception.parseFrom`,
/// `stable_type_identifier` for the type `t: pm.Exception`, and
/// `stable_identifier` for the pattern `case pm.Exception.CODE` -- so read the
/// prefix from each rather than from the source text.
fn written_qualifier_segments(node: Node<'_>, source: &str) -> Option<Vec<String>> {
    let parent = node.parent()?;
    match parent.kind() {
        "field_expression" => {
            if parent.child_by_field_name("field") != Some(node) {
                return None;
            }
            qualified_path_segments(parent.child_by_field_name("value")?, source)
        }
        "stable_type_identifier" | "stable_identifier" => {
            let mut cursor = parent.walk();
            let children = parent.named_children(&mut cursor).collect::<Vec<_>>();
            let (last, prefix) = children.split_last()?;
            if *last != node {
                return None;
            }
            let mut segments = Vec::new();
            for child in prefix {
                segments.extend(qualified_path_segments(*child, source)?);
            }
            (!segments.is_empty()).then_some(segments)
        }
        _ => None,
    }
}

/// The dotted path a qualified-name node spells, read from the AST. `None` when
/// any part of it is not a plain name: a call, a type application or a `this`
/// is a term whose type this scan does not resolve, and reporting it as a path
/// would attribute a site to a declaration the source never named.
fn qualified_path_segments(node: Node<'_>, source: &str) -> Option<Vec<String>> {
    let mut segments = Vec::new();
    let mut stack = vec![node];
    while let Some(current) = stack.pop() {
        match current.kind() {
            "identifier" | "type_identifier" | "operator_identifier" => {
                let segment = node_text(current, source).trim().trim_end_matches('$');
                if segment.is_empty() {
                    return None;
                }
                segments.push(segment.to_string());
            }
            "field_expression" | "stable_type_identifier" | "stable_identifier" => {
                let mut cursor = current.walk();
                let mut children = current.named_children(&mut cursor).collect::<Vec<_>>();
                children.reverse();
                stack.extend(children);
            }
            _ => return None,
        }
    }
    (!segments.is_empty()).then_some(segments)
}

/// Whether the prefix written before the target's own name denotes the path
/// that name has to follow: the target's package for a top-level type, the
/// package plus the owner chain for a nested one.
fn qualifier_denotes_target_owner(
    node: Node<'_>,
    segments: &[String],
    ctx: &ScalaJavaScanCtx<'_, '_>,
) -> bool {
    let Some(head) = segments.first() else {
        return false;
    };
    if qualifier_matches_target_owner(&segments.join("."), ctx.spec) {
        return true;
    }
    if is_term_shadowed(ctx, head) || is_type_shadowed(ctx, head) {
        return false;
    }
    let owner_prefix = target_owner_prefix(&ctx.spec.owner);
    ctx.bindings
        .denoted_paths(segments, ctx.packages.prefixes_at(node.start_byte()))
        .contains(&owner_prefix)
}

/// The dotted path the target's own simple name is written after.
fn target_owner_prefix(target: &CodeUnit) -> String {
    match nested_owner_qualifier(target) {
        Some(owner) => join_qualified(target.package_name(), owner),
        None => target.package_name().to_string(),
    }
}

/// `new JavaClass(..)` written from Scala. Tree-sitter models the constructed
/// type as a child of `instance_expression`, wrapped in the qualified, generic
/// and annotated type nodes when the source spells any of those, so the type
/// leaf reaches the `new` only through that chain.
fn maybe_record_java_constructor_hit(node: Node<'_>, ctx: &mut ScalaJavaScanCtx<'_, '_>) {
    let Some(constructed) = constructed_type_root(node) else {
        return;
    };
    if !scala_name_denotes_target_owner(node, ctx) {
        return;
    }
    // The argument list belongs to the `instance_expression`, which the shape
    // helper reads from the outermost type node rather than from the leaf.
    let Some(call_shape) = call_site_shape_for_reference(constructed) else {
        return;
    };
    if call_shape.type_arguments_only || call_shape.lists.len() != 1 {
        return;
    }
    let Some(expected_arities) = ctx.spec.callable_arities.as_ref() else {
        return;
    };
    let actual_arity = call_shape.lists[0].arity;
    if expected_arities
        .iter()
        .copied()
        .any(|expected| expected.accepts(actual_arity))
    {
        push_scala_hit(node, ctx);
    }
}

/// The outermost type node of a `new` expression, reached from the type leaf,
/// or `None` when the leaf is not the constructed type of any `new`. Only the
/// last segment of a qualified type is the type itself; `lib` in
/// `new lib.Stats()` names a package.
fn constructed_type_root(node: Node<'_>) -> Option<Node<'_>> {
    let mut constructed = node;
    loop {
        let parent = constructed.parent()?;
        if parent.kind() == "instance_expression" {
            return Some(constructed);
        }
        let wraps_the_constructed_type = match parent.kind() {
            "stable_type_identifier" => {
                let mut cursor = parent.walk();
                parent.named_children(&mut cursor).last() == Some(constructed)
            }
            "generic_type" | "applied_constructor_type" | "annotated_type" | "type" => {
                parent.child_by_field_name("type") == Some(constructed)
                    || parent.named_child(0) == Some(constructed)
            }
            _ => false,
        };
        if !wraps_the_constructed_type {
            return None;
        }
        constructed = parent;
    }
}

fn java_type_import_owner_matches_target(node: Node<'_>, ctx: &ScalaJavaScanCtx<'_, '_>) -> bool {
    if node_text(node, ctx.source).trim_end_matches('$') != ctx.spec.owner.identifier() {
        return false;
    }
    let mut ancestor = node.parent();
    let import = loop {
        let Some(current) = ancestor else {
            return false;
        };
        if current.kind() == "import_declaration" {
            break current;
        }
        ancestor = current.parent();
    };
    let mut segments = Vec::new();
    let mut cursor = import.walk();
    for child in import.named_children(&mut cursor).filter(|child| {
        matches!(
            child.kind(),
            "identifier" | "type_identifier" | "operator_identifier"
        )
    }) {
        let segment = node_text(child, ctx.source).trim();
        if segment.is_empty() {
            return false;
        }
        if segment != "_root_" {
            segments.push(segment.to_string());
        }
        if child == node {
            let path = segments.join(".");
            return path == ctx.spec.owner.fq_name()
                || scala_file_package(ctx.scala, ctx.file).is_some_and(|package| {
                    format!("{package}.{path}") == ctx.spec.owner.fq_name()
                });
        }
    }
    false
}

/// The leading segment of a qualified path. Tree-sitter models the three Scala
/// positions of `Stats.Type` with three node kinds -- `field_expression` for
/// the expression `Stats.Type.NEWADDR`, `stable_type_identifier` for the type
/// `t: Stats.Type`, and `stable_identifier` for the pattern
/// `case Stats.Type.NEWADDR` -- and in all three the leading segment is the
/// first named child. Accepting only the expression form left the qualifier of
/// a Java nested type unrecorded in type and pattern position (#1855).
fn is_leading_path_segment(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        matches!(
            parent.kind(),
            "field_expression" | "stable_type_identifier" | "stable_identifier"
        ) && parent.named_child(0) == Some(node)
    })
}

fn maybe_record_java_static_field_hit(node: Node<'_>, ctx: &mut ScalaJavaScanCtx<'_, '_>) {
    if is_target_member_identifier(node, ctx)
        && scala_static_receiver_matches_target_owner(node, ctx)
    {
        push_scala_hit(node, ctx);
    }
}

fn maybe_record_java_static_method_hit(node: Node<'_>, ctx: &mut ScalaJavaScanCtx<'_, '_>) {
    if !is_target_member_identifier(node, ctx)
        || !scala_static_receiver_matches_target_owner(node, ctx)
    {
        return;
    }
    let Some(call_shape) = call_site_shape_for_reference(node) else {
        // Scala writes a zero-argument Java call, and an eta-expanded method
        // value, with no argument list at all -- `Stats.origin`, never
        // `Stats.origin()`. There is no shape to select an overload with, and
        // the owner-qualified member name proved the reference already, so the
        // site is recorded against the whole target family.
        push_scala_hit(node, ctx);
        return;
    };
    if call_shape.type_arguments_only || call_shape.lists.len() != 1 {
        return;
    }
    let Some(expected_arities) = ctx.spec.callable_arities.as_ref() else {
        return;
    };
    let actual_arity = call_shape.lists[0].arity;
    if expected_arities
        .iter()
        .copied()
        .any(|expected| expected.accepts(actual_arity))
    {
        push_scala_hit(node, ctx);
    }
}

fn is_target_member_identifier(node: Node<'_>, ctx: &ScalaJavaScanCtx<'_, '_>) -> bool {
    if has_ancestor_kind(node, "import_declaration") || is_declaration_name(node) {
        return false;
    }
    if node_text(node, ctx.source).trim_end_matches('$') != ctx.spec.member_name {
        return false;
    }
    node.parent().is_some_and(|parent| {
        parent.kind() == "field_expression" && parent.child_by_field_name("field") == Some(node)
    })
}

fn scala_static_receiver_matches_target_owner(
    node: Node<'_>,
    ctx: &ScalaJavaScanCtx<'_, '_>,
) -> bool {
    let Some(receiver) = member_qualifier_node(node) else {
        return false;
    };
    let Some(segments) = qualified_path_segments(receiver, ctx.source) else {
        return false;
    };
    let head = segments
        .first()
        .expect("a qualified path has at least one segment");
    if is_term_shadowed(ctx, head) || is_type_shadowed(ctx, head) {
        return false;
    }
    // The owner's own visible spelling, or the name an import rename binds it
    // to, stands alone as the receiver.
    if segments.len() == 1 && ctx.visibility.contains(head) {
        return true;
    }
    // Otherwise the receiver is a written path: an imported prefix followed by
    // the rest of the owner's nested chain, `Outer.Inner` in
    // `Outer.Inner.newBuilder()`, or the owner spelled out in full.
    let owner_fq_name = ctx.spec.owner.fq_name();
    ctx.bindings
        .denoted_paths(&segments, ctx.packages.prefixes_at(node.start_byte()))
        .contains(&owner_fq_name)
}

fn push_scala_hit(node: Node<'_>, ctx: &mut ScalaJavaScanCtx<'_, '_>) {
    *ctx.raw_match_count += 1;
    if *ctx.limit_exceeded {
        return;
    }

    let range = Range {
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: find_line_index_for_offset(ctx.line_starts, node.start_byte()),
        end_line: find_line_index_for_offset(ctx.line_starts, node.end_byte()),
    };
    let Some(enclosing) = ctx
        .owners
        .enclosing_code_unit(ctx.file, &range)
        .or_else(|| nearest_scala_declaration(ctx.scala, ctx.file))
    else {
        return;
    };

    let line_idx = range.start_line;
    ctx.hits.insert(usage_hit(
        ctx.file,
        line_idx,
        range.start_byte,
        range.end_byte,
        enclosing,
        snippet_around_line(ctx.source, ctx.line_starts, line_idx, SNIPPET_CONTEXT_LINES),
    ));
    if brokk_bifrost_core::analyzer::usages::common::external_usage_hit_count(ctx.hits)
        > ctx.max_usages
    {
        *ctx.limit_exceeded = true;
    }
}

fn nearest_scala_declaration(scala: &dyn ScalaSource, file: &ProjectFile) -> Option<CodeUnit> {
    scala.declarations(file).into_iter().next()
}

fn scala_file_package(scala: &dyn ScalaSource, file: &ProjectFile) -> Option<String> {
    scala
        .declarations(file)
        .into_iter()
        .next()
        .map(|unit| unit.package_name().to_string())
}

fn is_top_level_type(target: &CodeUnit) -> bool {
    !target.short_name().contains('.')
}

fn nested_owner_qualifier(target: &CodeUnit) -> Option<&str> {
    target.short_name().rsplit_once('.').map(|(owner, _)| owner) // fqname-M4: package-less short_name owner; fq.parent() would render the package-qualified owner
}

fn qualifier_matches_target_owner(qualifier: &str, spec: &TargetSpec) -> bool {
    if is_top_level_type(&spec.owner) {
        return qualifier == spec.owner.package_name();
    }

    let Some(owner_qualifier) = nested_owner_qualifier(&spec.owner) else {
        return false;
    };
    qualifier == owner_qualifier
        || qualifier == format!("{}.{}", spec.owner.package_name(), owner_qualifier)
}

fn seed_type_shadow(node: Node<'_>, ctx: &mut ScalaJavaScanCtx<'_, '_>) {
    if !matches!(
        node.kind(),
        "class_definition" | "object_definition" | "trait_definition" | "enum_definition"
    ) {
        return;
    }
    let Some(name) = node.child_by_field_name("name") else {
        return;
    };
    let name = node_text(name, ctx.source).trim_end_matches('$');
    if !name.is_empty()
        && (ctx.visibility.contains(name) || ctx.bindings.binds(name))
        && let Some(scope) = ctx.type_shadow_scopes.last_mut()
    {
        scope.insert(name.to_string());
    }
}

fn seed_term_shadow(node: Node<'_>, ctx: &mut ScalaJavaScanCtx<'_, '_>) {
    match node.kind() {
        "parameter" | "class_parameter" | "function_definition" => {
            let Some(name) = node.child_by_field_name("name") else {
                return;
            };
            insert_term_shadow(name, ctx);
        }
        "val_definition" | "var_definition" => {
            let Some(pattern) = node.child_by_field_name("pattern") else {
                return;
            };
            for name in scala_definition_binder_names(pattern, ctx.source) {
                if let Some(scope) = ctx.term_shadow_scopes.last_mut() {
                    scope.insert(name.to_string());
                }
            }
        }
        _ => {}
    }
}

fn insert_term_shadow(node: Node<'_>, ctx: &mut ScalaJavaScanCtx<'_, '_>) {
    let name = node_text(node, ctx.source).trim();
    if !name.is_empty()
        && let Some(scope) = ctx.term_shadow_scopes.last_mut()
    {
        scope.insert(name.to_string());
    }
}

fn enters_local_scope(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "class_definition"
            | "object_definition"
            | "trait_definition"
            | "enum_definition"
            | "function_definition"
            | "block"
            | "block_expression"
            | "case_clause"
            | "lambda_expression"
            | "anonymous_function"
    )
}

fn is_type_shadowed(ctx: &ScalaJavaScanCtx<'_, '_>, name: &str) -> bool {
    ctx.type_shadow_scopes
        .iter()
        .rev()
        .any(|scope| scope.contains(name))
}

fn is_term_shadowed(ctx: &ScalaJavaScanCtx<'_, '_>, name: &str) -> bool {
    ctx.term_shadow_scopes
        .iter()
        .rev()
        .any(|scope| scope.contains(name))
}
