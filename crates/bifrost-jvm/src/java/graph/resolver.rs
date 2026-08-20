use super::JavaGraphSource;
use super::extractor::{MethodCallReturnCacheKey, ScanCtx};
use super::hits::enclosing_context;
use super::return_type::{
    FileReturnCache, JavaReturnTypeContext, LexicalTypeResolution, METHOD_RECEIVER_CHAIN_LIMIT,
    MethodAnonymousReturnCache, MethodReturnCache, is_java_nominal_type_node,
    java_call_answering_units, java_lexical_type_from_declaration, java_lexical_type_from_node,
    java_type_name_from_node, merge_receiver_type_outcomes,
    method_anonymous_return_type_for_owner_fqn, method_return_type_for_owner_fqns,
};
use crate::java::graph_support::{
    JavaSource, normalize_java_type_text, resolve_java_usage_type_name,
    resolve_java_usage_type_name_in,
};
use crate::java::hierarchy::java_nearest_declaring_ancestors;
use brokk_bifrost_core::analyzer::model::{CallableArity, CodeUnit, Language, ProjectFile};
use brokk_bifrost_core::analyzer::query_token::QueryToken;
use brokk_bifrost_core::analyzer::symbol_path::parse_symbol_path;
pub use brokk_bifrost_core::analyzer::usages::common::node_text;
use brokk_bifrost_core::analyzer::usages::local_inference::LocalInferenceEngine;
use brokk_bifrost_core::analyzer::usages::receiver_analysis::ReceiverAnalysisOutcome;
use brokk_bifrost_core::hash::HashSet;
use tree_sitter::Node;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TargetKind {
    Type,
    Constructor,
    Method,
    Field,
}

pub struct TargetSpec {
    pub target: CodeUnit,
    pub targets: HashSet<CodeUnit>,
    pub kind: TargetKind,
    pub owner: CodeUnit,
    pub receiver_owner_fq_names: HashSet<String>,
    pub declaration_owner_fq_names: HashSet<String>,
    pub member_name: String,
    pub callable_arities: Option<HashSet<CallableArity>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ReceiverTargetMatch {
    Matched,
    Incompatible,
    Unresolved,
}

impl TargetSpec {
    pub fn from_targets(
        analyzer: &dyn JavaSource,
        token: QueryToken<'_>,
        targets: &[CodeUnit],
    ) -> Option<Self> {
        let mut spec = Self::from_target(analyzer, token, targets.first()?)?;
        spec.targets.extend(targets.iter().cloned());
        if let Some(arities) = spec.callable_arities.as_mut() {
            for target in &targets[1..] {
                if target.fq_name() == spec.target.fq_name() && target.is_function() {
                    arities.insert(java_callable_arity(analyzer, target));
                }
            }
        }
        Some(spec)
    }

    pub fn from_target(
        analyzer: &dyn JavaSource,
        token: QueryToken<'_>,
        target: &CodeUnit,
    ) -> Option<Self> {
        if target.is_class() {
            let fq_name = target.fq_name();
            return Some(Self {
                target: target.clone(),
                targets: HashSet::from_iter([target.clone()]),
                kind: TargetKind::Type,
                owner: target.clone(),
                receiver_owner_fq_names: [fq_name.clone()].into_iter().collect(),
                declaration_owner_fq_names: [fq_name].into_iter().collect(),
                member_name: target.identifier().to_string(),
                callable_arities: None,
            });
        }

        let owner = analyzer.parent_of(target)?;
        let kind = if target.is_field() {
            TargetKind::Field
        } else if target.identifier() == owner.identifier() {
            TargetKind::Constructor
        } else {
            TargetKind::Method
        };

        let owner_sets = target_owner_sets(analyzer, token, target, &owner, kind);

        Some(Self {
            target: target.clone(),
            targets: HashSet::from_iter([target.clone()]),
            kind,
            receiver_owner_fq_names: owner_sets.receiver,
            declaration_owner_fq_names: owner_sets.declarations,
            member_name: target.identifier().to_string(),
            callable_arities: (kind == TargetKind::Method || kind == TargetKind::Constructor)
                .then(|| HashSet::from_iter([java_callable_arity(analyzer, target)])),
            owner,
        })
    }
}

/// Return the receiver type of a constructor method reference such as
/// `Request::new`. Tree-sitter models `new` as an unnamed keyword child, so it
/// cannot be recovered through the named-child method-reference helper used for
/// ordinary `Type::method` references.
pub fn constructor_method_reference_receiver(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() != "method_reference" {
        return None;
    }
    let mut cursor = node.walk();
    let children: Vec<_> = node.children(&mut cursor).collect();
    if !children.iter().any(|child| child.kind() == "new") {
        return None;
    }
    children.into_iter().find(|child| child.is_named())
}

struct TargetOwnerSets {
    receiver: HashSet<String>,
    declarations: HashSet<String>,
}

fn target_owner_sets(
    analyzer: &dyn JavaSource,
    token: QueryToken<'_>,
    target: &CodeUnit,
    owner: &CodeUnit,
    kind: TargetKind,
) -> TargetOwnerSets {
    let receiver = HashSet::from_iter([owner.fq_name()]);
    let mut declarations = HashSet::from_iter([owner.fq_name()]);
    if kind != TargetKind::Method {
        return TargetOwnerSets {
            receiver,
            declarations,
        };
    }
    for descendant in analyzer.get_descendants(owner) {
        if java_owner_declares_matching_method(analyzer, token, &descendant, target) {
            declarations.insert(descendant.fq_name());
        }
    }
    for ancestor in analyzer.get_ancestors(owner) {
        if java_owner_declares_matching_method(analyzer, token, &ancestor, target) {
            declarations.insert(ancestor.fq_name());
        }
    }
    TargetOwnerSets {
        receiver,
        declarations,
    }
}

fn java_owner_declares_matching_method(
    analyzer: &dyn JavaSource,
    token: QueryToken<'_>,
    owner: &CodeUnit,
    target: &CodeUnit,
) -> bool {
    analyzer
        .usage_definitions(token)
        .fqn(&format!("{}.{}", owner.fq_name(), target.identifier()))
        .iter()
        .any(|unit| unit.is_function() && java_method_signatures_match(analyzer, target, unit))
}

pub fn java_method_signatures_match(
    analyzer: &dyn JavaSource,
    target: &CodeUnit,
    candidate: &CodeUnit,
) -> bool {
    match (target.signature(), candidate.signature()) {
        (Some(target), Some(candidate)) => {
            normalize_java_signature(target) == normalize_java_signature(candidate)
        }
        _ => java_callable_arity(analyzer, target) == java_callable_arity(analyzer, candidate),
    }
}

pub fn java_callable_arity(analyzer: &dyn JavaSource, unit: &CodeUnit) -> CallableArity {
    analyzer
        .signature_metadata(unit)
        .first()
        .and_then(|metadata| metadata.callable_arity())
        .unwrap_or_else(|| CallableArity::exact(signature_arity(unit.signature())))
}

fn normalize_java_signature(signature: &str) -> String {
    signature.chars().filter(|ch| !ch.is_whitespace()).collect()
}

pub fn signature_arity(signature: Option<&str>) -> usize {
    let Some(signature) = signature else {
        return 0;
    };
    let inner = signature
        .strip_prefix('(')
        .and_then(|rest| rest.strip_suffix(')'))
        .unwrap_or(signature)
        .trim();
    if inner.is_empty() {
        return 0;
    }
    inner.split(',').count()
}

pub fn seed_class_binding(
    java: &dyn JavaSource,
    token: QueryToken<'_>,
    file: &ProjectFile,
    spec: &TargetSpec,
    bindings: &mut LocalInferenceEngine<String>,
) {
    if spec.kind == TargetKind::Type
        || resolve_java_usage_type_name(java, token, file, spec.owner.identifier())
            .is_some_and(|resolved| resolved.fq_name() == spec.owner.fq_name())
    {
        bindings.seed_symbol(spec.owner.identifier().to_string(), spec.owner.fq_name());
    }
}

impl JavaReturnTypeContext for ScanCtx<'_> {
    fn java(&self) -> &dyn JavaSource {
        self.java
    }

    fn file(&self) -> &ProjectFile {
        self.file
    }

    fn source(&self) -> &str {
        self.source
    }

    fn root(&self) -> Node<'_> {
        self.root
    }

    fn method_return_cache(&self) -> &MethodReturnCache {
        self.method_return_cache
    }

    fn method_anonymous_return_cache(&self) -> &MethodAnonymousReturnCache {
        self.method_anonymous_return_cache
    }

    fn file_return_cache(&self) -> &FileReturnCache {
        self.file_return_cache
    }
}

pub fn receiver_matches_target(
    receiver: Node<'_>,
    token: QueryToken<'_>,
    ctx: &mut ScanCtx<'_>,
) -> ReceiverTargetMatch {
    match receiver.kind() {
        "identifier" => {
            let name = node_text(receiver, ctx.source);
            match ctx.bindings.resolve_symbol(name).as_precise() {
                Some(targets) => receiver_fq_names_match_target(targets.iter(), token, ctx),
                // A simple name that declares no value here can still name a
                // type: `InstanceMode.MANAGER` written inside `InstanceMode`
                // reads a nested type the file scope alone cannot name, so the
                // lexical chain has to answer it.
                None if !ctx.bindings.is_shadowed(name) => {
                    resolve_type_from_node(receiver, token, ctx)
                        .map(|resolved| receiver_type_matches_target(&resolved, token, ctx))
                        .unwrap_or(ReceiverTargetMatch::Unresolved)
                }
                None => ReceiverTargetMatch::Unresolved,
            }
        }
        "type_identifier" | "scoped_type_identifier" | "generic_type" => {
            resolve_type_from_node(receiver, token, ctx)
                .map(|resolved| receiver_type_matches_target(&resolved, token, ctx))
                .unwrap_or(ReceiverTargetMatch::Unresolved)
        }
        "object_creation_expression" => receiver
            .child_by_field_name("type")
            .and_then(|type_node| resolve_type_from_node(type_node, token, ctx))
            .map(|resolved| receiver_type_matches_target(&resolved, token, ctx))
            .unwrap_or(ReceiverTargetMatch::Unresolved),
        "method_invocation" => {
            let match_result = method_invocation_return_type(receiver, token, ctx)
                .map(|resolved| receiver_type_matches_target(&resolved, token, ctx))
                .unwrap_or(ReceiverTargetMatch::Unresolved);
            if match_result == ReceiverTargetMatch::Matched {
                match_result
            } else {
                method_invocation_anonymous_return_match(receiver, token, ctx)
                    .unwrap_or(match_result)
            }
        }
        "this" | "super" => {
            if owner_matches_target_context(receiver, token, ctx)
                || anonymous_creation_context_matches_target(receiver, token, ctx)
            {
                ReceiverTargetMatch::Matched
            } else {
                ReceiverTargetMatch::Unresolved
            }
        }
        "field_access" => field_access_receiver_type(receiver, token, ctx)
            .map(|resolved| receiver_type_matches_target(&resolved, token, ctx))
            .unwrap_or(ReceiverTargetMatch::Unresolved),
        _ => ReceiverTargetMatch::Unresolved,
    }
}

/// The class a Java `field_access` receiver names.
///
/// The same syntax spells two different things. `Settings.Basic` is a nested
/// *type* path, which [`resolve_field_access_type`] answers from declarations.
/// `config.mode` is a *value*: it reads a field, and its static type is that
/// field's declared type. The receiver matcher could only do the first, so a
/// switch selector written as a field read left every case label under it
/// unclaimed even though the forward side binds them (#2162).
fn field_access_receiver_type(
    node: Node<'_>,
    token: QueryToken<'_>,
    ctx: &ScanCtx<'_>,
) -> Option<CodeUnit> {
    resolve_field_access_type(
        node,
        ctx.source,
        |base| {
            let name = node_text(base, ctx.source);
            if ctx.bindings.is_shadowed(name) {
                Err(())
            } else {
                Ok(resolve_type_from_node(base, token, ctx))
            }
        },
        |qualified| ctx.resolve_realm_type_name(qualified),
        |owner, name| nested_type_for_owner(owner, name, ctx),
    )
    .or_else(|| field_access_value_type(node, token, ctx, 0))
}

/// The class a `field_access` denotes when it is read as a value: the declared
/// type of the field its receiver's type declares.
fn field_access_value_type(
    node: Node<'_>,
    token: QueryToken<'_>,
    ctx: &ScanCtx<'_>,
    depth: usize,
) -> Option<CodeUnit> {
    if depth > METHOD_RECEIVER_CHAIN_LIMIT {
        return None;
    }
    let field_node = node.child_by_field_name("field")?;
    let field = node_text(field_node, ctx.source);
    if field.is_empty() {
        return None;
    }
    let object = node.child_by_field_name("object")?;
    let owner = receiver_type_from_node_at_depth(object, token, ctx, depth + 1)?;
    java_field_declared_type(&owner, token, field, ctx)
}

/// The class named by the declared type of `owner`'s field `field`.
///
/// A field's declared type is written in the field's own compilation unit, so
/// its simple name must resolve through that file's nesting, imports and
/// package -- never through the imports of whatever file reads the field. The
/// forward resolver learned this in #2043 for the same selector shape; this is
/// the same rule on the inverse side.
fn java_field_declared_type(
    owner: &CodeUnit,
    token: QueryToken<'_>,
    field: &str,
    ctx: &ScanCtx<'_>,
) -> Option<CodeUnit> {
    let mut scopes = vec![owner.clone()];
    if let Some(provider) = ctx.graph.hierarchy {
        scopes.extend(provider.get_ancestors(owner));
    }
    for scope in scopes {
        let candidates =
            ctx.java
                .usage_definitions(token)
                .fqn(&format!("{}.{}", scope.fq_name(), field));
        if let Some(unit) = candidates.iter().find(|unit| unit.is_field()) {
            let declared = ctx
                .java
                .signature_metadata(unit)
                .into_iter()
                .find_map(|metadata| metadata.return_type_text().map(str::to_owned))?;
            let spelled = normalize_java_type_text(&declared);
            // The declaration's own lexical chain binds a simple name first --
            // a sibling nested type such as `MultiMap.MultiMapEntry` is written
            // unqualified inside `MultiMap` and names no file-scope type -- and
            // only then the declaring file's imports and package.
            return match java_lexical_type_from_declaration(
                ctx.java,
                token,
                unit,
                &parse_symbol_path(Language::Java, spelled),
            ) {
                LexicalTypeResolution::Resolved(resolved) => Some(resolved),
                LexicalTypeResolution::Blocked => None,
                LexicalTypeResolution::NotFound => ctx.graph.with_definitions(|definitions| {
                    resolve_java_usage_type_name_in(
                        ctx.java,
                        ctx.graph.token,
                        definitions,
                        unit.source(),
                        spelled,
                    )
                }),
            };
        }
        if let Some(nested) = candidates.into_iter().find(CodeUnit::is_class) {
            return Some(nested);
        }
    }
    None
}

fn receiver_fq_names_match_target<'a>(
    fq_names: impl Iterator<Item = &'a String>,
    token: QueryToken<'_>,
    ctx: &ScanCtx<'_>,
) -> ReceiverTargetMatch {
    let outcomes: Vec<_> = fq_names
        .filter_map(|fq_name| class_definition(ctx, fq_name))
        .map(|resolved| receiver_type_matches_target(&resolved, token, ctx))
        .collect();
    if outcomes.contains(&ReceiverTargetMatch::Matched) {
        ReceiverTargetMatch::Matched
    } else if outcomes
        .iter()
        .all(|outcome| *outcome == ReceiverTargetMatch::Incompatible)
        && !outcomes.is_empty()
    {
        ReceiverTargetMatch::Incompatible
    } else {
        ReceiverTargetMatch::Unresolved
    }
}

pub fn receiver_type_matches_target(
    receiver_type: &CodeUnit,
    token: QueryToken<'_>,
    ctx: &ScanCtx<'_>,
) -> ReceiverTargetMatch {
    let receiver_fq_name = receiver_type.fq_name();
    if let Some(cached) = ctx
        .receiver_target_match_cache
        .borrow()
        .get(&receiver_fq_name)
    {
        return *cached;
    }
    let resolved = receiver_type_matches_target_uncached(receiver_type, token, ctx);
    ctx.receiver_target_match_cache
        .borrow_mut()
        .insert(receiver_fq_name, resolved);
    resolved
}

fn receiver_type_matches_target_uncached(
    receiver_type: &CodeUnit,
    token: QueryToken<'_>,
    ctx: &ScanCtx<'_>,
) -> ReceiverTargetMatch {
    if ctx
        .spec
        .receiver_owner_fq_names
        .contains(&receiver_type.fq_name())
    {
        return ReceiverTargetMatch::Matched;
    }

    let Some(provider) = ctx.graph.hierarchy else {
        return ReceiverTargetMatch::Unresolved;
    };
    if ctx.spec.kind == TargetKind::Method {
        if java_owner_declares_matching_method(ctx.java, token, receiver_type, &ctx.spec.target) {
            return ReceiverTargetMatch::Incompatible;
        }
        if !provider
            .get_ancestors(receiver_type)
            .iter()
            .any(|ancestor| ancestor == &ctx.spec.owner)
        {
            return ReceiverTargetMatch::Incompatible;
        }
        if java_owner_declares_same_arity_overload(ctx.java, token, receiver_type, &ctx.spec.target)
        {
            return ReceiverTargetMatch::Unresolved;
        }
        if provider
            .get_ancestors(receiver_type)
            .iter()
            .filter(|ancestor| *ancestor != &ctx.spec.owner)
            .any(|ancestor| {
                java_owner_declares_same_arity_overload(ctx.java, token, ancestor, &ctx.spec.target)
            })
        {
            return ReceiverTargetMatch::Unresolved;
        }
        if nearest_declaring_ancestor_matches_target(ctx, receiver_type, |ancestor| {
            java_owner_declares_matching_method(ctx.java, token, ancestor, &ctx.spec.target)
        })
        .unwrap_or(false)
        {
            return ReceiverTargetMatch::Matched;
        }
    }
    if ctx.spec.kind == TargetKind::Field {
        // A field is inherited, not overridden: `derived.shared` reads the
        // `shared` its nearest declaring supertype declares. A field the
        // receiver's own type declares hides that one (JLS 8.3), so it is a
        // different field with the same spelling.
        if !owner_declares_target_field(receiver_type, token, ctx)
            && nearest_declaring_ancestor_matches_target(ctx, receiver_type, |ancestor| {
                owner_declares_target_field(ancestor, token, ctx)
            })
            .unwrap_or(false)
        {
            return ReceiverTargetMatch::Matched;
        }
    }
    ReceiverTargetMatch::Incompatible
}

fn java_owner_declares_same_arity_overload(
    analyzer: &dyn JavaSource,
    token: QueryToken<'_>,
    owner: &CodeUnit,
    target: &CodeUnit,
) -> bool {
    let target_arity = java_callable_arity(analyzer, target);
    analyzer
        .usage_definitions(token)
        .fqn(&format!("{}.{}", owner.fq_name(), target.identifier()))
        .iter()
        .any(|unit| {
            unit.is_function()
                && java_callable_arity(analyzer, unit) == target_arity
                && !java_method_signatures_match(analyzer, target, unit)
        })
}

fn method_invocation_anonymous_return_match(
    node: Node<'_>,
    token: QueryToken<'_>,
    ctx: &ScanCtx<'_>,
) -> Option<ReceiverTargetMatch> {
    let name_node = node.child_by_field_name("name")?;
    let name = node_text(name_node, ctx.source);
    if name.is_empty() {
        return None;
    }
    let owner = match node.child_by_field_name("object") {
        Some(object) => receiver_type_from_node_at_depth(object, token, ctx, 1),
        None => enclosing_owner(node, ctx),
    };
    let owner = owner?;
    let arity = argument_list_arity(node);
    if let Some(outcome) =
        method_anonymous_return_type_for_owner_fqn(&owner.fq_name(), token, name, arity, ctx)
    {
        return anonymous_return_types_match_target(outcome, token, ctx);
    }
    let provider = ctx.graph.hierarchy?;
    let outcomes = provider
        .get_ancestors(&owner)
        .into_iter()
        .filter_map(|ancestor| {
            method_anonymous_return_type_for_owner_fqn(&ancestor.fq_name(), token, name, arity, ctx)
        })
        .collect::<Vec<_>>();
    (!outcomes.is_empty()).then(|| {
        anonymous_return_types_match_target(merge_receiver_type_outcomes(outcomes), token, ctx)
    })?
}

fn anonymous_return_types_match_target(
    outcome: ReceiverAnalysisOutcome<String>,
    token: QueryToken<'_>,
    ctx: &ScanCtx<'_>,
) -> Option<ReceiverTargetMatch> {
    let targets = outcome.into_precise()?;
    let outcomes = targets
        .iter()
        .filter_map(|fq_name| class_definition(ctx, fq_name))
        .map(|receiver_type| receiver_type_matches_target(&receiver_type, token, ctx))
        .collect::<Vec<_>>();
    if outcomes.contains(&ReceiverTargetMatch::Matched) {
        Some(ReceiverTargetMatch::Matched)
    } else if outcomes.len() == targets.len() && !outcomes.is_empty() {
        // An inline anonymous object cannot be an unknown concrete subtype of
        // its declared nominal type: it is exactly the class being created.
        Some(ReceiverTargetMatch::Incompatible)
    } else {
        None
    }
}

pub fn has_proven_static_import(token: QueryToken<'_>, ctx: &ScanCtx<'_>) -> bool {
    let target_fq_name = ctx.spec.owner.fq_name();
    let mut target_visible = false;

    for import in (ctx.graph.import_statements)(ctx.file) {
        let trimmed = import.trim();
        if !trimmed.starts_with("import static ") {
            continue;
        }
        let path = trimmed
            .strip_prefix("import static ")
            .unwrap_or(trimmed)
            .trim_end_matches(';')
            .trim();

        if let Some(owner) = path.strip_suffix(".*") {
            if owner == target_fq_name {
                target_visible = true;
            } else if java_static_import_owner_matches_target(owner, token, ctx) {
                return false;
            }
            continue;
        }

        // `path` is a raw `import static a.b.C.member;` statement's dotted
        // target text; Java identifiers never contain a literal `.`, so
        // re-tokenizing with the shared structured splitter and rejoining
        // every part but the last with the same `.` reproduces
        // `rsplit_once('.')`'s (owner, member) split exactly.
        let segments = parse_symbol_path(Language::Java, path);
        let Some((member, owner_parts)) = segments.split_last() else {
            continue;
        };
        if owner_parts.is_empty() {
            continue;
        }
        if member.as_str() != ctx.spec.member_name.as_str() {
            continue;
        }
        let owner = owner_parts.join(".");
        if owner == target_fq_name {
            target_visible = true;
        } else if java_static_import_owner_matches_target(&owner, token, ctx) {
            return false;
        }
    }

    target_visible
}

fn java_static_import_owner_matches_target(
    owner_fq_name: &str,
    token: QueryToken<'_>,
    ctx: &ScanCtx<'_>,
) -> bool {
    ctx.java
        .usage_definitions(token)
        .fqn(&format!("{owner_fq_name}.{}", ctx.spec.member_name))
        .iter()
        .any(|candidate| java_static_import_candidate_matches_target(candidate, ctx))
}

fn java_static_import_candidate_matches_target(candidate: &CodeUnit, ctx: &ScanCtx<'_>) -> bool {
    match ctx.spec.kind {
        TargetKind::Field => candidate.is_field(),
        TargetKind::Method => {
            candidate.is_function() && java_static_import_callable_matches_target(candidate, ctx)
        }
        TargetKind::Type | TargetKind::Constructor => false,
    }
}

fn java_static_import_callable_matches_target(candidate: &CodeUnit, ctx: &ScanCtx<'_>) -> bool {
    if java_method_signatures_match(ctx.java, &ctx.spec.target, candidate) {
        return true;
    }
    let Some(expected_arities) = ctx.spec.callable_arities.as_ref() else {
        return false;
    };
    let candidate_arity = java_callable_arity(ctx.java, candidate);
    expected_arities.contains(&candidate_arity)
}

pub fn bare_method_context_matches_target(
    node: Node<'_>,
    token: QueryToken<'_>,
    ctx: &mut ScanCtx<'_>,
) -> bool {
    let context = enclosing_context(node, ctx);
    let Some(owner) = context.owner.as_ref() else {
        return false;
    };
    if owner.fq_name() == ctx.spec.owner.fq_name() {
        return true;
    }
    if java_owner_declares_matching_method(ctx.java, token, owner, &ctx.spec.target) {
        return false;
    }
    nearest_declaring_ancestor_matches_target(ctx, owner, |ancestor| {
        java_owner_declares_matching_method(ctx.java, token, ancestor, &ctx.spec.target)
    })
    .unwrap_or(false)
}

/// Whether a bare (simple-name) field read at `node` binds to the target field.
///
/// JLS 6.5.6.1 searches the innermost enclosing class's member scope first --
/// what it declares, then what it inherits -- and only if nothing there
/// declares the name does the search move out to the class that lexically
/// encloses it. The first scope that declares the name answers outright, so an
/// inner class with its own `type` hides an outer `type` and never reads the
/// target.
///
/// The scan used to stop at the innermost owner and its ancestors, so a nested
/// class reading an outer class's constant produced no hit at all. That is 148
/// of the 277 keys #2042 records, and flatbuffers' `FlexBuffers.Reference`
/// reading `FBT_BOOL` is the dense witness. #2046 gave the forward resolver
/// this same chain for a bare call.
pub fn bare_field_context_matches_target(
    node: Node<'_>,
    token: QueryToken<'_>,
    ctx: &mut ScanCtx<'_>,
) -> bool {
    let context = enclosing_context(node, ctx);
    let mut scope = context.owner.clone();
    let mut visited = HashSet::default();
    while let Some(owner) = scope {
        if !visited.insert(owner.fq_name()) {
            return false;
        }
        scope = ctx.java.parent_of(&owner);
        // An anonymous or local class is indexed under the method that writes
        // it (#2045), so a callable step is part of the chain, not the end of
        // it. Only a package ends the walk.
        if !owner.is_class() {
            continue;
        }
        if owner.fq_name() == ctx.spec.owner.fq_name() {
            return true;
        }
        if owner_declares_target_field(&owner, token, ctx) {
            return false;
        }
        if let Some(matched) = nearest_declaring_ancestor_matches_target(ctx, &owner, |ancestor| {
            owner_declares_target_field(ancestor, token, ctx)
        }) {
            return matched;
        }
    }
    false
}

fn owner_declares_target_field(owner: &CodeUnit, token: QueryToken<'_>, ctx: &ScanCtx<'_>) -> bool {
    ctx.java
        .usage_definitions(token)
        .fqn(&format!("{}.{}", owner.fq_name(), ctx.spec.member_name))
        .iter()
        .any(CodeUnit::is_field)
}

/// What `owner`'s inheritance says about the target member: `Some(true)` when
/// the nearest level that declares the name declares exactly the target,
/// `Some(false)` when that level declares something else, and `None` when no
/// ancestor declares the name at all. The caller distinguishes the last case
/// because a lexical search continues outward only when the whole member scope
/// -- inherited members included -- says nothing.
fn nearest_declaring_ancestor_matches_target(
    ctx: &ScanCtx<'_>,
    owner: &CodeUnit,
    declares_target_member: impl FnMut(&CodeUnit) -> bool,
) -> Option<bool> {
    let provider = ctx.graph.hierarchy?;
    let preferred =
        java_nearest_declaring_ancestors(ctx.java, provider, owner, declares_target_member)?;
    Some(preferred.len() == 1 && preferred[0].fq_name() == ctx.spec.owner.fq_name())
}

pub fn same_owner_context(node: Node<'_>, ctx: &mut ScanCtx<'_>) -> bool {
    enclosing_context(node, ctx)
        .owner
        .as_ref()
        .is_some_and(|owner| owner.fq_name() == ctx.spec.owner.fq_name())
}

pub fn owner_matches_target_context(
    node: Node<'_>,
    token: QueryToken<'_>,
    ctx: &mut ScanCtx<'_>,
) -> bool {
    let context = enclosing_context(node, ctx);
    let Some(owner) = context.owner.as_ref() else {
        return false;
    };
    receiver_type_matches_target(owner, token, ctx) == ReceiverTargetMatch::Matched
}

fn anonymous_creation_context_matches_target(
    node: Node<'_>,
    token: QueryToken<'_>,
    ctx: &ScanCtx<'_>,
) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == "object_creation_expression"
            && let Some(type_node) = parent.child_by_field_name("type")
            && resolve_type_from_node(type_node, token, ctx)
                .is_some_and(|resolved| resolved.fq_name() == ctx.spec.owner.fq_name())
        {
            return true;
        }
        current = parent.parent();
    }
    false
}

pub fn argument_list_arity(node: Node<'_>) -> usize {
    let Some(arguments) = node.child_by_field_name("arguments") else {
        return 0;
    };
    let mut cursor = arguments.walk();
    arguments
        .children(&mut cursor)
        .filter(|child| child.is_named() && !child.is_extra())
        .count()
}

pub fn resolve_type_from_node(
    node: Node<'_>,
    token: QueryToken<'_>,
    ctx: &ScanCtx<'_>,
) -> Option<CodeUnit> {
    if matches!(node.kind(), "scoped_type_identifier" | "scoped_identifier")
        && let Some(resolved) = resolve_nested_type_from_scoped_node(node, token, ctx)
    {
        return Some(resolved);
    }

    resolve_non_nested_type_from_node(node, token, ctx)
}

pub fn resolve_non_nested_type_from_node(
    node: Node<'_>,
    token: QueryToken<'_>,
    ctx: &ScanCtx<'_>,
) -> Option<CodeUnit> {
    match java_lexical_type_from_node(ctx.java, token, ctx.graph, ctx.file, ctx.source, node) {
        LexicalTypeResolution::Resolved(unit) => return Some(unit),
        LexicalTypeResolution::Blocked => return None,
        LexicalTypeResolution::NotFound => {}
    }

    let type_name = java_type_name_from_node(node, ctx.source)?;
    ctx.resolve_realm_type_name(&type_name)
}

/// Resolves each semantic class segment in a Java type reference, preserving the
/// exact token that named that segment. For example, `Service.Repository`
/// yields the `Service` token paired with `example.Service`, followed by the
/// `Repository` token paired with `example.Service.Repository`.
///
/// Package components deliberately do not appear: they cannot resolve to a
/// class identity on their own. Callers provide their resolution context so the
/// forward scanner and persisted edge builder use the same structured walk.
pub fn resolve_type_segments<'tree, ResolveNode, ResolveNested>(
    node: Node<'tree>,
    source: &str,
    mut resolve_node: ResolveNode,
    mut resolve_nested: ResolveNested,
) -> Vec<(CodeUnit, Node<'tree>)>
where
    ResolveNode: FnMut(Node<'tree>) -> Option<CodeUnit>,
    ResolveNested: FnMut(&CodeUnit, &str) -> Option<CodeUnit>,
{
    let mut prefixes = Vec::new();
    let mut current = node;
    loop {
        while matches!(
            current.kind(),
            "array_type" | "annotated_type" | "generic_type"
        ) {
            let Some(nominal) = nominal_type_child(current) else {
                return Vec::new();
            };
            current = nominal;
        }
        match current.kind() {
            "identifier" | "type_identifier" => {
                prefixes.push((current, current));
                break;
            }
            "scoped_identifier" | "scoped_type_identifier" => {
                let mut cursor = current.walk();
                let typed_children: Vec<_> = current
                    .named_children(&mut cursor)
                    .filter(|child| is_java_nominal_type_node(child.kind()))
                    .collect();
                let Some((name, qualifier)) = typed_children.split_last() else {
                    return Vec::new();
                };
                let Some(terminal) = terminal_type_node(*name) else {
                    return Vec::new();
                };
                prefixes.push((current, terminal));
                let Some(qualifier) = qualifier.last().copied() else {
                    break;
                };
                current = qualifier;
            }
            _ => return Vec::new(),
        }
    }
    prefixes.reverse();

    let mut segments = Vec::new();
    for (prefix, terminal) in prefixes {
        let name = node_text(terminal, source);
        if name.is_empty() {
            continue;
        }
        let resolved = segments
            .last()
            .and_then(|(owner, _)| resolve_nested(owner, name))
            .or_else(|| resolve_node(prefix));
        if let Some(resolved) = resolved {
            if segments.last().is_none_or(|(owner, _)| *owner != resolved) {
                segments.push((resolved, terminal));
            }
        } else if !segments.is_empty() {
            // Initial unresolved prefixes may be package components (for
            // example, `app` in `app.Service.Repository`), but an unresolved
            // segment after a class identity invalidates the remaining nested
            // path. Continuing would let a later name resolve from the stale
            // owner and create a false edge.
            break;
        }
    }
    segments
}

/// Resolve a method-reference receiver that tree-sitter represents as a
/// `field_access`, such as `Settings.Basic` in `Settings.Basic::enabled`.
/// Components come exclusively from AST identifier fields. Resolution must
/// establish a real type prefix and then a declaration-backed nested type for
/// every remaining component, so ordinary dotted value expressions do not
/// become static type references.
pub fn resolve_field_access_type<ResolveBase, ResolveQualified, ResolveNested>(
    node: Node<'_>,
    source: &str,
    resolve_base: ResolveBase,
    resolve_qualified: ResolveQualified,
    resolve_nested: ResolveNested,
) -> Option<CodeUnit>
where
    ResolveBase: FnMut(Node<'_>) -> Result<Option<CodeUnit>, ()>,
    ResolveQualified: FnMut(&str) -> Option<CodeUnit>,
    ResolveNested: FnMut(&CodeUnit, &str) -> Option<CodeUnit>,
{
    let terminal = node.child_by_field_name("field")?;
    resolve_field_access_type_segments(
        node,
        source,
        resolve_base,
        resolve_qualified,
        resolve_nested,
    )
    .into_iter()
    .last()
    .filter(|(_, segment)| segment.id() == terminal.id())
    .map(|(resolved, _)| resolved)
}

/// Resolve every declaration-backed type prefix in an expression-shaped Java
/// selector. Unlike [`resolve_field_access_type`], this intentionally retains
/// a proven intermediate type when a later component is an ordinary field or
/// method member. The exact identifier node paired with each type lets callers
/// report `Feature` in `JSONWriter.Feature.FieldBased` without misclassifying
/// `FieldBased` itself as a type.
pub fn resolve_field_access_type_segments<'tree, ResolveBase, ResolveQualified, ResolveNested>(
    node: Node<'tree>,
    source: &str,
    mut resolve_base: ResolveBase,
    mut resolve_qualified: ResolveQualified,
    mut resolve_nested: ResolveNested,
) -> Vec<(CodeUnit, Node<'tree>)>
where
    ResolveBase: FnMut(Node<'tree>) -> Result<Option<CodeUnit>, ()>,
    ResolveQualified: FnMut(&str) -> Option<CodeUnit>,
    ResolveNested: FnMut(&CodeUnit, &str) -> Option<CodeUnit>,
{
    if node.kind() != "field_access" {
        return Vec::new();
    }

    let mut components = Vec::new();
    let mut current = node;
    while current.kind() == "field_access" {
        let Some(field) = current.child_by_field_name("field") else {
            return Vec::new();
        };
        if field.kind() != "identifier" {
            return Vec::new();
        }
        components.push(field);
        let Some(object) = current.child_by_field_name("object") else {
            return Vec::new();
        };
        current = object;
    }
    if !matches!(current.kind(), "identifier" | "type_identifier") {
        return Vec::new();
    }
    components.push(current);
    components.reverse();

    let mut qualified = node_text(components[0], source).to_string();
    if qualified.is_empty() {
        return Vec::new();
    }
    let Ok(mut owner) = resolve_base(components[0]) else {
        return Vec::new();
    };
    let mut segments = Vec::new();
    let mut consumed = 1;
    if let Some(resolved) = owner.as_ref() {
        segments.push((resolved.clone(), components[0]));
    }
    if owner.is_none() {
        for (index, component) in components[1..].iter().enumerate() {
            let name = node_text(*component, source);
            if name.is_empty() {
                return Vec::new();
            }
            qualified.push('.');
            qualified.push_str(name);
            if let Some(resolved) = resolve_qualified(&qualified) {
                segments.push((resolved.clone(), *component));
                owner = Some(resolved);
                consumed = index + 2;
                break;
            }
        }
    }

    let Some(mut owner) = owner else {
        return Vec::new();
    };
    for component in &components[consumed..] {
        let name = node_text(*component, source);
        if name.is_empty() {
            return Vec::new();
        }
        let Some(nested) = resolve_nested(&owner, name) else {
            break;
        };
        owner = nested;
        segments.push((owner.clone(), *component));
    }
    segments
}

fn nominal_type_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| is_java_nominal_type_node(child.kind()))
}

fn terminal_type_node(node: Node<'_>) -> Option<Node<'_>> {
    let mut current = node;
    loop {
        match current.kind() {
            "identifier" | "type_identifier" => return Some(current),
            "array_type" | "annotated_type" | "generic_type" => {
                current = nominal_type_child(current)?;
            }
            "scoped_identifier" | "scoped_type_identifier" => {
                let mut cursor = current.walk();
                current = current
                    .named_children(&mut cursor)
                    .filter(|child| is_java_nominal_type_node(child.kind()))
                    .last()?;
            }
            _ => return None,
        }
    }
}

fn resolve_nested_type_from_scoped_node(
    node: Node<'_>,
    token: QueryToken<'_>,
    ctx: &ScanCtx<'_>,
) -> Option<CodeUnit> {
    let mut cursor = node.walk();
    let typed_children: Vec<_> = node
        .named_children(&mut cursor)
        .filter(|child| {
            matches!(
                child.kind(),
                "identifier"
                    | "type_identifier"
                    | "scoped_identifier"
                    | "scoped_type_identifier"
                    | "generic_type"
            )
        })
        .collect();
    let (name, qualifier) = typed_children.split_last()?;
    let qualifier = qualifier.last().copied()?;
    let qualifier_type = resolve_type_from_node(qualifier, token, ctx)?;
    let name = node_text(*name, ctx.source);
    if name.is_empty() {
        return None;
    }

    nested_type_for_owner(&qualifier_type, name, ctx)
}

pub fn nested_type_for_owner(owner: &CodeUnit, name: &str, ctx: &ScanCtx<'_>) -> Option<CodeUnit> {
    resolve_nested_type_for_owner(ctx.graph, owner, name)
}

pub fn resolve_nested_type_for_owner(
    graph: &JavaGraphSource<'_>,
    owner: &CodeUnit,
    name: &str,
) -> Option<CodeUnit> {
    let nested = |candidate: &CodeUnit| {
        graph.with_definitions(|definitions| {
            definitions
                .fqn(&format!("{}.{}", candidate.fq_name(), name))
                .iter()
                .find(|unit| unit.is_class())
                .cloned()
        })
    };
    nested(owner).or_else(|| {
        graph
            .hierarchy?
            .get_ancestors(owner)
            .into_iter()
            .find_map(|ancestor| nested(&ancestor))
    })
}

pub fn infer_type_from_value(
    node: Node<'_>,
    token: QueryToken<'_>,
    ctx: &ScanCtx<'_>,
) -> Option<CodeUnit> {
    match node.kind() {
        "object_creation_expression" => node
            .child_by_field_name("type")
            .and_then(|type_node| resolve_type_from_node(type_node, token, ctx)),
        "method_invocation" => method_invocation_return_type(node, token, ctx),
        "identifier" => {
            let name = node_text(node, ctx.source);
            let targets = ctx.bindings.resolve_symbol(name);
            let fq_name = targets.as_precise()?.iter().next()?;
            class_definition(ctx, fq_name)
        }
        _ => None,
    }
}

fn method_invocation_return_type(
    node: Node<'_>,
    token: QueryToken<'_>,
    ctx: &ScanCtx<'_>,
) -> Option<CodeUnit> {
    method_invocation_return_type_at_depth(node, token, ctx, 0)
}

fn method_invocation_return_type_at_depth(
    node: Node<'_>,
    token: QueryToken<'_>,
    ctx: &ScanCtx<'_>,
    depth: usize,
) -> Option<CodeUnit> {
    if depth > METHOD_RECEIVER_CHAIN_LIMIT {
        return None;
    }
    let name_node = node.child_by_field_name("name")?;
    let name = node_text(name_node, ctx.source);
    if name.is_empty() {
        return None;
    }
    let owner = match node.child_by_field_name("object") {
        Some(object) => receiver_type_from_node_at_depth(object, token, ctx, depth + 1)?,
        None => enclosing_owner(node, ctx)?,
    };
    method_return_type_for_call(&owner, token, name, argument_list_arity(node), ctx)
}

fn receiver_type_from_node_at_depth(
    node: Node<'_>,
    token: QueryToken<'_>,
    ctx: &ScanCtx<'_>,
    depth: usize,
) -> Option<CodeUnit> {
    if depth > METHOD_RECEIVER_CHAIN_LIMIT {
        return None;
    }
    match node.kind() {
        "identifier" => {
            let name = node_text(node, ctx.source);
            let targets = ctx.bindings.resolve_symbol(name);
            if let Some(fq_name) = targets
                .as_precise()
                .and_then(|targets| (targets.len() == 1).then(|| targets.iter().next().unwrap()))
            {
                return class_definition(ctx, fq_name);
            }
            (!ctx.bindings.is_shadowed(name))
                .then(|| resolve_type_from_node(node, token, ctx))
                .flatten()
        }
        "type_identifier" | "scoped_type_identifier" | "generic_type" => {
            resolve_type_from_node(node, token, ctx)
        }
        "object_creation_expression" => node
            .child_by_field_name("type")
            .and_then(|type_node| resolve_type_from_node(type_node, token, ctx)),
        "method_invocation" => method_invocation_return_type_at_depth(node, token, ctx, depth),
        "this" | "super" => enclosing_owner(node, ctx),
        "field_access" => field_access_value_type(node, token, ctx, depth),
        _ => None,
    }
}

fn method_return_type_for_call(
    owner: &CodeUnit,
    token: QueryToken<'_>,
    method_name: &str,
    arity: usize,
    ctx: &ScanCtx<'_>,
) -> Option<CodeUnit> {
    let cache_key = MethodCallReturnCacheKey {
        owner_fqn: owner.fq_name(),
        method_name: method_name.to_string(),
        arity,
    };
    if let Some(cached) = ctx
        .method_call_return_cache
        .borrow()
        .get(&cache_key)
        .cloned()
    {
        return single_return_class(ctx, cached);
    }

    // A method call binds to one declaration: the receiver's own type answers
    // it when it declares the method, and otherwise the nearest level of the
    // hierarchy that declares it does (JLS 15.12.2). The ancestor chain is a
    // lookup order, not a set of branches. Merging a return type across every
    // ancestor made each ancestor that declares nothing contribute `Unknown`,
    // which downgraded the one real answer to `Ambiguous` and left the call
    // untyped -- so a switch selector such as `field.getRoundingMode()` typed
    // only while the receiver's class had no supertype at all (#2181).
    let declaring_owners =
        if !java_call_answering_units(&cache_key.owner_fqn, token, method_name, arity, ctx)
            .is_empty()
        {
            vec![cache_key.owner_fqn.clone()]
        } else {
            ctx.graph
                .hierarchy
                .and_then(|provider| {
                    java_nearest_declaring_ancestors(ctx.java, provider, owner, |ancestor| {
                        !java_call_answering_units(
                            &ancestor.fq_name(),
                            token,
                            method_name,
                            arity,
                            ctx,
                        )
                        .is_empty()
                    })
                })
                .map(|declaring| declaring.iter().map(CodeUnit::fq_name).collect())
                .unwrap_or_default()
        };
    let outcome = method_return_type_for_owner_fqns(
        declaring_owners.iter().map(String::as_str),
        token,
        method_name,
        arity,
        ctx,
    );
    ctx.method_call_return_cache
        .borrow_mut()
        .insert(cache_key, outcome.clone());
    single_return_class(ctx, outcome)
}

fn single_return_class(
    ctx: &ScanCtx<'_>,
    outcome: ReceiverAnalysisOutcome<String>,
) -> Option<CodeUnit> {
    match outcome {
        ReceiverAnalysisOutcome::Precise(values) if values.len() == 1 => {
            class_definition(ctx, &values[0])
        }
        ReceiverAnalysisOutcome::Precise(_)
        | ReceiverAnalysisOutcome::Ambiguous(_)
        | ReceiverAnalysisOutcome::Unsupported { .. }
        | ReceiverAnalysisOutcome::ExceededBudget { .. }
        | ReceiverAnalysisOutcome::Unknown => None,
    }
}

fn class_definition(ctx: &ScanCtx<'_>, fq_name: &str) -> Option<CodeUnit> {
    ctx.graph.with_definitions(|definitions| {
        definitions
            .fqn(fq_name)
            .iter()
            .find(|unit| unit.is_class())
            .cloned()
    })
}

fn enclosing_owner(node: Node<'_>, ctx: &ScanCtx<'_>) -> Option<CodeUnit> {
    let owner = ctx.class_ranges.enclosing(node.start_byte())?;
    class_definition(ctx, owner)
}

pub fn is_ignored_type_context(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    matches!(
        parent.kind(),
        "package_declaration" | "import_declaration" | "class_declaration"
    ) && parent.child_by_field_name("name") == Some(node)
}

/// Whether `node` is a class-name position in a Java module descriptor.
///
/// The Java grammar uses the general `_name` production for the `uses` and
/// `provides` directive fields. This means an unqualified class name is an
/// `identifier`, not a `type_identifier`, even though it names a type. Keep
/// this test tied to the directive fields so module names and package names in
/// `requires`, `exports`, and `opens` never enter the type-reference surface.
pub fn is_module_type_reference(node: Node<'_>) -> bool {
    let mut reference = node;
    while let Some(parent) = reference.parent()
        && parent.kind() == "scoped_identifier"
    {
        reference = parent;
    }
    let Some(parent) = reference.parent() else {
        return false;
    };
    match parent.kind() {
        "uses_module_directive" => parent.child_by_field_name("type") == Some(reference),
        "provides_module_directive" => {
            if parent.child_by_field_name("provided") == Some(reference) {
                return true;
            }

            // The grammar assigns the repeated `provider` field to providers
            // after the first one. The first `_name` after `with` is unnamed,
            // so use the structured child order after the `provided` field to
            // include it as well. No source text is inspected here.
            let Some(provided) = parent.child_by_field_name("provided") else {
                return false;
            };
            let mut seen_provided = false;
            let mut cursor = parent.walk();
            parent
                .children(&mut cursor)
                .enumerate()
                .any(|(index, child)| {
                    if child == provided {
                        seen_provided = true;
                        return false;
                    }
                    seen_provided
                        && child == reference
                        && matches!(child.kind(), "identifier" | "scoped_identifier")
                        && (parent.field_name_for_child(index as u32) == Some("provider")
                            || parent.field_name_for_child(index as u32).is_none())
                })
        }
        _ => false,
    }
}

/// Whether `node` names a module or package in a Java module directive.
///
/// These names use the same `_name` grammar production as class names, but
/// they are not type references. Keep them out of the inverted type graph.
pub fn is_non_type_module_reference(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    match parent.kind() {
        "requires_module_directive" => parent.child_by_field_name("module") == Some(node),
        "exports_module_directive" | "opens_module_directive" => {
            if parent.child_by_field_name("package") == Some(node) {
                return true;
            }
            let mut cursor = parent.walk();
            parent
                .children(&mut cursor)
                .enumerate()
                .any(|(index, child)| {
                    child == node && parent.field_name_for_child(index as u32) == Some("modules")
                })
        }
        _ => false,
    }
}

pub fn is_declaration_name(node: Node<'_>) -> bool {
    node.parent()
        .and_then(|parent| parent.child_by_field_name("name"))
        == Some(node)
}
