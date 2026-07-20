use crate::analyzer::rust::field_roles::rust_struct_field_references;
use crate::analyzer::rust::lexical_scope::{self, RustLexicalScopeIndex};
use crate::analyzer::tree_sitter_analyzer::PreparedSyntaxTree;
use crate::analyzer::usages::common::{TreeWalkAction, same_node, walk_tree_iterative};
use crate::analyzer::usages::get_definition::{
    RustTypeLookupCache, rust_expression_type_definition_fqn_cached, rust_resolve_type_node_fqn,
};
use crate::analyzer::usages::local_inference::{LocalInferenceConfig, LocalInferenceEngine};
use crate::analyzer::usages::model::UsageHit;
use crate::analyzer::usages::receiver_analysis::ReceiverAnalysisOutcome;
use crate::analyzer::usages::rust_graph::hits::{
    member_hit_enclosing, push_member_hit, push_self_receiver_member_hit, push_unproven_member_hit,
    record_hit, record_import_hit, record_module_qualified_hits,
};
use crate::analyzer::usages::rust_graph::resolver::{
    is_trait_owner, resolve_scoped_associated_item_matching, rust_token_path_segment_is_qualified,
    trait_member_for_impl_member,
};
use crate::analyzer::usages::traits::UsageScanScope;
use crate::analyzer::{
    CodeUnit, GlobalUsageDefinitionIndex, IAnalyzer, ImportAnalysisProvider, ProjectFile,
    RustAnalyzer, RustReferenceContext, TypeHierarchyProvider,
};
use crate::cancellation::CancellationToken;
use crate::hash::{HashMap, HashSet};
use rayon::prelude::*;
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use tree_sitter::{Node, Parser, Tree};

pub(crate) struct RustProjectGraph {
    parsed: HashMap<ProjectFile, Arc<PreparedSyntaxTree>>,
}

pub(super) fn build_rust_graph_for_files(
    rust: &RustAnalyzer,
    files: impl IntoIterator<Item = ProjectFile>,
    cancellation: Option<&CancellationToken>,
) -> RustProjectGraph {
    let parsed: HashMap<ProjectFile, Arc<PreparedSyntaxTree>> = files
        .into_iter()
        .collect::<Vec<_>>()
        .par_iter()
        .filter_map(|file| {
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return None;
            }
            let parsed = rust
                .prepared_syntax(file)
                .map(|prepared| (file.clone(), prepared));
            if cancellation.is_some_and(CancellationToken::is_cancelled) {
                return None;
            }
            parsed
        })
        .collect();

    RustProjectGraph { parsed }
}

pub(super) fn effective_scan_files(
    analyzer: &RustAnalyzer,
    scan_scope: &UsageScanScope<'_>,
    target: &CodeUnit,
    seeds: &BTreeSet<(ProjectFile, String)>,
) -> HashSet<ProjectFile> {
    let candidate_files = scan_scope.candidate_files();
    let analyzed = analyzer.get_analyzed_files();
    let filtered_candidates: HashSet<_> = candidate_files
        .iter()
        .filter(|file| analyzed.contains(*file))
        .cloned()
        .collect();

    if scan_scope.is_authoritative() {
        return filtered_candidates;
    }

    if !candidate_files.is_empty() && filtered_candidates.is_empty() {
        return [target.source().clone()].into_iter().collect();
    }

    if !filtered_candidates.is_empty() {
        return filtered_candidates;
    }

    let seed_names: HashSet<&str> = seeds.iter().map(|(_, name)| name.as_str()).collect();
    let textual_candidates = analyzed.into_iter().filter(|file| {
        if scan_scope.is_cancelled() {
            return false;
        }
        file.read_to_string().ok().is_some_and(|source| {
            if scan_scope.is_cancelled() {
                return false;
            }
            source.contains(target.identifier())
                || seed_names
                    .iter()
                    .any(|seed_name| source.contains(seed_name))
        })
    });

    analyzer
        .usage_importers(seeds)
        .into_iter()
        .chain(analyzer.referencing_files_of(target.source()))
        .chain(textual_candidates)
        .chain(std::iter::once(target.source().clone()))
        .collect()
}

pub(super) fn scan_files_for_target(
    analyzer: &dyn IAnalyzer,
    rust: &RustAnalyzer,
    graph: &RustProjectGraph,
    files: HashSet<ProjectFile>,
    target: &CodeUnit,
    seeds: Option<&BTreeSet<(ProjectFile, String)>>,
    cancellation: Option<&CancellationToken>,
) -> BTreeSet<UsageHit> {
    let target_short = target.identifier().to_string();
    let target_fqn = target.fq_name();
    let support = analyzer.global_usage_definition_index();
    let hits = Mutex::new(BTreeSet::new());
    let files_vec: Vec<_> = files.into_iter().collect();

    files_vec.par_iter().for_each(|file| {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return;
        }
        let Some(prepared) = graph
            .parsed
            .get(file)
            .cloned()
            .or_else(|| rust.prepared_syntax(file))
        else {
            return;
        };
        let source = prepared.source();
        let tree = prepared.tree();
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return;
        }

        let line_starts = prepared.line_starts();
        let lexical_scope = RustLexicalScopeIndex::new(tree.root_node(), source);
        let refs = rust.reference_context_of(file);
        let (mut direct_names, _namespace_names) = match seeds {
            Some(seeds) => rust.usage_binding_names(file, seeds),
            None => (HashSet::default(), HashSet::default()),
        };
        // A file that re-exports a seed (`pub use path::name`) can also reference
        // `name` directly in its own body, but a re-export is not recorded as a
        // local import binding. Treat any seed rooted in this file as a direct name
        // so those in-module references resolve.
        if let Some(seeds) = seeds {
            for (seed_file, seed_name) in seeds {
                if seed_file == file {
                    direct_names.insert(seed_name.clone());
                }
            }
            direct_names.extend(refs.bare_names_resolving_to(&target_fqn));
        }
        let target_self_file = file == target.source();

        let mut local_hits = BTreeSet::new();
        let mut ctx = ScanCtx {
            file,
            source,
            line_starts,
            analyzer,
            rust,
            refs: &refs,
            support,
            target,
            target_fqn: &target_fqn,
            target_is_path_qualifier: target.is_class() || rust.is_type_alias(target),
            target_is_module: target.is_module(),
            target_short: &target_short,
            direct_names: &direct_names,
            lexical_scope: &lexical_scope,
            target_self_file,
            hits: &mut local_hits,
        };
        scan_node(tree.root_node(), &mut ctx);
        record_module_qualified_hits(tree.root_node(), &mut ctx);

        if !local_hits.is_empty() {
            let mut sink = hits.lock().expect("poisoned Rust graph collector");
            sink.extend(local_hits);
        }
    });

    hits.into_inner().expect("poisoned Rust graph collector")
}

pub(super) struct ScanCtx<'a> {
    pub(super) file: &'a ProjectFile,
    pub(super) source: &'a str,
    pub(super) line_starts: &'a [usize],
    pub(super) analyzer: &'a dyn IAnalyzer,
    pub(super) rust: &'a RustAnalyzer,
    pub(super) refs: &'a RustReferenceContext,
    pub(super) support: &'a GlobalUsageDefinitionIndex,
    target: &'a CodeUnit,
    pub(super) target_fqn: &'a str,
    pub(super) target_is_path_qualifier: bool,
    pub(super) target_is_module: bool,
    pub(super) target_short: &'a str,
    direct_names: &'a HashSet<String>,
    lexical_scope: &'a RustLexicalScopeIndex,
    target_self_file: bool,
    pub(super) hits: &'a mut BTreeSet<UsageHit>,
}

impl ScanCtx<'_> {
    fn matches_identifier(&self, text: &str) -> bool {
        self.direct_names.contains(text) || (self.target_self_file && text == self.target_short)
    }

    pub(super) fn name_shadowed_at(&self, name: &str, byte: usize) -> bool {
        self.lexical_scope.name_bound_at(name, byte)
            || (!self.target_self_file && self.lexical_scope.item_bound_at(name, byte))
    }
}

fn scan_node(root: Node<'_>, ctx: &mut ScanCtx<'_>) {
    walk_tree_iterative(
        root,
        ctx,
        |node, ctx| {
            match node.kind() {
                "use_declaration" => {
                    record_use_import_hits(node, ctx);
                    return TreeWalkAction::Skip;
                }
                "identifier" | "type_identifier" if !ctx.target_is_module => {
                    let text = node
                        .utf8_text(ctx.source.as_bytes())
                        .ok()
                        .map(str::trim)
                        .unwrap_or_default();
                    let matching_self_type =
                        text == "Self" && self_reference_matches_target(node, ctx);
                    let matching_identifier = !identifier_is_scoped_path_part(node)
                        && ctx.matches_identifier(text)
                        && !is_shadowed_identifier(text, node, ctx);
                    if matching_self_type || matching_identifier {
                        record_hit(node, ctx);
                    }
                }
                _ => {}
            }
            TreeWalkAction::Descend
        },
        |_| {},
    );
}

fn identifier_is_scoped_path_part(node: Node<'_>) -> bool {
    rust_token_path_segment_is_qualified(node)
        || node.parent().is_some_and(|parent| {
            matches!(
                parent.kind(),
                "scoped_identifier" | "scoped_type_identifier"
            )
        })
}

fn self_reference_matches_target(node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    if !ctx.target.is_class() {
        return false;
    }
    let Some(type_node) =
        enclosing_impl_item(node).and_then(|impl_item| impl_item.child_by_field_name("type"))
    else {
        return false;
    };
    rust_resolve_type_node_fqn(
        ctx.analyzer,
        ctx.support,
        ctx.file,
        ctx.source,
        type_node,
        Some(type_node.start_byte()),
    )
    .is_some_and(|fqn| fqn_matches_owner(ctx.rust, &fqn, ctx.target))
}

fn record_use_import_hits(node: Node<'_>, ctx: &mut ScanCtx<'_>) {
    walk_tree_iterative(
        node,
        ctx,
        |current, ctx| {
            if matches!(current.kind(), "identifier" | "type_identifier")
                && is_local_use_binding_node(current)
            {
                let text = current
                    .utf8_text(ctx.source.as_bytes())
                    .ok()
                    .map(str::trim)
                    .unwrap_or_default();
                if ctx.direct_names.contains(text)
                    || (ctx.target_self_file && text == ctx.target_short)
                {
                    record_import_hit(current, ctx);
                }
            }
            TreeWalkAction::Descend
        },
        |_| {},
    );
}

fn is_local_use_binding_node(node: Node<'_>) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == "use_declaration" {
            return true;
        }
        if parent.kind() == "use_as_clause" {
            return parent
                .child_by_field_name("alias")
                .is_some_and(|alias| same_node(alias, node));
        }
        current = parent.parent();
    }
    true
}

fn is_shadowed_identifier(text: &str, node: Node<'_>, ctx: &ScanCtx<'_>) -> bool {
    if lexical_scope::is_pattern_binding_identifier(node)
        || ctx.name_shadowed_at(text, node.start_byte())
    {
        return true;
    }
    let start = node.start_byte();
    let end = node.end_byte();
    ctx.analyzer
        .find_nearest_declaration(ctx.file, start, end, text)
        .is_some_and(|decl| {
            decl.identifier == text
                && (decl.range.start_byte != start || decl.range.end_byte != end)
        })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn scan_files_for_member_target(
    analyzer: &dyn IAnalyzer,
    graph: &RustProjectGraph,
    rust: &RustAnalyzer,
    files: HashSet<ProjectFile>,
    target: &CodeUnit,
    requested_target: &CodeUnit,
    seeds: &BTreeSet<(ProjectFile, String)>,
    cancellation: Option<&CancellationToken>,
) -> RustMemberScanResult {
    let Some(owner) = rust.parent_of(target) else {
        return RustMemberScanResult::default();
    };
    let member_name = target.identifier().to_string();
    let hits = Mutex::new(BTreeSet::new());
    let unproven_hits = Mutex::new(BTreeSet::new());
    let constructor_returns = self_like_constructor_returns(rust, &owner);
    let self_like_constructors = self_like_constructor_seeds(rust, &owner, &constructor_returns);
    let support = analyzer.global_usage_definition_index();

    files.par_iter().for_each(|file| {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return;
        }
        let Some(prepared) = graph
            .parsed
            .get(file)
            .cloned()
            .or_else(|| rust.prepared_syntax(file))
        else {
            return;
        };
        let source = prepared.source();
        let tree = prepared.tree();
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return;
        }
        let line_starts = prepared.line_starts();
        let refs = rust.reference_context_of(file);
        let mut owner_local_names: HashSet<String> = if file == target.source() {
            [owner.identifier().to_string()].into_iter().collect()
        } else {
            rust.usage_binding_local_names(file, seeds)
        };
        owner_local_names.extend(refs.bare_names_resolving_to(&owner.fq_name()));
        let trait_owner = is_trait_owner(rust, &owner);
        let receiver_type_names = if trait_owner {
            rust.trait_implementer_names(&owner, file)
        } else {
            owner_local_names.clone()
        };
        if owner_local_names.is_empty()
            && receiver_type_names.is_empty()
            && !source.contains(&member_name)
        {
            return;
        }
        let visible_bare_constructors =
            visible_bare_constructor_names(rust, file, &self_like_constructors);
        let mut receiver_names = infer_receiver_names(
            source,
            &receiver_type_names,
            &constructor_returns,
            &visible_bare_constructors,
        );
        receiver_names.extend(resolved_owner_receiver_names(
            tree.root_node(),
            source,
            analyzer,
            rust,
            support,
            file,
            &owner,
        ));
        receiver_names.sort();
        receiver_names.dedup();
        let static_owner_names = owner_local_names;
        let has_static_trait_call = trait_owner && source.contains(&format!("::{}", member_name));
        let record_unproven_receivers =
            !receiver_names.is_empty() || !static_owner_names.is_empty() || has_static_trait_call;
        let mut type_lookup_cache = RustTypeLookupCache::default();
        let mut local_hits = BTreeSet::new();
        let mut local_unproven_hits = BTreeSet::new();
        let mut ctx = MemberScanCtx {
            analyzer,
            rust,
            support,
            refs: &refs,
            file,
            source,
            root: tree.root_node(),
            line_starts,
            owner: &owner,
            member_name: &member_name,
            scan_target: target,
            requested_target,
            target_is_field: requested_target.is_field(),
            target_is_enum_variant: requested_target.is_field()
                && rust
                    .parent_of(requested_target)
                    .is_some_and(|owner| rust.is_rust_enum_declaration(&owner)),
            target_owner_is_trait: trait_owner,
            receiver_names: &receiver_names,
            receiver_type_names: &receiver_type_names,
            record_unproven_receivers,
            type_lookup_cache: &mut type_lookup_cache,
            hits: &mut local_hits,
            unproven_hits: &mut local_unproven_hits,
        };
        scan_member_node(tree.root_node(), &mut ctx);

        if !local_hits.is_empty() {
            let mut sink = hits.lock().expect("poisoned Rust member collector");
            sink.extend(local_hits);
        }
        if !local_unproven_hits.is_empty() {
            let mut sink = unproven_hits
                .lock()
                .expect("poisoned Rust member unproven collector");
            sink.extend(local_unproven_hits);
        }
    });

    RustMemberScanResult {
        hits: hits.into_inner().expect("poisoned Rust member collector"),
        unproven_hits: unproven_hits
            .into_inner()
            .expect("poisoned Rust member unproven collector"),
    }
}

#[derive(Default)]
pub(super) struct RustMemberScanResult {
    pub(super) hits: BTreeSet<UsageHit>,
    pub(super) unproven_hits: BTreeSet<UsageHit>,
}

struct MemberScanCtx<'a> {
    analyzer: &'a dyn IAnalyzer,
    rust: &'a RustAnalyzer,
    support: &'a GlobalUsageDefinitionIndex,
    refs: &'a RustReferenceContext,
    file: &'a ProjectFile,
    source: &'a str,
    root: Node<'a>,
    line_starts: &'a [usize],
    owner: &'a CodeUnit,
    member_name: &'a str,
    scan_target: &'a CodeUnit,
    requested_target: &'a CodeUnit,
    target_is_field: bool,
    target_is_enum_variant: bool,
    target_owner_is_trait: bool,
    receiver_names: &'a Vec<String>,
    receiver_type_names: &'a HashSet<String>,
    record_unproven_receivers: bool,
    type_lookup_cache: &'a mut RustTypeLookupCache,
    hits: &'a mut BTreeSet<UsageHit>,
    unproven_hits: &'a mut BTreeSet<UsageHit>,
}

fn scan_member_node(node: Node<'_>, ctx: &mut MemberScanCtx<'_>) {
    match node.kind() {
        "field_expression" => record_instance_member_hit(node, ctx),
        "token_tree" => {
            record_token_tree_instance_member_hits(node, ctx);
            record_token_tree_static_member_hits(node, ctx);
        }
        "scoped_identifier" | "scoped_type_identifier" => record_static_member_hit(node, ctx),
        "struct_expression" | "struct_pattern" if ctx.target_is_field => {
            record_struct_field_hits(node, ctx)
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        scan_member_node(child, ctx);
    }
}

fn record_instance_member_hit(node: Node<'_>, ctx: &mut MemberScanCtx<'_>) {
    // A method target is referenced by a call (`receiver.method()`); a field target
    // is referenced by a read/write (`receiver.field`), never as the callee.
    if ctx.target_is_field {
        if field_expression_is_called(node) {
            return;
        }
    } else if !field_expression_is_called(node) {
        return;
    }
    let Some(field) = node.child_by_field_name("field") else {
        return;
    };
    if simple_node_text(field, ctx.source).as_deref() != Some(ctx.member_name) {
        return;
    }
    let Some(receiver) = node.child_by_field_name("value") else {
        return;
    };
    let start = field.start_byte();
    let end = field.end_byte();
    let Some(enclosing) = member_hit_enclosing(ctx.analyzer, ctx.file, ctx.line_starts, start, end)
    else {
        return;
    };
    let receiver_name = simple_node_text(receiver, ctx.source);
    let inferred_match =
        match receiver_owner_proof(receiver, receiver_name.as_deref(), &enclosing, ctx) {
            ReceiverOwnerProof::Structured => false,
            ReceiverOwnerProof::Inferred => true,
            ReceiverOwnerProof::Mismatches => return,
            ReceiverOwnerProof::Unknown => {
                if ctx.record_unproven_receivers
                    && receiver_name.as_ref().is_some_and(|receiver_name| {
                        !receiver_name_explicitly_mismatched(receiver_name, &enclosing, ctx)
                    })
                {
                    push_unproven_member_hit(
                        ctx.file,
                        ctx.source,
                        ctx.line_starts,
                        start,
                        end,
                        enclosing,
                        ctx.unproven_hits,
                    );
                }
                return;
            }
        };

    // The explicit-mismatch guard only applies to a simple named receiver whose type
    // could be re-annotated in the enclosing scope; a resolved `self.field` receiver
    // already proved its type structurally.
    if inferred_match && let Some(receiver_name) = receiver_name.as_ref() {
        let receiver_mismatched = ctx
            .analyzer
            .get_source(&enclosing, false)
            .map(|enclosing_source| {
                receiver_explicitly_mismatched(
                    ctx.source,
                    &enclosing_source,
                    ctx.receiver_type_names,
                    receiver_name,
                )
            })
            .unwrap_or(false);
        if receiver_mismatched {
            return;
        }
    }
    if !ctx.target_is_field && receiver_is_self_rooted(receiver) {
        push_self_receiver_member_hit(
            ctx.file,
            ctx.source,
            ctx.line_starts,
            start,
            end,
            enclosing,
            ctx.hits,
        );
    } else {
        push_member_hit(
            ctx.file,
            ctx.source,
            ctx.line_starts,
            start,
            end,
            enclosing,
            ctx.hits,
        );
    }
}

fn record_token_tree_instance_member_hits(node: Node<'_>, ctx: &mut MemberScanCtx<'_>) {
    let mut cursor = node.walk();
    let children: Vec<Node<'_>> = node.children(&mut cursor).collect();
    for (index, window) in children.windows(3).enumerate() {
        let [receiver, dot, member] = window else {
            continue;
        };
        if !matches!(receiver.kind(), "identifier" | "self") || dot.kind() != "." {
            continue;
        }
        if simple_node_text(*member, ctx.source).as_deref() != Some(ctx.member_name) {
            continue;
        }
        let is_call = children.get(index + 3).is_some_and(|call_args| {
            call_args.kind() == "token_tree"
                && call_args.child(0).is_some_and(|open| open.kind() == "(")
        });
        if ctx.target_is_field == is_call {
            continue;
        }
        let receiver_name = simple_node_text(*receiver, ctx.source);
        let start = member.start_byte();
        let end = member.end_byte();
        let Some(enclosing) =
            member_hit_enclosing(ctx.analyzer, ctx.file, ctx.line_starts, start, end)
        else {
            continue;
        };
        let inferred_match =
            match receiver_owner_proof(*receiver, receiver_name.as_deref(), &enclosing, ctx) {
                ReceiverOwnerProof::Structured => false,
                ReceiverOwnerProof::Inferred => true,
                ReceiverOwnerProof::Mismatches => continue,
                ReceiverOwnerProof::Unknown => {
                    if ctx.record_unproven_receivers
                        && receiver_name.as_ref().is_some_and(|receiver_name| {
                            !receiver_name_explicitly_mismatched(receiver_name, &enclosing, ctx)
                        })
                    {
                        push_unproven_member_hit(
                            ctx.file,
                            ctx.source,
                            ctx.line_starts,
                            start,
                            end,
                            enclosing,
                            ctx.unproven_hits,
                        );
                    }
                    continue;
                }
            };
        if inferred_match && let Some(receiver_name) = receiver_name.as_ref() {
            let receiver_mismatched = ctx
                .analyzer
                .get_source(&enclosing, false)
                .map(|enclosing_source| {
                    receiver_explicitly_mismatched(
                        ctx.source,
                        &enclosing_source,
                        ctx.receiver_type_names,
                        receiver_name,
                    )
                })
                .unwrap_or(false);
            if receiver_mismatched {
                continue;
            }
        }
        if !ctx.target_is_field && receiver_is_self_rooted(*receiver) {
            push_self_receiver_member_hit(
                ctx.file,
                ctx.source,
                ctx.line_starts,
                start,
                end,
                enclosing,
                ctx.hits,
            );
        } else {
            push_member_hit(
                ctx.file,
                ctx.source,
                ctx.line_starts,
                start,
                end,
                enclosing,
                ctx.hits,
            );
        }
    }
}

fn record_token_tree_static_member_hits(node: Node<'_>, ctx: &mut MemberScanCtx<'_>) {
    let mut cursor = node.walk();
    let children: Vec<Node<'_>> = node.children(&mut cursor).collect();
    for member_index in 2..children.len() {
        let owner_index = member_index - 2;
        let owner = children[owner_index];
        let separator = children[member_index - 1];
        let member = children[member_index];
        if !rust_token_path_segment(owner)
            || separator.kind() != "::"
            || simple_node_text(member, ctx.source).as_deref() != Some(ctx.member_name)
        {
            continue;
        }
        let is_call = children.get(member_index + 1).is_some_and(|arguments| {
            arguments.kind() == "token_tree"
                && arguments.child(0).is_some_and(|open| open.kind() == "(")
        });
        if !static_member_role_matches_target(is_call, ctx) {
            continue;
        }
        let Some(owner_name) = rust_token_owner_path(&children, owner_index, ctx.source) else {
            continue;
        };
        if !scoped_static_member_matches_target(owner, &owner_name, ctx) {
            continue;
        }
        record_static_member_name_hit(member, ctx);
    }
}

fn rust_token_owner_path(children: &[Node<'_>], mut index: usize, source: &str) -> Option<String> {
    let mut segments = vec![simple_node_text(children[index], source)?];
    while index >= 2 && children[index - 1].kind() == "::" {
        let segment = children[index - 2];
        if !rust_token_path_segment(segment) {
            break;
        }
        segments.push(simple_node_text(segment, source)?);
        index -= 2;
    }
    segments.reverse();
    Some(segments.join("::"))
}

fn rust_token_path_segment(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "identifier" | "type_identifier" | "self" | "super" | "crate"
    )
}

fn receiver_name_explicitly_mismatched(
    receiver_name: &str,
    enclosing: &CodeUnit,
    ctx: &MemberScanCtx<'_>,
) -> bool {
    ctx.analyzer
        .get_source(enclosing, false)
        .map(|enclosing_source| {
            receiver_explicitly_mismatched(
                ctx.source,
                &enclosing_source,
                ctx.receiver_type_names,
                receiver_name,
            )
        })
        .unwrap_or(false)
}

/// Struct literal and destructuring labels reference fields on their resolved owner.
fn record_struct_field_hits(node: Node<'_>, ctx: &mut MemberScanCtx<'_>) {
    let Some((type_node, fields)) = rust_struct_field_references(node) else {
        return;
    };
    if !resolved_type_matches_owner(type_node, ctx) {
        return;
    }
    for field in fields {
        if simple_node_text(field, ctx.source).as_deref() != Some(ctx.member_name) {
            continue;
        }
        let start = field.start_byte();
        let end = field.end_byte();
        let Some(enclosing) =
            member_hit_enclosing(ctx.analyzer, ctx.file, ctx.line_starts, start, end)
        else {
            continue;
        };
        push_member_hit(
            ctx.file,
            ctx.source,
            ctx.line_starts,
            start,
            end,
            enclosing,
            ctx.hits,
        );
    }
}

enum ReceiverOwnerProof {
    Structured,
    Inferred,
    Mismatches,
    Unknown,
}

fn receiver_owner_proof(
    receiver: Node<'_>,
    receiver_name: Option<&str>,
    enclosing: &CodeUnit,
    ctx: &mut MemberScanCtx<'_>,
) -> ReceiverOwnerProof {
    if let Some(fqn) = rust_expression_type_definition_fqn_cached(
        ctx.analyzer,
        ctx.support,
        ctx.file,
        ctx.source,
        ctx.root,
        receiver,
        receiver.start_byte(),
        ctx.type_lookup_cache,
    ) {
        if !ctx.target_owner_is_trait && fqn_matches_owner(ctx.rust, &fqn, ctx.owner) {
            return ReceiverOwnerProof::Structured;
        }
        if let Some(matches) = receiver_type_matches_requested_dispatch(&fqn, ctx) {
            return if matches {
                ReceiverOwnerProof::Structured
            } else {
                ReceiverOwnerProof::Mismatches
            };
        }
        let resolved_is_alias = ctx
            .support
            .fqn(&fqn)
            .iter()
            .any(|unit| ctx.rust.is_type_alias(unit));
        if !ctx.target_owner_is_trait && !resolved_is_alias {
            return ReceiverOwnerProof::Mismatches;
        }
    }

    if receiver_name.is_some_and(|name| ctx.receiver_names.iter().any(|receiver| receiver == name))
    {
        return ReceiverOwnerProof::Inferred;
    }

    let matches = match receiver.kind() {
        "self" => enclosing_impl_type_matches_owner(receiver, ctx),
        "field_expression" => self_field_receiver_matches_owner(receiver, enclosing, ctx),
        _ => false,
    };
    if matches {
        ReceiverOwnerProof::Inferred
    } else {
        ReceiverOwnerProof::Unknown
    }
}

fn receiver_type_matches_requested_dispatch(fqn: &str, ctx: &MemberScanCtx<'_>) -> Option<bool> {
    let receiver_types: Vec<_> = ctx
        .support
        .fqn(fqn)
        .into_iter()
        .filter(|unit| ctx.rust.supports_type_hierarchy(unit))
        .collect();
    if receiver_types.is_empty()
        || receiver_types
            .iter()
            .any(|unit| ctx.rust.is_type_alias(unit))
    {
        return None;
    }

    if ctx.requested_target != ctx.scan_target {
        let requested_owner = ctx.rust.parent_of(ctx.requested_target)?;
        let result = receiver_types.into_iter().any(|receiver_type| {
            same_rust_declaration_identity(&receiver_type, &requested_owner)
                && ctx
                    .rust
                    .get_ancestors(&receiver_type)
                    .iter()
                    .any(|ancestor| same_rust_declaration_identity(ancestor, ctx.owner))
        });
        return Some(result);
    }

    ctx.target_owner_is_trait.then(|| {
        receiver_types.into_iter().any(|receiver_type| {
            same_rust_declaration_identity(&receiver_type, ctx.owner)
                || ctx
                    .rust
                    .get_ancestors(&receiver_type)
                    .iter()
                    .any(|ancestor| same_rust_declaration_identity(ancestor, ctx.owner))
        })
    })
}

fn same_rust_declaration_identity(left: &CodeUnit, right: &CodeUnit) -> bool {
    left.fq_name() == right.fq_name()
        && left.source() == right.source()
        && left.kind() == right.kind()
}

fn receiver_is_self_rooted(receiver: Node<'_>) -> bool {
    match receiver.kind() {
        "self" => true,
        "parenthesized_expression" => receiver.named_child(0).is_some_and(receiver_is_self_rooted),
        _ => false,
    }
}

/// Whether `receiver` is direct `self` inside an inherent impl whose resolved
/// target type is the owner, so `self.member` resolves to that owner member.
fn enclosing_impl_type_matches_owner(receiver: Node<'_>, ctx: &MemberScanCtx<'_>) -> bool {
    let Some(impl_item) = enclosing_impl_item(receiver) else {
        return false;
    };
    let Some(type_node) = impl_item.child_by_field_name("type") else {
        return false;
    };
    resolved_type_matches_owner(type_node, ctx)
}

/// Whether `receiver` is `self.<field>` and that field's declared type on the
/// enclosing `impl` type is the owner type — so a `self.field.member` access
/// resolves without the receiver being a simple local of the owner type.
fn self_field_receiver_matches_owner(
    receiver: Node<'_>,
    enclosing: &CodeUnit,
    ctx: &MemberScanCtx<'_>,
) -> bool {
    if receiver.kind() != "field_expression" {
        return false;
    }
    if receiver
        .child_by_field_name("value")
        .is_none_or(|value| value.kind() != "self")
    {
        return false;
    }
    let Some(field_name) = receiver
        .child_by_field_name("field")
        .and_then(|field| simple_node_text(field, ctx.source))
    else {
        return false;
    };
    let Some(self_type) = ctx.analyzer.parent_of(enclosing) else {
        return false;
    };
    ctx.analyzer
        .get_members_in_class(&self_type)
        .into_iter()
        .filter(|member| member.is_field() && member.identifier() == field_name)
        .any(|member| field_declared_type_matches_receiver(&member, ctx))
}

fn enclosing_impl_item(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        if node.kind() == "impl_item" {
            return Some(node);
        }
        node = node.parent()?;
    }
}

fn resolved_type_matches_owner(type_node: Node<'_>, ctx: &MemberScanCtx<'_>) -> bool {
    let Some(fqn) = rust_resolve_type_node_fqn(
        ctx.analyzer,
        ctx.support,
        ctx.file,
        ctx.source,
        type_node,
        Some(type_node.start_byte()),
    ) else {
        return false;
    };
    fqn_matches_owner(ctx.rust, &fqn, ctx.owner)
}

fn fqn_matches_owner(rust: &RustAnalyzer, fqn: &str, owner: &CodeUnit) -> bool {
    rust.definitions(fqn).any(|unit| &unit == owner)
}

fn field_declared_type_matches_receiver(member: &CodeUnit, ctx: &MemberScanCtx<'_>) -> bool {
    let Some(range) = ctx.analyzer.ranges(member).into_iter().next() else {
        return false;
    };
    let Ok(source) = member.source().read_to_string() else {
        return false;
    };
    let Some(tree) = parse_rust_source(&source) else {
        return false;
    };
    let Some(field) = node_for_exact_range(tree.root_node(), range.start_byte, range.end_byte)
    else {
        return false;
    };
    field
        .child_by_field_name("type")
        .and_then(|ty| simple_type_name(ty, &source))
        .is_some_and(|ty| ctx.receiver_type_names.contains(&ty))
}

fn node_for_exact_range(root: Node<'_>, start: usize, end: usize) -> Option<Node<'_>> {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.start_byte() == start && node.end_byte() == end {
            return Some(node);
        }
        if node.start_byte() <= start && node.end_byte() >= end {
            let mut cursor = node.walk();
            let mut children: Vec<_> = node.named_children(&mut cursor).collect();
            children.reverse();
            stack.extend(children);
        }
    }
    None
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConstructorReturn {
    DirectReceiver,
    NeedsUnwrap,
}

fn field_expression_is_called(node: Node<'_>) -> bool {
    node.parent().is_some_and(|parent| {
        parent.kind() == "call_expression"
            && parent
                .child_by_field_name("function")
                .is_some_and(|function| same_node(function, node))
    })
}

fn record_static_member_hit(node: Node<'_>, ctx: &mut MemberScanCtx<'_>) {
    if node_in_use_declaration(node) {
        return;
    }
    let Some(name) = node.child_by_field_name("name") else {
        return;
    };
    if simple_node_text(name, ctx.source).as_deref() != Some(ctx.member_name) {
        return;
    }
    let Some(path) = node.child_by_field_name("path") else {
        return;
    };
    if !static_member_role_matches_target(field_expression_is_called(node), ctx) {
        return;
    }
    let Some(owner_name) = simple_node_text(path, ctx.source) else {
        return;
    };
    if !scoped_static_member_matches_target(path, &owner_name, ctx) {
        return;
    }

    record_static_member_name_hit(name, ctx);
}

fn record_static_member_name_hit(name: Node<'_>, ctx: &mut MemberScanCtx<'_>) {
    let start = name.start_byte();
    let end = name.end_byte();
    let Some(enclosing) = member_hit_enclosing(ctx.analyzer, ctx.file, ctx.line_starts, start, end)
    else {
        return;
    };
    push_member_hit(
        ctx.file,
        ctx.source,
        ctx.line_starts,
        start,
        end,
        enclosing,
        ctx.hits,
    );
}

fn static_member_role_matches_target(is_call: bool, ctx: &MemberScanCtx<'_>) -> bool {
    ctx.target_is_enum_variant || !ctx.target_is_field || !is_call
}

fn node_in_use_declaration(mut node: Node<'_>) -> bool {
    while let Some(parent) = node.parent() {
        if parent.kind() == "use_declaration" {
            return true;
        }
        node = parent;
    }
    false
}

fn scoped_static_member_matches_target(
    owner_node: Node<'_>,
    owner_name: &str,
    ctx: &MemberScanCtx<'_>,
) -> bool {
    if owner_name == "Self" {
        return self_static_owner_matches_target(owner_node, ctx);
    }

    let item_matches = if ctx.target_is_field {
        CodeUnit::is_field
    } else {
        CodeUnit::is_function
    };
    match resolve_scoped_associated_item_matching(
        ctx.rust,
        ctx.support,
        ctx.refs,
        ctx.file,
        owner_name,
        ctx.member_name,
        item_matches,
    ) {
        ReceiverAnalysisOutcome::Precise(candidates) => candidates.into_iter().any(|candidate| {
            same_rust_declaration_identity(&candidate, ctx.requested_target)
                || (ctx.rust.is_rust_trait_impl_member_declaration(&candidate)
                    && trait_member_for_impl_member(ctx.rust, &candidate)
                        .as_ref()
                        .is_some_and(|trait_member| {
                            same_rust_declaration_identity(trait_member, ctx.requested_target)
                        }))
        }),
        ReceiverAnalysisOutcome::Ambiguous(_)
        | ReceiverAnalysisOutcome::Unknown
        | ReceiverAnalysisOutcome::Unsupported { .. }
        | ReceiverAnalysisOutcome::ExceededBudget { .. } => false,
    }
}

fn self_static_owner_matches_target(owner_node: Node<'_>, ctx: &MemberScanCtx<'_>) -> bool {
    let mut current = Some(owner_node);
    while let Some(node) = current {
        match node.kind() {
            "impl_item" => {
                let owner = if ctx.target_owner_is_trait {
                    node.child_by_field_name("trait")
                } else {
                    node.child_by_field_name("type")
                };
                return owner.is_some_and(|owner| resolved_type_matches_owner(owner, ctx));
            }
            "trait_item" => {
                return node
                    .child_by_field_name("name")
                    .is_some_and(|name| resolved_type_matches_owner(name, ctx));
            }
            _ => current = node.parent(),
        }
    }
    false
}

fn self_like_constructor_returns(
    rust: &RustAnalyzer,
    owner: &CodeUnit,
) -> HashMap<String, ConstructorReturn> {
    let Ok(source) = owner.source().read_to_string() else {
        return HashMap::default();
    };
    let Some(tree) = parse_rust_source(&source) else {
        return HashMap::default();
    };

    rust.get_all_declarations()
        .into_iter()
        .filter(|code_unit| code_unit.source() == owner.source())
        .filter(|code_unit| code_unit.is_function())
        .filter(|code_unit| {
            // Associated constructors of the owner (`Owner::new`) and free functions
            // in the same module (`build_owner`) both return the owner type; a method
            // on a different type is excluded by the return-type check below.
            match rust.parent_of(code_unit) {
                None => true,
                Some(parent) => parent.is_module() || parent == *owner,
            }
        })
        .filter_map(|code_unit| {
            let range = rust.ranges(&code_unit).into_iter().next()?;
            let function =
                node_for_exact_range(tree.root_node(), range.start_byte, range.end_byte)?;
            let return_type = function_return_type_node(function)?;
            let ctx = ConstructorReturnCtx {
                rust,
                file: code_unit.source(),
                source: &source,
                owner,
            };
            constructor_return_kind_from_type_node(return_type, &ctx)
                .map(|kind| (code_unit.identifier().to_string(), kind))
        })
        .collect()
}

struct ConstructorReturnCtx<'a> {
    rust: &'a RustAnalyzer,
    file: &'a ProjectFile,
    source: &'a str,
    owner: &'a CodeUnit,
}

/// Whether a function's return type produces the owner type either directly as a
/// method receiver (`Self`, owner, `Box`/`Arc`/`Rc`) or behind an explicit
/// `Option`/`Result` unwrap. This inspects tree-sitter type nodes instead of
/// reparsing Rust type syntax from source text.
fn constructor_return_kind_from_type_node(
    type_node: Node<'_>,
    ctx: &ConstructorReturnCtx<'_>,
) -> Option<ConstructorReturn> {
    match type_node.kind() {
        "type_identifier" | "identifier" | "scoped_type_identifier" | "scoped_identifier" => {
            type_node_matches_constructor_owner(type_node, ctx)
                .then_some(ConstructorReturn::DirectReceiver)
        }
        "generic_type" => {
            let base = type_node.child_by_field_name("type").or_else(|| {
                let mut cursor = type_node.walk();
                type_node.named_children(&mut cursor).next()
            })?;
            let base_name = type_node_last_segment(base, ctx.source)?;
            if matches!(base_name.as_str(), "Box" | "Arc" | "Rc") {
                return first_generic_type_argument(type_node)
                    .and_then(|inner| constructor_return_kind_from_type_node(inner, ctx))
                    .filter(|kind| *kind == ConstructorReturn::DirectReceiver);
            }
            if matches!(base_name.as_str(), "Result" | "Option") {
                return first_generic_type_argument(type_node)
                    .and_then(|inner| constructor_return_kind_from_type_node(inner, ctx))
                    .map(|_| ConstructorReturn::NeedsUnwrap);
            }
            type_node_matches_constructor_owner(base, ctx)
                .then_some(ConstructorReturn::DirectReceiver)
        }
        "reference_type" | "pointer_type" => {
            let mut cursor = type_node.walk();
            type_node
                .named_children(&mut cursor)
                .find_map(|child| constructor_return_kind_from_type_node(child, ctx))
        }
        _ => None,
    }
}

fn function_return_type_node(function: Node<'_>) -> Option<Node<'_>> {
    if let Some(return_type) = function.child_by_field_name("return_type") {
        return Some(return_type);
    }

    let parameters = function.child_by_field_name("parameters")?;
    let body = function.child_by_field_name("body");
    let mut cursor = function.walk();
    function
        .named_children(&mut cursor)
        .filter(|child| child.start_byte() >= parameters.end_byte())
        .filter(|child| body.is_none_or(|body| !same_node(*child, body)))
        .find(|child| is_rust_type_node(*child))
}

pub(super) fn first_generic_type_argument(type_node: Node<'_>) -> Option<Node<'_>> {
    let type_arguments = type_node.child_by_field_name("type_arguments");
    let mut cursor = type_arguments.unwrap_or(type_node).walk();
    type_arguments
        .unwrap_or(type_node)
        .named_children(&mut cursor)
        .filter(|child| is_rust_type_node(*child))
        .find(|child| {
            type_node
                .child_by_field_name("type")
                .is_none_or(|base| !same_node(*child, base))
        })
}

fn is_rust_type_node(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "type_identifier"
            | "identifier"
            | "scoped_type_identifier"
            | "scoped_identifier"
            | "generic_type"
            | "reference_type"
            | "pointer_type"
            | "array_type"
            | "slice_type"
            | "tuple_type"
            | "unit_type"
            | "never_type"
    )
}

fn type_node_matches_constructor_owner(
    type_node: Node<'_>,
    ctx: &ConstructorReturnCtx<'_>,
) -> bool {
    if simple_node_text(type_node, ctx.source).as_deref() == Some("Self") {
        return true;
    }
    constructor_type_node_fqn(type_node, ctx)
        .as_deref()
        .is_some_and(|fqn| fqn_matches_owner(ctx.rust, fqn, ctx.owner))
}

fn constructor_type_node_fqn(
    type_node: Node<'_>,
    ctx: &ConstructorReturnCtx<'_>,
) -> Option<String> {
    let refs = ctx.rust.reference_context_of(ctx.file);

    match type_node.kind() {
        "type_identifier" | "identifier" => {
            let name = simple_node_text(type_node, ctx.source)?;
            refs.resolve_bare(&name).map(str::to_string)
        }
        "scoped_type_identifier" | "scoped_identifier" => {
            let path = type_node
                .child_by_field_name("path")
                .and_then(|path| simple_node_text(path, ctx.source))?;
            let name = type_node
                .child_by_field_name("name")
                .and_then(|name| simple_node_text(name, ctx.source))?;
            refs.resolve_scoped(&path, &name)
        }
        "generic_type" => type_node
            .child_by_field_name("type")
            .and_then(|base| constructor_type_node_fqn(base, ctx)),
        "reference_type" | "pointer_type" => {
            let mut cursor = type_node.walk();
            type_node
                .named_children(&mut cursor)
                .find_map(|child| constructor_type_node_fqn(child, ctx))
        }
        _ => None,
    }
}

pub(super) fn type_node_last_segment(type_node: Node<'_>, source: &str) -> Option<String> {
    match type_node.kind() {
        "type_identifier" | "identifier" => simple_node_text(type_node, source),
        "scoped_type_identifier" | "scoped_identifier" => type_node
            .child_by_field_name("name")
            .and_then(|name| simple_node_text(name, source)),
        "generic_type" => type_node
            .child_by_field_name("type")
            .and_then(|base| type_node_last_segment(base, source)),
        _ => None,
    }
}

fn self_like_constructor_seeds(
    rust: &RustAnalyzer,
    owner: &CodeUnit,
    constructor_returns: &HashMap<String, ConstructorReturn>,
) -> HashMap<String, BTreeSet<(ProjectFile, String)>> {
    constructor_returns
        .keys()
        .map(|name| {
            let seeds = rust.usage_seeds(owner.source(), name);
            (name.clone(), seeds)
        })
        .collect()
}

fn visible_bare_constructor_names(
    rust: &RustAnalyzer,
    file: &ProjectFile,
    constructors: &HashMap<String, BTreeSet<(ProjectFile, String)>>,
) -> HashSet<String> {
    let mut visible = HashSet::default();
    for (constructor, seeds) in constructors {
        let (direct_names, _) = rust.usage_binding_names(file, seeds);
        if direct_names.contains(constructor)
            || seeds
                .iter()
                .any(|(seed_file, seed_name)| seed_file == file && seed_name == constructor)
        {
            visible.insert(constructor.clone());
        }
    }
    visible
}

fn expanded_receiver_type_names(
    source: &str,
    owner_local_names: &HashSet<String>,
) -> HashSet<String> {
    let mut owner_type_names = owner_local_names.clone();
    let aliases = parse_rust_source(source)
        .map(|tree| collect_type_aliases(tree.root_node(), source))
        .unwrap_or_default();

    loop {
        let mut changed = false;
        for (alias, target) in &aliases {
            if owner_type_names.contains(target) && owner_type_names.insert(alias.clone()) {
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    owner_type_names
}

fn receiver_explicitly_mismatched(
    file_source: &str,
    enclosing_source: &str,
    owner_local_names: &HashSet<String>,
    receiver_name: &str,
) -> bool {
    let owner_type_names = expanded_receiver_type_names(file_source, owner_local_names);
    let Some(tree) = parse_rust_source(enclosing_source) else {
        return false;
    };

    for (name, ty) in collect_explicit_receiver_annotations(tree.root_node(), enclosing_source) {
        if name == receiver_name {
            return ty.as_ref().is_none_or(|ty| !owner_type_names.contains(ty));
        }
    }

    false
}

fn infer_receiver_names(
    source: &str,
    owner_local_names: &HashSet<String>,
    self_like_constructors: &HashMap<String, ConstructorReturn>,
    visible_bare_constructors: &HashSet<String>,
) -> Vec<String> {
    let owner_type_names = expanded_receiver_type_names(source, owner_local_names);
    let bindings = collect_receiver_bindings(
        source,
        &owner_type_names,
        self_like_constructors,
        visible_bare_constructors,
    );
    let mut receivers: Vec<_> = bindings
        .snapshot()
        .matching_symbols(|target| owner_type_names.contains(target))
        .into_iter()
        .collect();
    receivers.sort();
    receivers
}

#[allow(clippy::too_many_arguments)]
fn resolved_owner_receiver_names(
    root: Node<'_>,
    source: &str,
    analyzer: &dyn IAnalyzer,
    rust: &RustAnalyzer,
    support: &GlobalUsageDefinitionIndex,
    file: &ProjectFile,
    owner: &CodeUnit,
) -> Vec<String> {
    let mut receivers = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if matches!(node.kind(), "parameter" | "let_declaration")
            && let Some(pattern) = node.child_by_field_name("pattern")
            && let Some(name) = simple_pattern_name(pattern, source)
            && let Some(type_node) = node.child_by_field_name("type")
            && rust_resolve_type_node_fqn(
                analyzer,
                support,
                file,
                source,
                type_node,
                Some(type_node.start_byte()),
            )
            .is_some_and(|fqn| fqn_matches_owner(rust, &fqn, owner))
        {
            receivers.push(name);
        }

        let mut cursor = node.walk();
        let mut children: Vec<_> = node.named_children(&mut cursor).collect();
        children.reverse();
        stack.extend(children);
    }
    receivers
}

fn collect_receiver_bindings(
    source: &str,
    owner_type_names: &HashSet<String>,
    self_like_constructors: &HashMap<String, ConstructorReturn>,
    visible_bare_constructors: &HashSet<String>,
) -> LocalInferenceEngine<String> {
    let mut engine = LocalInferenceEngine::new(LocalInferenceConfig::default());
    let Some(tree) = parse_rust_source(source) else {
        return engine;
    };
    let root = tree.root_node();

    // A stable owner-type name to seed receivers whose owner type is known only
    // indirectly (a function whose return type is the owner). Any element of
    // `owner_type_names` matches in `infer_receiver_names`, so pick deterministically.
    let owner_repr = owner_type_names.iter().min().cloned();

    let option_field_types = collect_option_field_types(root, source);
    let mut aliases = Vec::new();
    for event in collect_receiver_events(root, source, &option_field_types) {
        match event {
            ReceiverEvent::TypedBinding { name, ty } => {
                if owner_type_names.contains(&ty) {
                    engine.seed_symbol(name, ty);
                }
            }
            ReceiverEvent::Constructed {
                name,
                ty,
                constructor,
                unwrapped,
            } => match constructor {
                // `Owner::new(...)` / tuple-struct `Owner(...)`: the path text is the
                // owner type and (for the scoped form) the associated fn must return it.
                Some(ctor) => {
                    if owner_type_names.contains(&ty)
                        && self_like_constructors
                            .get(&ctor)
                            .is_some_and(|kind| constructor_return_can_seed(*kind, unwrapped))
                    {
                        engine.seed_symbol(name, ty);
                    }
                }
                None if owner_type_names.contains(&ty) => {
                    engine.seed_symbol(name, ty);
                }
                // `let x = build_owner();` — a bare call to a free or associated
                // function whose return type is the owner. Seed the receiver's type so
                // method/field accesses on it resolve.
                None if visible_bare_constructors.contains(&ty)
                    && self_like_constructors
                        .get(&ty)
                        .is_some_and(|kind| constructor_return_can_seed(*kind, unwrapped)) =>
                {
                    if let Some(owner_repr) = owner_repr.clone() {
                        engine.seed_symbol(name, owner_repr);
                    }
                }
                None => {}
            },
            ReceiverEvent::Alias { name, source } => aliases.push((name, source)),
        }
    }
    engine.apply_aliases_until_stable(aliases);

    engine
}

fn constructor_return_can_seed(kind: ConstructorReturn, unwrapped: bool) -> bool {
    kind == ConstructorReturn::DirectReceiver || unwrapped
}

enum ReceiverEvent {
    TypedBinding {
        name: String,
        ty: String,
    },
    Constructed {
        name: String,
        ty: String,
        constructor: Option<String>,
        unwrapped: bool,
    },
    Alias {
        name: String,
        source: String,
    },
}

fn parse_rust_source(source: &str) -> Option<Tree> {
    if source.trim().is_empty() {
        return None;
    }
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .ok()?;
    parser.parse(source, None)
}

fn collect_type_aliases(root: Node<'_>, source: &str) -> Vec<(String, String)> {
    let mut aliases = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "type_item"
            && let (Some(alias), Some(target)) = (
                node.child_by_field_name("name")
                    .and_then(|name| simple_node_text(name, source)),
                node.child_by_field_name("type")
                    .and_then(|ty| simple_type_name(ty, source)),
            )
        {
            aliases.push((alias, target));
        }

        let mut cursor = node.walk();
        let mut children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
        children.reverse();
        stack.extend(children);
    }
    aliases
}

fn collect_explicit_receiver_annotations(
    root: Node<'_>,
    source: &str,
) -> Vec<(String, Option<String>)> {
    let mut bindings = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "parameter" | "let_declaration" => {
                if let Some((name, ty)) = explicit_receiver_annotation(node, source) {
                    bindings.push((name, ty));
                }
            }
            _ => {}
        }

        let mut cursor = node.walk();
        let mut children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
        children.reverse();
        stack.extend(children);
    }
    bindings
}

fn collect_option_field_types(root: Node<'_>, source: &str) -> HashMap<String, String> {
    let mut fields = HashMap::default();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "field_declaration"
            && let (Some(name), Some(ty)) = (
                node.child_by_field_name("name")
                    .and_then(|name| simple_node_text(name, source)),
                node.child_by_field_name("type")
                    .and_then(|ty| option_inner_type_name(ty, source)),
            )
        {
            fields.insert(name, ty);
        }

        let mut cursor = node.walk();
        let mut children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
        children.reverse();
        stack.extend(children);
    }
    fields
}

fn collect_receiver_events(
    root: Node<'_>,
    source: &str,
    option_field_types: &HashMap<String, String>,
) -> Vec<ReceiverEvent> {
    let mut events = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "parameter" => {
                if let Some((name, ty)) = typed_parameter_binding(node, source) {
                    events.push(ReceiverEvent::TypedBinding { name, ty });
                }
            }
            "let_declaration" => {
                collect_let_receiver_event(node, source, option_field_types, &mut events)
            }
            _ => {}
        }

        let mut cursor = node.walk();
        let mut children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
        children.reverse();
        stack.extend(children);
    }
    events
}

fn collect_let_receiver_event(
    node: Node<'_>,
    source: &str,
    option_field_types: &HashMap<String, String>,
    events: &mut Vec<ReceiverEvent>,
) {
    if let Some((name, ty)) = typed_let_binding(node, source) {
        events.push(ReceiverEvent::TypedBinding { name, ty });
        return;
    }

    if let Some((name, ty)) = self_field_as_ref_let_else_binding(node, source, option_field_types) {
        events.push(ReceiverEvent::TypedBinding { name, ty });
        return;
    }

    let Some(pattern) = node.child_by_field_name("pattern") else {
        return;
    };
    let Some(name) = simple_pattern_name(pattern, source) else {
        return;
    };
    let Some(value) = node.child_by_field_name("value") else {
        return;
    };

    if let Some((ty, constructor, unwrapped)) = constructed_receiver_type(value, source) {
        events.push(ReceiverEvent::Constructed {
            name,
            ty,
            constructor,
            unwrapped,
        });
    } else if let Some(source) = simple_node_text(value, source) {
        events.push(ReceiverEvent::Alias { name, source });
    }
}

fn typed_parameter_binding(node: Node<'_>, source: &str) -> Option<(String, String)> {
    let name = node
        .child_by_field_name("pattern")
        .and_then(|pattern| simple_pattern_name(pattern, source))?;
    let ty = node
        .child_by_field_name("type")
        .and_then(|ty| simple_type_name(ty, source))?;
    Some((name, ty))
}

fn typed_let_binding(node: Node<'_>, source: &str) -> Option<(String, String)> {
    let name = node
        .child_by_field_name("pattern")
        .and_then(|pattern| simple_pattern_name(pattern, source))?;
    let ty = node
        .child_by_field_name("type")
        .and_then(|ty| simple_type_name(ty, source))?;
    Some((name, ty))
}

fn explicit_receiver_annotation(node: Node<'_>, source: &str) -> Option<(String, Option<String>)> {
    let pattern = node.child_by_field_name("pattern")?;
    let name = simple_pattern_name(pattern, source)?;
    let ty = node.child_by_field_name("type")?;
    Some((name, direct_receiver_type_name(ty, source)))
}

fn direct_receiver_type_name(node: Node<'_>, source: &str) -> Option<String> {
    if let Some(name) = simple_type_name(node, source) {
        return Some(name);
    }
    if node.kind() != "reference_type" {
        return None;
    }
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find_map(|child| direct_receiver_type_name(child, source))
}

fn self_field_as_ref_let_else_binding(
    node: Node<'_>,
    source: &str,
    option_field_types: &HashMap<String, String>,
) -> Option<(String, String)> {
    let pattern = node.child_by_field_name("pattern")?;
    let name = some_tuple_pattern_name(pattern, source)?;
    let value = node.child_by_field_name("value")?;
    let field_name = self_field_as_ref_field_name(value, source)?;
    let ty = option_field_types.get(&field_name)?.clone();
    Some((name, ty))
}

fn some_tuple_pattern_name(node: Node<'_>, source: &str) -> Option<String> {
    if node.kind() != "tuple_struct_pattern" {
        return None;
    }
    let type_name = node
        .child_by_field_name("type")
        .and_then(|ty| simple_node_text(ty, source))?;
    if type_name != "Some" {
        return None;
    }
    let type_id = node.child_by_field_name("type").map(|ty| ty.id());
    let mut cursor = node.walk();
    let identifiers: Vec<_> = node
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "identifier" && Some(child.id()) != type_id)
        .filter_map(|child| simple_node_text(child, source))
        .collect();
    (identifiers.len() == 1).then(|| identifiers[0].clone())
}

fn self_field_as_ref_field_name(node: Node<'_>, source: &str) -> Option<String> {
    if node.kind() != "call_expression" {
        return None;
    }
    let function = node.child_by_field_name("function")?;
    if function.kind() != "field_expression" {
        return None;
    }
    if function
        .child_by_field_name("field")
        .and_then(|field| simple_node_text(field, source))
        .as_deref()
        != Some("as_ref")
    {
        return None;
    }
    let receiver = function.child_by_field_name("value")?;
    if receiver.kind() != "field_expression" {
        return None;
    }
    if receiver
        .child_by_field_name("value")
        .is_some_and(|value| value.kind() == "self")
    {
        receiver
            .child_by_field_name("field")
            .and_then(|field| simple_node_text(field, source))
    } else {
        None
    }
}

fn constructed_receiver_type(
    node: Node<'_>,
    source: &str,
) -> Option<(String, Option<String>, bool)> {
    match node.kind() {
        "struct_expression" => node
            .child_by_field_name("name")
            .and_then(|name| simple_type_name(name, source))
            .map(|name| (name, None, false)),
        "call_expression" => {
            let function = node.child_by_field_name("function")?;
            match function.kind() {
                "identifier" | "type_identifier" => {
                    simple_node_text(function, source).map(|name| (name, None, false))
                }
                "scoped_identifier" => {
                    let ty = function
                        .child_by_field_name("path")
                        .and_then(|path| simple_type_name(path, source))?;
                    let constructor = function
                        .child_by_field_name("name")
                        .and_then(|name| simple_node_text(name, source));
                    Some((ty, constructor, false))
                }
                "field_expression" => {
                    let method = function
                        .child_by_field_name("field")
                        .and_then(|field| simple_node_text(field, source));
                    let unwrapped = matches!(method.as_deref(), Some("unwrap" | "expect"));
                    function
                        .child_by_field_name("value")
                        .and_then(|value| constructed_receiver_type(value, source))
                        .map(|(ty, constructor, inner_unwrapped)| {
                            (ty, constructor, inner_unwrapped || unwrapped)
                        })
                }
                _ => None,
            }
        }
        _ => None,
    }
}

fn option_inner_type_name(node: Node<'_>, source: &str) -> Option<String> {
    if node.kind() != "generic_type" {
        return None;
    }
    if node
        .child_by_field_name("type")
        .and_then(|ty| simple_node_text(ty, source))
        .as_deref()
        != Some("Option")
    {
        return None;
    }
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|child| child.kind() != "type_identifier")
        .find_map(|child| first_simple_type_name(child, source))
}

fn first_simple_type_name(node: Node<'_>, source: &str) -> Option<String> {
    if let Some(name) = simple_type_name(node, source) {
        return Some(name);
    }
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find_map(|child| first_simple_type_name(child, source))
}

fn simple_type_name(node: Node<'_>, source: &str) -> Option<String> {
    matches!(node.kind(), "type_identifier" | "identifier")
        .then(|| simple_node_text(node, source))
        .flatten()
}

fn simple_pattern_name(node: Node<'_>, source: &str) -> Option<String> {
    (node.kind() == "identifier")
        .then(|| simple_node_text(node, source))
        .flatten()
}

fn simple_node_text(node: Node<'_>, source: &str) -> Option<String> {
    let text = source.get(node.start_byte()..node.end_byte())?.trim();
    (!text.is_empty()).then(|| text.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{AnalyzerQueryScope, Language, TestProject};

    #[test]
    fn pre_cancelled_graph_build_skips_file_parsing() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::write(root.join("lib.rs"), "pub fn target() {}\n").unwrap();
        let file = ProjectFile::new(root.clone(), "lib.rs");
        let analyzer = RustAnalyzer::from_project(TestProject::new(root, Language::Rust));
        let _scope = AnalyzerQueryScope::new(&analyzer);

        let live = build_rust_graph_for_files(&analyzer, [file.clone()], None);
        assert!(live.parsed.contains_key(&file));

        let cancellation = CancellationToken::default();
        cancellation.cancel();
        let cancelled = build_rust_graph_for_files(&analyzer, [file], Some(&cancellation));
        assert!(cancelled.parsed.is_empty());
    }

    #[test]
    fn graph_build_reuses_prepared_syntax_within_query_scope() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::write(root.join("lib.rs"), "pub fn target() {}\n").unwrap();
        let file = ProjectFile::new(root.clone(), "lib.rs");
        let analyzer = RustAnalyzer::from_project(TestProject::new(root, Language::Rust));
        let _scope = AnalyzerQueryScope::new(&analyzer);

        let first = build_rust_graph_for_files(&analyzer, [file.clone()], None);
        let second = build_rust_graph_for_files(&analyzer, [file.clone()], None);

        let first = first.parsed.get(&file).expect("first prepared syntax");
        let second = second.parsed.get(&file).expect("reused prepared syntax");
        assert!(Arc::ptr_eq(first, second));
        assert_eq!(analyzer.prepared_syntax_parse_count_for_test(&file), 1);
    }
}
