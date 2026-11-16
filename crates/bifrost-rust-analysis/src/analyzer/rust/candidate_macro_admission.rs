//! Query-local package and scope proof. This operation never materializes IR.
use super::RustAnalyzer;
use brokk_bifrost_analysis::analyzer::i_analyzer::QueryReadReceipt;
use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
use brokk_bifrost_core::analyzer::model::ProjectFile;
use brokk_bifrost_rust::format_args::RustMacroRuntimeLayout;
use brokk_bifrost_rust::graph_support::RustCargoRouteError;
use brokk_bifrost_rust::usage_walks::RustUsageWalks;

/// An admission answer owns its read evidence even when the proof refuses.
#[allow(dead_code)] // The procedure owner will consume the receipt and digest.
pub(crate) struct CandidateMacroAdmission {
    pub proof: Result<CandidateMacroProof, CandidateMacroRefusal>,
    pub answer_digest: [u8; 32],
    pub reads: QueryReadReceipt,
}

#[derive(Debug)]
#[allow(dead_code)] // Consumed by the subsequent procedure owner.
pub(crate) struct CandidateMacroProof {
    pub package: String,
    pub package_identity_digest: [u8; 32],
    pub layout: RustMacroRuntimeLayout,
}

#[derive(Debug)]
pub(crate) enum CandidateMacroRefusal {
    Evidence(String),
    Route(RustCargoRouteError),
}

impl From<String> for CandidateMacroRefusal {
    fn from(reason: String) -> Self {
        Self::Evidence(reason)
    }
}

#[cfg(test)]
pub(crate) fn admit_candidate_macro(
    rust: &RustAnalyzer,
    walks: &RustUsageWalks<'_>,
    file: &ProjectFile,
    exposed: &str,
    member: &str,
    byte: usize,
    leading_absolute: bool,
) -> CandidateMacroAdmission {
    admit_candidate_macro_in_scopes(
        rust,
        walks,
        file,
        exposed,
        member,
        &super::format_macro_dispatch::RustMacroSourceScope {
            byte,
            leading_absolute,
            fragments: &[],
            source: "",
        },
    )
}

pub(super) fn admit_candidate_macro_in_scopes(
    rust: &RustAnalyzer,
    walks: &RustUsageWalks<'_>,
    file: &ProjectFile,
    exposed: &str,
    member: &str,
    scope: &super::format_macro_dispatch::RustMacroSourceScope<'_>,
) -> CandidateMacroAdmission {
    let byte = scope.byte;
    let leading_absolute = scope.leading_absolute;
    let (proof, reads) = QueryReadReceipt::capture(rust, || {
        // An empty exposed name is the isolated descriptor convention for bare candidates.
        if exposed.is_empty() {
            prove_bare_logging_binding(walks, file, member, scope)?;
        }
        let exposed = if exposed.is_empty() { "log" } else { exposed };
        let package = rust.selected_dependency_package(file, exposed)?;
        if package != "log" {
            return Err(CandidateMacroRefusal::Evidence(format!(
                "selected dependency names package {package:?}, not log"
            )));
        }
        if super::format_macro_dispatch::rust_macro_root_is_shadowed_in_scopes(
            rust, walks, file, exposed, scope,
        )
        .map_err(CandidateMacroRefusal::Route)?
        {
            return Err("written root is shadowed by a module or import"
                .to_owned()
                .into());
        }
        if !walks
            .has_available_declared_dependency(file, exposed)
            .unwrap_or(false)
        {
            return Err("declared dependency route is unavailable".to_owned().into());
        }
        let layout = brokk_bifrost_rust::format_args::rust_macro_runtime_layout("log", member)
            .ok_or_else(|| {
                CandidateMacroRefusal::Evidence(format!("unsupported logging member {member:?}"))
            })?;
        let mut identity = CanonicalHasher::new(b"rust-candidate-macro-package:v1");
        identity.value(package.as_bytes());
        Ok(CandidateMacroProof {
            package,
            layout,
            package_identity_digest: identity.finish(),
        })
    });
    let mut digest = CanonicalHasher::new(b"rust-candidate-macro-admission:v1");
    digest.value(exposed.as_bytes());
    digest.value(member.as_bytes());
    digest.value(&[u8::from(leading_absolute)]);
    digest.value(
        &u64::try_from(byte)
            .expect("source offset fits u64")
            .to_le_bytes(),
    );
    digest.value(format!("{:?}", reads.digest()).as_bytes());
    match &proof {
        Err(CandidateMacroRefusal::Evidence(reason)) => digest.value(reason.as_bytes()),
        _ => digest.value(format!("{proof:?}").as_bytes()),
    }
    CandidateMacroAdmission {
        proof,
        answer_digest: digest.finish(),
        reads,
    }
}

/// Bare names require positive import evidence and a closed lexical namespace.
/// Fragment-local import and macro scopes are deliberately refused until projected.
fn prove_bare_logging_binding(
    walks: &RustUsageWalks<'_>,
    file: &ProjectFile,
    member: &str,
    scope: &super::format_macro_dispatch::RustMacroSourceScope<'_>,
) -> Result<(), CandidateMacroRefusal> {
    let route = CandidateMacroRefusal::Route;
    if !scope.fragments.is_empty() || scope.leading_absolute {
        return Err("bare macro fragment scope is unproved".to_owned().into());
    }
    let Some(module) = walks
        .queries()
        .module_at_byte(file, scope.byte)
        .map_err(route)?
    else {
        return Err("bare macro module is unavailable".to_owned().into());
    };
    for declaration in walks.macro_declarations_named(member).map_err(route)? {
        if walks
            .macro_visible_ranges_of(&declaration)
            .map_err(route)?
            .iter()
            .any(|(key, ranges)| {
                key.file == *file
                    && key.module == module
                    && ranges
                        .iter()
                        .any(|&(start, end)| start <= scope.byte && scope.byte < end)
            })
        {
            return Err("visible local macro shadows bare logging name"
                .to_owned()
                .into());
        }
    }
    let mut bound = false;
    for owner in walks.files_for_module(&module).iter() {
        for binding in walks.import_bindings_of(owner).map_err(route)?.iter() {
            if binding.importer_module != module || !binding.extent.contains(scope.byte) {
                continue;
            }
            if binding.local_name.is_glob() {
                return Err("bare macro has an unproved glob in scope".to_owned().into());
            }
            if binding.local_name.named() == Some(member) {
                if binding.is_extern_crate
                    || binding.path.as_slice() != ["log", member]
                    || bound
                    || binding.cfg_condition
                        != brokk_bifrost_core::analyzer::rust_facts::RustCfgCondition::Always
                {
                    return Err("competing import binds bare macro name".to_owned().into());
                }
                bound = true;
            }
        }
    }
    for root in walks.target_roots_of(file) {
        for binding in walks.import_bindings_of(&root).map_err(route)?.iter() {
            if binding.is_macro_use && binding.is_extern_crate {
                if binding.path.as_slice() != ["log"]
                    || binding.cfg_condition
                        != brokk_bifrost_core::analyzer::rust_facts::RustCfgCondition::Always
                {
                    return Err("competing macro-use crate has unknown exports"
                        .to_owned()
                        .into());
                }
                bound = true;
            }
        }
    }
    if !bound {
        return Err("no structured log import binds bare macro name"
            .to_owned()
            .into());
    }
    Ok(())
}

/// LanguageSupport bridge; package and scope policy remain in the single proof helper.
pub(super) fn admit_procedure_candidates(
    context: brokk_bifrost_analysis::analyzer::languages::CandidateMacroAdmissionRequest<'_>,
) -> Vec<brokk_bifrost_analysis::analyzer::languages::CandidateMacroAdmissionAnswer> {
    use brokk_bifrost_analysis::analyzer::languages::{
        CandidateMacroAdmissionAnswer, CandidateMacroDecision, CandidateMacroRealization,
        CandidateMacroRefusal as Refusal,
    };
    use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;
    context
        .candidates
        .iter()
        .map(|candidate| {
            let (decision, reads) = QueryReadReceipt::capture(context.analyzer, || {
                if context.cancellation.is_cancelled() {
                    context.analyzer.record_query_incomplete(
                        brokk_bifrost_analysis::analyzer::i_analyzer::QueryReadIncomplete::Cancelled,
                    );
                    return CandidateMacroDecision::Refused(Refusal::Cancelled);
                }
                let runtime_argument_count = match candidate.realization {
                    CandidateMacroRealization::RuntimeCall {
                        runtime_argument_count,
                    } => runtime_argument_count,
                    CandidateMacroRealization::Intrinsic => {
                        return admit_matches_intrinsic(&context, candidate);
                    }
                    CandidateMacroRealization::LexicalNoItemsIntroduced => {
                        return admit_lexical_no_items(&context, candidate);
                    }
                };
                let descriptor = || {
                    let start = candidate.anchor.start_byte as usize;
                    fn invocation(
                        tree: &tree_sitter::Tree,
                        start: usize,
                    ) -> Option<tree_sitter::Node<'_>> {
                        let mut node = tree
                            .root_node()
                            .named_descendant_for_byte_range(start, start.checked_add(1)?)?;
                        while node.kind() != "macro_invocation" || node.start_byte() != start {
                            node = node.parent()?;
                        }
                        Some(node)
                    }
                    // Parse enclosing operands, not just the nested invocation:
                    // their block-local bindings remain part of its lexical scope.
                    let mut fragments: Vec<tree_sitter::Tree> = Vec::new();
                    let mut wrappers = Vec::new();
                    loop {
                        let tree = fragments.last().unwrap_or(context.syntax.tree());
                        if invocation(tree, start).is_some() {
                            break;
                        }
                        let mut containing = tree
                            .root_node()
                            .named_descendant_for_byte_range(start, start.checked_add(1)?)?;
                        while containing.kind() != "macro_invocation" {
                            containing = containing.parent()?;
                        }
                        let path = containing.child_by_field_name("macro")?;
                        let segments = brokk_bifrost_rust::graph_support::rust_path_segments(path)?;
                        let [owner, member] = segments.as_slice() else {
                            return None;
                        };
                        // Conservative by design: unknown and renamed enclosing wrappers refuse.
                        // Only known runtime layouts guarantee that the operand
                        // becomes executable code without introducing bindings.
                        brokk_bifrost_rust::format_args::rust_macro_runtime_layout(
                            brokk_bifrost_rust::declarations::rust_node_text(
                                *owner,
                                context.syntax.source(),
                            ),
                            brokk_bifrost_rust::declarations::rust_node_text(
                                *member,
                                context.syntax.source(),
                            ),
                        )?;
                        wrappers.push((
                            brokk_bifrost_rust::declarations::rust_node_text(
                                *owner,
                                context.syntax.source(),
                            )
                            .to_owned(),
                            brokk_bifrost_rust::declarations::rust_node_text(
                                *member,
                                context.syntax.source(),
                            )
                            .to_owned(),
                            containing.start_byte(),
                            brokk_bifrost_rust::graph_support::rust_path_is_leading_absolute(path),
                        ));
                        let operands = brokk_bifrost_rust::macro_matcher::parse_macro_operands(
                            containing,
                            context.syntax.source(),
                        )?;
                        let operand = operands.into_iter().find(|operand| {
                            operand.binding.start_byte <= start && start < operand.binding.end_byte
                        })?;
                        fragments.push(operand.tree);
                    }
                    let tree = fragments.last().unwrap_or(context.syntax.tree());
                    let node = invocation(tree, start)?;
                    let path = node.child_by_field_name("macro")?;
                    let segments = brokk_bifrost_rust::graph_support::rust_path_segments(path)?;
                    // Keep bare descriptor interpretation here for the producer merge.
                    let source = context.syntax.source();
                    let name = |node| {
                        brokk_bifrost_core::analyzer::symbol_path::strip_raw_identifier_prefix(
                            brokk_bifrost_rust::declarations::rust_node_text(node, source),
                        )
                        .to_owned()
                    };
                    let (exposed, member) = match segments.as_slice() {
                        [member] => (String::new(), name(*member)),
                        [exposed, member] => (name(*exposed), name(*member)),
                        _ => return None,
                    };
                    Some((
                        exposed,
                        member,
                        start,
                        brokk_bifrost_rust::graph_support::rust_path_is_leading_absolute(path),
                        fragments,
                        wrappers,
                    ))
                };
                let Some((exposed, member, start_byte, leading_absolute, fragments, wrappers)) =
                    descriptor()
                else {
                    return CandidateMacroDecision::Refused(Refusal::Evidence(
                        "candidate source mapping has no supported macro path".to_owned(),
                    ));
                };
                // The lowering realizes a matches! as a call only when this file binds
                // the name to a macro of its own (#11251).
                if member == "matches" {
                    return refuse_matches_call(&context, candidate);
                }
                let Some(rust) = resolve_analyzer::<RustAnalyzer>(context.analyzer) else {
                    return CandidateMacroDecision::Refused(Refusal::UnavailableAnalyzer);
                };
                brokk_bifrost_rust::graph_support::with_usage_read_frame(rust, || {
                    let keep_going = || !context.cancellation.is_cancelled();
                    let walks = match RustUsageWalks::new_while(rust, context.token, &keep_going) {
                        Ok(walks) => walks,
                        Err(error) => {
                            return CandidateMacroDecision::Refused(Refusal::Route(format!(
                                "{error:?}"
                            )));
                        }
                    };
                    for (owner, member, byte, leading_absolute) in &wrappers {
                        let scope = super::format_macro_dispatch::RustMacroSourceScope {
                            byte: *byte,
                            leading_absolute: *leading_absolute,
                            fragments: &fragments,
                            source: context.syntax.source(),
                        };
                        if owner == "log" {
                            let admission = admit_candidate_macro_in_scopes(
                                rust,
                                &walks,
                                context.file,
                                owner,
                                member,
                                &scope,
                            );
                            admission.reads.replay(context.analyzer);
                            match admission.proof {
                                Ok(_) => continue,
                                Err(reason) => {
                                    return CandidateMacroDecision::Refused(Refusal::Evidence(
                                        format!("enclosing macro identity: {reason:?}"),
                                    ));
                                }
                            }
                        }
                        match super::format_macro_dispatch::rust_macro_root_is_shadowed_in_scopes(
                            rust,
                            &walks,
                            context.file,
                            owner,
                            &scope,
                        ) {
                            Ok(false) if matches!(owner.as_str(), "std" | "core" | "alloc") => {}
                            Ok(_) => {
                                return CandidateMacroDecision::Refused(Refusal::Evidence(
                                    "enclosing macro root has no proven standard crate identity"
                                        .to_owned(),
                                ));
                            }
                            Err(error) => {
                                return CandidateMacroDecision::Refused(Refusal::Route(format!(
                                    "{error:?}"
                                )));
                            }
                        }
                    }
                    let admission = admit_candidate_macro_in_scopes(
                        rust,
                        &walks,
                        context.file,
                        &exposed,
                        &member,
                        &super::format_macro_dispatch::RustMacroSourceScope {
                            byte: start_byte,
                            leading_absolute,
                            fragments: &fragments,
                            source: context.syntax.source(),
                        },
                    );
                    admission.reads.replay(context.analyzer);
                    match admission.proof {
                        Ok(proof) if runtime_argument_count != proof.layout.arguments.len() => {
                            CandidateMacroDecision::Refused(Refusal::RealizationIncomplete)
                        }
                        Ok(proof) => CandidateMacroDecision::Admitted {
                            package_identity_digest: proof.package_identity_digest,
                        },
                        Err(CandidateMacroRefusal::Evidence(reason)) => {
                            CandidateMacroDecision::Refused(Refusal::Evidence(reason))
                        }
                        Err(CandidateMacroRefusal::Route(error)) => {
                            CandidateMacroDecision::Refused(Refusal::Route(format!("{error:?}")))
                        }
                    }
                })
            });
            reads.replay(context.analyzer);
            CandidateMacroAdmissionAnswer::new(candidate.region, decision, reads)
        })
        .collect()
}

/// Admit a matches! intrinsic only when its identity is proven to be std or core
/// matches, including every enclosing wrapper (#11251). The answer carries no
/// source offset.
fn admit_matches_intrinsic(
    context: &brokk_bifrost_analysis::analyzer::languages::CandidateMacroAdmissionRequest<'_>,
    candidate: &brokk_bifrost_analysis::analyzer::languages::CandidateMacroInvocation,
) -> brokk_bifrost_analysis::analyzer::languages::CandidateMacroDecision {
    use brokk_bifrost_analysis::analyzer::languages::{
        CandidateMacroDecision, CandidateMacroRefusal as Refusal,
    };
    use brokk_bifrost_rust::macro_matcher::{StandardMacroIdentity, StandardMacroIdentityUnknown};
    match candidate_standard_identity(context, candidate) {
        Ok(StandardMacroIdentity::Standard { owner, member }) if member == "matches" => {
            let mut identity = CanonicalHasher::new(b"rust-standard-macro-intrinsic:v1");
            identity.value(owner.as_str().as_bytes());
            identity.value(member.as_bytes());
            CandidateMacroDecision::Admitted {
                package_identity_digest: identity.finish(),
            }
        }
        Ok(StandardMacroIdentity::Unknown(StandardMacroIdentityUnknown::Route(error))) => {
            CandidateMacroDecision::Refused(Refusal::Route(format!("{error:?}")))
        }
        Ok(identity) => CandidateMacroDecision::Refused(Refusal::Evidence(format!(
            "matches! identity is not proven standard: {identity:?}"
        ))),
        Err(refusal) => refusal,
    }
}

/// A matches! lowered as an opaque call is one this file binds to a macro of its
/// own: the intrinsic is never realized as a call. Refuse it with the identity the
/// shared proof reaches, so the candidate row keeps a typed reason instead of the
/// logging-macro descriptor's.
fn refuse_matches_call(
    context: &brokk_bifrost_analysis::analyzer::languages::CandidateMacroAdmissionRequest<'_>,
    candidate: &brokk_bifrost_analysis::analyzer::languages::CandidateMacroInvocation,
) -> brokk_bifrost_analysis::analyzer::languages::CandidateMacroDecision {
    use brokk_bifrost_analysis::analyzer::languages::{
        CandidateMacroDecision, CandidateMacroRefusal as Refusal,
    };
    use brokk_bifrost_rust::macro_matcher::StandardMacroIdentity;
    use brokk_bifrost_rust::macro_matcher::StandardMacroIdentityUnknown;
    match candidate_standard_identity(context, candidate) {
        Ok(StandardMacroIdentity::Unknown(StandardMacroIdentityUnknown::Route(error))) => {
            CandidateMacroDecision::Refused(Refusal::Route(format!("{error:?}")))
        }
        Ok(identity) => CandidateMacroDecision::Refused(Refusal::Evidence(format!(
            "matches! is realized as a call, not the standard intrinsic: {identity:?}"
        ))),
        Err(refusal) => refusal,
    }
}

pub(super) fn audited_item_free_stdlib_selected(analyzer: &dyn crate::analyzer::IAnalyzer) -> bool {
    use brokk_bifrost_rust::macro_matcher::ITEM_FREE_MACRO_STDLIB_REVISION;
    let Some(models) = analyzer.active_semantic_models() else {
        return false;
    };
    let mut found = false;
    for shard in &models.shards {
        if shard.metadata.manifest.pack_id != "bifrost.rust-stdlib" {
            continue;
        }
        found = true;
        if shard.metadata.manifest.provenance.revision.as_deref()
            != Some(ITEM_FREE_MACRO_STDLIB_REVISION)
        {
            return false;
        }
    }
    found
}

/// This proof is captured in the enclosing candidate admission receipt. The
/// model-set read binds the audit to the selected standard-library revision.
fn admit_lexical_no_items(
    context: &brokk_bifrost_analysis::analyzer::languages::CandidateMacroAdmissionRequest<'_>,
    candidate: &brokk_bifrost_analysis::analyzer::languages::CandidateMacroInvocation,
) -> brokk_bifrost_analysis::analyzer::languages::CandidateMacroDecision {
    use brokk_bifrost_analysis::analyzer::languages::{
        CandidateMacroDecision, CandidateMacroRefusal,
    };
    use brokk_bifrost_rust::macro_matcher::{
        StandardMacroLexicalEffect, standard_macro_lexical_effect,
    };
    let refusal = || {
        CandidateMacroDecision::Refused(CandidateMacroRefusal::Evidence(
            "macro lacks an audited enclosing-scope no-items proof".to_owned(),
        ))
    };
    if !audited_item_free_stdlib_selected(context.analyzer) {
        return refusal();
    }
    let revision = brokk_bifrost_rust::macro_matcher::ITEM_FREE_MACRO_STDLIB_REVISION;
    match candidate_standard_identity(context, candidate) {
        Ok(identity)
            if standard_macro_lexical_effect(&identity, revision)
                == StandardMacroLexicalEffect::NoItemsIntroduced =>
        {
            let mut digest = CanonicalHasher::new(b"rust-lexical-no-items:v1");
            digest.value(revision.as_bytes());
            if let brokk_bifrost_rust::macro_matcher::StandardMacroIdentity::Standard {
                owner,
                member,
            } = identity
            {
                digest.value(owner.as_str().as_bytes());
                digest.value(member.as_bytes());
            }
            CandidateMacroDecision::Admitted {
                package_identity_digest: digest.finish(),
            }
        }
        Ok(brokk_bifrost_rust::macro_matcher::StandardMacroIdentity::Unknown(
            brokk_bifrost_rust::macro_matcher::StandardMacroIdentityUnknown::Route(error),
        )) => CandidateMacroDecision::Refused(CandidateMacroRefusal::Route(format!("{error:?}"))),
        Err(refusal) => refusal,
        _ => refusal(),
    }
}

/// The standard identity of the invocation at the candidate's anchor, proven
/// through the shared standard_macro_identity with every enclosing wrapper. The
/// refusal is the decision for an invocation that cannot be located or whose
/// enclosing macros have no known executable operand layout.
fn candidate_standard_identity(
    context: &brokk_bifrost_analysis::analyzer::languages::CandidateMacroAdmissionRequest<'_>,
    candidate: &brokk_bifrost_analysis::analyzer::languages::CandidateMacroInvocation,
) -> Result<
    brokk_bifrost_rust::macro_matcher::StandardMacroIdentity,
    brokk_bifrost_analysis::analyzer::languages::CandidateMacroDecision,
> {
    use brokk_bifrost_analysis::analyzer::languages::{
        CandidateMacroDecision, CandidateMacroRefusal as Refusal,
    };
    use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;
    let source = context.syntax.source();
    let start = candidate.anchor.start_byte as usize;
    let end = candidate.anchor.end_byte as usize;
    fn invocation_at(tree: &tree_sitter::Tree, start: usize) -> Option<tree_sitter::Node<'_>> {
        let mut node = tree
            .root_node()
            .named_descendant_for_byte_range(start, start.checked_add(1)?)?;
        while node.kind() != "macro_invocation" || node.start_byte() != start {
            node = node.parent()?;
        }
        Some(node)
    }
    // Parse enclosing operands so that a nested invocation is found in its own
    // fragment tree. Only wrappers with a known runtime layout guarantee that
    // the operand is executable code that introduces no bindings.
    let mut fragments: Vec<tree_sitter::Tree> = Vec::new();
    loop {
        let tree = fragments.last().unwrap_or(context.syntax.tree());
        if invocation_at(tree, start).is_some() {
            break;
        }
        let located = (|| {
            let mut containing = tree
                .root_node()
                .named_descendant_for_byte_range(start, start.checked_add(1)?)?;
            while containing.kind() != "macro_invocation" {
                containing = containing.parent()?;
            }
            let segments = brokk_bifrost_rust::graph_support::rust_path_segments(
                containing.child_by_field_name("macro")?,
            )?;
            let text = |node| {
                brokk_bifrost_core::analyzer::symbol_path::strip_raw_identifier_prefix(
                    brokk_bifrost_rust::declarations::rust_node_text(node, source),
                )
            };
            let (owner, member) = match segments.as_slice() {
                [member] => ("std", text(*member)),
                [owner, member] => (text(*owner), text(*member)),
                _ => return None,
            };
            brokk_bifrost_rust::format_args::rust_macro_runtime_layout(owner, member)?;
            let operands =
                brokk_bifrost_rust::macro_matcher::parse_macro_operands(containing, source)?;
            operands
                .into_iter()
                .find(|operand| {
                    operand.binding.start_byte <= start && start < operand.binding.end_byte
                })
                .map(|operand| operand.tree)
        })();
        let Some(fragment) = located else {
            return Err(CandidateMacroDecision::Refused(Refusal::Evidence(
                "matches! is nested in an enclosing macro with no known executable operand layout"
                    .to_owned(),
            )));
        };
        fragments.push(fragment);
    }
    let tree = fragments.last().unwrap_or(context.syntax.tree());
    let Some(invocation) = invocation_at(tree, start).filter(|node| node.end_byte() == end) else {
        return Err(CandidateMacroDecision::Refused(Refusal::Evidence(
            "candidate anchor does not name a macro invocation".to_owned(),
        )));
    };
    let Some(lexical_context) = context
        .syntax
        .tree()
        .root_node()
        .descendant_for_byte_range(start, end)
    else {
        return Err(CandidateMacroDecision::Refused(Refusal::Evidence(
            "candidate anchor has no lexical context".to_owned(),
        )));
    };
    let Some(rust) = resolve_analyzer::<RustAnalyzer>(context.analyzer) else {
        return Err(CandidateMacroDecision::Refused(
            Refusal::UnavailableAnalyzer,
        ));
    };
    // The file's own macro_rules! definitions bind the name before any route does.
    let exported = brokk_bifrost_rust::macro_matcher::ExportedMacroDefinitions::from_root(
        context.syntax.tree().root_node(),
        source,
    );
    brokk_bifrost_rust::graph_support::with_usage_read_frame(rust, || {
        let keep_going = || !context.cancellation.is_cancelled();
        let walks = match RustUsageWalks::new_while(rust, context.token, &keep_going) {
            Ok(walks) => walks,
            Err(error) => {
                return Err(CandidateMacroDecision::Refused(Refusal::Route(format!(
                    "{error:?}"
                ))));
            }
        };
        Ok(brokk_bifrost_rust::macro_matcher::standard_macro_identity(
            rust,
            &walks,
            context.file,
            invocation,
            source,
            Some(&exported),
            lexical_context,
            &fragments,
        ))
    })
}
