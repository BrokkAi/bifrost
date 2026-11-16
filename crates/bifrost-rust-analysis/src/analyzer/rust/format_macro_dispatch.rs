//! Rust-owned exact dispatch for value-carrying built-in macro invocations.
//!
//! The shared call dispatcher offers structured call syntax to the registered
//! language adapter; Rust resolves macro identity here through its query-local
//! usage walk and leaves ordinary calls to the framework resolver.

use std::collections::BTreeSet;

use brokk_bifrost_core::analyzer::usages::model::UsageProof;

use brokk_bifrost_analysis::analyzer::usages::call_relations::CallDispatchBoundaryKind;

use brokk_bifrost_analysis::analyzer::usages::call_relations::CallDispatchLanguageRequest;

use brokk_bifrost_analysis::analyzer::usages::call_relations::CallDispatchLookup;

use brokk_bifrost_analysis::analyzer::usages::call_relations::CallDispatchTarget;

use crate::analyzer::usages::call_relations::CallRelationWork;

use brokk_bifrost_analysis::analyzer::usages::call_relations::unresolved_dispatch_lookup;

use brokk_bifrost_analysis::analyzer::usages::get_definition::DefinitionLookupStatus;

use brokk_bifrost_analysis::analyzer::usages::get_definition::ExactExternalCallProof;

use brokk_bifrost_core::analyzer::model::CodeUnit;

use brokk_bifrost_core::analyzer::model::Language;

use crate::analyzer::RustAnalyzer;

use brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer;

use brokk_bifrost_core::cancellation::CancellationToken;
use brokk_bifrost_rust::graph_support::RustCargoRouteError;
use brokk_bifrost_rust::usage::{RustReferenceNamespace, RustReferenceResolution};
use brokk_bifrost_rust::usage_walks::RustUsageWalks;

/// Resolve a built-in macro through Rust's query-local visibility
/// facts before ordinary call-reference dispatch. The final path segment only
/// selects this parser/resolver route; identity always comes from the Rust
/// macro resolver, so a same-spelled local macro remains opaque.
pub(crate) fn dispatch(
    request: CallDispatchLanguageRequest<'_>,
    selected: Option<&brokk_bifrost_analysis::analyzer::semantic::ProcedureHandle>,
) -> Option<CallDispatchLookup> {
    let CallDispatchLanguageRequest {
        analyzer,
        token,
        file,
        source,
        tree,
        macro_inventory,
        call_span,
        member_selection: _,
        cancellation,
        mut work,
    } = request;
    let mut invocation = tree.root_node().named_descendant_for_byte_range(
        call_span.start_byte,
        call_span.start_byte.checked_add(1)?,
    )?;
    while invocation.kind() != "macro_invocation" || invocation.start_byte() != call_span.start_byte
    {
        invocation = invocation.parent()?;
    }
    if invocation.end_byte() != call_span.end_byte {
        let statement = invocation.parent()?;
        if statement.kind() != "expression_statement"
            || statement.start_byte() != call_span.start_byte
            || statement.end_byte() != call_span.end_byte
        {
            return None;
        }
    }
    let standard_dispatch = |owner: &str, member: &str, work| {
        let mut lookup = rust_standard_macro_dispatch(owner, member, work);
        if member == "vec"
            && let Ok(arguments) =
                brokk_bifrost_rust::format_args::rust_vec_macro_arguments(invocation, source)
        {
            lookup.exact_external_call = Some(ExactExternalCallProof::rust_external_call(
                "alloc::vec",
                u32::try_from(arguments.into_operands().len()).expect("vec operand count fits u32"),
            ));
        }
        lookup
    };
    let path = invocation.child_by_field_name("macro")?;
    let leading_absolute = brokk_bifrost_rust::graph_support::rust_path_is_leading_absolute(path);
    let path_segments = brokk_bifrost_rust::graph_support::rust_path_segments(path)?;
    let terminal = *path_segments.last()?;
    let terminal_name = brokk_bifrost_core::analyzer::symbol_path::strip_raw_identifier_prefix(
        brokk_bifrost_rust::declarations::rust_node_text(terminal, source),
    );
    let path_names = path_segments
        .iter()
        .map(|segment| {
            brokk_bifrost_core::analyzer::symbol_path::strip_raw_identifier_prefix(
                brokk_bifrost_rust::declarations::rust_node_text(*segment, source),
            )
        })
        .collect::<Vec<_>>();
    let formatting_macro =
        brokk_bifrost_rust::format_args::rust_formatting_macro(terminal_name).is_some();
    // matches! is never a call: its alternate is an intrinsic (#11251).
    let value_macro = brokk_bifrost_rust::format_args::rust_value_macro(terminal_name)
        .is_some_and(|kind| kind != brokk_bifrost_rust::format_args::RustValueMacro::Matches);
    let logging_macro = match path_names.as_slice() {
        [member] => brokk_bifrost_rust::format_args::rust_logging_macro("log", member).is_some(),
        [owner, member] => {
            brokk_bifrost_rust::format_args::rust_logging_macro(owner, member).is_some()
        }
        _ => false,
    };
    if let Some(selected) = selected
        && brokk_bifrost_analysis::analyzer::usages::call_shape::admitted_candidate_call(
            selected, *call_span,
        )
        .is_some()
    {
        return Some(standard_dispatch("log", terminal_name, work));
    }
    if !formatting_macro && !value_macro && !logging_macro {
        return None;
    }
    let rust = resolve_analyzer::<RustAnalyzer>(analyzer)?;
    brokk_bifrost_rust::graph_support::with_usage_read_frame(rust, || {
        if cancellation.is_some_and(CancellationToken::is_cancelled) {
            return Some(CallDispatchLookup {
                cancelled: true,
                work,
                ..CallDispatchLookup::default()
            });
        }
        let keep_going = || !cancellation.is_some_and(CancellationToken::is_cancelled);
        let walks = match RustUsageWalks::new_while(rust, token, &keep_going) {
            Ok(walks) => walks,
            Err(error) => return Some(rust_macro_route_error(error, work)),
        };
        if logging_macro && path_names.len() == 1 {
            let admission = super::candidate_macro_admission::admit_candidate_macro_in_scopes(
                rust,
                &walks,
                file,
                "",
                terminal_name,
                &RustMacroSourceScope {
                    byte: call_span.start_byte,
                    leading_absolute,
                    fragments: &[],
                    source,
                },
            );
            if let Ok(proof) = admission.proof {
                return Some(standard_dispatch(&proof.package, terminal_name, work));
            }
            return None;
        }
        let declarations = match walks.macro_declarations_named(terminal_name) {
            Ok(declarations) => declarations,
            Err(error) => return Some(rust_macro_route_error(error, work)),
        };
        let roots = declarations.into_iter().collect::<BTreeSet<CodeUnit>>();
        work.examined_candidates = work.examined_candidates.saturating_add(roots.len());
        let seeds = match walks.binding_seeds_while(rust, &roots, &keep_going) {
            Ok(Some(seeds)) => seeds,
            Ok(None) if cancellation.is_some_and(CancellationToken::is_cancelled) => {
                return Some(CallDispatchLookup {
                    cancelled: true,
                    work,
                    ..CallDispatchLookup::default()
                });
            }
            Ok(None) => {
                return Some(unresolved_dispatch_lookup(
                    DefinitionLookupStatus::Incomplete,
                    format!("Rust macro binding seeds are incomplete for {terminal_name:?}"),
                    work,
                ));
            }
            Err(error) => return Some(rust_macro_route_error(error, work)),
        };
        let resolution = match brokk_bifrost_rust::usage::usage_reference_at_with_walks(
            rust,
            &walks,
            file,
            &seeds,
            &path_names,
            path.start_byte(),
            RustReferenceNamespace::Macro,
            false,
            leading_absolute,
        ) {
            Ok(resolution) => resolution,
            Err(error) => return Some(rust_macro_route_error(error.into(), work)),
        };
        let owned_inventory;
        let inventory = if let Some(inventory) =
            macro_inventory.filter(|inventory| inventory.matches_tree(tree))
        {
            inventory
        } else {
            owned_inventory =
                match brokk_bifrost_rust::macro_matcher::MacroDefinitionInventory::build(
                    tree,
                    source,
                    &keep_going,
                ) {
                    Ok(inventory) => inventory,
                    Err(error) => return Some(rust_macro_route_error(error, work)),
                };
            &owned_inventory
        };
        let exported = inventory.exported();
        let standard_identity =
            brokk_bifrost_rust::macro_matcher::standard_macro_identity_with_resolution(
                rust,
                &walks,
                file,
                invocation,
                source,
                Some(&exported),
                invocation,
                &[],
                &seeds,
                &resolution,
            );
        if let brokk_bifrost_rust::macro_matcher::StandardMacroIdentity::Standard {
            owner,
            member,
        } = &standard_identity
        {
            return Some(standard_dispatch(owner.as_str(), member, work));
        }
        if let brokk_bifrost_rust::macro_matcher::StandardMacroIdentity::Unknown(
            brokk_bifrost_rust::macro_matcher::StandardMacroIdentityUnknown::Route(error),
        ) = &standard_identity
        {
            return Some(rust_macro_route_error(*error, work));
        }
        match resolution {
            RustReferenceResolution::Exact(identity) => {
                // The macro's source declaration is not the callable whose
                // macro-derived argument shape is being selected. Use the exact
                // resolved crate and macro identity to choose its external model
                // target, as the prelude route does when no declaration exists.
                let declarations = match walks.declarations_of_identity(&identity) {
                    Ok(declarations) => declarations
                        .into_iter()
                        .filter(CodeUnit::is_macro)
                        .collect::<Vec<_>>(),
                    Err(error) => return Some(rust_macro_route_error(error, work)),
                };
                match declarations.as_slice() {
                    [definition] => Some(CallDispatchLookup {
                        status: Some(DefinitionLookupStatus::Resolved),
                        targets: vec![CallDispatchTarget {
                            definition: definition.clone(),
                            proof: UsageProof::Proven,
                            native_incomplete_source_reason: None,
                        }],
                        diagnostics: vec![format!(
                            "Rust formatting macro resolves to source declaration {definition:?}"
                        )],
                        work,
                        ..CallDispatchLookup::default()
                    }),
                    [] => Some(unresolved_dispatch_lookup(
                        DefinitionLookupStatus::Incomplete,
                        format!("resolved Rust macro identity has no declaration: {identity:?}"),
                        work,
                    )),
                    _ => Some(unresolved_dispatch_lookup(
                        DefinitionLookupStatus::Ambiguous,
                        format!(
                            "resolved Rust macro identity has multiple declarations: {identity:?}"
                        ),
                        work,
                    )),
                }
            }
            RustReferenceResolution::Ambiguous(identities) => Some(unresolved_dispatch_lookup(
                DefinitionLookupStatus::Ambiguous,
                format!("Rust formatting macro resolution is ambiguous: {identities:?}"),
                work,
            )),
            RustReferenceResolution::Unresolved => {
                if matches!(
                    standard_identity,
                    brokk_bifrost_rust::macro_matcher::StandardMacroIdentity::Shadowed
                ) && let [owner, member] = path_names.as_slice()
                    && brokk_bifrost_rust::macro_matcher::rust_standard_macro_in_crate(
                        owner, member,
                    )
                {
                    return Some(unresolved_dispatch_lookup(
                        DefinitionLookupStatus::Incomplete,
                        format!("Rust formatting macro root is shadowed: {path_names:?}"),
                        work,
                    ));
                }
                if path_names.len() == 1 {
                    let candidates = match walks.selected_macro_invocation_candidates_named(
                        &seeds,
                        file,
                        terminal_name,
                        call_span.start_byte,
                    ) {
                        Ok(candidates) => candidates,
                        Err(error) => return Some(rust_macro_route_error(error, work)),
                    };
                    if !candidates.is_empty() {
                        return Some(unresolved_dispatch_lookup(
                            DefinitionLookupStatus::Incomplete,
                            format!(
                                "Rust formatting macro has visible candidates but no exact selection: {candidates:?}"
                            ),
                            work,
                        ));
                    }
                } else if path_names.len() == 2 {
                    let owner = path_names[0];
                    let member = path_names[1];
                    let is_log_macro =
                        brokk_bifrost_rust::format_args::rust_logging_macro(owner, member)
                            .is_some();
                    if is_log_macro {
                        let shadowed = match rust_macro_root_is_shadowed(
                            rust,
                            &walks,
                            file,
                            owner,
                            call_span.start_byte,
                            leading_absolute,
                        ) {
                            Ok(shadowed) => shadowed,
                            Err(error) => return Some(rust_macro_route_error(error, work)),
                        };
                        if shadowed {
                            return Some(unresolved_dispatch_lookup(
                                DefinitionLookupStatus::Incomplete,
                                format!("Rust formatting macro root is shadowed: {path_names:?}"),
                                work,
                            ));
                        }
                        // An unknown answer (a partial crate) is not available:
                        // the lookup stays Incomplete rather than certifying
                        // the macro.
                        let dependency_available = !is_log_macro
                            || (rust.selected_dependency_package(file, owner).as_deref()
                                == Ok("log")
                                && walks.has_available_declared_dependency(file, owner)
                                    == Some(true));
                        if dependency_available {
                            return Some(standard_dispatch(owner, member, work));
                        }
                    }
                }
                Some(unresolved_dispatch_lookup(
                    DefinitionLookupStatus::Incomplete,
                    format!("Rust formatting macro identity is unresolved: {path_names:?}"),
                    work,
                ))
            }
        }
    })
}

#[cfg(test)]
use brokk_bifrost_rust::macro_matcher::rust_standard_macro_prelude_owner;
fn rust_standard_macro_dispatch(
    owner: &str,
    member: &str,
    work: CallRelationWork,
) -> CallDispatchLookup {
    let layout = brokk_bifrost_rust::format_args::rust_macro_runtime_layout(owner, member);
    let (owner, member, parameter_count) = if let Some(layout) = layout {
        (
            layout.owner,
            layout.member,
            (member != "vec").then(|| {
                u32::try_from(layout.arguments.len()).expect("built-in macro arity fits u32")
            }),
        )
    } else {
        match brokk_bifrost_rust::format_args::rust_value_macro(member) {
            Some(brokk_bifrost_rust::format_args::RustValueMacro::Vec) => ("alloc", "vec", None),
            _ => (owner, member, None),
        }
    };
    let identity = crate::analyzer::semantic::ResolverOwnedExternalCalleeIdentity::new(
        Language::Rust,
        owner,
        member,
    );
    let exact_external_call = parameter_count.map(|parameter_count| {
        ExactExternalCallProof::rust_external_call(
            format!("{}::{member}", owner.replace('.', "::")),
            parameter_count,
        )
    });
    CallDispatchLookup {
        status: Some(DefinitionLookupStatus::Resolved),
        boundaries: vec![CallDispatchBoundaryKind::External {
            callee_text: None,
            normalized_static_owner: Some(owner.into()),
            external_callee_identity: Some(identity),
        }],
        exact_external_call,
        work,
        ..CallDispatchLookup::default()
    }
}

fn rust_macro_route_error(
    error: RustCargoRouteError,
    work: CallRelationWork,
) -> CallDispatchLookup {
    match error {
        RustCargoRouteError::Cancelled => CallDispatchLookup {
            cancelled: true,
            work,
            ..CallDispatchLookup::default()
        },
        RustCargoRouteError::Unavailable => unresolved_dispatch_lookup(
            DefinitionLookupStatus::Unavailable,
            "Rust macro visibility facts are unavailable".to_string(),
            work,
        ),
    }
}

pub(super) use brokk_bifrost_rust::macro_matcher::RustMacroSourceScope;

pub(super) fn rust_macro_root_is_shadowed(
    rust: &RustAnalyzer,
    walks: &RustUsageWalks<'_>,
    file: &brokk_bifrost_core::analyzer::model::ProjectFile,
    root_name: &str,
    byte: usize,
    leading_absolute: bool,
) -> Result<bool, RustCargoRouteError> {
    rust_macro_root_is_shadowed_in_scopes(
        rust,
        walks,
        file,
        root_name,
        &RustMacroSourceScope {
            byte,
            leading_absolute,
            fragments: &[],
            source: "",
        },
    )
}

pub(super) use brokk_bifrost_rust::macro_matcher::rust_macro_root_is_shadowed_in_scopes;
#[cfg(test)]
mod tests {

    use crate::analyzer::rust::RustAnalyzer;
    use crate::analyzer::rust::format_macro_dispatch::*;
    use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;
    use brokk_bifrost_core::analyzer::model::{Language, ProjectFile};
    use brokk_bifrost_core::analyzer::query_token::QueryScope;
    use brokk_bifrost_rust::usage_walks::RustUsageWalks;
    use brokk_bifrost_test_macros::hardwon;

    fn candidate_admission(
        files: &[(&str, &str)],
        source_path: &str,
        source: &str,
    ) -> super::super::candidate_macro_admission::CandidateMacroAdmission {
        let mut project = crate::inline_project::InlineTestProject::with_language(Language::Rust);
        for (path, contents) in files {
            project = project.file(*path, *contents);
        }
        if !files.iter().any(|(path, _)| *path == source_path) {
            project = project.file(source_path, source);
        }
        let project = project.build();
        let filesystem = brokk_bifrost_analysis::analyzer::FilesystemProject::new(project.root())
            .expect("filesystem fixture project");
        let workspace = brokk_bifrost_analysis::WorkspaceAnalyzer::build_ephemeral_footgun(
            std::sync::Arc::new(filesystem),
            brokk_bifrost_analysis::AnalyzerConfig::default(),
        )
        .expect("workspace should build");
        let analyzer = brokk_bifrost_analysis::analyzer::multi_analyzer::resolve_analyzer::<
            RustAnalyzer,
        >(workspace.analyzer())
        .expect("workspace owns its Rust analyzer");
        let scope = AnalyzerQueryScope::new(analyzer);
        let walks = RustUsageWalks::new(analyzer, scope.token()).expect("Rust usage walks");
        let file = ProjectFile::new(project.root(), source_path);
        let exposed = if source.contains("renamed::info!") {
            "renamed"
        } else {
            "log"
        };
        let byte = source
            .find(&format!("{exposed}::info!"))
            .expect("candidate invocation");
        super::super::candidate_macro_admission::admit_candidate_macro(
            analyzer, &walks, &file, exposed, "info", byte, false,
        )
    }

    fn assert_receipt(
        admission: &super::super::candidate_macro_admission::CandidateMacroAdmission,
    ) {
        assert_ne!(
            admission.reads.digest().as_bytes(),
            &[0; 32],
            "empty read receipt"
        );
    }

    const SOURCE: &str = "pub fn run() { log::info!(\"message\"); }";
    const MANIFEST: &str = "[package]\nname=\"candidate\"\nversion=\"0.1.0\"\nedition=\"2021\"\n";

    #[test]
    #[hardwon("#11541: cancelled identity walks were reported as unresolved")]
    fn standard_macro_identity_preserves_cancellation() {
        use super::super::test_support::{analyzed_file, certified_analyzer, project};
        use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;
        use brokk_bifrost_core::analyzer::query_token::QueryScope;
        use brokk_bifrost_rust::macro_matcher::{
            StandardMacroIdentity, StandardMacroIdentityUnknown, standard_macro_identity,
        };
        let source = "pub fn run() { println!(\"hello\"); }";
        let (temp, _) = project(&[("Cargo.toml", MANIFEST), ("src/lib.rs", source)]);
        let (_workspace, analyzer) = certified_analyzer(temp.path());
        let scope = AnalyzerQueryScope::new(&analyzer);
        let cancelled = std::cell::Cell::new(false);
        let keep_going = || !cancelled.get();
        let walks = RustUsageWalks::new_while(&analyzer, scope.token(), &keep_going).unwrap();
        let file = analyzed_file(&analyzer, "src/lib.rs");
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let mut pending = vec![tree.root_node()];
        let invocation = loop {
            let node = pending.pop().unwrap();
            if node.kind() == "macro_invocation" {
                break node;
            }
            let mut cursor = node.walk();
            pending.extend(node.named_children(&mut cursor));
        };
        cancelled.set(true);
        assert_eq!(
            standard_macro_identity(
                &analyzer,
                &walks,
                &file,
                invocation,
                source,
                None,
                invocation,
                &[]
            ),
            StandardMacroIdentity::Unknown(StandardMacroIdentityUnknown::Route(
                RustCargoRouteError::Cancelled
            ))
        );
        assert!(
            rust_macro_route_error(RustCargoRouteError::Cancelled, CallRelationWork::default())
                .cancelled
        );
    }

    #[test]
    #[hardwon("#11251: indexed standard macro aliases and imports lost modeled dispatch")]
    fn indexed_standard_macro_alias_dispatch() {
        use super::super::test_support::{analyzed_file, certified_analyzer, project};
        use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;
        use brokk_bifrost_core::analyzer::query_token::QueryScope;
        use brokk_bifrost_rust::macro_matcher::{
            StandardMacroIdentity, StandardMacroOwner, standard_macro_identity,
        };
        for source in [
            "use std as s; pub fn run() { s::println!(\"hello\"); }",
            "use std::println; pub fn run() { println!(\"hello\"); }",
        ] {
            let (temp, _) = project(&[
                (
                    "Cargo.toml",
                    r#"[package]
name="app"
version="0.1.0"
edition="2021"
[dependencies]
std={path="std"}
[workspace]
members=["std"]
"#,
                ),
                ("src/lib.rs", source),
                (
                    "std/Cargo.toml",
                    r#"[package]
name="std"
version="0.1.0"
edition="2021"
"#,
                ),
                (
                    "std/src/lib.rs",
                    "#[macro_export] macro_rules! println { ($($t:tt)*) => {} }",
                ),
            ]);
            let (_workspace, analyzer) = certified_analyzer(temp.path());
            let scope = AnalyzerQueryScope::new(&analyzer);
            let walks = RustUsageWalks::new(&analyzer, scope.token()).unwrap();
            let file = analyzed_file(&analyzer, "src/lib.rs");
            assert!(
                !walks
                    .macro_declarations_named("println")
                    .unwrap()
                    .is_empty()
            );
            let mut parser = tree_sitter::Parser::new();
            parser
                .set_language(&tree_sitter_rust::LANGUAGE.into())
                .unwrap();
            let tree = parser.parse(source, None).unwrap();
            let mut pending = vec![tree.root_node()];
            let invocation = loop {
                let node = pending.pop().unwrap();
                if node.kind() == "macro_invocation" {
                    break node;
                }
                let mut cursor = node.walk();
                pending.extend(node.named_children(&mut cursor));
            };
            assert_eq!(
                standard_macro_identity(
                    &analyzer,
                    &walks,
                    &file,
                    invocation,
                    source,
                    None,
                    invocation,
                    &[]
                ),
                StandardMacroIdentity::Standard {
                    owner: StandardMacroOwner::Std,
                    member: "println".into()
                }
            );
            let range = brokk_bifrost_core::analyzer::model::Range {
                start_byte: invocation.start_byte(),
                end_byte: invocation.end_byte(),
                start_line: invocation.start_position().row + 1,
                end_line: invocation.end_position().row + 1,
            };
            let answer = dispatch(
                CallDispatchLanguageRequest {
                    analyzer: &analyzer,
                    token: scope.token(),
                    file: &file,
                    source,
                    tree: &tree,
                    macro_inventory: None,
                    call_span: &range,
                    member_selection: None,
                    cancellation: None,
                    work: Default::default(),
                },
                None,
            )
            .unwrap();
            let expected = rust_standard_macro_dispatch("std", "println", Default::default());
            assert_eq!(answer.status, expected.status);
            assert_eq!(
                format!("{:?}", answer.boundaries),
                format!("{:?}", expected.boundaries)
            );
            assert_eq!(
                format!("{:?}", answer.exact_external_call),
                format!("{:?}", expected.exact_external_call)
            );
            assert!(answer.targets.is_empty());
        }
    }

    #[test]
    #[hardwon("#11532: warm lexical macro identity must refuse a newly shadowing macro or import")]
    fn lexical_macro_shadow_edits_match_cold_identity() {
        use super::super::test_support::{analyzed_file, certified_analyzer, project};
        use brokk_bifrost_analysis::IAnalyzer;
        use brokk_bifrost_analysis::analyzer::ReadKey;
        use brokk_bifrost_analysis::analyzer::i_analyzer::capture_query_reads;
        use brokk_bifrost_rust::macro_matcher::{
            ExportedMacroDefinitions, ITEM_FREE_MACRO_STDLIB_REVISION, StandardMacroLexicalEffect,
            standard_macro_identity, standard_macro_lexical_effect,
        };
        const MANIFEST: &str = "[package]\nname=\"app\"\nversion=\"0.1.0\"\nedition=\"2021\"\n";
        const CALL: &str = "pub fn run() { println!(\"hello\"); }";
        let prove = |analyzer: &RustAnalyzer, source: &str| {
            let scope = AnalyzerQueryScope::new(analyzer);
            let walks = RustUsageWalks::new(analyzer, scope.token()).unwrap();
            let mut parser = tree_sitter::Parser::new();
            parser
                .set_language(&tree_sitter_rust::LANGUAGE.into())
                .unwrap();
            let tree = parser.parse(source, None).unwrap();
            let start = source.rfind("println!(").unwrap();
            let mut invocation = tree
                .root_node()
                .named_descendant_for_byte_range(start, start + 1)
                .unwrap();
            while invocation.kind() != "macro_invocation" {
                invocation = invocation.parent().unwrap();
            }
            let exported = ExportedMacroDefinitions::from_root(tree.root_node(), source);
            let (identity, reads) = capture_query_reads(analyzer, || {
                standard_macro_identity(
                    analyzer,
                    &walks,
                    &analyzed_file(analyzer, "src/lib.rs"),
                    invocation,
                    source,
                    Some(&exported),
                    invocation,
                    &[],
                )
            });
            assert!(reads.keys().iter().any(|key| matches!(key, ReadKey::File { rel_path, .. } if rel_path.as_ref() == "src/lib.rs")), "identity must read selected source: {:?}", reads.keys());
            standard_macro_lexical_effect(&identity, ITEM_FREE_MACRO_STDLIB_REVISION)
        };
        for prefix in [
            "macro_rules! println { ($($t:tt)*) => { struct Generated; } }",
            "mod other { macro_rules! replacement { ($($t:tt)*) => {} } pub(crate) use replacement as println; } use other::println;",
        ] {
            let (temp, _) = project(&[("Cargo.toml", MANIFEST), ("src/lib.rs", CALL)]);
            let (_workspace, analyzer) = certified_analyzer(temp.path());
            assert_eq!(
                prove(&analyzer, CALL),
                StandardMacroLexicalEffect::NoItemsIntroduced
            );
            assert_eq!(
                prove(&analyzer, CALL),
                StandardMacroLexicalEffect::NoItemsIntroduced
            );
            let changed = format!("{prefix}\n{CALL}");
            std::fs::write(temp.path().join("src/lib.rs"), &changed).unwrap();
            let updated = analyzer.update_all();
            let warm = prove(&updated, &changed);
            let (cold_temp, _) =
                project(&[("Cargo.toml", MANIFEST), ("src/lib.rs", changed.as_str())]);
            let (_cold_workspace, cold) = certified_analyzer(cold_temp.path());
            assert_eq!(warm, prove(&cold, &changed));
            assert_eq!(warm, StandardMacroLexicalEffect::Unknown);
        }
    }

    #[test]
    fn standard_macro_identity_outcomes() {
        use super::super::test_support::{analyzed_file, certified_analyzer, project};
        use brokk_bifrost_analysis::analyzer::i_analyzer::AnalyzerQueryScope;
        use brokk_bifrost_core::analyzer::query_token::QueryScope;
        use brokk_bifrost_rust::macro_matcher::{
            ExportedMacroDefinitions, StandardMacroIdentity as Identity,
            StandardMacroIdentityUnknown as Unknown, StandardMacroOwner as Owner,
            standard_macro_identity,
        };
        let manifest = "[package]\nname=\"app\"\nversion=\"0.1.0\"\nedition=\"2021\"\n";
        for (source, expected) in [
            (
                "pub fn run() { std::println!(\"hello\"); }",
                Identity::Standard {
                    owner: Owner::Std,
                    member: "println".into(),
                },
            ),
            (
                "pub fn run() { core::panic!(\"hello\"); }",
                Identity::Standard {
                    owner: Owner::Core,
                    member: "panic".into(),
                },
            ),
            (
                "macro_rules! println { () => {} } pub fn run() { println!(); }",
                Identity::LocallyBound,
            ),
            (
                "use other::println; pub fn run() { println!(); }",
                Identity::Shadowed,
            ),
            ("pub fn run() { other!(); }", Identity::NotStandard),
            (
                "#![no_implicit_prelude] pub fn run() { println!(); }",
                Identity::Unknown(Unknown::PreludeDisabled),
            ),
            (
                "pub fn run() { println!(); }",
                Identity::Unknown(Unknown::Route(RustCargoRouteError::Unavailable)),
            ),
        ] {
            let partial = matches!(expected, Identity::Unknown(Unknown::Route(_)));
            let source_path = if partial {
                "src/orphan.rs"
            } else {
                "src/lib.rs"
            };
            let partial_manifest = format!("{manifest}[lib]\nmystery = true\n");
            let (temp, uncertified) = if partial {
                project(&[
                    ("Cargo.toml", partial_manifest.as_str()),
                    ("src/lib.rs", ""),
                    (source_path, source),
                ])
            } else {
                project(&[("Cargo.toml", manifest), (source_path, source)])
            };
            let (_workspace, analyzer) = if matches!(expected, Identity::Unknown(Unknown::Route(_)))
            {
                (None, uncertified)
            } else {
                let (workspace, analyzer) = certified_analyzer(temp.path());
                (Some(workspace), analyzer)
            };
            let scope = AnalyzerQueryScope::new(&analyzer);
            let walks = RustUsageWalks::new(&analyzer, scope.token()).unwrap();
            if partial {
                let routes = walks.file_routes(&analyzed_file(&analyzer, source_path));
                assert!(!routes.is_complete());
                assert!(
                    routes
                        .target_roots(&analyzed_file(&analyzer, source_path))
                        .is_empty()
                );
            }
            let mut parser = tree_sitter::Parser::new();
            parser
                .set_language(&tree_sitter_rust::LANGUAGE.into())
                .unwrap();
            let tree = parser.parse(source, None).unwrap();
            let mut pending = vec![tree.root_node()];
            let mut invocation = None;
            while let Some(node) = pending.pop() {
                if node.kind() == "macro_invocation" {
                    invocation = Some(node);
                    break;
                }
                let mut cursor = node.walk();
                pending.extend(node.named_children(&mut cursor));
            }
            let invocation = invocation.unwrap();
            let exported = ExportedMacroDefinitions::from_root(tree.root_node(), source);
            assert_eq!(
                standard_macro_identity(
                    &analyzer,
                    &walks,
                    &analyzed_file(&analyzer, source_path),
                    invocation,
                    source,
                    Some(&exported),
                    invocation,
                    &[]
                ),
                expected,
                "{source}"
            );
        }
    }

    #[test]
    #[hardwon("#10972: macro-only log import falsely shadowed the crate path")]
    fn candidate_macro_qualified_with_macro_namespace_import() {
        for prefix in ["", "use log::log;"] {
            let source = format!("{prefix}\n{SOURCE}");
            let manifest = format!("{MANIFEST}[dependencies]\nlog=\"0.4\"\n");
            let answer = candidate_admission(&[("Cargo.toml", &manifest)], "src/lib.rs", &source);
            assert!(answer.proof.is_ok(), "{prefix}: {:?}", answer.proof);
        }
    }

    #[test]
    fn candidate_macro_admission_accepts_registry_workspace_and_real_package_rename() {
        let cases = [
            (
                "registry dependency",
                vec![("Cargo.toml", format!("{MANIFEST}[dependencies]\nlog=\"0.4\"\n"))],
            ),
            (
                "inherited workspace dependency",
                vec![
                    (
                        "Cargo.toml",
                        "[workspace]\nmembers=[\"app\"]\nresolver=\"2\"\n[workspace.dependencies]\nlog=\"0.4\"\n".to_owned(),
                    ),
                    (
                        "app/Cargo.toml",
                        "[package]\nname=\"candidate\"\nversion=\"0.1.0\"\nedition=\"2021\"\n[dependencies]\nlog={workspace=true}\n".to_owned(),
                    ),
                ],
            ),
            (
                "renamed real log package",
                vec![(
                    "Cargo.toml",
                    format!("{MANIFEST}[dependencies]\nrenamed={{package=\"log\",version=\"0.4\"}}\n"),
                )],
            ),
        ];

        for (label, manifest_files) in cases {
            let mut files: Vec<(&str, &str)> = manifest_files
                .iter()
                .map(|(path, contents)| (*path, contents.as_str()))
                .collect();
            let source_path = if label == "inherited workspace dependency" {
                "app/src/lib.rs"
            } else {
                "src/lib.rs"
            };
            let source = if label == "renamed real log package" {
                "pub fn run() { renamed::info!(\"message\"); }"
            } else {
                SOURCE
            };
            files.push((source_path, source));
            let admission = candidate_admission(&files, source_path, source);
            // Qualified dependency paths are unaffected by unrelated macro names
            // and by edition-2021 glob imports (rustc rejects ambiguous roots).
            for prefix in ["macro_rules! info { ($($t:tt)*) => {} }", "use std::io::*;"] {
                let decorated = format!("{prefix}\n{source}");
                let mut decorated_files = files.clone();
                decorated_files.retain(|(path, _)| *path != source_path);
                decorated_files.push((source_path, decorated.as_str()));
                assert!(
                    candidate_admission(&decorated_files, source_path, &decorated)
                        .proof
                        .is_ok(),
                    "{label}: {prefix}"
                );
            }

            let proof = admission
                .proof
                .as_ref()
                .unwrap_or_else(|reason| panic!("{label}: {reason:?}"));
            assert_eq!(proof.package, "log", "{label}");
            assert!(!format!("{:?}", proof.layout).is_empty(), "{label}");
            assert_receipt(&admission);
        }
    }

    #[test]
    #[hardwon("#10972: unproved macro identity exposed executable operands")]
    fn candidate_macro_admission_refuses_unproved_scope_and_package_identities() {
        let patch_manifest = format!(
            "{MANIFEST}[dependencies]\nlog=\"0.4\"\n[patch.crates-io]\nlog={{path=\"vendor/log\"}}\n"
        );
        type RefusalCase<'a> = (&'a str, &'a str, Vec<(&'a str, String)>, &'a str);
        let cases: [RefusalCase<'_>; 6] = [
            (
                "local module re-export",
                "src/lib.rs",
                vec![
                    ("Cargo.toml", format!("{MANIFEST}[dependencies]\nlog=\"0.4\"\n")),
                    ("src/lib.rs", "mod log { pub use ::log::info; }\npub fn run() { log::info!(\"message\"); }".to_owned()),
                ],
                "shadow",
            ),
            (
                "shadowing import",
                "src/lib.rs",
                vec![
                    ("Cargo.toml", format!("{MANIFEST}[dependencies]\nlog=\"0.4\"\n")),
                    ("src/lib.rs", "mod fake {}\nuse crate::fake as log;\npub fn run() { log::info!(\"message\"); }".to_owned()),
                ],
                "shadow",
            ),
            (
                "renamed different package",
                "src/lib.rs",
                vec![("Cargo.toml", format!("{MANIFEST}[dependencies]\nlog={{package=\"notlog\",version=\"0.4\"}}\n"))],
                "not log",
            ),
            (
                "patched registry package",
                "src/lib.rs",
                vec![
                    ("Cargo.toml", patch_manifest),
                    ("vendor/log/Cargo.toml", "[package]\nname=\"log\"\nversion=\"0.4.0\"\nedition=\"2021\"\n".to_owned()),
                ],
                "patch",
            ),
            (
                "Cargo config override",
                "src/lib.rs",
                vec![
                    ("Cargo.toml", format!("{MANIFEST}[dependencies]\nlog=\"0.4\"\n")),
                    (".cargo/config.toml", "[patch.crates-io]\nlog={path=\"vendor/log\"}\n".to_owned()),
                ],
                "config",
            ),
            (
                "unavailable selected identity",
                "Cargo.toml",
                vec![
                    ("Cargo.toml", "[workspace]\nmembers=[\"app\",\"neighbor\"]\nresolver=\"2\"\n".to_owned()),
                    ("app/Cargo.toml", "[package]\nname=\"app\"\nversion=\"0.1.0\"\nedition=\"2021\"\n[lib]\npath=\"../neighbor/src/actual.rs\"\n[dependencies]\nlog={package=\"notlog\",version=\"0.4\"}\n".to_owned()),
                    ("neighbor/Cargo.toml", "[package]\nname=\"neighbor\"\nversion=\"0.1.0\"\nedition=\"2021\"\n[dependencies]\nlog=\"0.4\"\n".to_owned()),
                    ("neighbor/src/lib.rs", "pub fn unrelated() {}".to_owned()),
                ],
                "unavailable",
            ),
        ];

        for (label, source_path, setup, reason_fragment) in cases {
            let mut files: Vec<(&str, &str)> = setup
                .iter()
                .map(|(path, contents)| (*path, contents.as_str()))
                .collect();
            let source = if label == "local module re-export" {
                "mod log { pub use ::log::info; }\npub fn run() { log::info!(\"message\"); }"
            } else if label == "macro_rules shadow" {
                "macro_rules! info { ($($t:tt)*) => {} }\npub fn run() { log::info!(\"message\"); }"
            } else if label == "shadowing import" {
                "mod fake {}\nuse crate::fake as log;\npub fn run() { log::info!(\"message\"); }"
            } else if label == "glob import" {
                "mod fake {}\nuse crate::fake::*;\npub fn run() { log::info!(\"message\"); }"
            } else {
                SOURCE
            };
            files.push(("neighbor/src/actual.rs", source));
            let path = if source_path == "Cargo.toml" {
                "neighbor/src/actual.rs"
            } else {
                source_path
            };
            if !files.iter().any(|(file, _)| *file == path) {
                files.push((path, source));
            }
            let admission = candidate_admission(&files, path, source);
            let reason = admission.proof.as_ref().expect_err(label);
            assert!(
                format!("{reason:?}")
                    .to_lowercase()
                    .contains(reason_fragment),
                "{label}: {reason:?}"
            );
            assert_receipt(&admission);
        }
    }

    #[test]
    fn candidate_macro_admission_digest_tracks_manifest_and_cargo_config() {
        let source_path = "src/lib.rs";
        let base_manifest = format!("{MANIFEST}[dependencies]\nlog=\"0.4\"\n");
        let base_files = [
            ("Cargo.toml", base_manifest.as_str()),
            (source_path, SOURCE),
        ];
        let base = candidate_admission(&base_files, source_path, SOURCE);
        let repeat = candidate_admission(&base_files, source_path, SOURCE);
        assert_eq!(base.answer_digest, repeat.answer_digest);
        assert_eq!(base.proof.is_ok(), repeat.proof.is_ok());
        assert_receipt(&base);

        let wrong_manifest =
            format!("{MANIFEST}[dependencies]\nlog={{package=\"notlog\",version=\"0.4\"}}\n");
        let wrong_files = [
            ("Cargo.toml", wrong_manifest.as_str()),
            (source_path, SOURCE),
        ];
        let wrong = candidate_admission(&wrong_files, source_path, SOURCE);
        assert_ne!(base.proof.is_ok(), wrong.proof.is_ok());
        assert_ne!(base.answer_digest, wrong.answer_digest);
        assert_receipt(&wrong);

        let config = "[source.crates-io]\nreplace-with=\"mirror\"\n[source.mirror]\nregistry=\"sparse+https://example.invalid/index/\"\n";
        let config_files = [
            ("Cargo.toml", base_manifest.as_str()),
            (source_path, SOURCE),
            (".cargo/config.toml", config),
        ];
        let configured = candidate_admission(&config_files, source_path, SOURCE);
        // Cargo source replacement must serve exactly the same packages.
        assert_eq!(
            configured
                .proof
                .as_ref()
                .expect("source replacement preserves identity")
                .package,
            "log"
        );
        assert_eq!(base.answer_digest, configured.answer_digest);
        assert_receipt(&configured);
        for config in [
            "[patch.crates-io]\nlog={path=\"vendor/log\"}\n",
            "paths=[\"vendor/log\"]\n",
        ] {
            let configured = candidate_admission(
                &[
                    ("Cargo.toml", base_manifest.as_str()),
                    (source_path, SOURCE),
                    (".cargo/config.toml", config),
                ],
                source_path,
                SOURCE,
            );
            let reason = format!("{:?}", configured.proof.as_ref().unwrap_err());
            assert!(reason.contains("config-overridden"), "{reason}");
            assert_ne!(base.answer_digest, configured.answer_digest);
            assert_receipt(&configured);
        }
    }

    #[test]
    #[hardwon("#11036: a crate-local log item shadowing the log crate was admitted as log")]
    fn local_log_shadow_refuses_and_tracks_cross_file_edits() {
        use super::super::test_support::{
            analyzed_file, certified_analyzer, project as base_project,
        };
        use brokk_bifrost_analysis::IAnalyzer;
        let project = |files: &[(&str, &str)]| {
            let (temp, _) = base_project(files);
            let (workspace, analyzer) = certified_analyzer(temp.path());
            (temp, workspace, analyzer)
        };
        use brokk_bifrost_analysis::analyzer::ReadKey;
        use brokk_bifrost_analysis::analyzer::i_analyzer::{
            AnalyzerQueryScope, capture_query_reads,
        };
        use brokk_bifrost_core::analyzer::query_token::QueryScope;

        const MANIFEST: &str = "[package]\nname=\"app\"\nversion=\"0.1.0\"\nedition=\"2021\"\n[dependencies]\nlog=\"0.4\"\n";
        const CALL: &str = "pub fn run() { log::info!(\"message\"); }";
        let shadowed = |analyzer: &RustAnalyzer, path: &str, source: &str| {
            let scope = AnalyzerQueryScope::new(analyzer);
            let walks = RustUsageWalks::new(analyzer, scope.token()).unwrap();
            rust_macro_root_is_shadowed(
                analyzer,
                &walks,
                &analyzed_file(analyzer, path),
                "log",
                source.find("log::info!").unwrap(),
                source.contains("::log::info!"),
            )
            .unwrap()
        };
        for (prefix, expected) in [
            ("", false),
            ("mod log { pub use ::log::info; }", true),
            ("mod other {} use other as log;", true),
            ("extern crate other as log;", true),
            ("extern crate log;", false),
            ("extern crate log as log;", false),
            ("use log;", false),
            ("use ::log;", false),
            ("use unknown::*;", false),
            ("fn log() {}", false),
            ("static log: i32 = 0;", false),
            ("const log: i32 = 0;", false),
            ("fn value() {} use value as log;", false),
        ] {
            let source = format!("{prefix}\n{CALL}");
            let (_temp, _workspace, analyzer) =
                project(&[("Cargo.toml", MANIFEST), ("src/lib.rs", &source)]);
            assert_eq!(
                shadowed(&analyzer, "src/lib.rs", &source),
                expected,
                "{prefix}"
            );
        }
        for (edition, source, expected) in [
            (
                Some("2021"),
                "extern crate other as log; pub fn run() { ::log::info!(\"message\"); }",
                true,
            ),
            (
                Some("2021"),
                "extern crate other as log; pub fn run() { log::info!(\"message\"); }",
                true,
            ),
            (
                Some("2015"),
                "extern crate log; pub fn run() { log::info!(\"message\"); }",
                false,
            ),
            (
                Some("2018"),
                "use log; pub fn run() { log::info!(\"message\"); }",
                false,
            ),
            (
                Some("2018"),
                "use std::io::*; pub fn run() { log::info!(\"message\"); }",
                false,
            ),
            (
                Some("2018"),
                "mod tests { use super::*; pub fn run() { log::info!(\"message\"); } }",
                false,
            ),
            (
                Some("2015"),
                "use std::io::*; pub fn run() { log::info!(\"message\"); }",
                true,
            ),
            (
                None,
                "use std::io::*; pub fn run() { log::info!(\"message\"); }",
                true,
            ),
            (
                Some("2018"),
                "mod log; pub fn run() { log::info!(\"message\"); }",
                true,
            ),
            (
                Some("2018"),
                "mod log {} pub fn run() { ::log::info!(\"message\"); }",
                false,
            ),
            (
                Some("2021"),
                "mod log {} pub fn run() { ::log::info!(\"message\"); }",
                false,
            ),
            (
                Some("2015"),
                "mod log {} pub fn run() { ::log::info!(\"message\"); }",
                true,
            ),
        ] {
            let manifest = match edition {
                Some(edition) => MANIFEST.replace("2021", edition),
                None => MANIFEST.replace("edition=\"2021\"\n", ""),
            };
            let (_temp, _workspace, analyzer) =
                project(&[("Cargo.toml", manifest.as_str()), ("src/lib.rs", source)]);
            assert_eq!(
                shadowed(&analyzer, "src/lib.rs", source),
                expected,
                "{edition:?}: {source}"
            );
        }
        let (_temp, _workspace, mut analyzer) =
            project(&[("Cargo.toml", MANIFEST), ("src/lib.rs", CALL)]);
        let (before, reads) =
            capture_query_reads(&analyzer, || shadowed(&analyzer, "src/lib.rs", CALL));
        assert!(!before);
        let root = analyzed_file(&analyzer, "src/lib.rs");
        assert!(reads.keys().iter().any(|key| matches!(key, ReadKey::File { rel_path, .. } if rel_path.as_ref() == "src/lib.rs")), "{:?}", reads.keys());
        let added = format!("mod log; {CALL}");
        std::fs::write(root.abs_path(), &added).unwrap();
        let log = brokk_bifrost_core::analyzer::model::ProjectFile::new(root.root(), "src/log.rs");
        std::fs::write(log.abs_path(), "pub use ::log::info;").unwrap();
        analyzer =
            analyzer.update_with_listing(&std::collections::BTreeSet::from([root, log]), None);
        let warm = shadowed(&analyzer, "src/lib.rs", &added);
        let (_fresh_temp, _fresh_workspace, fresh) = project(&[
            ("Cargo.toml", MANIFEST),
            ("src/lib.rs", added.as_str()),
            ("src/log.rs", "pub use ::log::info;"),
        ]);
        assert!(warm);
        assert_eq!(warm, shadowed(&fresh, "src/lib.rs", &added));
    }

    #[test]
    #[hardwon("#11036: leading absolute macro paths use the selected target root")]
    fn absolute_log_shadow_checks_the_selected_crate_root() {
        use super::super::test_support::{
            analyzed_file, certified_analyzer, project as base_project,
        };
        use brokk_bifrost_analysis::analyzer::ReadKey;
        use brokk_bifrost_analysis::analyzer::i_analyzer::{
            AnalyzerQueryScope, capture_query_reads,
        };
        use brokk_bifrost_core::analyzer::query_token::QueryScope;

        const CHILD: &str = "pub fn run() { ::log::info!(\"message\"); }";
        let check = |edition: &str, dependency: &str, root: &str, expected| {
            let manifest = format!(
                "[package]\nname=\"app\"\nversion=\"0.1.0\"\nedition=\"{edition}\"\n[dependencies]\n{dependency}\n"
            );
            let (temp, _) = base_project(&[
                ("Cargo.toml", manifest.as_str()),
                ("src/lib.rs", root),
                ("src/child.rs", CHILD),
            ]);
            let (_workspace, analyzer) = certified_analyzer(temp.path());
            let scope = AnalyzerQueryScope::new(&analyzer);
            let walks = RustUsageWalks::new(&analyzer, scope.token()).unwrap();
            let child = analyzed_file(&analyzer, "src/child.rs");
            let (shadowed, reads) = capture_query_reads(&analyzer, || {
                rust_macro_root_is_shadowed(
                    &analyzer,
                    &walks,
                    &child,
                    "log",
                    CHILD.find("log::info!").unwrap(),
                    true,
                )
                .unwrap()
            });
            assert_eq!(shadowed, expected, "{edition}: {root}");
            assert!(reads.keys().iter().any(
                |key| matches!(key, ReadKey::File { rel_path, .. } if rel_path.as_ref() == "src/lib.rs")
            ), "crate root read was not recorded: {:?}", reads.keys());
        };

        check(
            "2015",
            "log=\"0.4\"",
            "extern crate log as other; mod log { pub use other::info; } mod child;",
            true,
        );
        check(
            "2021",
            "other={package=\"log\",version=\"0.4\"}",
            "extern crate other as log; mod child;",
            true,
        );
        check("2021", "log=\"0.4\"", "mod log {} mod child;", false);
    }

    #[test]
    #[hardwon("#4304: built-in macro lowering must target CodeQL's exact Rust sink identities")]
    fn rust_value_macro_dispatch_uses_exact_external_identities() {
        let cases = [
            ("assert", "core.panicking", "panic_fmt"),
            ("assert_eq", "core.panicking", "assert_failed"),
            ("assert_ne", "core.panicking", "assert_failed"),
            ("debug_assert", "core.panicking", "panic_fmt"),
            ("debug_assert_eq", "core.panicking", "assert_failed"),
            ("debug_assert_ne", "core.panicking", "assert_failed"),
            ("panic", "core.panicking", "panic_fmt"),
            ("unreachable", "core.panicking", "panic_fmt"),
            ("todo", "core.panicking", "panic_fmt"),
            ("unimplemented", "core.panicking", "panic_fmt"),
            ("dbg", "std.io.stdio", "_eprint"),
            ("matches", "core", "matches"),
            ("vec", "alloc", "vec"),
        ];

        for (macro_name, expected_owner, expected_member) in cases {
            let lookup = rust_standard_macro_dispatch(
                rust_standard_macro_prelude_owner(macro_name).expect("standard macro owner"),
                macro_name,
                CallRelationWork::default(),
            );
            assert!(
                matches!(lookup.status, Some(DefinitionLookupStatus::Resolved)),
                "{macro_name}: {lookup:?}"
            );
            let [
                CallDispatchBoundaryKind::External {
                    external_callee_identity: Some(identity),
                    ..
                },
            ] = lookup.boundaries.as_slice()
            else {
                panic!("{macro_name} must produce one exact external identity: {lookup:?}");
            };
            assert_eq!(identity.language(), Language::Rust, "{macro_name}");
            assert_eq!(identity.owner_fqn(), expected_owner, "{macro_name}");
            assert_eq!(identity.member(), expected_member, "{macro_name}");
        }
    }
}
