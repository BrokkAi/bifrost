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
pub(crate) fn dispatch(request: CallDispatchLanguageRequest<'_>) -> Option<CallDispatchLookup> {
    let CallDispatchLanguageRequest {
        analyzer,
        token,
        file,
        source,
        tree,
        call_span,
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
    let path = invocation.child_by_field_name("macro")?;
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
    let value_macro = brokk_bifrost_rust::format_args::rust_value_macro(terminal_name).is_some();
    let logging_macro = path_names.len() == 2
        && brokk_bifrost_rust::format_args::rust_logging_macro(path_names[0], path_names[1])
            .is_some();
    if !formatting_macro && !value_macro && !logging_macro {
        return None;
    }
    let rust = resolve_analyzer::<RustAnalyzer>(analyzer)?;
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
        brokk_bifrost_rust::graph_support::rust_path_is_leading_absolute(path),
    ) {
        Ok(resolution) => resolution,
        Err(error) => return Some(rust_macro_route_error(error.into(), work)),
    };
    match resolution {
        RustReferenceResolution::Exact(identity) => {
            // The macro's source declaration is not the callable whose
            // macro-derived argument shape is being selected. Use the exact
            // resolved crate and macro identity to choose its external model
            // target, as the prelude route does when no declaration exists.
            if identity.namespace == brokk_bifrost_rust::usage::RustSymbolNamespace::Macro {
                let owner = match identity.module.crate_root.as_str() {
                    "std" | "core" | "alloc"
                        if rust_standard_macro_in_crate(
                            &identity.module.crate_root,
                            &identity.name,
                        ) =>
                    {
                        Some(identity.module.crate_root.as_str())
                    }
                    "log"
                        if brokk_bifrost_rust::format_args::rust_logging_macro(
                            "log",
                            &identity.name,
                        )
                        .is_some() =>
                    {
                        Some("log")
                    }
                    _ => None,
                };
                if let Some(owner) = owner {
                    return Some(rust_standard_macro_dispatch(owner, &identity.name, work));
                }
            }
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
                    format!("resolved Rust macro identity has multiple declarations: {identity:?}"),
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
                match walks.standard_macro_prelude_enabled(file) {
                    Ok(true) => {
                        if let Some(owner) = rust_standard_macro_prelude_owner(terminal_name) {
                            return Some(rust_standard_macro_dispatch(owner, terminal_name, work));
                        }
                    }
                    Ok(false) => {}
                    Err(error) => return Some(rust_macro_route_error(error, work)),
                }
            } else if path_names.len() == 2 {
                let owner = path_names[0];
                let member = path_names[1];
                let is_log_macro =
                    brokk_bifrost_rust::format_args::rust_logging_macro(owner, member).is_some();
                if rust_standard_macro_in_crate(owner, member) || is_log_macro {
                    let shadowed = match rust_macro_root_is_shadowed(
                        &walks,
                        file,
                        owner,
                        call_span.start_byte,
                    ) {
                        Ok(shadowed) => shadowed,
                        Err(error) => return Some(rust_macro_route_error(error, work)),
                    };
                    let dependency_available = !is_log_macro
                        || walks
                            .cargo_routes()
                            .has_available_declared_dependency(file, owner);
                    if !shadowed && dependency_available {
                        return Some(rust_standard_macro_dispatch(owner, member, work));
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
}

pub(crate) fn rust_standard_macro_prelude_owner(member: &str) -> Option<&'static str> {
    match member {
        "format" => Some("alloc"),
        "format_args" | "write" | "writeln" | "panic" | "assert" | "assert_eq" | "assert_ne"
        | "debug_assert" | "debug_assert_eq" | "debug_assert_ne" | "unreachable" | "todo"
        | "unimplemented" | "matches" => Some("core"),
        "print" | "println" | "eprint" | "eprintln" => Some("std"),
        "dbg" => Some("std"),
        "vec" => Some("alloc"),
        _ => None,
    }
}

fn rust_standard_macro_in_crate(owner: &str, member: &str) -> bool {
    match owner {
        "std" => {
            brokk_bifrost_rust::format_args::rust_formatting_macro(member).is_some()
                || brokk_bifrost_rust::format_args::rust_value_macro(member).is_some()
        }
        "core" => {
            matches!(member, "format_args" | "write" | "writeln" | "panic")
                || brokk_bifrost_rust::format_args::rust_value_macro(member).is_some_and(|value| {
                    !matches!(
                        value,
                        brokk_bifrost_rust::format_args::RustValueMacro::Dbg
                            | brokk_bifrost_rust::format_args::RustValueMacro::Vec
                    )
                })
        }
        "alloc" => {
            member == "format"
                || brokk_bifrost_rust::format_args::rust_value_macro(member)
                    == Some(brokk_bifrost_rust::format_args::RustValueMacro::Vec)
        }
        _ => false,
    }
}

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
            Some(u32::try_from(layout.arguments.len()).expect("built-in macro arity fits u32")),
        )
    } else {
        match brokk_bifrost_rust::format_args::rust_value_macro(member) {
            Some(brokk_bifrost_rust::format_args::RustValueMacro::Matches) => {
                ("core", "matches", None)
            }
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

fn rust_macro_root_is_shadowed(
    walks: &RustUsageWalks<'_>,
    file: &brokk_bifrost_core::analyzer::model::ProjectFile,
    root_name: &str,
    byte: usize,
) -> Result<bool, RustCargoRouteError> {
    let Some(module) = walks.queries().module_at_byte(file, byte)? else {
        return Ok(true);
    };
    let root = vec![root_name.to_owned()];
    if !walks
        .resolve_segments(file, &module.package(), &root)?
        .is_empty()
    {
        return Ok(true);
    }
    let routes = walks.origin_routes_of(file)?;
    Ok(routes.get(root_name).is_some_and(|routes| {
        routes.iter().any(|route| {
            route.importer_module == module
                && route.extent.contains(byte)
                && route.namespace == brokk_bifrost_rust::usage::RustSymbolNamespace::Module
        })
    }))
}
#[cfg(test)]
mod tests {

    use crate::analyzer::rust::format_macro_dispatch::*;
    use brokk_bifrost_test_macros::hardwon;

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
