//! Exact `net/http` handler dispatch for the interface registration forms
//! (issue #3428).
//!
//! `http.Handle`, `(*http.ServeMux).Handle`, `http.Serve`, and
//! `http.ListenAndServe` take an `http.Handler` interface value whose callback
//! is the dynamic type's `ServeHTTP` method. The reviewed pack models each
//! registration as one task spawn of its handler argument, and this module
//! answers the one question the binder cannot: whether the argument's dynamic
//! type is exact, and which callable the registration therefore spawns.
//!
//! Two source shapes are exact:
//!
//! 1. The argument's source expression has a bounded type lookup that resolves
//!    to exactly one workspace type declaration with exactly one `ServeHTTP`
//!    method. The spawn is that method, with the argument bound as its
//!    receiver. An address-of expression (`&counter{}`, `&handler`) is looked
//!    up at its operand, which carries the type its operator points to.
//! 2. The argument is the result of a conversion whose callee is exactly the
//!    modeled `net/http.HandlerFunc` declaration. The spawn is the
//!    conversion's own argument, which #3408's callable-reference events
//!    already resolve (`http.HandlerFunc(f)` spawns `f`).
//!
//! Everything else -- an interface-typed variable, an unresolved constructor,
//! a middleware wrapper whose result type is open -- stays open, so the caller
//! keeps the reviewed `unsupported_synchronization:net/http.Handler` boundary.
//! Every fact this module reads is structured: the argument's source locator,
//! the analyzer's declaration index, tree-sitter fields, the file's import
//! namespaces, and the active declaration overlay. No source text is searched
//! or reparsed by hand.

use super::package_identity::{GoModeledPackageCallResolution, GoOverlayPackages};
use crate::analyzer::semantic::type_flow::file_for_locator;
use crate::analyzer::semantic::{
    ProcedureHandle, ProcedureRangeLookupStatus, SemanticOutcome, SemanticProviderError,
    SemanticRequest, SemanticWork, ValueId, procedures_for_definition_with_limits,
};
use crate::analyzer::semantic_model::{
    ActiveSemanticModelSnapshot, SemanticModelSymbolKind, Visibility,
};
use crate::analyzer::usages::get_definition::{go_imported_package_at_range, parse_go_tree};
use crate::analyzer::usages::get_type::{
    TypeLookupOutcome, TypeLookupStatus, resolve_type_at_reference_site_with_budget,
};
use crate::analyzer::usages::receiver_analysis::ReceiverAnalysisBudget;
use crate::analyzer::usages::reference_site::{
    SourceLocationRequest, resolve_reference_site, smallest_named_node_covering,
};
use crate::analyzer::{AnalyzerQueryScope, CodeUnit, IAnalyzer, ProjectFile, WorkspaceAnalyzer};
use brokk_bifrost_go::graph::reference::go_name_shadowed_at_with_scope;
use std::sync::Arc;

/// The modeled `net/http` handler func type whose conversion is a pure
/// callable rename.
const NET_HTTP_HANDLER_FUNC: &str = "HandlerFunc";

const NET_HTTP_PACKAGE: &str = "net/http";

/// The one interface method a registered `http.Handler` dispatches to.
const NET_HTTP_SERVE_HTTP: &str = "ServeHTTP";

/// What one modeled interface-form registration spawns.
#[derive(Debug, Clone)]
pub enum GoHttpHandlerDispatch {
    /// The handler argument's exact dynamic type declares `ServeHTTP`, which
    /// is the spawned task; the argument is the task's receiver.
    ServeHttp { method: ProcedureHandle },
    /// The handler argument is the result of a `net/http.HandlerFunc`
    /// conversion, so the spawned callable is the conversion's own argument.
    HandlerFuncConversion { argument: ValueId },
    /// No exact dynamic type is provable from the argument's source shape.
    Open { reason: GoHttpHandlerOpenReason },
}

/// Why a modeled interface-form registration keeps its typed boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GoHttpHandlerOpenReason {
    /// The argument's source shape is not one of the two exact shapes.
    NotExact,
    /// The bounded proof stopped before it could answer.
    BudgetExhausted,
}

/// Resolve the callable one modeled interface-form `net/http` registration
/// spawns, when the handler argument's dynamic type is exact.
///
/// `procedure` owns `argument`; both come from the call site the binder
/// already selected, so no second call-shape derivation is needed.
pub fn go_http_handler_dispatch(
    workspace: &WorkspaceAnalyzer,
    active_models: Option<&Arc<ActiveSemanticModelSnapshot>>,
    procedure: &ProcedureHandle,
    argument: ValueId,
    request: &mut SemanticRequest<'_>,
) -> Result<GoHttpHandlerDispatch, SemanticProviderError> {
    let semantics = procedure.semantics();
    let Some(value) = semantics.value(argument) else {
        return Ok(open(GoHttpHandlerOpenReason::NotExact));
    };
    let Some(mapping) = semantics.source_mapping(value.source) else {
        return Ok(open(GoHttpHandlerOpenReason::NotExact));
    };
    let Some(file) = file_for_locator(workspace, &mapping.locator) else {
        return Ok(open(GoHttpHandlerOpenReason::NotExact));
    };
    let Some(source) = workspace.analyzer().indexed_source(&file) else {
        return Ok(open(GoHttpHandlerOpenReason::NotExact));
    };
    if let Err(reason) = charge(
        request,
        SemanticWork {
            source_bytes: source.len(),
            ..SemanticWork::default()
        },
    ) {
        return Ok(open(reason));
    }

    let analyzer = workspace.analyzer();
    let Some(tree) = parse_go_tree(&source) else {
        return Ok(open(GoHttpHandlerOpenReason::NotExact));
    };
    if tree.root_node().has_error() {
        return Ok(open(GoHttpHandlerOpenReason::NotExact));
    }
    let argument_span = mapping.locator.anchor().span();
    let argument_start = handler_type_lookup_start(
        tree.root_node(),
        argument_span.start_byte() as usize,
        argument_span.end_byte() as usize,
    );

    match serve_http_method(
        workspace,
        active_models,
        analyzer,
        &file,
        &source,
        &tree,
        argument_start,
        request,
    )? {
        ServeHttpResolution::Method(method) => {
            return Ok(GoHttpHandlerDispatch::ServeHttp { method });
        }
        ServeHttpResolution::Open(reason) => return Ok(open(reason)),
        ServeHttpResolution::NotExact => {}
    }
    match handler_func_conversion_argument(
        analyzer,
        active_models,
        procedure,
        argument,
        &file,
        &source,
        &tree,
        request,
    ) {
        Ok(Some(conversion_argument)) => {
            return Ok(GoHttpHandlerDispatch::HandlerFuncConversion {
                argument: conversion_argument,
            });
        }
        Ok(None) => {}
        Err(reason) => return Ok(open(reason)),
    }
    Ok(open(GoHttpHandlerOpenReason::NotExact))
}

fn open(reason: GoHttpHandlerOpenReason) -> GoHttpHandlerDispatch {
    GoHttpHandlerDispatch::Open { reason }
}

/// The byte the dynamic-type lookup starts at for one handler argument.
///
/// The producer maps the argument value to its source expression. When that
/// expression is an address-of expression, the type belongs to the operand
/// (`&counter{}`, `&handler`), so the lookup starts at the operand instead of
/// at the operator, where no reference token exists. Every other shape starts
/// at the expression's own first byte, and the reference-site resolver expands
/// the single token there.
fn handler_type_lookup_start(
    root: tree_sitter::Node<'_>,
    argument_start: usize,
    argument_end: usize,
) -> usize {
    let Some(mut node) = smallest_named_node_covering(root, argument_start, argument_end) else {
        return argument_start;
    };
    let Some(operand) = address_of_operand(node) else {
        return argument_start;
    };
    node = operand;
    while let Some(inner) = address_of_operand(node) {
        node = inner;
    }
    node.start_byte()
}

/// The operand of one address-of expression, or `None` when the node is not an
/// address-of expression.
fn address_of_operand(node: tree_sitter::Node<'_>) -> Option<tree_sitter::Node<'_>> {
    if node.kind() != "unary_expression" {
        return None;
    }
    let operator = node.child_by_field_name("operator")?;
    if operator.kind() != "&" {
        return None;
    }
    node.child_by_field_name("operand")
}

/// Charge one unit of proof work. `Err` is the answer the caller returns: the
/// bounded proof stopped before it could name the dynamic type.
fn charge(
    request: &mut SemanticRequest<'_>,
    work: SemanticWork,
) -> Result<(), GoHttpHandlerOpenReason> {
    if request.budget.charge(work).is_err() || request.cancellation.is_cancelled() {
        return Err(GoHttpHandlerOpenReason::BudgetExhausted);
    }
    Ok(())
}

/// The three answers of the exact-`ServeHTTP` step.
enum ServeHttpResolution {
    /// The argument's exact workspace type declares this one `ServeHTTP`.
    Method(ProcedureHandle),
    /// The argument's source shape proves no exact workspace type.
    NotExact,
    /// The bounded proof stopped before it could answer.
    Open(GoHttpHandlerOpenReason),
}

/// The `ServeHTTP` procedure of the argument's exact workspace dynamic type,
/// when the argument's own source expression has one.
#[allow(clippy::too_many_arguments)]
fn serve_http_method(
    workspace: &WorkspaceAnalyzer,
    active_models: Option<&Arc<ActiveSemanticModelSnapshot>>,
    analyzer: &dyn IAnalyzer,
    file: &ProjectFile,
    source: &str,
    tree: &tree_sitter::Tree,
    argument_start: usize,
    request: &mut SemanticRequest<'_>,
) -> Result<ServeHttpResolution, SemanticProviderError> {
    // The producer maps the argument value to the source expression itself,
    // and the reference-site resolver expands the single token at its start.
    let Ok(site) = resolve_reference_site(
        &SourceLocationRequest {
            file: file.clone(),
            line: None,
            column: None,
            start_byte: Some(argument_start),
            end_byte: None,
        },
        source,
        Some(tree.root_node()),
    ) else {
        return Ok(ServeHttpResolution::NotExact);
    };
    let scope =
        AnalyzerQueryScope::with_active_semantic_model_snapshot(analyzer, active_models.cloned());
    let outcome = resolve_type_at_reference_site_with_budget(
        analyzer,
        file,
        source,
        Some(tree),
        site,
        ReceiverAnalysisBudget::default(),
    );
    drop(scope);
    if let Err(reason) = charge(
        request,
        SemanticWork {
            // The lookup is internally bounded by the receiver budget, so one
            // unit accounts for one bounded resolution.
            nested_entries: 1,
            ..SemanticWork::default()
        },
    ) {
        return Ok(ServeHttpResolution::Open(reason));
    }
    let Some(declaration) = exact_workspace_type_declaration(&outcome) else {
        return Ok(ServeHttpResolution::NotExact);
    };

    let members = analyzer.get_members_in_class(&declaration);
    if let Err(reason) = charge(
        request,
        SemanticWork {
            nested_entries: members.len(),
            ..SemanticWork::default()
        },
    ) {
        return Ok(ServeHttpResolution::Open(reason));
    }
    let mut methods = members
        .into_iter()
        .filter(|member| member.is_function() && member.terminal_name() == NET_HTTP_SERVE_HTTP);
    let Some(method) = methods.next() else {
        return Ok(ServeHttpResolution::NotExact);
    };
    if methods.next().is_some() {
        // Two declarations of one Go method is not an exact dispatch.
        return Ok(ServeHttpResolution::NotExact);
    }
    let method_file = method.source().clone();
    let outcome = workspace.materialize_program_semantics(&method_file, request)?;
    let artifact = match outcome {
        SemanticOutcome::Complete { value, .. } => value,
        SemanticOutcome::ExceededBudget { .. } | SemanticOutcome::Cancelled { .. } => {
            return Ok(ServeHttpResolution::Open(
                GoHttpHandlerOpenReason::BudgetExhausted,
            ));
        }
        _ => return Ok(ServeHttpResolution::NotExact),
    };
    let lookup = procedures_for_definition_with_limits(
        analyzer,
        &method,
        &artifact,
        request.budget.remaining().nested_entries,
        request.cancellation,
    );
    match lookup.status {
        ProcedureRangeLookupStatus::Complete => {
            if let Err(reason) = charge(
                request,
                SemanticWork {
                    nested_entries: lookup.examined,
                    ..SemanticWork::default()
                },
            ) {
                return Ok(ServeHttpResolution::Open(reason));
            }
            match lookup.handles.as_slice() {
                [method] => Ok(ServeHttpResolution::Method(method.clone())),
                _ => Ok(ServeHttpResolution::NotExact),
            }
        }
        ProcedureRangeLookupStatus::BudgetExhausted => Ok(ServeHttpResolution::Open(
            GoHttpHandlerOpenReason::BudgetExhausted,
        )),
        ProcedureRangeLookupStatus::Cancelled | ProcedureRangeLookupStatus::SourceChanged => {
            Ok(ServeHttpResolution::NotExact)
        }
    }
}

/// The one workspace class declaration an exact dynamic-type lookup names.
///
/// A semantic-model type is deliberately excluded: the interface forms that
/// reach this module are registrations of *workspace* types, and a modeled
/// external handler type has no materializable `ServeHTTP` body to spawn.
fn exact_workspace_type_declaration(outcome: &TypeLookupOutcome) -> Option<CodeUnit> {
    if outcome.status != TypeLookupStatus::Resolved {
        return None;
    }
    let [resolved] = outcome.types.as_slice() else {
        return None;
    };
    if resolved.semantic_model_id.is_some() {
        return None;
    }
    let [declaration] = resolved.definitions.as_slice() else {
        return None;
    };
    declaration.is_class().then(|| declaration.clone())
}

/// The conversion's own argument, when the handler argument is the single
/// result of an exact `net/http.HandlerFunc` conversion in this procedure.
#[allow(clippy::too_many_arguments)]
fn handler_func_conversion_argument(
    analyzer: &dyn IAnalyzer,
    active_models: Option<&Arc<ActiveSemanticModelSnapshot>>,
    procedure: &ProcedureHandle,
    argument: ValueId,
    file: &ProjectFile,
    source: &str,
    tree: &tree_sitter::Tree,
    request: &mut SemanticRequest<'_>,
) -> Result<Option<ValueId>, GoHttpHandlerOpenReason> {
    let semantics = procedure.semantics();
    let mut conversion = None;
    for call in semantics.call_sites() {
        if call.result != Some(argument) {
            continue;
        }
        if conversion.is_some() {
            // Two producers of one value is not an exact conversion.
            return Ok(None);
        }
        conversion = Some(call);
    }
    let Some(call) = conversion else {
        return Ok(None);
    };
    let [written] = call.arguments.as_ref() else {
        return Ok(None);
    };
    let Some(callee) = semantics.value(call.callee) else {
        return Ok(None);
    };
    let Some(mapping) = semantics.source_mapping(callee.source) else {
        return Ok(None);
    };
    if !mapping.locator.belongs_to_procedure(semantics.locator()) {
        return Ok(None);
    }
    let span = mapping.locator.anchor().span();
    let Some(callee_node) = smallest_named_node_covering(
        tree.root_node(),
        span.start_byte() as usize,
        span.end_byte() as usize,
    ) else {
        return Ok(None);
    };
    if callee_node.kind() != "selector_expression" {
        return Ok(None);
    }
    let (Some(operand), Some(field)) = (
        callee_node.child_by_field_name("operand"),
        callee_node.child_by_field_name("field"),
    ) else {
        return Ok(None);
    };
    if field.kind() != "field_identifier"
        || &source[field.start_byte()..field.end_byte()] != NET_HTTP_HANDLER_FUNC
    {
        return Ok(None);
    }
    if operand.kind() != "identifier"
        || go_imported_package_at_range(
            analyzer,
            file,
            source,
            operand.start_byte(),
            operand.end_byte(),
        )
        .as_deref()
            != Some(NET_HTTP_PACKAGE)
    {
        return Ok(None);
    }
    let mut shadow_denied = false;
    let shadowed = go_name_shadowed_at_with_scope(
        tree.root_node(),
        source,
        operand.start_byte(),
        &source[operand.start_byte()..operand.end_byte()],
        || {
            // One unit per enumerated syntax node keeps the walk inside the
            // caller's budget; denial abstains instead of inventing exactness.
            if charge(
                request,
                SemanticWork {
                    nested_entries: 1,
                    ..SemanticWork::default()
                },
            )
            .is_err()
            {
                shadow_denied = true;
                return false;
            }
            true
        },
    );
    match shadowed {
        Some(false) => {}
        Some(true) => return Ok(None),
        None => {
            debug_assert!(shadow_denied);
            return Err(GoHttpHandlerOpenReason::BudgetExhausted);
        }
    }
    if !modeled_handler_func_type(active_models) {
        return Ok(None);
    }
    Ok(Some(written.value))
}

/// Whether the active declaration overlay publishes `net/http.HandlerFunc` as
/// a public declared type, rather than as some other kind of member.
fn modeled_handler_func_type(active_models: Option<&Arc<ActiveSemanticModelSnapshot>>) -> bool {
    let Some(overlay) = active_models
        .and_then(|snapshot| snapshot.semantic_model_overlay())
        .map(Arc::as_ref)
    else {
        return false;
    };
    let packages = GoOverlayPackages::new(Some(overlay));
    let Some(member) = packages.visible_member(NET_HTTP_PACKAGE, NET_HTTP_HANDLER_FUNC) else {
        return false;
    };
    if member.language != "go"
        || member.visibility != Visibility::Public
        || !matches!(
            member.kind,
            SemanticModelSymbolKind::Class
                | SemanticModelSymbolKind::Interface
                | SemanticModelSymbolKind::Struct
                | SemanticModelSymbolKind::TypeAlias
        )
    {
        return false;
    }
    // A type conversion, not a package function call: the same declaration
    // facts must prove this name is not an applicable one-argument function.
    packages.package_call_resolution(NET_HTTP_PACKAGE, NET_HTTP_HANDLER_FUNC, 1)
        == Some(GoModeledPackageCallResolution::DefinitelyNotApplicable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::Language;
    use crate::analyzer::semantic::{
        CancellationToken, SemanticBudget, SemanticRequest, procedures_in_artifact,
    };
    use crate::test_support::AnalyzerFixture;

    fn dispatch_for_handle_argument(source: &str) -> GoHttpHandlerDispatch {
        let fixture = AnalyzerFixture::new_for_language(
            Language::Go,
            &[("go.mod", "module example.com/app\n"), ("main.go", source)],
        );
        let workspace = &fixture.analyzer;
        let file = ProjectFile::new(fixture.project_root(), "main.go");
        let cancellation = CancellationToken::default();
        let mut budget = SemanticBudget::uniform(1 << 20).expect("positive budget");
        let mut request = SemanticRequest::new(&mut budget, &cancellation);
        let outcome = workspace
            .materialize_program_semantics(&file, &mut request)
            .expect("main.go materializes");
        let artifact = outcome.available_value().expect("a complete artifact");
        let procedures = procedures_in_artifact(artifact, usize::MAX, &cancellation);
        assert_eq!(
            procedures.status,
            ProcedureRangeLookupStatus::Complete,
            "the fixture artifact scans completely"
        );
        let procedure = procedures
            .handles
            .iter()
            .find(|procedure| {
                procedure
                    .semantics()
                    .locator()
                    .declaration()
                    .segments()
                    .last()
                    .and_then(|segment| segment.name())
                    == Some("register")
            })
            .expect("the register procedure is materialized");
        let two_argument_calls = procedure
            .semantics()
            .call_sites()
            .iter()
            .filter(|call| call.arguments.len() == 2)
            .collect::<Vec<_>>();
        let [call] = two_argument_calls.as_slice() else {
            panic!("the fixture root holds one two-argument registration: {two_argument_calls:#?}");
        };
        let argument = call.arguments[1].value;
        go_http_handler_dispatch(workspace, None, procedure, argument, &mut request)
            .expect("the bounded proof answers")
    }

    const STRUCT_HANDLER: &str = r#"package main

import "net/http"

type counter struct{ hits int }

func (c *counter) ServeHTTP(w http.ResponseWriter, r *http.Request) { c.hits++ }

func register() {
	c := &counter{}
	http.Handle("/", c)
	c.hits = 0
}
"#;

    /// The spawned method's name, asserting the dispatch is an exact
    /// `ServeHTTP`.
    fn serve_http_name(dispatch: GoHttpHandlerDispatch) -> String {
        let GoHttpHandlerDispatch::ServeHttp { method } = dispatch else {
            panic!("an exact workspace handler resolves: {dispatch:?}");
        };
        method
            .semantics()
            .locator()
            .declaration()
            .segments()
            .last()
            .and_then(|segment| segment.name())
            .expect("the method declaration names itself")
            .to_owned()
    }

    #[test]
    fn a_workspace_pointer_handler_resolves_to_its_serve_http_method() {
        assert_eq!(
            serve_http_name(dispatch_for_handle_argument(STRUCT_HANDLER)),
            "ServeHTTP"
        );
    }

    #[test]
    fn an_addressed_composite_literal_resolves_to_its_serve_http_method() {
        let source = r#"package main

import "net/http"

type counter struct{ hits int }

func (c *counter) ServeHTTP(w http.ResponseWriter, r *http.Request) { c.hits++ }

func register() {
	http.Handle("/", &counter{})
}
"#;
        assert_eq!(
            serve_http_name(dispatch_for_handle_argument(source)),
            "ServeHTTP"
        );
    }

    #[test]
    fn a_handler_type_without_serve_http_keeps_the_boundary() {
        let source = r#"package main

import "net/http"

type counter struct{ hits int }

type plain struct{ hits int }

func register() {
	p := &plain{}
	http.Handle("/", p)
	p.hits = 0
}
"#;
        assert!(matches!(
            dispatch_for_handle_argument(source),
            GoHttpHandlerDispatch::Open {
                reason: GoHttpHandlerOpenReason::NotExact
            }
        ));
    }
}
