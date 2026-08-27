//! Typed projection of decorators applied to formal parameters.
//!
//! The relation is deliberately anchored by the structural parameter fact and
//! its `Decorator` role edges. Names and import identity come from the
//! analyzer's lexical environment; parameter ordinals come from semantic
//! source mappings or the shared formal-parameter layout. No source-text
//! parsing is performed here.

use super::super::lexical_environment::{
    BindingOfOutcome, EnvironmentFileResult, environment_for_file,
};
use super::super::occurrence_rows::ast_id;
use super::super::occurrences::Namespace;
use super::callable_signature::declaration_site_id;
use super::results::CodeQueryDecoratedParameter;
use super::*;
use crate::analyzer::lexical_definitions::formal_parameter_slots;
use crate::analyzer::semantic::SemanticValueKind;
use crate::analyzer::usages::get_definition::parse_tree_for_language;
use brokk_bifrost_core::analyzer::structural::resolution::BoundaryStatus;

pub(super) const BINDING_STATUS: &[&str] = &[
    "imported",
    "local",
    "unresolved",
    "ambiguous",
    "unsupported",
    "incomplete",
];
pub(super) const COMPLETION: &[&str] = &["complete", "incomplete"];
pub(super) const COVERAGE: &[&str] = &["complete", "partial"];

#[derive(Debug, Clone)]
pub(super) struct DecoratedParameterValue {
    pub(super) file: ProjectFile,
    pub(super) range: Range,
    pub(super) row: CodeQueryDecoratedParameter,
}

impl DecoratedParameterValue {
    pub(super) fn id(&self) -> &str {
        &self.row.id
    }
}

/// Expand one structural parameter match into one row per decorator role edge.
pub(super) fn expansions_for_seed(
    analyzer: &dyn IAnalyzer,
    seed: &SeedMatch,
    declarations: &mut HashMap<ProjectFile, EnclosingDeclarationIndex>,
    semantic: Option<&mut SemanticQueryContext<'_>>,
) -> Vec<PipelineExpansion> {
    let parameter = seed.facts.node(seed.fact_match.node);
    let parameter_range = seed_range(seed);
    let parameter_id = ast_id(seed.facts.source_identity(), seed.fact_match.node);
    let owner = enclosing_declaration_value(analyzer, seed, declarations).0;
    let owner_id = owner.as_ref().map(declaration_site_id);
    let environment = environment_for_file(analyzer, &seed.file);
    let semantic_identity = semantic.and_then(|context| {
        let procedures = context.procedure_of_match(seed);
        semantic_parameter_identity(&procedures, parameter_range)
    });
    let syntax_ordinal = owner.as_ref().and_then(|owner| {
        let tree = parse_tree_for_language(&seed.file, seed.language, seed.facts.source())?;
        let layout = formal_parameter_slots(
            seed.language,
            tree.root_node(),
            seed.facts.source(),
            &owner.range,
        )?;
        let parameter_slot = layout
            .slots
            .iter()
            .enumerate()
            .find(|(_, slot)| slot.declaration_range == parameter_range)?;
        Some(
            layout.slots[..=parameter_slot.0]
                .iter()
                .filter(|slot| !slot.receiver)
                .count()
                .saturating_sub(1),
        )
    });
    let identity = semantic_identity.or_else(|| {
        syntax_ordinal.map(|ordinal| ParameterIdentity {
            procedure_id: None,
            ordinal: Some(ordinal),
            port_id: Some(parameter_port_id(
                owner_id.as_deref().unwrap_or(&parameter_id),
                ordinal as u32,
            )),
            coverage: "partial",
            completion: "incomplete",
        })
    });
    let decorator_targets = seed
        .facts
        .role_targets(seed.fact_match.node, Role::Decorator)
        .collect::<Vec<_>>();
    decorator_targets
        .into_iter()
        .map(|target| {
            let decorator_range = Range {
                start_byte: target.span.start_byte,
                end_byte: target.span.end_byte,
                start_line: seed.facts.line_column_of_byte(target.span.start_byte).0,
                end_line: seed.facts.line_column_of_byte(target.span.end_byte).0,
            };
            let decorator_id = target
                .node
                .map(|node| ast_id(seed.facts.source_identity(), node));
            let structured_name = target
                .name
                .and_then(|span| seed.facts.source().get(span.start_byte..span.end_byte))
                .filter(|name| !name.is_empty());
            let (decorator_name, binding) = match structured_name {
                Some(name) => (
                    name.to_owned(),
                    decorator_binding(&environment, name, decorator_range.start_byte),
                ),
                None => (
                    "<unknown>".to_string(),
                    DecoratorBinding {
                        status: "unsupported",
                        boundary: BoundaryStatus::ExternalUnknown.label(),
                        reason: Some(
                            "the structural decorator target has no supported name span"
                                .to_string(),
                        ),
                        ..DecoratorBinding::default()
                    },
                ),
            };
            let mut reason = binding.reason;
            let identity = identity
                .clone()
                .unwrap_or_else(ParameterIdentity::incomplete);
            if identity.ordinal.is_none() && reason.is_none() {
                reason = Some(
                    "the parameter has no exact semantic source mapping or formal slot".to_string(),
                );
            }
            let binding_status = binding.status;
            let effective_completion = if identity.completion == "complete" && binding.complete {
                "complete"
            } else {
                "incomplete"
            };
            let effective_coverage = if binding.complete {
                identity.coverage
            } else {
                "partial"
            };
            let id =
                decorated_parameter_id(&parameter_id, decorator_id.as_deref(), decorator_range);
            let row = CodeQueryDecoratedParameter {
                id,
                parameter_id: parameter_id.clone(),
                decorator_id,
                path: rel_path_string(&seed.file),
                language: seed.language.config_label(),
                range: range_for_span(&seed.facts, parameter.span()),
                decorator_range: range_for_span(&seed.facts, target.span),
                owner_id: owner_id.clone(),
                procedure_id: identity.procedure_id,
                parameter_ordinal: identity.ordinal,
                port_id: identity.port_id,
                decorator_name,
                local_name: binding.local_name,
                imported_name: binding.imported_name,
                module: binding.module,
                binding_status,
                boundary: binding.boundary,
                completion: effective_completion,
                coverage: effective_coverage,
                reason,
                terminal: true,
            };
            pipeline_expansion(PipelineValue::DecoratedParameter(DecoratedParameterValue {
                file: seed.file.clone(),
                range: parameter_range,
                row,
            }))
        })
        .collect()
}

#[derive(Debug, Default)]
struct DecoratorBinding {
    status: &'static str,
    boundary: &'static str,
    complete: bool,
    local_name: Option<String>,
    imported_name: Option<String>,
    module: Option<String>,
    reason: Option<String>,
}

#[derive(Debug, Clone)]
struct ParameterIdentity {
    procedure_id: Option<String>,
    ordinal: Option<usize>,
    port_id: Option<String>,
    coverage: &'static str,
    completion: &'static str,
}

impl ParameterIdentity {
    fn incomplete() -> Self {
        Self {
            procedure_id: None,
            ordinal: None,
            port_id: None,
            coverage: "partial",
            completion: "incomplete",
        }
    }
}

fn decorator_binding(
    environment: &EnvironmentFileResult,
    name: &str,
    position: usize,
) -> DecoratorBinding {
    let outcome = super::super::lexical_environment::binding_of(
        environment,
        name,
        position,
        Some(Namespace::Value),
    );
    let index = match outcome {
        BindingOfOutcome::Reached(index) => index,
        BindingOfOutcome::Shadowed { winner, .. } => winner,
        BindingOfOutcome::NoBinding => {
            return DecoratorBinding {
                status: "unresolved",
                boundary: BoundaryStatus::ExternalUnknown.label(),
                reason: Some("no lexical binding is in effect at the decorator".to_string()),
                ..DecoratorBinding::default()
            };
        }
        BindingOfOutcome::Incomplete(axis) => {
            return DecoratorBinding {
                status: "incomplete",
                boundary: BoundaryStatus::ExternalUnknown.label(),
                reason: Some(format!("lexical environment does not cover {axis:?}")),
                ..DecoratorBinding::default()
            };
        }
    };
    let row = &environment.bindings[index];
    let Some(import) = row.import.as_ref() else {
        return DecoratorBinding {
            status: "local",
            boundary: BoundaryStatus::WorkspaceLocal.label(),
            complete: true,
            local_name: Some(row.name.clone()),
            reason: Some("the decorator resolves to a local binding, not an import".to_string()),
            ..DecoratorBinding::default()
        };
    };
    // TypeScript module specifiers are retained as one structured segment by
    // the adapter. Do not reconstruct a module target by joining arbitrary
    // path segments: their separator/form is language-specific.
    let module = match import.target_segments.as_slice() {
        [module] => Some(module.clone()),
        _ => None,
    };
    let complete = environment
        .completeness
        .covers(super::super::resolution::EnvironmentAxis::ImportBinders)
        && module.is_some()
        && import.imported_name.is_some();
    DecoratorBinding {
        status: if complete { "imported" } else { "incomplete" },
        boundary: import.boundary.label(),
        complete,
        local_name: Some(import.local_name.clone()),
        imported_name: import.imported_name.clone(),
        module,
        reason: (!complete).then(|| {
            "import binder coverage or structured module/symbol identity is incomplete".to_string()
        }),
    }
}

fn semantic_parameter_identity(
    procedures: &[SemanticProcedureValue],
    range: Range,
) -> Option<ParameterIdentity> {
    for procedure in procedures {
        for value in procedure.handle.semantics().values() {
            let SemanticValueKind::Parameter { ordinal, .. } = value.kind else {
                continue;
            };
            let Some(mapping) = procedure.handle.semantics().source_mapping(value.source) else {
                continue;
            };
            let span = mapping.locator.anchor().span();
            if span.start_byte() as usize != range.start_byte
                || span.end_byte() as usize != range.end_byte
            {
                continue;
            }
            let procedure_id = procedure.wire_id();
            let port_id = parameter_port_id(&procedure_id, ordinal);
            return Some(ParameterIdentity {
                procedure_id: Some(procedure_id),
                ordinal: Some(ordinal as usize),
                port_id: Some(port_id),
                coverage: "complete",
                completion: "complete",
            });
        }
    }
    None
}

fn parameter_port_id(procedure_id: &str, ordinal: u32) -> String {
    let mut digest = LengthDelimitedDigest::new(b"bifrost.code_query.parameter_port.v1");
    digest.push(procedure_id.as_bytes());
    digest.push(&ordinal.to_le_bytes());
    digest.finish().to_string()
}

fn decorated_parameter_id(parameter_id: &str, decorator_id: Option<&str>, range: Range) -> String {
    let mut digest = LengthDelimitedDigest::new(b"bifrost.code_query.decorated_parameter.v1");
    digest.push(parameter_id.as_bytes());
    if let Some(decorator_id) = decorator_id {
        digest.push(decorator_id.as_bytes());
    }
    digest.push(&range.start_byte.to_le_bytes());
    digest.push(&range.end_byte.to_le_bytes());
    digest.finish().to_string()
}
