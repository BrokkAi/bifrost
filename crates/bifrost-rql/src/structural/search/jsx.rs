use super::*;
use crate::analyzer::structural::RoleTarget;

#[derive(Debug)]
struct IdentityProjection {
    identity: JsxElementIdentity,
    component: Option<CodeUnit>,
    attribute_target: Option<CodeUnit>,
    coverage: JsxValueCoverage,
    reason: Option<&'static str>,
}

pub(super) fn jsx_attribute_value_expansions(
    analyzer: &dyn IAnalyzer,
    seed: &Arc<SeedMatch>,
    filter: &brokk_bifrost_rql::JsxAttributeValueTraversal,
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
) -> Vec<PipelineExpansion> {
    let facts = &seed.facts;
    let attribute_node = seed.fact_match.node;
    let attribute = facts.node(attribute_node);
    if !matches!(
        attribute.kind,
        NormalizedKind::JsxAttribute | NormalizedKind::JsxSpreadAttribute
    ) {
        push_incomplete(
            diagnostics,
            seed.language,
            "jsx-attribute-value requires a jsx_attribute or jsx_spread_attribute match",
        );
        return Vec::new();
    }

    let Some(element_node) = normalized_ancestor(facts, attribute_node, NormalizedKind::JsxElement)
    else {
        push_incomplete(
            diagnostics,
            seed.language,
            "JSX attribute has no normalized JSX element owner",
        );
        return Vec::new();
    };
    let tag = facts.role_targets(element_node, Role::Tag).next();
    let element_name = tag
        .and_then(|target| target.name)
        .and_then(|span| facts.source().get(span.start_byte..span.end_byte))
        .map(str::to_owned);
    let attribute_name = attribute
        .name
        .and_then(|span| facts.source().get(span.start_byte..span.end_byte))
        .map(str::to_owned);

    let identity = project_identity(analyzer, seed, tag, attribute.name, element_name.as_deref());
    if identity.coverage == JsxValueCoverage::Incomplete {
        push_incomplete(
            diagnostics,
            seed.language,
            identity
                .reason
                .unwrap_or("JSX owner identity is incomplete"),
        );
    }

    if filter
        .identity
        .is_some_and(|wanted| wanted.label() != identity.identity.label())
    {
        return Vec::new();
    }
    if filter
        .element_name
        .as_deref()
        .is_some_and(|wanted| element_name.as_deref() != Some(wanted))
    {
        return Vec::new();
    }

    let Some(direct_value) = facts
        .role_targets(attribute_node, Role::Value)
        .find_map(|target| target.node)
    else {
        let reason = if attribute.kind == NormalizedKind::JsxSpreadAttribute {
            "JSX spread attribute has no exact named attribute value"
        } else {
            "JSX attribute has no normalized value operand"
        };
        push_incomplete(diagnostics, seed.language, reason);
        return Vec::new();
    };

    if attribute.kind == NormalizedKind::JsxSpreadAttribute && filter.property_name.is_some() {
        push_incomplete(
            diagnostics,
            seed.language,
            "JSX spread may provide the requested attribute but has no exact property operand",
        );
        return Vec::new();
    }

    let mut selected = Vec::new();
    let mut property_incomplete = false;
    if let Some(property_name) = filter.property_name.as_deref() {
        let direct = facts.node(direct_value);
        if direct.kind != NormalizedKind::CollectionLiteral {
            push_incomplete(
                diagnostics,
                seed.language,
                "requested JSX property projection requires an object literal value",
            );
            return Vec::new();
        }
        for target in facts.role_targets(direct_value, Role::Element) {
            let Some(entry_node) = target.node else {
                property_incomplete = true;
                continue;
            };
            let entry = facts.node(entry_node);
            match entry.kind {
                NormalizedKind::ObjectProperty => {
                    let key = facts
                        .role_targets(entry_node, Role::Key)
                        .next()
                        .and_then(|target| target.name)
                        .or(entry.name)
                        .and_then(|span| facts.source().get(span.start_byte..span.end_byte));
                    if key.is_none() {
                        property_incomplete = true;
                    }
                    if key == Some(property_name)
                        && let Some(value) = facts
                            .role_targets(entry_node, Role::Value)
                            .find_map(|value| value.node)
                    {
                        selected.push(value);
                    }
                }
                NormalizedKind::ComputedProperty | NormalizedKind::SpreadElement => {
                    property_incomplete = true;
                }
                NormalizedKind::Identifier => {
                    let key = entry
                        .name
                        .and_then(|span| facts.source().get(span.start_byte..span.end_byte));
                    if key == Some(property_name) {
                        selected.push(entry_node);
                    }
                }
                _ => {}
            }
        }
        if property_incomplete {
            push_incomplete(
                diagnostics,
                seed.language,
                "computed or spread object property may provide or override the requested JSX value",
            );
        }
    } else {
        selected.push(direct_value);
    }

    selected
        .into_iter()
        .map(|value_node| {
            let coverage = if property_incomplete
                || identity.coverage == JsxValueCoverage::Incomplete
                || attribute.kind == NormalizedKind::JsxSpreadAttribute
            {
                JsxValueCoverage::Incomplete
            } else {
                JsxValueCoverage::Complete
            };
            let reason = if property_incomplete {
                Some("computed_or_spread_property")
            } else if attribute.kind == NormalizedKind::JsxSpreadAttribute {
                Some("jsx_spread_attribute")
            } else {
                identity.reason
            };
            pipeline_expansion(PipelineValue::JsxAttributeValue(Box::new(
                JsxAttributeValue {
                    seed: seed.clone(),
                    value_node,
                    attribute_node,
                    element_identity: identity.identity,
                    element_name: element_name.clone(),
                    attribute_name: attribute_name.clone(),
                    property_name: filter.property_name.clone(),
                    coverage,
                    reason,
                    component: identity.component.clone(),
                    attribute_target: identity.attribute_target.clone(),
                },
            )))
        })
        .collect()
}

fn project_identity(
    analyzer: &dyn IAnalyzer,
    seed: &SeedMatch,
    tag: Option<&RoleTarget>,
    attribute_name: Option<Span>,
    element_name: Option<&str>,
) -> IdentityProjection {
    if element_name.is_some_and(|name| name.as_bytes().first().is_some_and(u8::is_ascii_lowercase))
    {
        return IdentityProjection {
            identity: JsxElementIdentity::Intrinsic,
            component: None,
            attribute_target: None,
            coverage: JsxValueCoverage::Complete,
            reason: None,
        };
    }
    let Some(name) = element_name else {
        return unknown("qualified_or_unresolved_element_identity");
    };
    if !name.as_bytes().first().is_some_and(u8::is_ascii_uppercase) {
        return unknown("unsupported_element_identity");
    }
    if seed.language != Language::TypeScript {
        return unknown("component_identity_unsupported_language");
    }
    let Some(tag) = tag else {
        return unknown("missing_element_tag");
    };
    let Some(attribute_name) = attribute_name else {
        return unknown("spread_attribute_owner_unknown");
    };
    let requests = [tag.span, attribute_name]
        .into_iter()
        .map(|span| DefinitionLookupRequest {
            file: seed.file.clone(),
            line: None,
            column: None,
            start_byte: Some(span.start_byte),
            end_byte: Some(span.end_byte),
        })
        .collect();
    let outcomes = resolve_definition_batch_with_source(
        analyzer,
        requests,
        seed.file.clone(),
        Arc::<str>::from(seed.facts.source()),
    );
    let component = exact_definition(outcomes.first());
    let attribute_target = exact_definition(outcomes.get(1));
    match (component, attribute_target) {
        (component, Some(attribute_target)) => IdentityProjection {
            identity: JsxElementIdentity::Component,
            component,
            attribute_target: Some(attribute_target),
            coverage: JsxValueCoverage::Complete,
            reason: None,
        },
        (Some(component), None) => IdentityProjection {
            identity: JsxElementIdentity::Component,
            component: Some(component),
            attribute_target: None,
            coverage: JsxValueCoverage::Incomplete,
            reason: Some("component_attribute_owner_unresolved"),
        },
        (None, None) => unknown("component_identity_unresolved"),
    }
}

fn exact_definition(outcome: Option<&DefinitionLookupOutcome>) -> Option<CodeUnit> {
    let outcome = outcome?;
    (outcome.status == DefinitionLookupStatus::Resolved && outcome.definitions.len() == 1)
        .then(|| outcome.definitions[0].clone())
}

fn unknown(reason: &'static str) -> IdentityProjection {
    IdentityProjection {
        identity: JsxElementIdentity::Unknown,
        component: None,
        attribute_target: None,
        coverage: JsxValueCoverage::Incomplete,
        reason: Some(reason),
    }
}

fn normalized_ancestor(facts: &FileFacts, mut node: u32, kind: NormalizedKind) -> Option<u32> {
    loop {
        let fact = facts.node(node);
        if fact.kind == kind {
            return Some(node);
        }
        node = fact.parent?;
    }
}

fn push_incomplete(
    diagnostics: &mut Vec<CodeQueryDiagnostic>,
    language: Language,
    message: &'static str,
) {
    if diagnostics.iter().any(|diagnostic| {
        diagnostic.code == CodeQueryDiagnosticCode::JsxProjectionIncomplete
            && diagnostic.message == message
    }) {
        return;
    }
    diagnostics.push(CodeQueryDiagnostic {
        code: CodeQueryDiagnosticCode::JsxProjectionIncomplete,
        impact: CodeQueryDiagnosticImpact::Incomplete,
        branch: Vec::new(),
        language: language.config_label(),
        message: message.to_string(),
    });
}
