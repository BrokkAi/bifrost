//! Generic structural relations over authored XML configuration facts.
//!
//! XML element order and same-element attributes are parser facts, not
//! language-policy semantics. Keeping these checks here lets Android and
//! Spring policies share one relation without scanning source text.

use super::configuration::ConfigurationFactValue;
use crate::query::ConfigurationFactsFilter;
use brokk_bifrost_core::analyzer::configuration::{
    ConfigurationDocumentFacts, ConfigurationFact, ConfigurationFactId, ConfigurationMemberRole,
    ConfigurationNodeKind,
};

/// Whether a filter asks for any XML relation beyond the ordinary fact axes.
pub(super) fn has_xml_relation_filter(filter: &ConfigurationFactsFilter) -> bool {
    !filter.xml_parent_keys.is_empty()
        || !filter.xml_preceding_sibling_keys.is_empty()
        || !filter.xml_sibling_attribute_keys.is_empty()
        || !filter.xml_sibling_attribute_values.is_empty()
        || !filter.xml_sibling_attribute_values_ignore_case.is_empty()
        || has_reference_relation(filter)
        || has_peer_relation(filter)
}

/// Apply the XML-only relation axes in a configuration seed filter.
pub(super) fn matches_xml_relations(
    value: &ConfigurationFactValue,
    filter: &ConfigurationFactsFilter,
) -> bool {
    if !has_xml_relation_filter(filter) {
        return true;
    }
    if value.format() != crate::query::domain::ConfigurationFormat::Xml {
        return false;
    }
    if !filter.xml_parent_keys.is_empty()
        && !filter
            .xml_parent_keys
            .iter()
            .any(|key| containing_element_key(value) == Some(key.as_str()))
    {
        return false;
    }
    if !filter.xml_preceding_sibling_keys.is_empty()
        && !has_preceding_element_sibling(value, &filter.xml_preceding_sibling_keys)
    {
        return false;
    }
    if has_sibling_attribute_filter(filter)
        && !has_matching_sibling_attribute(
            value,
            &filter.xml_sibling_attribute_keys,
            &filter.xml_sibling_attribute_values,
            &filter.xml_sibling_attribute_values_ignore_case,
        )
    {
        return false;
    }
    let reference_matches = if filter.xml_reference_target_child_keys.is_empty() {
        matches_incoming_reference(value, filter)
    } else {
        matches_reference_target_child(value, filter)
    };
    if has_reference_relation(filter) && !reference_matches {
        return false;
    }
    if has_peer_relation(filter) && !matches_peer_element(value, filter) {
        return false;
    }
    true
}

/// Validate same-document reference coverage before a relation can support an
/// absence result. A missing or ambiguous target is deliberately open: it may
/// be declared in a document outside the selected set.
pub(super) fn xml_reference_coverage(
    value: &ConfigurationFactValue,
    filter: &ConfigurationFactsFilter,
) -> Option<String> {
    if !has_reference_relation(filter) {
        return None;
    }
    if filter.xml_reference_source_keys.is_empty() || filter.xml_reference_target_keys.is_empty() {
        return Some(
            "same-document XML reference relation requires both source and target attribute keys"
                .to_string(),
        );
    }
    let unresolved = value
        .document
        .facts()
        .iter()
        .filter_map(|fact| {
            let ConfigurationNodeKind::Member {
                role: ConfigurationMemberRole::XmlAttribute,
                key,
                value: Some(member_value),
            } = fact.kind()
            else {
                return None;
            };
            if !filter
                .xml_reference_source_keys
                .iter()
                .any(|candidate| candidate == key.text())
            {
                return None;
            }
            let Some(reference_value) = scalar_value_at(value, *member_value) else {
                return Some(true);
            };
            let targets = reference_targets(value, &reference_value, filter);
            Some(targets.len() != 1)
        })
        .filter(|is_unresolved| *is_unresolved)
        .count();
    if unresolved == 0 {
        None
    } else {
        Some(format!(
            "{} XML reference attribute(s) do not resolve to exactly one same-document target; the target may be outside the selected document set",
            unresolved
        ))
    }
}

fn has_sibling_attribute_filter(filter: &ConfigurationFactsFilter) -> bool {
    !filter.xml_sibling_attribute_keys.is_empty()
        || !filter.xml_sibling_attribute_values.is_empty()
        || !filter.xml_sibling_attribute_values_ignore_case.is_empty()
}

fn containing_element_key(value: &ConfigurationFactValue) -> Option<&str> {
    let parent_id = value.fact().parent()?;
    let parent = value.document.fact(parent_id)?;
    let ConfigurationNodeKind::Section { .. } = parent.kind() else {
        return None;
    };
    let element_id = parent.parent()?;
    let element = value.document.fact(element_id)?;
    let ConfigurationNodeKind::Member {
        role: ConfigurationMemberRole::XmlElement,
        key,
        ..
    } = element.kind()
    else {
        return None;
    };
    Some(key.text())
}

fn containing_members(value: &ConfigurationFactValue) -> Option<(&[ConfigurationFactId], usize)> {
    let parent_id = value.fact().parent()?;
    let parent = value.document.fact(parent_id)?;
    let members = match parent.kind() {
        ConfigurationNodeKind::Section { members, .. } => members,
        _ => return None,
    };
    Some((members, value.index))
}

fn has_preceding_element_sibling(value: &ConfigurationFactValue, keys: &[String]) -> bool {
    let Some((members, target)) = containing_members(value) else {
        return false;
    };
    for member_id in members {
        if member_id.index() == target {
            return false;
        }
        let Some(member) = value.document.fact(*member_id) else {
            continue;
        };
        let ConfigurationNodeKind::Member {
            role: ConfigurationMemberRole::XmlElement,
            key,
            ..
        } = member.kind()
        else {
            continue;
        };
        if keys.iter().any(|candidate| candidate == key.text()) {
            return true;
        }
    }
    false
}

fn has_matching_sibling_attribute(
    value: &ConfigurationFactValue,
    keys: &[String],
    values: &[String],
    values_ignore_case: &[String],
) -> bool {
    let Some((members, target)) = containing_members(value) else {
        return false;
    };
    members.iter().any(|member_id| {
        if member_id.index() == target {
            return false;
        }
        let Some(member) = value.document.fact(*member_id) else {
            return false;
        };
        let ConfigurationNodeKind::Member {
            role: ConfigurationMemberRole::XmlAttribute,
            key,
            value: member_value,
        } = member.kind()
        else {
            return false;
        };
        if !keys.is_empty() && !keys.iter().any(|candidate| candidate == key.text()) {
            return false;
        }
        let Some(member_value) = member_value else {
            return values.is_empty() && values_ignore_case.is_empty();
        };
        let candidate = scalar_value_at(value, *member_value);
        if !values.is_empty()
            && !candidate
                .as_deref()
                .is_some_and(|actual| values.iter().any(|expected| expected == actual))
        {
            return false;
        }
        if !values_ignore_case.is_empty()
            && !candidate.as_deref().is_some_and(|actual| {
                values_ignore_case
                    .iter()
                    .any(|expected| expected.eq_ignore_ascii_case(actual))
            })
        {
            return false;
        }
        true
    })
}

fn scalar_value_at(value: &ConfigurationFactValue, fact_id: ConfigurationFactId) -> Option<String> {
    let candidate = ConfigurationFactValue {
        file: value.file.clone(),
        document: value.document.clone(),
        source: value.source.clone(),
        index: fact_id.index(),
    };
    candidate.scalar_value()
}

fn has_reference_relation(filter: &ConfigurationFactsFilter) -> bool {
    !filter.xml_reference_source_keys.is_empty()
        || !filter.xml_reference_target_keys.is_empty()
        || !filter.xml_reference_target_element_keys.is_empty()
        || !filter.xml_reference_target_child_keys.is_empty()
}

fn has_peer_relation(filter: &ConfigurationFactsFilter) -> bool {
    !filter.xml_peer_element_keys.is_empty()
        || !filter.xml_peer_attribute_keys.is_empty()
        || !filter.xml_peer_child_keys.is_empty()
        || filter.xml_peer_min_shared_children.is_some()
}

fn matches_incoming_reference(
    value: &ConfigurationFactValue,
    filter: &ConfigurationFactsFilter,
) -> bool {
    if !is_xml_element(value.fact())
        || filter.xml_reference_source_keys.is_empty()
        || filter.xml_reference_target_keys.is_empty()
    {
        return false;
    }
    let target_id = ConfigurationFactId::new(value.index).expect("XML fact index is finite");
    value
        .document
        .facts()
        .iter()
        .filter_map(|fact| {
            let ConfigurationNodeKind::Member {
                role: ConfigurationMemberRole::XmlAttribute,
                key,
                value: Some(member_value),
            } = fact.kind()
            else {
                return None;
            };
            filter
                .xml_reference_source_keys
                .iter()
                .any(|candidate| candidate == key.text())
                .then(|| scalar_value_at(value, *member_value))
                .flatten()
        })
        .any(|reference_value| {
            reference_targets(value, &reference_value, filter).contains(&target_id)
        })
}

fn matches_reference_target_child(
    value: &ConfigurationFactValue,
    filter: &ConfigurationFactsFilter,
) -> bool {
    if !is_xml_element(value.fact())
        || filter.xml_reference_source_keys.is_empty()
        || filter.xml_reference_target_keys.is_empty()
    {
        return false;
    }
    let Some(source_element) = containing_element_id(value) else {
        return false;
    };
    let Some(reference_value) = element_reference_value(value, source_element, filter) else {
        return false;
    };
    let targets = reference_targets(value, &reference_value, filter);
    if targets.len() != 1 {
        return false;
    }
    let Some(selected_signature) = xml_element_signature(value, value.index) else {
        return false;
    };
    let target = targets[0];
    direct_child_elements(value.document.as_ref(), target)
        .into_iter()
        .filter(|child| {
            element_key(value.document.as_ref(), *child).is_some_and(|key| {
                filter
                    .xml_reference_target_child_keys
                    .iter()
                    .any(|candidate| candidate == key)
            })
        })
        .any(|child| {
            xml_element_signature(value, child.index()) == Some(selected_signature.clone())
        })
}

fn matches_peer_element(value: &ConfigurationFactValue, filter: &ConfigurationFactsFilter) -> bool {
    if !is_xml_element(value.fact())
        || filter.xml_peer_element_keys.is_empty()
        || filter.xml_peer_child_keys.is_empty()
    {
        return false;
    }
    let minimum = filter.xml_peer_min_shared_children.unwrap_or(1) as usize;
    let selected_children = peer_child_signatures(value, value.index, filter);
    if selected_children.len() < minimum {
        return false;
    }
    value
        .document
        .facts()
        .iter()
        .enumerate()
        .filter_map(|(index, fact)| {
            let candidate = ConfigurationFactId::new(index).expect("XML fact index is finite");
            if candidate.index() == value.index
                || !is_xml_element(fact)
                || !filter
                    .xml_peer_element_keys
                    .iter()
                    .any(|key| element_key(value.document.as_ref(), candidate) == Some(key))
                || !peer_attributes_match(value, value.index, candidate, filter)
            {
                return None;
            }
            let peer_children = peer_child_signatures(value, candidate.index(), filter);
            (peer_children == selected_children && peer_children.len() >= minimum)
                .then_some(candidate)
        })
        .next()
        .is_some()
}

fn peer_attributes_match(
    value: &ConfigurationFactValue,
    left: usize,
    right: ConfigurationFactId,
    filter: &ConfigurationFactsFilter,
) -> bool {
    filter.xml_peer_attribute_keys.iter().all(|key| {
        let left_value = element_attribute_value(value, left, key);
        let right_value = element_attribute_value(value, right.index(), key);
        left_value.is_some() && left_value == right_value
    })
}

fn peer_child_signatures(
    value: &ConfigurationFactValue,
    element: usize,
    filter: &ConfigurationFactsFilter,
) -> Vec<Vec<XmlSignaturePart>> {
    let mut signatures = direct_child_elements(
        value.document.as_ref(),
        ConfigurationFactId::new(element).expect("XML fact index is finite"),
    )
    .into_iter()
    .filter(|child| {
        element_key(value.document.as_ref(), *child).is_some_and(|key| {
            filter
                .xml_peer_child_keys
                .iter()
                .any(|candidate| candidate == key)
        })
    })
    .filter_map(|child| xml_element_signature(value, child.index()))
    .collect::<Vec<_>>();
    signatures.sort();
    signatures.dedup();
    signatures
}

fn element_reference_value(
    value: &ConfigurationFactValue,
    element: ConfigurationFactId,
    filter: &ConfigurationFactsFilter,
) -> Option<String> {
    direct_attributes(value.document.as_ref(), element)
        .into_iter()
        .filter(|attribute| {
            member_key(value.document.as_ref(), *attribute).is_some_and(|key| {
                filter
                    .xml_reference_source_keys
                    .iter()
                    .any(|candidate| candidate == key)
            })
        })
        .find_map(|attribute| {
            let ConfigurationNodeKind::Member {
                value: Some(member_value),
                ..
            } = value.document.fact(attribute)?.kind()
            else {
                return None;
            };
            scalar_value_at(value, *member_value)
        })
}

fn reference_targets(
    value: &ConfigurationFactValue,
    reference_value: &str,
    filter: &ConfigurationFactsFilter,
) -> Vec<ConfigurationFactId> {
    value
        .document
        .facts()
        .iter()
        .enumerate()
        .filter_map(|(index, fact)| {
            let target = ConfigurationFactId::new(index).expect("XML fact index is finite");
            if !is_xml_element(fact)
                || (!filter.xml_reference_target_element_keys.is_empty()
                    && !filter
                        .xml_reference_target_element_keys
                        .iter()
                        .any(|key| element_key(value.document.as_ref(), target) == Some(key)))
            {
                return None;
            }
            let matches = direct_attributes(value.document.as_ref(), target)
                .into_iter()
                .filter(|attribute| {
                    member_key(value.document.as_ref(), *attribute).is_some_and(|key| {
                        filter
                            .xml_reference_target_keys
                            .iter()
                            .any(|candidate| candidate == key)
                    })
                })
                .any(|attribute| {
                    let Some(ConfigurationNodeKind::Member {
                        value: Some(member_value),
                        ..
                    }) = value.document.fact(attribute).map(ConfigurationFact::kind)
                    else {
                        return false;
                    };
                    scalar_value_at(value, *member_value).as_deref() == Some(reference_value)
                });
            matches.then_some(target)
        })
        .collect()
}

fn containing_element_id(value: &ConfigurationFactValue) -> Option<ConfigurationFactId> {
    let section = value.fact().parent()?;
    let section = value.document.fact(section)?;
    matches!(section.kind(), ConfigurationNodeKind::Section { .. })
        .then(|| section.parent())
        .flatten()
}

fn direct_child_elements(
    document: &ConfigurationDocumentFacts,
    element: ConfigurationFactId,
) -> Vec<ConfigurationFactId> {
    let Some(ConfigurationNodeKind::Member {
        value: Some(section),
        ..
    }) = document.fact(element).map(ConfigurationFact::kind)
    else {
        return Vec::new();
    };
    let Some(ConfigurationNodeKind::Section { members, .. }) =
        document.fact(*section).map(ConfigurationFact::kind)
    else {
        return Vec::new();
    };
    members
        .iter()
        .copied()
        .filter(|member| document.fact(*member).is_some_and(is_xml_element))
        .collect()
}

fn direct_attributes(
    document: &ConfigurationDocumentFacts,
    element: ConfigurationFactId,
) -> Vec<ConfigurationFactId> {
    let Some(ConfigurationNodeKind::Member {
        value: Some(section),
        ..
    }) = document.fact(element).map(ConfigurationFact::kind)
    else {
        return Vec::new();
    };
    let Some(ConfigurationNodeKind::Section { members, .. }) =
        document.fact(*section).map(ConfigurationFact::kind)
    else {
        return Vec::new();
    };
    members
        .iter()
        .copied()
        .filter(|member| {
            document.fact(*member).is_some_and(|fact| {
                matches!(
                    fact.kind(),
                    ConfigurationNodeKind::Member {
                        role: ConfigurationMemberRole::XmlAttribute,
                        ..
                    }
                )
            })
        })
        .collect()
}

fn element_key(
    document: &ConfigurationDocumentFacts,
    element: ConfigurationFactId,
) -> Option<&str> {
    let ConfigurationNodeKind::Member {
        role: ConfigurationMemberRole::XmlElement,
        key,
        ..
    } = document.fact(element)?.kind()
    else {
        return None;
    };
    Some(key.text())
}

fn member_key(document: &ConfigurationDocumentFacts, member: ConfigurationFactId) -> Option<&str> {
    let ConfigurationNodeKind::Member { key, .. } = document.fact(member)?.kind() else {
        return None;
    };
    Some(key.text())
}

fn is_xml_element(fact: &brokk_bifrost_core::analyzer::configuration::ConfigurationFact) -> bool {
    matches!(
        fact.kind(),
        ConfigurationNodeKind::Member {
            role: ConfigurationMemberRole::XmlElement,
            ..
        }
    )
}

fn element_attribute_value(
    value: &ConfigurationFactValue,
    element: usize,
    key: &str,
) -> Option<String> {
    direct_attributes(
        value.document.as_ref(),
        ConfigurationFactId::new(element).expect("XML fact index is finite"),
    )
    .into_iter()
    .filter(|attribute| member_key(value.document.as_ref(), *attribute) == Some(key))
    .find_map(|attribute| {
        let ConfigurationNodeKind::Member {
            value: Some(member_value),
            ..
        } = value.document.fact(attribute)?.kind()
        else {
            return None;
        };
        scalar_value_at(value, *member_value)
    })
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum XmlSignaturePart {
    Member { role: u8, key: String },
    SectionStart,
    SectionEnd,
    Scalar(String),
}

enum XmlSignatureWork {
    Fact(ConfigurationFactId),
    EndSection,
}

fn xml_element_signature(
    value: &ConfigurationFactValue,
    root: usize,
) -> Option<Vec<XmlSignaturePart>> {
    let mut signature = Vec::new();
    let mut work = vec![XmlSignatureWork::Fact(
        ConfigurationFactId::new(root).expect("XML fact index is finite"),
    )];
    while let Some(item) = work.pop() {
        match item {
            XmlSignatureWork::EndSection => signature.push(XmlSignaturePart::SectionEnd),
            XmlSignatureWork::Fact(fact_id) => match value.document.fact(fact_id)?.kind() {
                ConfigurationNodeKind::Member {
                    role,
                    key,
                    value: member_value,
                } => {
                    signature.push(XmlSignaturePart::Member {
                        role: xml_role_number(*role),
                        key: key.text().to_string(),
                    });
                    if let Some(member_value) = member_value {
                        work.push(XmlSignatureWork::Fact(*member_value));
                    }
                }
                ConfigurationNodeKind::Section { header, members } => {
                    signature.push(XmlSignaturePart::SectionStart);
                    work.push(XmlSignatureWork::EndSection);
                    // Attributes are an unordered set keyed by qualified name.
                    // Child element order remains part of the signature.
                    let mut attributes = members
                        .iter()
                        .copied()
                        .filter(|member| {
                            matches!(
                                value.document.fact(*member).map(ConfigurationFact::kind),
                                Some(ConfigurationNodeKind::Member {
                                    role: ConfigurationMemberRole::XmlAttribute,
                                    ..
                                })
                            )
                        })
                        .collect::<Vec<_>>();
                    attributes.sort_by(|left, right| {
                        member_key(value.document.as_ref(), *left)
                            .cmp(&member_key(value.document.as_ref(), *right))
                    });
                    for member in members.iter().rev() {
                        if !attributes.contains(member) {
                            work.push(XmlSignatureWork::Fact(*member));
                        }
                    }
                    for attribute in attributes.into_iter().rev() {
                        work.push(XmlSignatureWork::Fact(attribute));
                    }
                    if let Some(header) = header {
                        work.push(XmlSignatureWork::Fact(*header));
                    }
                }
                ConfigurationNodeKind::Scalar { .. } => {
                    signature.push(XmlSignaturePart::Scalar(scalar_value_at(value, fact_id)?));
                }
                ConfigurationNodeKind::Document { .. }
                | ConfigurationNodeKind::Object { .. }
                | ConfigurationNodeKind::Sequence { .. } => return None,
            },
        }
    }
    Some(signature)
}

fn xml_role_number(role: ConfigurationMemberRole) -> u8 {
    match role {
        ConfigurationMemberRole::ObjectMember => 0,
        ConfigurationMemberRole::TableEntry => 1,
        ConfigurationMemberRole::Property => 2,
        ConfigurationMemberRole::XmlAttribute => 3,
        ConfigurationMemberRole::XmlElement => 4,
    }
}
