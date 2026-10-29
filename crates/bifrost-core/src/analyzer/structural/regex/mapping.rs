//! Language-neutral decoded-character source mapping for embedded regex facts.
use super::Fact;
use crate::analyzer::Range;
use crate::analyzer::structural::spec::EmbeddedLeafFact;
use crate::text_utils::{compute_line_starts, find_line_index_for_offset};

/// One decoded Unicode scalar's original source bytes.
#[derive(Debug, Clone)]
pub struct MappedChar {
    pub source_start: usize,
    pub source_end: usize,
}

pub fn facts_to_embedded(
    facts: Vec<Fact>,
    chars: &[MappedChar],
    source_range: Range,
    source: &str,
) -> Vec<EmbeddedLeafFact> {
    let mut children = vec![Vec::new(); facts.len()];
    let mut roots = Vec::new();
    for (id, fact) in facts.iter().enumerate() {
        if let Some(parent) = fact.parent {
            assert!(
                parent < id,
                "regex facts are parent-before-child before ordering"
            );
            children[parent].push(id);
        } else {
            roots.push(id);
        }
    }
    let order_children = |ids: &mut Vec<usize>| {
        ids.sort_by_key(|id| (facts[*id].start, facts[*id].end, *id));
    };
    order_children(&mut roots);
    for child_ids in &mut children {
        order_children(child_ids);
    }
    let mut order = Vec::with_capacity(facts.len());
    let mut stack = roots.into_iter().rev().collect::<Vec<_>>();
    while let Some(id) = stack.pop() {
        order.push(id);
        stack.extend(children[id].iter().rev().copied());
    }
    assert_eq!(
        order.len(),
        facts.len(),
        "regex AST fact tree reaches every node"
    );
    let mut remap = vec![0usize; facts.len()];
    for (new, old) in order.iter().copied().enumerate() {
        remap[old] = new;
    }
    let line_starts = compute_line_starts(source);
    order
        .into_iter()
        .map(|old| {
            let fact = &facts[old];
            let range =
                mapped_source_range(fact.start, fact.end, chars, source_range, &line_starts);
            EmbeddedLeafFact {
                kind: fact.kind,
                range,
                parent: fact.parent.map(|parent| remap[parent]),
                construct: fact.construct.clone(),
                occurrence_role: None,
            }
        })
        .collect()
}

fn mapped_source_range(
    start: usize,
    end: usize,
    chars: &[MappedChar],
    source_range: Range,
    line_starts: &[usize],
) -> Range {
    assert!(
        start <= end && end <= chars.len(),
        "regex parser ranges stay within the decoded pattern"
    );
    let (start_byte, end_byte) = if start < end {
        (
            chars[start..end]
                .iter()
                .map(|c| c.source_start)
                .min()
                .expect("nonempty decoded range"),
            chars[start..end]
                .iter()
                .map(|c| c.source_end)
                .max()
                .expect("nonempty decoded range"),
        )
    } else {
        // An empty regex sequence (for example the body of `()`) still has a
        // precise source boundary. Mapping it to the whole source literal
        // makes that child extend outside its enclosing group.
        let boundary = chars.get(start).map_or_else(
            || {
                chars
                    .last()
                    .map_or(source_range.start_byte, |last| last.source_end)
            },
            |next| next.source_start,
        );
        (boundary, boundary)
    };
    Range {
        start_byte,
        end_byte,
        start_line: find_line_index_for_offset(line_starts, start_byte) + 1,
        end_line: find_line_index_for_offset(
            line_starts,
            end_byte.saturating_sub(1).max(start_byte),
        ) + 1,
    }
}
