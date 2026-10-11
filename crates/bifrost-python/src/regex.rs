//! Python `re` pattern-value facts.
//!
//! Source structure comes from tree-sitter-python. This module decodes only a
//! string AST node selected as the pattern argument of a recognized `re` API,
//! then parses that decoded value with Python `re` rules. Unsupported syntax
//! is emitted as an incomplete fact instead of being treated as harmless.

use crate::bindings::{
    PythonLexicalNameResolution, python_comprehension_binds_name_at,
    python_module_or_class_scope_binds_name_bounded, python_name_resolution_at,
};
use crate::syntax::python_static_attribute_path;
use brokk_bifrost_core::analyzer::Range;
use brokk_bifrost_core::analyzer::structural::kinds::NormalizedKind;
use brokk_bifrost_core::analyzer::structural::spec::EmbeddedLeafFact;
use brokk_bifrost_core::text_utils::{compute_line_starts, find_line_index_for_offset};
use std::collections::{HashMap, HashSet, VecDeque};
use tree_sitter::Node;

const MAX_PATTERN_CHARS: usize = 8192;
const MAX_PATTERN_FACTS: usize = 4096;
const MAX_GROUP_DEPTH: usize = 128;
const MAX_NFA_STATES: usize = 512;
const MAX_NFA_PRODUCT_PAIRS: usize = 65_536;
const MAX_NFA_REPEAT: u32 = 32;
const MAX_REDOSE_GROUPS: usize = 16;
const MAX_REDOSE_ALTERNATIVES: usize = 8;

#[derive(Debug)]
struct MappedChar {
    source_start: usize,
    source_end: usize,
}

#[derive(Debug)]
struct DecodedValue {
    value: String,
    chars: Vec<MappedChar>,
    source_range: Range,
    is_bytes: bool,
}

#[derive(Debug, Clone, Copy)]
struct RegexFlags {
    dotall: bool,
    multiline: bool,
    ignorecase: bool,
    ascii: bool,
    verbose: bool,
    complete: bool,
}

#[derive(Debug, Clone, Copy)]
struct Api {
    flags_position: usize,
    scans_from_each_offset: bool,
}

#[derive(Debug, Clone)]
struct Fact {
    kind: NormalizedKind,
    start: usize,
    end: usize,
    parent: Option<usize>,
    construct: Option<String>,
    first_set: Option<CharacterSet>,
    quantifier: Option<Quantifier>,
    minimum_width: Option<u32>,
}

fn polynomial_atoms_overlap(left: &Fact, right: &Fact) -> bool {
    match (&left.first_set, &right.first_set) {
        (Some(left), Some(right)) => left.intersects(right),
        _ => matches!(
            (left.construct.as_deref(), right.construct.as_deref()),
            (Some("category:d"), Some("category:d" | "category:w"))
                | (Some("category:w"), Some("category:d" | "category:w"))
                | (Some("category:s"), Some("category:s"))
        ),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CharacterSet {
    ranges: Vec<(u32, u32)>,
}

impl CharacterSet {
    fn one(value: char) -> Self {
        let value = value as u32;
        Self {
            ranges: vec![(value, value)],
        }
    }

    fn any_except_newline() -> Self {
        Self {
            ranges: vec![(0, 9), (11, 0x10ffff)],
        }
    }

    fn complement(mut self) -> Self {
        let mut ranges = Vec::new();
        let mut next = 0u32;
        self.ranges.sort_unstable();
        for (start, end) in self.ranges {
            if next < start {
                ranges.push((next, start - 1));
            }
            next = end.saturating_add(1);
            if next > 0x10ffff {
                break;
            }
        }
        if next <= 0x10ffff {
            ranges.push((next, 0x10ffff));
        }
        Self { ranges }
    }

    fn union_with(&mut self, other: &Self) {
        self.ranges.extend_from_slice(&other.ranges);
        self.ranges.sort_unstable();
        let mut merged: Vec<(u32, u32)> = Vec::with_capacity(self.ranges.len());
        for (start, end) in self.ranges.drain(..) {
            if let Some((_, previous_end)) = merged.last_mut()
                && start <= previous_end.saturating_add(1)
            {
                *previous_end = (*previous_end).max(end);
            } else {
                merged.push((start, end));
            }
        }
        self.ranges = merged;
    }

    fn intersects(&self, other: &Self) -> bool {
        self.ranges.iter().any(|(left_start, left_end)| {
            other
                .ranges
                .iter()
                .any(|(right_start, right_end)| left_start <= right_end && right_start <= left_end)
        })
    }

    fn contains(&self, character: char) -> bool {
        let value = character as u32;
        self.ranges
            .iter()
            .any(|(start, end)| *start <= value && value <= *end)
    }

    fn with_ascii_case_variants(mut self) -> Self {
        for lower in 'a'..='z' {
            let upper = lower.to_ascii_uppercase();
            match (self.contains(lower), self.contains(upper)) {
                (true, false) => self.union_with(&Self::one(upper)),
                (false, true) => self.union_with(&Self::one(lower)),
                _ => {}
            }
        }
        self
    }
}

#[derive(Debug, Clone, Default)]
struct NfaState {
    epsilon: Vec<usize>,
    transitions: Vec<(CharacterSet, usize)>,
    capture_ends: Vec<usize>,
}

#[derive(Debug, Clone)]
struct NfaFragment {
    start: usize,
    end: usize,
    states: Vec<usize>,
}

#[derive(Debug)]
struct RegexNfa {
    states: Vec<NfaState>,
    start: usize,
    end: usize,
}

#[derive(Debug, Clone, Copy)]
enum NfaError {
    Unsupported,
    Budget,
}

impl RegexNfa {
    fn compile(
        facts: &[Fact],
        root: usize,
        selected_branch: Option<usize>,
    ) -> Result<Self, NfaError> {
        let mut children = vec![Vec::new(); facts.len()];
        for (id, fact) in facts.iter().enumerate() {
            if let Some(parent) = fact.parent {
                children[parent].push(id);
            }
        }
        let mut capture_ids = vec![None; facts.len()];
        let mut next_capture = 1;
        for (id, fact) in facts.iter().enumerate() {
            if fact.kind == NormalizedKind::RegexGroup
                && matches!(
                    fact.construct.as_deref(),
                    Some("capturing" | "named-capturing")
                )
            {
                capture_ids[id] = Some(next_capture);
                next_capture += 1;
            }
        }
        let mut builder = NfaBuilder {
            facts,
            children,
            selected_branch: selected_branch.map(|branch| (root, branch)),
            capture_ids: &capture_ids,
            states: Vec::new(),
        };
        let mut fragments = vec![None; facts.len()];
        let mut stack = vec![(root, false)];
        while let Some((id, expanded)) = stack.pop() {
            if fragments[id].is_some() {
                continue;
            }
            if expanded {
                fragments[id] = Some(builder.compile_fact(id, &fragments)?);
                continue;
            }
            stack.push((id, true));
            let dependencies = builder.dependencies(id);
            for dependency in dependencies.into_iter().rev() {
                stack.push((dependency, false));
            }
        }
        let fragment = fragments[root].take().ok_or(NfaError::Unsupported)?;
        Ok(Self {
            states: builder.states,
            start: fragment.start,
            end: fragment.end,
        })
    }

    fn match_prefix_capture_groups(&self, sample: &str) -> (bool, HashSet<usize>) {
        let chars = sample.chars().collect::<Vec<_>>();
        let width = chars.len() + 1;
        let node_id = |state: usize, position: usize| state * width + position;
        let mut reachable = vec![false; self.states.len() * width];
        let mut reverse = vec![Vec::new(); self.states.len() * width];
        let start = node_id(self.start, 0);
        reachable[start] = true;
        let mut pending = VecDeque::from([start]);
        while let Some(node) = pending.pop_front() {
            let state = node / width;
            let position = node % width;
            let mut successors = self.states[state]
                .epsilon
                .iter()
                .map(|&target| node_id(target, position))
                .collect::<Vec<_>>();
            if let Some(&character) = chars.get(position) {
                successors.extend(
                    self.states[state]
                        .transitions
                        .iter()
                        .filter(|(set, _)| set.contains(character))
                        .map(|(_, target)| node_id(*target, position + 1)),
                );
            }
            for successor in successors {
                reverse[successor].push(node);
                if !std::mem::replace(&mut reachable[successor], true) {
                    pending.push_back(successor);
                }
            }
        }

        let accepting = (0..width)
            .map(|position| node_id(self.end, position))
            .filter(|&node| reachable[node])
            .collect::<Vec<_>>();
        if accepting.is_empty() {
            return (false, HashSet::new());
        }
        let mut reaches_accept = vec![false; reachable.len()];
        let mut pending = VecDeque::new();
        for node in accepting {
            reaches_accept[node] = true;
            pending.push_back(node);
        }
        while let Some(node) = pending.pop_front() {
            for &previous in &reverse[node] {
                if !std::mem::replace(&mut reaches_accept[previous], true) {
                    pending.push_back(previous);
                }
            }
        }
        let groups = self
            .states
            .iter()
            .enumerate()
            .filter(|(state, _)| {
                (0..width).any(|position| {
                    let node = node_id(*state, position);
                    reachable[node] && reaches_accept[node]
                })
            })
            .flat_map(|(_, state)| state.capture_ends.iter().copied())
            .collect();
        (true, groups)
    }

    fn intersects_on_nonempty_string(
        &self,
        other: &Self,
        remaining_budget: &mut usize,
    ) -> Result<bool, NfaError> {
        let mut pending = VecDeque::from([(self.start, other.start, false)]);
        let mut seen = HashSet::new();
        while let Some((left, right, consumed)) = pending.pop_front() {
            if !seen.insert((left, right, consumed)) {
                continue;
            }
            if *remaining_budget == 0 {
                return Err(NfaError::Budget);
            }
            *remaining_budget -= 1;
            if consumed && left == self.end && right == other.end {
                return Ok(true);
            }
            for &target in &self.states[left].epsilon {
                pending.push_back((target, right, consumed));
            }
            for &target in &other.states[right].epsilon {
                pending.push_back((left, target, consumed));
            }
            for (left_set, left_target) in &self.states[left].transitions {
                for (right_set, right_target) in &other.states[right].transitions {
                    if left_set.intersects(right_set) {
                        pending.push_back((*left_target, *right_target, true));
                    }
                }
            }
        }
        Ok(false)
    }

    fn has_repartitioned_prefix(
        &self,
        longer: &Self,
        repeated: &Self,
        remaining_budget: &mut usize,
    ) -> Result<bool, NfaError> {
        // Find a non-empty common prefix accepted by `self` while `longer`
        // continues, then require that continuation to match the repeated
        // alternation. This catches ambiguous partitions such as `__|.`.
        let mut pending = VecDeque::from([(0u8, self.start, longer.start, false)]);
        let mut seen = HashSet::new();
        while let Some((phase, left, right, consumed)) = pending.pop_front() {
            if !seen.insert((phase, left, right, consumed)) {
                continue;
            }
            if *remaining_budget == 0 {
                return Err(NfaError::Budget);
            }
            *remaining_budget -= 1;
            if phase == 0 {
                if consumed && left == self.end {
                    pending.push_back((1, right, repeated.start, false));
                }
                for &target in &self.states[left].epsilon {
                    pending.push_back((0, target, right, consumed));
                }
                for &target in &longer.states[right].epsilon {
                    pending.push_back((0, left, target, consumed));
                }
                for (left_set, left_target) in &self.states[left].transitions {
                    for (right_set, right_target) in &longer.states[right].transitions {
                        if left_set.intersects(right_set) {
                            pending.push_back((0, *left_target, *right_target, true));
                        }
                    }
                }
            } else {
                if consumed && left == longer.end && right == repeated.end {
                    return Ok(true);
                }
                for &target in &longer.states[left].epsilon {
                    pending.push_back((1, target, right, consumed));
                }
                for &target in &repeated.states[right].epsilon {
                    pending.push_back((1, left, target, consumed));
                }
                for (longer_set, longer_target) in &longer.states[left].transitions {
                    for (repeated_set, repeated_target) in &repeated.states[right].transitions {
                        if longer_set.intersects(repeated_set) {
                            pending.push_back((1, *longer_target, *repeated_target, true));
                        }
                    }
                }
            }
        }
        Ok(false)
    }

    fn has_pumpable_fork(&self, remaining_budget: &mut usize) -> Result<bool, NfaError> {
        let epsilon_closures = self.epsilon_closures();
        for fork in 0..self.states.len() {
            let mut outgoing = Vec::new();
            for &source in &epsilon_closures[fork] {
                for (set, target) in &self.states[source].transitions {
                    outgoing.push((source, set, *target));
                }
            }
            for left in 0..outgoing.len() {
                for right in left + 1..outgoing.len() {
                    if *remaining_budget == 0 {
                        return Err(NfaError::Budget);
                    }
                    *remaining_budget -= 1;
                    let (left_source, left_set, left_target) = outgoing[left];
                    let (right_source, right_set, right_target) = outgoing[right];
                    if left_source == right_source
                        && left_target == right_target
                        && left_set.ranges == right_set.ranges
                    {
                        continue;
                    }
                    if !left_set.intersects(right_set) {
                        continue;
                    }
                    if self.product_reaches_fork(
                        (left_target, right_target),
                        fork,
                        &epsilon_closures,
                        remaining_budget,
                    )? {
                        return Ok(true);
                    }
                }
            }
        }
        Ok(false)
    }

    fn epsilon_closures(&self) -> Vec<Vec<usize>> {
        (0..self.states.len())
            .map(|start| {
                let mut seen = vec![false; self.states.len()];
                let mut pending = vec![start];
                let mut closure = Vec::new();
                while let Some(state) = pending.pop() {
                    if std::mem::replace(&mut seen[state], true) {
                        continue;
                    }
                    closure.push(state);
                    pending.extend(self.states[state].epsilon.iter().copied());
                }
                closure
            })
            .collect()
    }

    fn product_reaches_fork(
        &self,
        start: (usize, usize),
        fork: usize,
        epsilon_closures: &[Vec<usize>],
        remaining_budget: &mut usize,
    ) -> Result<bool, NfaError> {
        let canonical = |(left, right): (usize, usize)| {
            if left <= right {
                (left, right)
            } else {
                (right, left)
            }
        };
        let mut pending = VecDeque::from([canonical(start)]);
        let mut seen = HashSet::new();
        while let Some((left, right)) = pending.pop_front() {
            if (left, right) == (fork, fork) {
                return Ok(true);
            }
            if !seen.insert((left, right)) {
                continue;
            }
            for &left_source in &epsilon_closures[left] {
                for (left_set, left_target) in &self.states[left_source].transitions {
                    for &right_source in &epsilon_closures[right] {
                        for (right_set, right_target) in &self.states[right_source].transitions {
                            if *remaining_budget == 0 {
                                return Err(NfaError::Budget);
                            }
                            *remaining_budget -= 1;
                            if left_set.intersects(right_set) {
                                pending.push_back(canonical((*left_target, *right_target)));
                            }
                        }
                    }
                }
            }
        }
        Ok(false)
    }

    fn positive_closure(mut self) -> Result<Self, NfaError> {
        if self.states.len().saturating_add(2) > MAX_NFA_STATES {
            return Err(NfaError::Budget);
        }
        let original_start = self.start;
        let original_end = self.end;
        let start = self.states.len();
        let end = start + 1;
        self.states.push(NfaState::default());
        self.states.push(NfaState::default());
        self.states[start].epsilon.push(original_start);
        self.states[original_end]
            .epsilon
            .extend([end, original_start]);
        self.start = start;
        self.end = end;
        Ok(self)
    }
}

struct NfaBuilder<'a> {
    facts: &'a [Fact],
    children: Vec<Vec<usize>>,
    selected_branch: Option<(usize, usize)>,
    capture_ids: &'a [Option<usize>],
    states: Vec<NfaState>,
}

impl NfaBuilder<'_> {
    fn dependencies(&self, id: usize) -> Vec<usize> {
        match self.facts[id].kind {
            NormalizedKind::RegexPattern | NormalizedKind::RegexGroup => self.children[id]
                .iter()
                .copied()
                .filter(|child| self.facts[*child].kind == NormalizedKind::RegexSequence)
                .collect(),
            NormalizedKind::RegexSequence => self.children[id]
                .iter()
                .copied()
                .filter(|child| {
                    !matches!(
                        self.facts[*child].kind,
                        NormalizedKind::RegexAlternation | NormalizedKind::RegexQuantifier
                    )
                })
                .collect(),
            _ => Vec::new(),
        }
    }

    fn compile_fact(
        &mut self,
        id: usize,
        fragments: &[Option<NfaFragment>],
    ) -> Result<NfaFragment, NfaError> {
        let fact = &self.facts[id];
        let kind = fact.kind;
        let is_comment = fact.construct.as_deref() == Some("comment");
        let first_set = fact.first_set.clone();
        let base = match kind {
            NormalizedKind::RegexPattern | NormalizedKind::RegexGroup => {
                if is_comment {
                    self.empty_fragment()?
                } else if kind == NormalizedKind::RegexGroup
                    && fact
                        .construct
                        .as_deref()
                        .is_some_and(|construct| construct.starts_with("look"))
                {
                    return Err(NfaError::Unsupported);
                } else {
                    let sequence = self.children[id]
                        .iter()
                        .copied()
                        .find(|child| self.facts[*child].kind == NormalizedKind::RegexSequence)
                        .ok_or(NfaError::Unsupported)?;
                    fragments[sequence].clone().ok_or(NfaError::Unsupported)?
                }
            }
            NormalizedKind::RegexSequence => self.compile_sequence(id, fragments)?,
            NormalizedKind::RegexAnchor => return Err(NfaError::Unsupported),
            NormalizedKind::RegexLiteral
            | NormalizedKind::RegexWildcard
            | NormalizedKind::RegexCharacterClass
            | NormalizedKind::RegexCharacterRange
            | NormalizedKind::RegexEscape => {
                let set = first_set.ok_or(NfaError::Unsupported)?;
                self.character_fragment(set)?
            }
            _ => return Err(NfaError::Unsupported),
        };
        let base = if let Some(capture) = self.capture_ids[id] {
            self.capture_group(base, capture)?
        } else {
            base
        };
        self.apply_quantifier(id, base)
    }

    fn capture_group(
        &mut self,
        mut inner: NfaFragment,
        capture: usize,
    ) -> Result<NfaFragment, NfaError> {
        let start = self.new_state()?;
        let end = self.new_state()?;
        self.states[start].epsilon.push(inner.start);
        self.states[inner.end].epsilon.push(end);
        self.states[end].capture_ends.push(capture);
        inner.states.extend([start, end]);
        inner.start = start;
        inner.end = end;
        Ok(inner)
    }

    fn compile_sequence(
        &mut self,
        sequence: usize,
        fragments: &[Option<NfaFragment>],
    ) -> Result<NfaFragment, NfaError> {
        let mut branches = vec![Vec::new()];
        let direct_children = self.children[sequence].clone();
        for child in direct_children {
            if self.facts[child].kind == NormalizedKind::RegexAlternation {
                branches.push(Vec::new());
            } else if self.facts[child].kind != NormalizedKind::RegexQuantifier {
                branches
                    .last_mut()
                    .expect("regex sequence always has a branch")
                    .push(fragments[child].clone().ok_or(NfaError::Unsupported)?);
            }
        }
        let branches = branches
            .into_iter()
            .map(|terms| self.concatenate(terms))
            .collect::<Result<Vec<_>, _>>()?;
        if let Some((selected_sequence, selected_index)) = self.selected_branch
            && selected_sequence == sequence
        {
            return branches
                .get(selected_index)
                .cloned()
                .ok_or(NfaError::Unsupported);
        }
        self.alternate(branches)
    }

    fn apply_quantifier(&mut self, id: usize, base: NfaFragment) -> Result<NfaFragment, NfaError> {
        let Some(quantifier_id) = self.children[id]
            .iter()
            .copied()
            .find(|child| self.facts[*child].kind == NormalizedKind::RegexQuantifier)
        else {
            return Ok(base);
        };
        let quantifier = self.facts[quantifier_id]
            .quantifier
            .ok_or(NfaError::Unsupported)?;
        if quantifier.minimum > MAX_NFA_REPEAT
            || quantifier
                .maximum
                .is_some_and(|maximum| maximum > MAX_NFA_REPEAT)
        {
            return Err(NfaError::Budget);
        }
        let mut result = if quantifier.minimum == 0 {
            self.empty_fragment()?
        } else {
            base.clone()
        };
        let mut copies = Vec::new();
        for _ in 1..quantifier.minimum {
            copies.push(self.clone_fragment(&base)?);
        }
        let unbounded = match quantifier.maximum {
            Some(maximum) => {
                for _ in quantifier.minimum..maximum {
                    let clone = self.clone_fragment(&base)?;
                    copies.push(self.optional(clone)?);
                }
                None
            }
            None => {
                let clone = self.clone_fragment(&base)?;
                Some(self.star(clone)?)
            }
        };
        for copy in copies {
            result = self.concatenate(vec![result, copy])?;
        }
        if let Some(unbounded) = unbounded {
            result = self.concatenate(vec![result, unbounded])?;
        }
        Ok(result)
    }

    fn new_state(&mut self) -> Result<usize, NfaError> {
        if self.states.len() >= MAX_NFA_STATES {
            return Err(NfaError::Budget);
        }
        let state = self.states.len();
        self.states.push(NfaState::default());
        Ok(state)
    }

    fn empty_fragment(&mut self) -> Result<NfaFragment, NfaError> {
        let start = self.new_state()?;
        let end = self.new_state()?;
        self.states[start].epsilon.push(end);
        Ok(NfaFragment {
            start,
            end,
            states: vec![start, end],
        })
    }

    fn character_fragment(&mut self, set: CharacterSet) -> Result<NfaFragment, NfaError> {
        let start = self.new_state()?;
        let end = self.new_state()?;
        self.states[start].transitions.push((set, end));
        Ok(NfaFragment {
            start,
            end,
            states: vec![start, end],
        })
    }

    fn concatenate(&mut self, mut fragments: Vec<NfaFragment>) -> Result<NfaFragment, NfaError> {
        let Some(mut result) = fragments.pop() else {
            return self.empty_fragment();
        };
        while let Some(next) = fragments.pop() {
            self.states[next.end].epsilon.push(result.start);
            result.start = next.start;
            result.states.extend(next.states);
        }
        Ok(result)
    }

    fn alternate(&mut self, fragments: Vec<NfaFragment>) -> Result<NfaFragment, NfaError> {
        if fragments.len() == 1 {
            return Ok(fragments
                .into_iter()
                .next()
                .expect("one alternative exists"));
        }
        let start = self.new_state()?;
        let end = self.new_state()?;
        let mut states = vec![start, end];
        for fragment in fragments {
            self.states[start].epsilon.push(fragment.start);
            self.states[fragment.end].epsilon.push(end);
            states.extend(fragment.states);
        }
        Ok(NfaFragment { start, end, states })
    }

    fn optional(&mut self, inner: NfaFragment) -> Result<NfaFragment, NfaError> {
        let start = self.new_state()?;
        let end = self.new_state()?;
        self.states[start].epsilon.extend([end, inner.start]);
        self.states[inner.end].epsilon.push(end);
        let mut states = vec![start, end];
        states.extend(inner.states);
        Ok(NfaFragment { start, end, states })
    }

    fn star(&mut self, inner: NfaFragment) -> Result<NfaFragment, NfaError> {
        let start = self.new_state()?;
        let end = self.new_state()?;
        self.states[start].epsilon.extend([end, inner.start]);
        self.states[inner.end].epsilon.extend([end, inner.start]);
        let mut states = vec![start, end];
        states.extend(inner.states);
        Ok(NfaFragment { start, end, states })
    }

    fn clone_fragment(&mut self, fragment: &NfaFragment) -> Result<NfaFragment, NfaError> {
        let mut remap = vec![usize::MAX; self.states.len()];
        for &old in &fragment.states {
            remap[old] = self.new_state()?;
        }
        for &old in &fragment.states {
            let new = remap[old];
            let old_state = self.states[old].clone();
            for target in old_state.epsilon {
                let Some(mapped) = remap
                    .get(target)
                    .copied()
                    .filter(|&mapped| mapped != usize::MAX)
                else {
                    return Err(NfaError::Unsupported);
                };
                self.states[new].epsilon.push(mapped);
            }
            for (set, target) in old_state.transitions {
                let Some(mapped) = remap
                    .get(target)
                    .copied()
                    .filter(|&mapped| mapped != usize::MAX)
                else {
                    return Err(NfaError::Unsupported);
                };
                self.states[new].transitions.push((set, mapped));
            }
        }
        Ok(NfaFragment {
            start: remap[fragment.start],
            end: remap[fragment.end],
            states: fragment.states.iter().map(|state| remap[*state]).collect(),
        })
    }
}

#[derive(Debug, Clone)]
struct BranchFrame {
    owner: usize,
    sequence: usize,
    group_start: Option<usize>,
    last_atom: Option<usize>,
    restore_flags: Option<RegexFlags>,
}

#[derive(Debug, Clone, Copy)]
struct Quantifier {
    minimum: u32,
    maximum: Option<u32>,
    possessive: bool,
}

#[derive(Debug)]
struct ClassAtom {
    start: usize,
    end: usize,
    value: Option<char>,
    set: Option<CharacterSet>,
    kind: NormalizedKind,
    construct: Option<String>,
    backspace: bool,
    incomplete: Option<&'static str>,
}

#[derive(Debug)]
struct EscapeValue {
    end: usize,
    anchor: bool,
    construct: Option<String>,
    first_set: Option<CharacterSet>,
    incomplete: Option<&'static str>,
    backspace: bool,
}

/// Return facts for a string-literal node or a call node in the Python AST.
/// A string is analyzed only when it is the first positional argument or the
/// `pattern` keyword of a statically named `re` API call.
pub(crate) fn embedded_facts(node: Node<'_>, source: &str) -> Vec<EmbeddedLeafFact> {
    if node.kind() == "call" {
        return dynamic_pattern_fact(node, source).into_iter().collect();
    }
    if !matches!(node.kind(), "string" | "concatenated_string")
        || (node.kind() == "string"
            && node
                .parent()
                .is_some_and(|parent| parent.kind() == "concatenated_string"))
    {
        return Vec::new();
    }
    let Some((call, api)) = pattern_call(node, source) else {
        return Vec::new();
    };
    let decoded = match decode_regex_pattern_string(node, source) {
        Ok(decoded) => decoded,
        Err(reason) => return vec![incomplete_fact(node, source, reason)],
    };
    let flags = call_flags(call, api, source);
    let facts = RegexParser::new(&decoded, flags, api).parse();
    facts_to_embedded(facts, &decoded, source)
}

pub(crate) fn module_assigned_facts(root: Node<'_>, source: &str) -> Vec<EmbeddedLeafFact> {
    assert_eq!(root.kind(), "module");
    let mut assignments = HashMap::<String, (usize, Option<Node<'_>>)>::new();
    let mut calls = Vec::new();
    let mut pending = vec![root];
    while let Some(node) = pending.pop() {
        if module_level_statement(node)
            .is_some_and(|statement| statement.kind() == "expression_statement")
            && node.kind() == "assignment"
            && let (Some(left), Some(right)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            )
            && left.kind() == "identifier"
        {
            let candidate =
                matches!(right.kind(), "string" | "concatenated_string").then_some(right);
            let entry = assignments
                .entry(node_text(left, source).to_owned())
                .or_insert((0, None));
            entry.0 += 1;
            entry.1 = (entry.0 == 1).then_some(candidate).flatten();
        }
        if node.kind() == "call"
            && let Some(function) = node.child_by_field_name("function")
            && let Some(api) = recognized_api(function, source)
            && let Some(arguments) = node.child_by_field_name("arguments")
            && let Some(pattern) = selected_pattern_argument(arguments, source)
            && pattern.kind() == "identifier"
        {
            calls.push((node, pattern, api, node_text(pattern, source).to_owned()));
        }
        let mut cursor = node.walk();
        let children = node.named_children(&mut cursor).collect::<Vec<_>>();
        pending.extend(children.into_iter().rev());
    }

    let mut facts = Vec::new();
    for (call, pattern, api, name) in calls {
        let resolved = assignments
            .get(&name)
            .and_then(|(writes, candidate)| {
                (*writes == 1)
                    .then_some(*candidate)
                    .flatten()
                    .filter(|candidate| candidate.end_byte() < call.start_byte())
            })
            .filter(|_| module_pattern_binding_is_visible(&name, pattern, source));
        let Some(selected) = resolved else {
            let range = node_range(pattern, source);
            facts.push(EmbeddedLeafFact {
                kind: NormalizedKind::RegexIncomplete,
                range,
                parent: None,
                construct: Some(format!("dynamic-pattern:{}", api.flags_position)),
                occurrence_role: None,
            });
            continue;
        };
        let decoded = match decode_regex_pattern_string(selected, source) {
            Ok(decoded) => decoded,
            Err(reason) => {
                facts.push(incomplete_fact(selected, source, reason));
                continue;
            }
        };
        let flags = call_flags(call, api, source);
        let mut parsed = facts_to_embedded(
            RegexParser::new(&decoded, flags, api).parse(),
            &decoded,
            source,
        );
        let base = facts.len();
        for fact in &mut parsed {
            fact.parent = fact.parent.map(|parent| base + parent);
        }
        facts.extend(parsed);
    }
    facts
}

fn module_pattern_binding_is_visible(name: &str, reference: Node<'_>, source: &str) -> bool {
    if python_comprehension_binds_name_at(name, reference, source)
        || matches!(
            python_name_resolution_at(name, reference, source),
            PythonLexicalNameResolution::Local | PythonLexicalNameResolution::Nonlocal
        )
    {
        return false;
    }

    let mut current = reference;
    while let Some(parent) = current.parent() {
        match parent.kind() {
            "function_definition" | "lambda" => break,
            "class_definition" => {
                return python_module_or_class_scope_binds_name_bounded(
                    parent,
                    name,
                    source,
                    || true,
                ) == Some(false);
            }
            _ => current = parent,
        }
    }
    true
}

fn module_level_statement<'tree>(node: Node<'tree>) -> Option<Node<'tree>> {
    let mut current = node;
    loop {
        let parent = current.parent()?;
        if parent.kind() == "module" {
            return Some(current);
        }
        current = parent;
    }
}

fn incomplete_fact(node: Node<'_>, source: &str, reason: &str) -> EmbeddedLeafFact {
    let range = node_range(node, source);
    EmbeddedLeafFact {
        kind: NormalizedKind::RegexIncomplete,
        range,
        parent: None,
        construct: Some(reason.to_owned()),
        occurrence_role: None,
    }
}

fn dynamic_pattern_fact(node: Node<'_>, source: &str) -> Option<EmbeddedLeafFact> {
    let function = node.child_by_field_name("function")?;
    let api = recognized_api(function, source)?;
    let arguments = node.child_by_field_name("arguments")?;
    let pattern = selected_pattern_argument(arguments, source)?;
    if matches!(pattern.kind(), "string" | "concatenated_string") {
        return None;
    }
    if pattern.kind() == "identifier" {
        return None;
    }
    let range = node_range(pattern, source);
    Some(EmbeddedLeafFact {
        kind: NormalizedKind::RegexIncomplete,
        range,
        parent: None,
        construct: Some(format!("dynamic-pattern:{}", api.flags_position)),
        occurrence_role: None,
    })
}

fn pattern_call<'tree>(node: Node<'tree>, source: &str) -> Option<(Node<'tree>, Api)> {
    let argument = node.parent()?;
    let (arguments, is_pattern_keyword) = match argument.kind() {
        "keyword_argument" => {
            let name = argument.child_by_field_name("name")?;
            let value = argument.child_by_field_name("value")?;
            (
                argument.parent()?,
                value.id() == node.id() && node_text(name, source) == "pattern",
            )
        }
        "argument_list" => (argument, false),
        _ => return None,
    };
    if arguments.kind() != "argument_list" {
        return None;
    }
    let call = arguments.parent()?;
    if call.kind() != "call" {
        return None;
    }
    let function = call.child_by_field_name("function")?;
    let api = recognized_api(function, source)?;
    let selected = if is_pattern_keyword {
        true
    } else {
        selected_pattern_argument(arguments, source)
            .is_some_and(|pattern| pattern.id() == node.id())
    };
    selected.then_some((call, api))
}

fn selected_pattern_argument<'tree>(arguments: Node<'tree>, source: &str) -> Option<Node<'tree>> {
    let mut positional = 0usize;
    let mut cursor = arguments.walk();
    for argument in arguments.named_children(&mut cursor) {
        match argument.kind() {
            "comment" => {}
            "keyword_argument" => {
                let name = argument.child_by_field_name("name")?;
                if node_text(name, source) == "pattern" {
                    return argument.child_by_field_name("value");
                }
            }
            _ => {
                if positional == 0 {
                    return Some(argument);
                }
                positional += 1;
            }
        }
    }
    None
}

fn recognized_api(function: Node<'_>, source: &str) -> Option<Api> {
    let path = python_static_attribute_path(function)?;
    if path.len() != 2 || node_text(path[0], source) != "re" {
        return None;
    }
    let (flags_position, scans_from_each_offset) = match node_text(path[1], source) {
        "compile" => (1, false),
        "search" | "findall" | "finditer" => (2, true),
        "match" | "fullmatch" => (2, false),
        "split" => (3, true),
        "sub" | "subn" => (4, true),
        _ => return None,
    };
    Some(Api {
        flags_position,
        scans_from_each_offset,
    })
}

fn call_flags(call: Node<'_>, api: Api, source: &str) -> RegexFlags {
    let mut flags_node = None;
    if let Some(arguments) = call.child_by_field_name("arguments") {
        let mut positional = 0usize;
        let mut cursor = arguments.walk();
        for argument in arguments.named_children(&mut cursor) {
            match argument.kind() {
                "comment" => {}
                "keyword_argument" => {
                    if argument
                        .child_by_field_name("name")
                        .is_some_and(|name| node_text(name, source) == "flags")
                    {
                        flags_node = argument.child_by_field_name("value");
                    }
                }
                _ => {
                    if positional == api.flags_position {
                        flags_node = Some(argument);
                    }
                    positional += 1;
                }
            }
        }
    }
    let Some(flags_node) = flags_node else {
        return RegexFlags {
            dotall: false,
            multiline: false,
            ignorecase: false,
            ascii: false,
            verbose: false,
            complete: true,
        };
    };
    let mut pending = vec![flags_node];
    let mut flags = RegexFlags {
        dotall: false,
        multiline: false,
        ignorecase: false,
        ascii: false,
        verbose: false,
        complete: true,
    };
    while let Some(node) = pending.pop() {
        match node.kind() {
            "integer" => {
                let text = node_text(node, source).replace('_', "");
                match python_integer_value(&text) {
                    Some(value) => {
                        flags.ignorecase |= value & 2 != 0;
                        flags.dotall |= value & 16 != 0;
                        flags.multiline |= value & 8 != 0;
                        flags.ascii |= value & 256 != 0;
                        flags.complete &=
                            value & !(2 | 8 | 16 | 32 | 256) == 0 && value & (64 | 128) == 0;
                    }
                    None => flags.complete = false,
                }
            }
            "attribute" | "identifier" => {
                let path = python_static_attribute_path(node);
                let name = path.as_ref().and_then(|path| {
                    (path.len() >= 2
                        && node_text(path[0], source) == "re"
                        && path[1..path.len() - 1]
                            .iter()
                            .all(|part| node_text(*part, source) == "re"))
                    .then(|| node_text(*path.last().expect("flag path is nonempty"), source))
                });
                match name {
                    Some("S" | "DOTALL") => flags.dotall = true,
                    Some("M" | "MULTILINE") => flags.multiline = true,
                    Some("I" | "IGNORECASE") => flags.ignorecase = true,
                    Some("A" | "ASCII") => flags.ascii = true,
                    Some("X" | "VERBOSE") => flags.verbose = true,
                    Some("U" | "UNICODE") => {}
                    Some("DEBUG") => flags.complete = false,
                    _ => flags.complete = false,
                }
            }
            "binary_operator" => {
                if let (Some(left), Some(right)) = (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                ) {
                    pending.push(right);
                    pending.push(left);
                } else {
                    flags.complete = false;
                }
            }
            _ => flags.complete = false,
        }
    }
    flags
}

fn parse_inline_flags(
    chars: &[char],
    mut index: usize,
    mut flags: RegexFlags,
) -> Option<(usize, RegexFlags)> {
    let mut enabled = true;
    let mut saw_flag = false;
    let mut ascii_mode = None;
    while let Some(character) = chars.get(index).copied() {
        match character {
            ')' | ':' if saw_flag => {
                if ascii_mode == Some((true, true)) {
                    return None;
                }
                return Some((index, flags));
            }
            '-' if enabled && saw_flag => enabled = false,
            'i' | 'm' | 's' | 'x' | 'a' | 'u' => {
                saw_flag = true;
                match character {
                    'i' => flags.ignorecase = enabled,
                    'm' => flags.multiline = enabled,
                    's' => flags.dotall = enabled,
                    'x' => flags.verbose = enabled,
                    'a' => {
                        flags.ascii = enabled;
                        ascii_mode =
                            Some((enabled, ascii_mode.is_some_and(|(_, unicode)| unicode)));
                    }
                    'u' => {
                        flags.ascii = !enabled;
                        ascii_mode = Some((ascii_mode.is_some_and(|(ascii, _)| ascii), enabled));
                    }
                    _ => unreachable!("inline flag arm includes only Python regex flags"),
                }
            }
            _ => return None,
        }
        index += 1;
    }
    None
}

fn python_integer_value(text: &str) -> Option<u64> {
    let (radix, digits) =
        if let Some(digits) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
            (16, digits)
        } else if let Some(digits) = text.strip_prefix("0o").or_else(|| text.strip_prefix("0O")) {
            (8, digits)
        } else if let Some(digits) = text.strip_prefix("0b").or_else(|| text.strip_prefix("0B")) {
            (2, digits)
        } else {
            (10, text)
        };
    u64::from_str_radix(digits, radix).ok()
}

fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    node.utf8_text(source.as_bytes())
        .expect("tree-sitter node ranges are valid UTF-8 source")
}

fn node_range(node: Node<'_>, source: &str) -> Range {
    let line_starts = compute_line_starts(source);
    let start_byte = node.start_byte();
    let end_byte = node.end_byte();
    Range {
        start_byte,
        end_byte,
        start_line: find_line_index_for_offset(&line_starts, start_byte) + 1,
        end_line: find_line_index_for_offset(
            &line_starts,
            end_byte.saturating_sub(1).max(start_byte),
        ) + 1,
    }
}

fn decode_python_string(node: Node<'_>, source: &str) -> Result<DecodedValue, &'static str> {
    let decoded = decode_string_literal(node, source)?;
    if decoded.is_bytes {
        return Err("non-text-or-formatted-string");
    }
    Ok(decoded)
}

fn decode_regex_pattern_string(node: Node<'_>, source: &str) -> Result<DecodedValue, &'static str> {
    decode_string_literal(node, source)
}

fn decode_string_literal(node: Node<'_>, source: &str) -> Result<DecodedValue, &'static str> {
    let mut strings = Vec::new();
    if node.kind() == "string" {
        strings.push(node);
    } else {
        let mut stack = vec![node];
        while let Some(current) = stack.pop() {
            if current.kind() == "string" {
                strings.push(current);
                continue;
            }
            let mut children = Vec::new();
            let mut cursor = current.walk();
            for child in current.named_children(&mut cursor) {
                if child.kind() == "concatenated_string" || child.kind() == "string" {
                    children.push(child);
                } else {
                    return Err("non-literal-string-segment");
                }
            }
            for child in children.into_iter().rev() {
                stack.push(child);
            }
        }
    }
    if strings.is_empty() {
        return Err("empty-concatenated-string");
    }
    let mut value = String::new();
    let mut chars = Vec::new();
    let mut byte_string = None;
    for string in strings {
        let is_bytes = decode_string_segment(string, source, &mut value, &mut chars)?;
        if byte_string.is_some_and(|previous| previous != is_bytes) {
            return Err("mixed-bytes-and-text-concatenation");
        }
        byte_string = Some(is_bytes);
        if chars.len() > MAX_PATTERN_CHARS {
            return Err("pattern-character-budget");
        }
    }
    Ok(DecodedValue {
        value,
        chars,
        source_range: node_range(node, source),
        is_bytes: byte_string.expect("non-empty literal expression has a string segment"),
    })
}

/// Decode the value of a tree-sitter-selected Python string expression.
///
/// Callers must select the literal from syntax before invoking this helper;
/// this function classifies only the selected expression's value.
pub fn decode_python_string_value(node: Node<'_>, source: &str) -> Result<String, &'static str> {
    decode_python_string(node, source).map(|decoded| decoded.value)
}

/// Decode each literal segment in a selected Python f-string, omitting its
/// interpolation expressions. The parse tree chooses the segments; this
/// helper reads only their decoded values.
pub fn decode_python_fstring_literal_segments(
    node: Node<'_>,
    source: &str,
) -> Result<Vec<String>, &'static str> {
    if node.kind() != "string" {
        return Err("not-a-python-fstring");
    }
    let mut start_token = None;
    let mut segments: Vec<Vec<Node<'_>>> = vec![Vec::new()];
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "string_start" if start_token.is_none() => start_token = Some(child),
            "string_start" => return Err("duplicate-fstring-start"),
            "string_end" => break,
            "interpolation" => segments.push(Vec::new()),
            "string_content" | "escape_sequence" => segments
                .last_mut()
                .expect("f-string literal segments retain a current segment")
                .push(child),
            _ => return Err("unsupported-fstring-prefix-node"),
        }
    }
    let start_token = start_token.ok_or("missing-fstring-start")?;
    let prefix = string_prefix(node_text(start_token, source));
    if !prefix.contains('f')
        || prefix
            .chars()
            .any(|character| !matches!(character, 'f' | 'r'))
        || prefix.matches('f').count() != 1
        || prefix.matches('r').count() > 1
    {
        return Err("unsupported-fstring-prefix");
    }
    let raw = prefix.contains('r');
    segments
        .into_iter()
        .map(|parts| {
            let mut value = String::new();
            let mut mapped = Vec::new();
            for part in parts {
                if raw {
                    append_mapped_text(
                        node_text(part, source),
                        part.start_byte(),
                        part.end_byte(),
                        &mut value,
                        &mut mapped,
                    )?;
                } else if part.kind() == "escape_sequence" {
                    decode_literal_escape(
                        node_text(part, source),
                        part.start_byte(),
                        &mut value,
                        &mut mapped,
                        false,
                    )?;
                } else {
                    decode_string_content(part, source, &mut value, &mut mapped, false)?;
                }
            }
            Ok(value.replace("{{", "{").replace("}}", "}"))
        })
        .collect()
}

fn decode_string_segment(
    node: Node<'_>,
    source: &str,
    value: &mut String,
    output: &mut Vec<MappedChar>,
) -> Result<bool, &'static str> {
    let mut start_token = None;
    let mut body = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "string_start" => start_token = Some(child),
            "string_end" => {}
            "string_content" | "escape_sequence" => body.push(child),
            "interpolation" => return Err("formatted-string-interpolation"),
            _ => return Err("unsupported-string-segment"),
        }
    }
    let start_token = start_token.ok_or("missing-string-start")?;
    let prefix = string_prefix(node_text(start_token, source));
    if prefix.contains('f') || prefix.contains('t') {
        return Err("non-text-or-formatted-string");
    }
    if prefix
        .chars()
        .any(|prefix| !matches!(prefix, 'r' | 'u' | 'b'))
        || prefix.matches('r').count() > 1
        || prefix.matches('u').count() > 1
        || prefix.matches('b').count() > 1
        || (prefix.contains('r') && prefix.contains('u'))
        || (prefix.contains('b') && prefix.contains('u'))
    {
        return Err("unsupported-string-prefix");
    }
    let is_bytes = prefix.contains('b');
    if is_bytes && !node_text(node, source).is_ascii() {
        return Err("non-ascii-byte-literal");
    }
    let raw = prefix.contains('r');
    for part in body {
        let raw_text = node_text(part, source);
        if raw && matches!(part.kind(), "escape_sequence" | "string_content") {
            append_mapped_text(raw_text, part.start_byte(), part.end_byte(), value, output)?;
        } else if !raw && part.kind() == "escape_sequence" {
            decode_literal_escape(raw_text, part.start_byte(), value, output, is_bytes)?;
        } else if !raw && part.kind() == "string_content" {
            decode_string_content(part, source, value, output, is_bytes)?;
        } else {
            append_mapped_text(raw_text, part.start_byte(), part.end_byte(), value, output)?;
        }
        if output.len() > MAX_PATTERN_CHARS {
            return Err("pattern-character-budget");
        }
    }
    if is_bytes && value.chars().any(|character| character as u32 > 0xff) {
        return Err("byte-pattern-value-out-of-range");
    }
    Ok(is_bytes)
}

fn string_prefix(start: &str) -> String {
    start
        .chars()
        .take_while(|character| !matches!(character, '\'' | '"'))
        .map(|character| character.to_ascii_lowercase())
        .collect()
}

fn append_mapped_text(
    text: &str,
    source_start: usize,
    source_end: usize,
    output_text: &mut String,
    output: &mut Vec<MappedChar>,
) -> Result<(), &'static str> {
    for (offset, value) in text.char_indices() {
        if output.len() >= MAX_PATTERN_CHARS {
            return Err("pattern-character-budget");
        }
        let start = source_start + offset;
        let end = start + value.len_utf8();
        output_text.push(value);
        output.push(MappedChar {
            source_start: start,
            source_end: end,
        });
    }
    debug_assert_eq!(source_start + text.len(), source_end);
    Ok(())
}

fn decode_string_content(
    node: Node<'_>,
    source: &str,
    output_text: &mut String,
    output: &mut Vec<MappedChar>,
    bytes: bool,
) -> Result<(), &'static str> {
    let mut position = node.start_byte();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        assert_eq!(child.kind(), "escape_sequence");
        assert!(position <= child.start_byte());
        if position < child.start_byte() {
            let plain = source
                .get(position..child.start_byte())
                .expect("tree-sitter string ranges are valid UTF-8 source");
            append_mapped_text(plain, position, child.start_byte(), output_text, output)?;
        }
        decode_literal_escape(
            node_text(child, source),
            child.start_byte(),
            output_text,
            output,
            bytes,
        )?;
        position = child.end_byte();
    }
    assert!(position <= node.end_byte());
    if position < node.end_byte() {
        let plain = source
            .get(position..node.end_byte())
            .expect("tree-sitter string ranges are valid UTF-8 source");
        append_mapped_text(plain, position, node.end_byte(), output_text, output)?;
    }
    Ok(())
}

fn decode_literal_escape(
    raw: &str,
    source_start: usize,
    output_text: &mut String,
    output: &mut Vec<MappedChar>,
    bytes: bool,
) -> Result<(), &'static str> {
    let chars: Vec<char> = raw.chars().collect();
    if chars.first() != Some(&'\\') || chars.len() < 2 {
        return Err("malformed-literal-escape");
    }
    if bytes && matches!(chars.get(1), Some('u' | 'U' | 'N')) {
        return append_mapped_text(
            raw,
            source_start,
            source_start + raw.len(),
            output_text,
            output,
        );
    }
    let escaped = chars[1];
    let replacement = match escaped {
        '\n' => None,
        '\r' if chars.get(2) == Some(&'\n') => None,
        '\r' => Some('\r'),
        '\\' => Some('\\'),
        '\'' => Some('\''),
        '"' => Some('"'),
        'a' => Some('\u{7}'),
        'b' => Some('\u{8}'),
        'f' => Some('\u{c}'),
        'n' => Some('\n'),
        'r' => Some('\r'),
        't' => Some('\t'),
        'v' => Some('\u{b}'),
        'x' => Some(
            char::from_u32(hex_value(&chars, 2, 2).ok_or("invalid-hex-escape")?)
                .ok_or("invalid-hex-scalar")?,
        ),
        'u' => Some(
            char::from_u32(hex_value(&chars, 2, 4).ok_or("invalid-unicode-escape")?)
                .ok_or("invalid-unicode-scalar")?,
        ),
        'U' => Some(
            char::from_u32(hex_value(&chars, 2, 8).ok_or("invalid-unicode-escape")?)
                .ok_or("invalid-unicode-scalar")?,
        ),
        'N' => return Err("named-unicode-escape"),
        '0'..='7' => {
            let mut value = (escaped as u32) - ('0' as u32);
            let mut digits = 1usize;
            while digits < 3 {
                let Some(digit @ '0'..='7') = chars.get(1 + digits).copied() else {
                    break;
                };
                value = value * 8 + (digit as u32 - '0' as u32);
                digits += 1;
            }
            Some(char::from_u32(value).ok_or("invalid-octal-scalar")?)
        }
        // Python preserves unrecognized escapes, including punctuation; the
        // regex parser must receive the backslash to classify them correctly.
        other => {
            if output.len().saturating_add(2) > MAX_PATTERN_CHARS {
                return Err("pattern-character-budget");
            }
            output_text.push('\\');
            output.push(MappedChar {
                source_start,
                source_end: source_start + 1,
            });
            output_text.push(other);
            output.push(MappedChar {
                source_start: source_start + 1,
                source_end: source_start + 1 + other.len_utf8(),
            });
            return Ok(());
        }
    };
    if let Some(replacement) = replacement {
        if output.len() >= MAX_PATTERN_CHARS {
            return Err("pattern-character-budget");
        }
        output_text.push(replacement);
        output.push(MappedChar {
            source_start,
            source_end: source_start + raw.len(),
        });
    }
    Ok(())
}

fn hex_value(chars: &[char], start: usize, digits: usize) -> Option<u32> {
    chars
        .get(start..start + digits)?
        .iter()
        .try_fold(0u32, |value, digit| {
            digit.to_digit(16).map(|digit| value * 16 + digit)
        })
}

struct RegexParser<'a> {
    decoded: &'a DecodedValue,
    flags: RegexFlags,
    api: Api,
    chars: Vec<char>,
    index: usize,
    facts: Vec<Fact>,
    frames: Vec<BranchFrame>,
    pending_risks: Vec<(NormalizedKind, usize, usize, usize, String)>,
    verbose_comments: Vec<(usize, usize)>,
    incomplete: Option<(usize, usize, String)>,
    exceeded: bool,
}

impl<'a> RegexParser<'a> {
    fn new(decoded: &'a DecodedValue, flags: RegexFlags, api: Api) -> Self {
        Self {
            decoded,
            flags,
            api,
            chars: decoded.value.chars().collect(),
            index: 0,
            facts: Vec::new(),
            frames: Vec::new(),
            pending_risks: Vec::new(),
            verbose_comments: Vec::new(),
            incomplete: None,
            exceeded: false,
        }
    }

    fn parse(mut self) -> Vec<Fact> {
        let length = self.chars.len();
        if !self.flags.complete {
            self.mark_incomplete(0, length, "unsupported-regex-flags");
        }
        let pattern = self.add_fact(
            NormalizedKind::RegexPattern,
            0,
            length,
            None,
            Some(self.decoded.value.clone()),
            None,
        );
        let sequence = self.add_fact(
            NormalizedKind::RegexSequence,
            0,
            length,
            Some(pattern),
            None,
            None,
        );
        self.frames.push(BranchFrame {
            owner: pattern,
            sequence,
            group_start: None,
            last_atom: None,
            restore_flags: None,
        });

        while self.index < length {
            if self.exceeded {
                break;
            }
            if self.flags.verbose {
                if matches!(
                    self.chars[self.index],
                    ' ' | '\t' | '\n' | '\r' | '\x0c' | '\x0b'
                ) {
                    self.index += 1;
                    continue;
                }
                if self.chars[self.index] == '#' {
                    let start = self.index;
                    while self.index < length && self.chars[self.index] != '\n' {
                        self.index += 1;
                    }
                    self.verbose_comments.push((start, self.index));
                    continue;
                }
            }
            if self.facts.len() >= MAX_PATTERN_FACTS - 2 {
                self.exceeded = true;
                break;
            }
            match self.chars[self.index] {
                '(' => self.open_group(),
                ')' => self.close_group(),
                '|' => self.alternation(),
                '[' => self.character_class(),
                '\\' => self.escape(false),
                '.' => self.wildcard(),
                '^' | '$' => self.anchor(),
                '*' | '+' | '?' => self.quantifier(),
                '{' if self.braced_quantifier_end().is_some() => self.quantifier(),
                _ => self.literal(),
            }
        }

        if self.frames.len() > 1 {
            let start = self
                .frames
                .last()
                .and_then(|frame| frame.group_start)
                .unwrap_or(length);
            self.mark_incomplete(start, length, "unclosed-group");
            for frame in self.frames.iter().skip(1) {
                self.facts[frame.owner].end = length;
                self.facts[frame.sequence].end = length;
            }
        }
        if self.exceeded {
            return self.budget_result();
        }
        self.compute_minimum_widths();
        self.classify_verbose_comment_duplicates();
        self.classify_unmatchable_anchors();
        self.classify_hostname();
        self.classify_bad_tag();
        self.classify_polynomial_redos();
        self.classify_redos();
        self.append_pending_facts();
        if self.exceeded {
            return self.budget_result();
        }
        self.facts
    }

    fn classify_verbose_comment_duplicates(&mut self) {
        if self.verbose_comments.is_empty()
            || !self
                .facts
                .iter()
                .any(|fact| fact.kind == NormalizedKind::RegexCharacterClass)
        {
            return;
        }
        let mut positions = HashMap::<char, Vec<usize>>::new();
        for &(start, end) in &self.verbose_comments {
            for (offset, character) in self.chars[start..end].iter().copied().enumerate() {
                if !character.is_whitespace() {
                    positions.entry(character).or_default().push(start + offset);
                }
            }
        }
        let mut duplicates = positions
            .into_iter()
            .filter_map(|(character, offsets)| {
                (offsets.len() > 1).then(|| (character, offsets[0], offsets[1]))
            })
            .collect::<Vec<_>>();
        duplicates.sort_unstable_by_key(|(character, _, _)| *character);
        if let Some((character, _, _)) = duplicates.first() {
            self.pending_risks.push((
                NormalizedKind::RegexRiskDuplicateClassCharacter,
                0,
                0,
                self.chars.len(),
                format!("duplicate-verbose-comment-character:{character}"),
            ));
        }
    }

    fn budget_result(&self) -> Vec<Fact> {
        let length = self.chars.len();
        vec![
            self.facts[0].clone(),
            self.facts[1].clone(),
            Fact {
                kind: NormalizedKind::RegexIncomplete,
                start: 0,
                end: length,
                parent: Some(0),
                construct: Some("regex-fact-budget".to_owned()),
                first_set: None,
                quantifier: None,
                minimum_width: None,
            },
        ]
    }

    fn add_fact(
        &mut self,
        kind: NormalizedKind,
        start: usize,
        end: usize,
        parent: Option<usize>,
        construct: Option<String>,
        first_set: Option<CharacterSet>,
    ) -> usize {
        let id = self.facts.len();
        assert!(
            id < MAX_PATTERN_FACTS,
            "regex fact budget checked before insertion"
        );
        let minimum_width = match kind {
            NormalizedKind::RegexLiteral
            | NormalizedKind::RegexWildcard
            | NormalizedKind::RegexCharacterClass
            | NormalizedKind::RegexCharacterRange
            | NormalizedKind::RegexEscape => Some(1),
            NormalizedKind::RegexAnchor => Some(0),
            _ => None,
        };
        self.facts.push(Fact {
            kind,
            start,
            end,
            parent,
            construct,
            first_set,
            quantifier: None,
            minimum_width,
        });
        id
    }

    fn mark_incomplete(&mut self, start: usize, end: usize, reason: &str) {
        if self.incomplete.is_none() {
            self.incomplete = Some((start, end, reason.to_owned()));
        }
    }

    fn current_sequence(&self) -> usize {
        self.frames
            .last()
            .expect("regex parser always has an outer frame")
            .sequence
    }

    fn record_atom(&mut self, fact: usize) {
        self.frames
            .last_mut()
            .expect("regex parser always has an outer frame")
            .last_atom = Some(fact);
    }

    fn add_atom(
        &mut self,
        kind: NormalizedKind,
        start: usize,
        end: usize,
        construct: Option<String>,
        first_set: Option<CharacterSet>,
    ) -> usize {
        let fact = self.add_fact(
            kind,
            start,
            end,
            Some(self.current_sequence()),
            construct,
            first_set,
        );
        self.record_atom(fact);
        fact
    }

    fn open_group(&mut self) {
        let start = self.index;
        let mut content_start = start + 1;
        let mut group_type = "capturing";
        let mut missing_special_group_end = None;
        let mut restore_flags = None;
        if self.chars.get(content_start) == Some(&'?') {
            match (
                self.chars.get(content_start + 1),
                self.chars.get(content_start + 2),
            ) {
                (Some(':'), _) => {
                    group_type = "noncapturing";
                    content_start += 2;
                }
                (Some('P'), Some('<')) => {
                    group_type = "named-capturing";
                    let mut close = content_start + 3;
                    while close < self.chars.len() && self.chars[close] != '>' {
                        close += 1;
                    }
                    if close == self.chars.len() {
                        self.mark_incomplete(start, self.chars.len(), "unclosed-group-name");
                        self.index = self.chars.len();
                        return;
                    }
                    content_start = close + 1;
                }
                (Some('#'), _) => {
                    let mut close = content_start + 2;
                    while close < self.chars.len() && self.chars[close] != ')' {
                        close += 1;
                    }
                    if close == self.chars.len() {
                        self.mark_incomplete(start, close, "unclosed-comment-group");
                        self.index = close;
                        return;
                    }
                    let group = self.add_fact(
                        NormalizedKind::RegexGroup,
                        start,
                        close + 1,
                        Some(self.current_sequence()),
                        Some("comment".to_owned()),
                        None,
                    );
                    self.facts[group].minimum_width = Some(0);
                    self.index = close + 1;
                    self.record_atom(group);
                    return;
                }
                (Some('='), _) => {
                    group_type = "lookahead-positive";
                    content_start += 2;
                }
                (Some('!'), _) => {
                    group_type = "lookahead-negative";
                    content_start += 2;
                }
                (Some('<'), Some('=')) => {
                    group_type = "lookbehind-positive";
                    content_start += 3;
                }
                (Some('<'), Some('!')) => {
                    group_type = "lookbehind-negative";
                    content_start += 3;
                }
                (Some('i' | 'm' | 's' | 'x' | 'a' | 'u' | '-'), _) => {
                    let flags_start = content_start + 1;
                    let Some((delimiter, flags)) =
                        parse_inline_flags(&self.chars, flags_start, self.flags)
                    else {
                        self.mark_incomplete(
                            start,
                            (start + 3).min(self.chars.len()),
                            "invalid-inline-flags",
                        );
                        self.index = (start + 3).min(self.chars.len());
                        return;
                    };
                    match self.chars[delimiter] {
                        ')' => {
                            self.flags = flags;
                            self.index = delimiter + 1;
                            return;
                        }
                        ':' => {
                            group_type = "scoped-flags";
                            restore_flags = Some(self.flags);
                            self.flags = flags;
                            content_start = delimiter + 1;
                        }
                        _ => unreachable!("inline flags stop at a group delimiter"),
                    }
                }
                _ => {
                    self.mark_incomplete(
                        start,
                        (start + 3).min(self.chars.len()),
                        "unsupported-special-group",
                    );
                    content_start += 1;
                }
            }
        } else if self.chars.get(content_start) == Some(&'P')
            && self.chars.get(content_start + 1) == Some(&'<')
        {
            let mut close = content_start + 2;
            while close < self.chars.len() && self.chars[close] != '>' {
                close += 1;
            }
            let name = &self.chars[content_start + 2..close.min(self.chars.len())];
            let valid_name = name
                .first()
                .is_some_and(|first| first.is_alphabetic() || *first == '_')
                && name
                    .iter()
                    .all(|character| character.is_alphanumeric() || *character == '_');
            if close < self.chars.len() && valid_name {
                missing_special_group_end = Some(close + 1);
            }
        }
        if self.frames.len() >= MAX_GROUP_DEPTH {
            self.mark_incomplete(
                start,
                (start + 1).min(self.chars.len()),
                "regex-group-depth-budget",
            );
            self.exceeded = true;
            return;
        }
        let owner = self.current_sequence();
        let group = self.add_fact(
            NormalizedKind::RegexGroup,
            start,
            self.chars.len(),
            Some(owner),
            Some(group_type.to_owned()),
            None,
        );
        if let Some(end) = missing_special_group_end {
            self.pending_risks.push((
                NormalizedKind::RegexRiskIncompleteSpecialGroup,
                group,
                start,
                end,
                "named-group-missing-question-mark".to_owned(),
            ));
        }
        let sequence = self.add_fact(
            NormalizedKind::RegexSequence,
            content_start,
            self.chars.len(),
            Some(group),
            None,
            None,
        );
        self.frames.push(BranchFrame {
            owner: group,
            sequence,
            group_start: Some(start),
            last_atom: None,
            restore_flags,
        });
        self.index = content_start;
    }

    fn close_group(&mut self) {
        if self.frames.len() == 1 {
            self.mark_incomplete(self.index, self.index + 1, "unmatched-close-parenthesis");
            self.index += 1;
            return;
        }
        let close = self.index;
        self.index += 1;
        let frame = self
            .frames
            .pop()
            .expect("a nested regex group frame exists");
        self.facts[frame.sequence].end = close;
        self.facts[frame.owner].end = self.index;
        self.facts[frame.owner].first_set = self.sequence_first_set(frame.sequence);
        self.facts[frame.sequence].minimum_width = self.sequence_minimum_width(frame.sequence);
        self.facts[frame.owner].minimum_width = if matches!(
            self.facts[frame.owner].construct.as_deref(),
            Some(
                "lookahead-positive"
                    | "lookahead-negative"
                    | "lookbehind-positive"
                    | "lookbehind-negative"
            )
        ) {
            Some(0)
        } else {
            self.facts[frame.sequence].minimum_width
        };
        if self.facts[frame.owner]
            .construct
            .as_deref()
            .is_some_and(|construct| construct.starts_with("look"))
        {
            self.facts[frame.owner].first_set = None;
        }
        if let Some(flags) = frame.restore_flags {
            self.flags = flags;
        }
        self.record_atom(frame.owner);
    }

    fn alternation(&mut self) {
        let start = self.index;
        self.index += 1;
        let sequence = self.current_sequence();
        self.add_fact(
            NormalizedKind::RegexAlternation,
            start,
            self.index,
            Some(sequence),
            None,
            None,
        );
        let frame = self.frames.last_mut().expect("outer regex frame exists");
        frame.last_atom = None;
        // A dollar assertion at the end of a branch does not constrain the
        // next branch. Anchors are classified after the complete tree exists.
        // (The branch boundary itself is represented by the alternation fact.)
    }

    fn literal(&mut self) {
        let start = self.index;
        let value = self.chars[self.index];
        self.index += 1;
        let set = CharacterSet::one(value);
        let set = if self.flags.ignorecase {
            set.with_ascii_case_variants()
        } else {
            set
        };
        self.add_atom(
            NormalizedKind::RegexLiteral,
            start,
            self.index,
            Some(value.to_string()),
            Some(set),
        );
    }

    fn wildcard(&mut self) {
        let start = self.index;
        self.index += 1;
        let set = if self.flags.dotall {
            CharacterSet {
                ranges: vec![(0, 0x10ffff)],
            }
        } else {
            CharacterSet::any_except_newline()
        };
        self.add_atom(
            NormalizedKind::RegexWildcard,
            start,
            self.index,
            Some("dot".to_owned()),
            Some(set),
        );
    }

    fn anchor(&mut self) {
        let start = self.index;
        let value = self.chars[self.index];
        self.index += 1;
        self.add_fact(
            NormalizedKind::RegexAnchor,
            start,
            self.index,
            Some(self.current_sequence()),
            Some(value.to_string()),
            None,
        );
        self.frames
            .last_mut()
            .expect("outer regex frame exists")
            .last_atom = None;
    }

    fn quantifier(&mut self) {
        let start = self.index;
        let Some(atom) = self.frames.last().and_then(|frame| frame.last_atom) else {
            self.mark_incomplete(
                start,
                (start + 1).min(self.chars.len()),
                "quantifier-without-atom",
            );
            self.index += 1;
            return;
        };
        if self.facts[atom].quantifier.is_some() {
            self.mark_incomplete(
                start,
                (start + 1).min(self.chars.len()),
                "nested-quantifier",
            );
            self.index += 1;
            return;
        }
        let mut quantifier = match self.chars[self.index] {
            '*' => {
                self.index += 1;
                Quantifier {
                    minimum: 0,
                    maximum: None,
                    possessive: false,
                }
            }
            '+' => {
                self.index += 1;
                Quantifier {
                    minimum: 1,
                    maximum: None,
                    possessive: false,
                }
            }
            '?' => {
                self.index += 1;
                Quantifier {
                    minimum: 0,
                    maximum: Some(1),
                    possessive: false,
                }
            }
            '{' => match self.braced_quantifier_end() {
                Some((end, quantifier)) => {
                    self.index = end;
                    quantifier
                }
                None => {
                    self.mark_incomplete(
                        start,
                        (start + 1).min(self.chars.len()),
                        "malformed-braced-quantifier",
                    );
                    self.index += 1;
                    return;
                }
            },
            _ => unreachable!("quantifier dispatch uses a quantifier character"),
        };
        if matches!(self.chars.get(self.index), Some('?') | Some('+')) {
            quantifier.possessive = self.chars[self.index] == '+';
            self.index += 1;
        }
        let end = self.index;
        let fact = self.add_fact(
            NormalizedKind::RegexQuantifier,
            start,
            end,
            Some(atom),
            Some(format!(
                "min={},max={},possessive={}",
                quantifier.minimum,
                quantifier
                    .maximum
                    .map_or_else(|| "*".to_owned(), |maximum| maximum.to_string()),
                quantifier.possessive
            )),
            None,
        );
        self.facts[fact].quantifier = Some(quantifier);
        self.facts[atom].minimum_width = self.facts[atom]
            .minimum_width
            .and_then(|width| width.checked_mul(quantifier.minimum));
        self.facts[atom].end = end;
    }

    fn braced_quantifier_end(&self) -> Option<(usize, Quantifier)> {
        let mut index = self.index + 1;
        let number_start = index;
        let mut minimum = 0u32;
        while let Some(digit @ '0'..='9') = self.chars.get(index).copied() {
            minimum = minimum
                .checked_mul(10)?
                .checked_add(digit as u32 - '0' as u32)?;
            index += 1;
        }
        if index == number_start {
            return None;
        }
        let mut maximum = Some(minimum);
        if self.chars.get(index) == Some(&',') {
            index += 1;
            let upper_start = index;
            let mut upper = 0u32;
            while let Some(digit @ '0'..='9') = self.chars.get(index).copied() {
                upper = upper
                    .checked_mul(10)?
                    .checked_add(digit as u32 - '0' as u32)?;
                index += 1;
            }
            maximum = if upper_start == index {
                None
            } else {
                Some(upper)
            };
        }
        if self.chars.get(index) != Some(&'}') || maximum.is_some_and(|maximum| maximum < minimum) {
            return None;
        }
        Some((
            index + 1,
            Quantifier {
                minimum,
                maximum,
                possessive: false,
            },
        ))
    }

    fn escape(&mut self, in_class: bool) {
        let start = self.index;
        let Some(escape) = parse_regex_escape(&self.chars, start, in_class, self.flags.ascii)
        else {
            self.mark_incomplete(
                start,
                (start + 2).min(self.chars.len()),
                "unsupported-escape",
            );
            self.index = (start + 2).min(self.chars.len());
            return;
        };
        self.index = escape.end;
        if let Some(reason) = escape.incomplete {
            self.mark_incomplete(start, self.index, reason);
        }
        let kind = if escape.anchor && !in_class {
            NormalizedKind::RegexAnchor
        } else {
            NormalizedKind::RegexEscape
        };
        let first_set = escape.first_set.map(|set| {
            if self.flags.ignorecase {
                set.with_ascii_case_variants()
            } else {
                set
            }
        });
        let fact = self.add_fact(
            kind,
            start,
            self.index,
            Some(self.current_sequence()),
            escape.construct,
            first_set,
        );
        if escape.anchor && !in_class {
            self.frames
                .last_mut()
                .expect("outer regex frame exists")
                .last_atom = None;
        } else {
            self.record_atom(fact);
        }
        if escape.backspace && in_class {
            self.pending_risks.push((
                NormalizedKind::RegexRiskBackspaceEscape,
                fact,
                start,
                self.index,
                "backspace-in-character-class".to_owned(),
            ));
        }
    }

    fn character_class(&mut self) {
        let start = self.index;
        self.index += 1;
        let class = self.add_fact(
            NormalizedKind::RegexCharacterClass,
            start,
            self.chars.len(),
            Some(self.current_sequence()),
            None,
            None,
        );
        let negated = self.chars.get(self.index) == Some(&'^');
        if negated {
            self.index += 1;
        }
        let mut members = CharacterSet { ranges: Vec::new() };
        let mut members_known = true;
        let mut saw_member = false;
        let mut closed = false;
        let mut explicit_members = HashSet::<String>::new();
        let mut range_members = Vec::<(usize, CharacterSet, u32)>::new();
        let mut category_members = Vec::new();
        while self.index < self.chars.len() {
            if self.facts.len() >= MAX_PATTERN_FACTS - 2 {
                self.exceeded = true;
                break;
            }
            if self.chars[self.index] == ']' && saw_member {
                self.index += 1;
                closed = true;
                break;
            }
            let Some(left) = parse_class_atom(&self.chars, self.index, self.flags.ascii) else {
                self.mark_incomplete(
                    self.index,
                    (self.index + 1).min(self.chars.len()),
                    "unsupported-class-escape",
                );
                self.index += 1;
                members_known = false;
                continue;
            };
            self.index = left.end;
            if let Some(reason) = left.incomplete {
                self.mark_incomplete(left.start, left.end, reason);
                members_known = false;
            }
            let has_range = self.chars.get(self.index) == Some(&'-')
                && self
                    .chars
                    .get(self.index + 1)
                    .is_some_and(|next| *next != ']');
            if has_range {
                let dash = self.index;
                self.index += 1;
                let Some(right) = parse_class_atom(&self.chars, self.index, self.flags.ascii)
                else {
                    self.mark_incomplete(dash, dash + 1, "unsupported-class-range");
                    members_known = false;
                    continue;
                };
                self.index = right.end;
                if let Some(reason) = right.incomplete {
                    self.mark_incomplete(right.start, right.end, reason);
                    members_known = false;
                }
                let Some((left_value, right_value)) = left.value.zip(right.value) else {
                    self.mark_incomplete(left.start, right.end, "non-literal-class-range");
                    members_known = false;
                    continue;
                };
                if left_value > right_value {
                    let range_fact = self.add_fact(
                        NormalizedKind::RegexCharacterRange,
                        left.start,
                        right.end,
                        Some(class),
                        Some(format!(
                            "U+{:04X}-U+{:04X}",
                            left_value as u32, right_value as u32
                        )),
                        Some(CharacterSet { ranges: Vec::new() }),
                    );
                    self.pending_risks.push((
                        NormalizedKind::RegexRiskRange,
                        range_fact,
                        left.start,
                        right.end,
                        "empty-descending-range".to_owned(),
                    ));
                    self.mark_incomplete(left.start, right.end, "descending-class-range");
                    members_known = false;
                    saw_member = true;
                    continue;
                }
                let range_set = CharacterSet {
                    ranges: vec![(left_value as u32, right_value as u32)],
                };
                let range_set = if self.flags.ignorecase {
                    range_set.with_ascii_case_variants()
                } else {
                    range_set
                };
                let compatibility_set = codeql_range_character_set(left_value, right_value);
                let range_fact = self.add_fact(
                    NormalizedKind::RegexCharacterRange,
                    left.start,
                    right.end,
                    Some(class),
                    Some(format!(
                        "U+{:04X}-U+{:04X}",
                        left_value as u32, right_value as u32
                    )),
                    Some(range_set.clone()),
                );
                if let Some((previous_fact, _, previous_width)) = range_members
                    .iter()
                    .find(|(_, previous, _)| previous.intersects(&compatibility_set))
                {
                    let current_width = compatibility_set
                        .ranges
                        .iter()
                        .map(|(start, end)| end.saturating_sub(*start))
                        .max()
                        .unwrap_or_default();
                    let previous_start = self.facts[*previous_fact].start;
                    let selected_fact = if current_width > *previous_width
                        || (current_width == *previous_width && left.start < previous_start)
                    {
                        range_fact
                    } else {
                        *previous_fact
                    };
                    self.pending_risks.push((
                        NormalizedKind::RegexRiskRange,
                        selected_fact,
                        self.facts[selected_fact].start,
                        self.facts[selected_fact].end,
                        "overlapping-class-range".to_owned(),
                    ));
                }
                if category_members
                    .iter()
                    .any(|previous: &CharacterSet| previous.intersects(&compatibility_set))
                {
                    self.pending_risks.push((
                        NormalizedKind::RegexRiskRange,
                        range_fact,
                        left.start,
                        right.end,
                        "range-overlaps-character-class-escape".to_owned(),
                    ));
                }
                let compatibility_width = compatibility_set
                    .ranges
                    .iter()
                    .map(|(start, end)| end.saturating_sub(*start))
                    .max()
                    .unwrap_or_default();
                range_members.push((range_fact, compatibility_set, compatibility_width));
                members.union_with(&range_set);
                saw_member = true;
                if is_overly_broad_range(left_value, right_value) {
                    self.pending_risks.push((
                        NormalizedKind::RegexRiskRange,
                        range_fact,
                        left.start,
                        right.end,
                        "ascii-punctuation-between-letter-ranges".to_owned(),
                    ));
                }
            } else {
                let semantic_set = left.set.as_ref().map(|set| {
                    if self.flags.ignorecase {
                        set.clone().with_ascii_case_variants()
                    } else {
                        set.clone()
                    }
                });
                let is_category = left
                    .construct
                    .as_deref()
                    .is_some_and(|construct| construct.starts_with("category:"));
                let member_fact = self.add_fact(
                    left.kind,
                    left.start,
                    left.end,
                    Some(class),
                    left.construct,
                    semantic_set.clone(),
                );
                if let Some(set) = &semantic_set {
                    if left.value.is_some() {
                        let syntax = self.chars[left.start..left.end].iter().collect::<String>();
                        if !explicit_members.insert(syntax) {
                            self.pending_risks.push((
                                NormalizedKind::RegexRiskDuplicateClassCharacter,
                                member_fact,
                                left.start,
                                left.end,
                                "duplicate-class-member".to_owned(),
                            ));
                        }
                    }
                    if is_category {
                        if range_members
                            .iter()
                            .any(|(_, range, _)| range.intersects(set))
                        {
                            self.pending_risks.push((
                                NormalizedKind::RegexRiskRange,
                                member_fact,
                                left.start,
                                left.end,
                                "range-overlaps-character-class-escape".to_owned(),
                            ));
                        }
                        category_members.push(set.clone());
                    }
                    members.union_with(set);
                } else {
                    members_known = false;
                }
                saw_member = true;
                if left.backspace {
                    self.pending_risks.push((
                        NormalizedKind::RegexRiskBackspaceEscape,
                        member_fact,
                        left.start,
                        left.end,
                        "backspace-in-character-class".to_owned(),
                    ));
                }
            }
        }
        self.facts[class].end = self.index;
        if !closed {
            self.mark_incomplete(start, self.index, "unclosed-character-class");
        }
        if !saw_member {
            self.mark_incomplete(start, self.index, "empty-character-class");
        }
        if negated && members_known {
            members = members.complement();
        }
        self.facts[class].first_set = members_known.then_some(members);
        self.record_atom(class);
    }

    fn sequence_first_set(&self, sequence: usize) -> Option<CharacterSet> {
        let branches = self.branch_first_sets(sequence);
        if branches.iter().any(Option::is_none) {
            return None;
        }
        let mut result = CharacterSet { ranges: Vec::new() };
        for branch in branches.into_iter().flatten() {
            result.union_with(&branch);
        }
        Some(result)
    }

    fn branch_first_sets(&self, sequence: usize) -> Vec<Option<CharacterSet>> {
        let mut branches = Vec::new();
        let mut current = None;
        let mut consumed = false;
        for fact in self
            .facts
            .iter()
            .filter(|fact| fact.parent == Some(sequence))
        {
            if fact.kind == NormalizedKind::RegexAlternation {
                branches.push(current.take());
                consumed = false;
                continue;
            }
            if consumed || fact.kind == NormalizedKind::RegexAnchor {
                continue;
            }
            match fact.kind {
                NormalizedKind::RegexLiteral
                | NormalizedKind::RegexWildcard
                | NormalizedKind::RegexCharacterClass
                | NormalizedKind::RegexEscape
                | NormalizedKind::RegexGroup => {
                    current = fact.first_set.clone();
                    consumed = true;
                }
                _ => {}
            }
        }
        branches.push(current);
        branches
    }

    fn compute_minimum_widths(&mut self) {
        for id in (0..self.facts.len()).rev() {
            match self.facts[id].kind {
                NormalizedKind::RegexSequence => {
                    self.facts[id].minimum_width = self.sequence_minimum_width(id);
                }
                NormalizedKind::RegexGroup => {
                    let sequence = self.facts.iter().position(|fact| {
                        fact.kind == NormalizedKind::RegexSequence && fact.parent == Some(id)
                    });
                    self.facts[id].minimum_width = if self.facts[id]
                        .construct
                        .as_deref()
                        .is_some_and(|construct| construct.starts_with("look"))
                    {
                        Some(0)
                    } else {
                        sequence.and_then(|sequence| self.facts[sequence].minimum_width)
                    };
                }
                _ => {}
            }
        }
    }

    fn sequence_minimum_width(&self, sequence: usize) -> Option<u32> {
        let mut branches = Vec::new();
        let mut width = Some(0u32);
        for fact in self
            .facts
            .iter()
            .filter(|fact| fact.parent == Some(sequence))
        {
            if fact.kind == NormalizedKind::RegexAlternation {
                branches.push(width.take()?);
                width = Some(0);
                continue;
            }
            width = width?.checked_add(fact.minimum_width?);
        }
        branches.push(width?);
        branches.into_iter().min()
    }

    fn classify_unmatchable_anchors(&mut self) {
        if self.incomplete.is_some() || self.flags.multiline {
            return;
        }
        let sequences = self
            .facts
            .iter()
            .enumerate()
            .filter(|(_, fact)| fact.kind == NormalizedKind::RegexSequence)
            .map(|(id, _)| id)
            .collect::<Vec<_>>();
        for sequence in sequences {
            let mut branches = vec![Vec::new()];
            for (id, fact) in self.facts.iter().enumerate() {
                if fact.parent != Some(sequence) {
                    continue;
                }
                if fact.kind == NormalizedKind::RegexAlternation {
                    branches.push(Vec::new());
                } else {
                    branches
                        .last_mut()
                        .expect("a regex sequence has a branch")
                        .push(id);
                }
            }
            for branch in branches {
                let mut prefix_width = Some(0u32);
                for (index, &id) in branch.iter().enumerate() {
                    let fact = &self.facts[id];
                    if fact.kind == NormalizedKind::RegexAnchor
                        && fact.construct.as_deref() == Some("^")
                        && (prefix_width.is_some_and(|width| width > 0)
                            || branch[..index].iter().any(|&prefix| {
                                self.facts[prefix].construct.as_deref()
                                    == Some("lookbehind-positive")
                                    && self.facts.iter().any(|body| {
                                        body.kind == NormalizedKind::RegexSequence
                                            && body.parent == Some(prefix)
                                            && body.minimum_width.is_some_and(|width| width > 0)
                                    })
                            }))
                    {
                        self.pending_risks.push((
                            NormalizedKind::RegexRiskUnmatchableCaret,
                            id,
                            fact.start,
                            fact.end,
                            "caret-after-consuming-term".to_owned(),
                        ));
                    } else if fact.kind == NormalizedKind::RegexAnchor
                        && fact.construct.as_deref() == Some("$")
                    {
                        let mut suffix_width = Some(0u32);
                        for &suffix_id in &branch[index + 1..] {
                            suffix_width = suffix_width.and_then(|width| {
                                self.facts[suffix_id]
                                    .minimum_width
                                    .and_then(|suffix| width.checked_add(suffix))
                            });
                        }
                        if suffix_width.is_some_and(|width| width > 0)
                            || branch[index + 1..].iter().any(|&suffix| {
                                self.facts[suffix].construct.as_deref()
                                    == Some("lookahead-positive")
                                    && self.facts.iter().any(|body| {
                                        body.kind == NormalizedKind::RegexSequence
                                            && body.parent == Some(suffix)
                                            && body.minimum_width.is_some_and(|width| width > 0)
                                    })
                            })
                        {
                            self.pending_risks.push((
                                NormalizedKind::RegexRiskUnmatchableDollar,
                                id,
                                fact.start,
                                fact.end,
                                "dollar-before-consuming-term".to_owned(),
                            ));
                        }
                    }
                    prefix_width =
                        prefix_width.and_then(|width| width.checked_add(fact.minimum_width?));
                }
            }
        }
    }

    fn classify_hostname(&mut self) {
        if self.incomplete.is_some() || !self.decoded.value.ends_with('/') {
            return;
        }
        let dots = self
            .facts
            .iter()
            .enumerate()
            .filter(|(_, fact)| {
                fact.kind == NormalizedKind::RegexWildcard
                    && fact.construct.as_deref() == Some("dot")
            })
            .map(|(id, _)| id)
            .collect::<Vec<_>>();
        if dots.len() < 2 {
            return;
        }
        let last_dot = dots
            .iter()
            .map(|&id| self.facts[id].start)
            .max()
            .expect("at least two wildcard dots");
        let suffix = self.chars[last_dot + 1..self.chars.len() - 1]
            .iter()
            .collect::<String>();
        if suffix.len() < 2
            || !suffix
                .chars()
                .all(|character| character.is_ascii_alphabetic())
        {
            return;
        }
        for dot in dots {
            let fact = &self.facts[dot];
            if fact.start >= last_dot {
                continue;
            }
            self.pending_risks.push((
                NormalizedKind::RegexRiskHostname,
                dot,
                fact.start,
                fact.end,
                "unescaped-dot-in-hostname-like-pattern".to_owned(),
            ));
        }
    }

    fn classify_bad_tag(&mut self) {
        if self.incomplete.is_some() || !self.flags.complete {
            return;
        }
        let value = &self.decoded.value;
        if !(value.contains('<') && value.contains('>'))
            && !["-->", "--!>", "<--", "<!--"]
                .iter()
                .any(|marker| value.contains(marker))
        {
            return;
        }
        let rust_pattern = value
            .replace("\\/", "/")
            .replace("\\\"", "\"")
            .replace("\\'", "'");
        let mut builder = regex::RegexBuilder::new(&rust_pattern);
        builder
            .case_insensitive(self.flags.ignorecase)
            .multi_line(self.flags.multiline)
            .dot_matches_new_line(self.flags.dotall)
            .unicode(!self.flags.ascii)
            .ignore_whitespace(self.flags.verbose);
        let Ok(regex) = builder.build() else {
            return;
        };
        let capture_nfa = match RegexNfa::compile(&self.facts, 0, None) {
            Ok(nfa) => Some(nfa),
            Err(error) => {
                self.mark_incomplete(
                    0,
                    self.chars.len(),
                    match error {
                        NfaError::Unsupported => "bad-tag-nfa-unsupported",
                        NfaError::Budget => "bad-tag-nfa-state-budget",
                    },
                );
                return;
            }
        };
        let matches = |sample: &str| {
            capture_nfa.as_ref().map_or_else(
                || regex.is_match(sample),
                |nfa| nfa.match_prefix_capture_groups(sample).0,
            )
        };
        let groups = |sample: &str| {
            capture_nfa.as_ref().map_or_else(
                || {
                    regex
                        .captures(sample)
                        .map(|captures| {
                            captures
                                .iter()
                                .enumerate()
                                .skip(1)
                                .filter_map(|(index, capture)| capture.map(|_| index))
                                .collect::<HashSet<_>>()
                        })
                        .unwrap_or_default()
                },
                |nfa| nfa.match_prefix_capture_groups(sample).1,
            )
        };
        let comment = "<!-- foo -->";
        let comment_bang = "<!-- foo --!>";
        let comment_groups = groups(comment);
        let comment_bang_groups = groups(comment_bang);
        let comment_group_mismatch = matches(comment)
            && matches(comment_bang)
            && comment_groups.iter().any(|group| {
                !comment_bang_groups.contains(group)
                    && comment_bang_groups.iter().any(|other| group != other)
            });
        let plain_tag_groups = groups("<foo>");
        let only_comment_group = groups(comment).iter().any(|group| {
            plain_tag_groups.iter().any(|other| other != group)
                && !matches(comment_bang)
                && !groups("<!- foo ->").contains(group)
                && !plain_tag_groups.contains(group)
                && !groups("<script>").contains(group)
        });
        let bounded_script_opener = value
            .to_ascii_lowercase()
            .find("<script")
            .map(|start| {
                let start = value[..start].chars().count() + "<script".len();
                self.facts
                    .iter()
                    .filter(|fact| {
                        fact.kind == NormalizedKind::RegexLiteral
                            && fact.construct.as_deref() == Some(">")
                            && fact.start >= start
                            && !fact.parent.is_some_and(|parent| {
                                self.facts[parent].kind == NormalizedKind::RegexCharacterClass
                            })
                    })
                    .map(|fact| fact.start)
                    .min()
                    .is_some_and(|tag_end| {
                        self.facts.iter().enumerate().any(|(id, fact)| {
                            fact.kind == NormalizedKind::RegexCharacterClass
                                && fact.start >= start
                                && fact.end <= tag_end
                                && fact
                                    .first_set
                                    .as_ref()
                                    .is_some_and(|set| !set.contains('>'))
                                && self.facts.iter().any(|quantifier| {
                                    quantifier.kind == NormalizedKind::RegexQuantifier
                                        && quantifier.parent == Some(id)
                                        && quantifier
                                            .quantifier
                                            .is_some_and(|quantifier| quantifier.maximum.is_none())
                                })
                        })
                    })
            })
            .unwrap_or(false);
        let script_warning = !bounded_script_opener
            && ((matches("<script>foo</script>")
                && matches("<script src=\"foo\"></script>")
                && !matches("<foo ></foo>")
                && (!matches("<script \n>foo</script>") || !matches("<script >foo\n</script>")))
                || (matches("<script>foo</script>")
                    && matches("<script src=\"foo\"></script>")
                    && !matches("<script src='foo'></script>")
                    && !matches("<foo>"))
                || (matches("<script>foo</script>")
                    && matches("<script src='foo'></script>")
                    && !matches("<script src=\"foo\"></script>")
                    && !matches("<foo>"))
                || (matches("<script>foo</script>")
                    && matches("<script src='foo'></script>")
                    && !matches("<script\tsrc='foo'></script>")
                    && !matches("<foo>")
                    && !matches("<foo src=\"foo\"></foo>"))
                || (matches("<script>foo</script>")
                    && !self.flags.ignorecase
                    && !matches("<foo>")
                    && !matches("<foo ></foo>")
                    && (!matches("<SCRIPT>foo</SCRIPT>")
                        || (matches("<SCRIPT>foo</SCRIPT>") && !matches("<sCrIpT>foo</ScRiPt>"))))
                || (matches("<script src=\"foo\"></script>")
                    && !matches("<foo>")
                    && !matches("<foo ></foo>")
                    && (!matches("<script src=\"foo\">foo</script >")
                        || !matches("<script src=\"foo\">foo</script foo=\"bar\">")
                        || !matches("<script src=\"foo\">foo</script\t\n bar>"))));
        let warning = comment_group_mismatch
            || only_comment_group
            || (matches("-->") && !matches("--!>") && !matches("--"))
            || (matches(comment)
                && !matches("<!-- foo\n -->")
                && !matches("<!- foo ->")
                && !matches("<foo>")
                && !matches("<script>"))
            || script_warning;
        if warning {
            self.pending_risks.push((
                NormalizedKind::RegexRiskBadTag,
                0,
                0,
                self.chars.len(),
                "matches-html-samples-inconsistently".to_owned(),
            ));
        }
    }

    fn classify_polynomial_redos(&mut self) {
        if self.incomplete.is_some() || !self.flags.complete {
            return;
        }
        let sequences = self
            .facts
            .iter()
            .enumerate()
            .filter(|(_, fact)| fact.kind == NormalizedKind::RegexSequence)
            .map(|(id, _)| id)
            .collect::<Vec<_>>();
        for sequence in sequences {
            let mut branches = vec![Vec::new()];
            for (id, fact) in self.facts.iter().enumerate() {
                if fact.parent != Some(sequence) {
                    continue;
                }
                if fact.kind == NormalizedKind::RegexAlternation {
                    branches.push(Vec::new());
                } else {
                    branches
                        .last_mut()
                        .expect("regex sequence always has a branch")
                        .push(id);
                }
            }
            for branch in branches {
                let Some(&terminal_anchor) = branch.last() else {
                    continue;
                };
                let terminal = &self.facts[terminal_anchor];
                if terminal.kind != NormalizedKind::RegexAnchor
                    || terminal.construct.as_deref() != Some("$")
                {
                    continue;
                }

                let mut repeated = Vec::new();
                for (position, &atom) in branch[..branch.len() - 1].iter().enumerate() {
                    if !matches!(
                        self.facts[atom].kind,
                        NormalizedKind::RegexLiteral
                            | NormalizedKind::RegexEscape
                            | NormalizedKind::RegexCharacterClass
                            | NormalizedKind::RegexWildcard
                    ) || self.facts[atom].minimum_width != Some(1)
                    {
                        continue;
                    }
                    let Some((quantifier_id, quantifier)) =
                        self.facts.iter().enumerate().find_map(|(id, fact)| {
                            (fact.kind == NormalizedKind::RegexQuantifier
                                && fact.parent == Some(atom))
                            .then_some((id, fact.quantifier?))
                        })
                    else {
                        continue;
                    };
                    if quantifier.minimum == 1
                        && quantifier.maximum.is_none()
                        && !quantifier.possessive
                    {
                        repeated.push((
                            position,
                            atom,
                            quantifier_id,
                            self.facts[atom].first_set.clone(),
                        ));
                    }
                }
                if self.flags.ignorecase && !self.flags.ascii && !repeated.is_empty() {
                    self.mark_incomplete(
                        self.facts[sequence].start,
                        self.facts[sequence].end,
                        "redos-unicode-casefold-bound",
                    );
                    continue;
                }

                let anchored_at_start = branch
                    .iter()
                    .take_while(|&&id| {
                        (self.facts[id].kind == NormalizedKind::RegexAnchor
                            && self.facts[id].construct.as_deref() == Some("^"))
                            || (self.facts[id].kind == NormalizedKind::RegexGroup
                                && self.facts[id].construct.as_deref() == Some("comment"))
                    })
                    .any(|&id| {
                        self.facts[id].kind == NormalizedKind::RegexAnchor
                            && self.facts[id].construct.as_deref() == Some("^")
                    });
                let mut risky_quantifier = None;
                let mut overlapping_repeated_runs = false;
                'pairs: for left in 0..repeated.len() {
                    for right in left + 1..repeated.len() {
                        let (left_position, left_atom, _, _) = &repeated[left];
                        let (right_position, right_atom, right_quantifier, _) = &repeated[right];
                        if !polynomial_atoms_overlap(
                            &self.facts[*left_atom],
                            &self.facts[*right_atom],
                        ) {
                            continue;
                        }
                        let separable =
                            branch[left_position + 1..*right_position]
                                .iter()
                                .all(|&separator| {
                                    if !matches!(
                                        self.facts[separator].kind,
                                        NormalizedKind::RegexLiteral
                                            | NormalizedKind::RegexEscape
                                            | NormalizedKind::RegexCharacterClass
                                            | NormalizedKind::RegexWildcard
                                    ) {
                                        return false;
                                    }
                                    let Some(quantifier) = self
                                        .facts
                                        .iter()
                                        .find(|fact| {
                                            fact.kind == NormalizedKind::RegexQuantifier
                                                && fact.parent == Some(separator)
                                        })
                                        .and_then(|fact| fact.quantifier)
                                    else {
                                        return false;
                                    };
                                    quantifier.minimum == 0
                                        && quantifier.maximum == Some(1)
                                        && !quantifier.possessive
                                });
                        if separable {
                            risky_quantifier = Some(*right_quantifier);
                            overlapping_repeated_runs = true;
                            break 'pairs;
                        }
                    }
                }

                if risky_quantifier.is_none() && self.api.scans_from_each_offset {
                    risky_quantifier = (!anchored_at_start)
                        .then(|| {
                            repeated
                                .first()
                                .map(|(_, _, quantifier_id, _)| *quantifier_id)
                        })
                        .flatten();
                }

                if let Some(quantifier) = risky_quantifier {
                    self.pending_risks.push((
                        NormalizedKind::RegexRiskPolynomial,
                        quantifier,
                        self.facts[quantifier].start,
                        self.facts[quantifier].end,
                        if overlapping_repeated_runs {
                            "overlapping-repeated-runs".to_owned()
                        } else {
                            "unanchored-repeated-run-before-end-anchor".to_owned()
                        },
                    ));
                }
            }
        }
    }

    fn has_rejecting_suffix(&self, repeated_group: usize) -> bool {
        let mut member = repeated_group;
        loop {
            let Some(sequence) = self.facts[member].parent else {
                return false;
            };
            if self.facts[sequence].kind != NormalizedKind::RegexSequence {
                return false;
            }
            let mut after_member = false;
            for (id, fact) in self.facts.iter().enumerate() {
                if fact.parent != Some(sequence) {
                    continue;
                }
                if id == member {
                    after_member = true;
                    continue;
                }
                if !after_member {
                    continue;
                }
                if fact.kind == NormalizedKind::RegexAlternation {
                    break;
                }
                if fact.kind == NormalizedKind::RegexAnchor
                    && matches!(
                        fact.construct.as_deref(),
                        Some("$" | "boundary:Z" | "boundary:z")
                    )
                {
                    return true;
                }
                if fact.kind == NormalizedKind::RegexGroup
                    && fact.construct.as_deref() == Some("lookahead-positive")
                    && self.facts.iter().any(|body| {
                        body.kind == NormalizedKind::RegexSequence
                            && body.parent == Some(id)
                            && body.minimum_width.is_some_and(|width| width > 0)
                    })
                {
                    return true;
                }
                if fact.minimum_width.is_some_and(|width| width > 0) {
                    return true;
                }
            }
            let Some(owner) = self.facts[sequence].parent else {
                return false;
            };
            if self.facts[owner].kind != NormalizedKind::RegexGroup {
                return false;
            }
            member = owner;
        }
    }

    fn suffix_is_covered_by_repeated_body(&self, repeated_group: usize) -> bool {
        let Some(body_set) = self.facts[repeated_group].first_set.as_ref() else {
            return false;
        };
        let mut member = repeated_group;
        loop {
            let Some(sequence) = self.facts[member].parent else {
                return false;
            };
            if self.facts[sequence].kind != NormalizedKind::RegexSequence {
                return false;
            }
            let mut after_member = false;
            let mut found_suffix = false;
            for (id, fact) in self.facts.iter().enumerate() {
                if fact.parent != Some(sequence) {
                    continue;
                }
                if fact.kind == NormalizedKind::RegexAlternation {
                    break;
                }
                if id == member {
                    after_member = true;
                    continue;
                }
                if !after_member {
                    continue;
                }
                if fact.kind == NormalizedKind::RegexAnchor {
                    return false;
                }
                if fact.minimum_width.is_some_and(|width| width > 0) {
                    found_suffix = true;
                    if fact.first_set.as_ref() != Some(body_set) {
                        return false;
                    }
                }
            }
            if found_suffix {
                return true;
            }
            let Some(owner) = self.facts[sequence].parent else {
                return false;
            };
            if self.facts[owner].kind != NormalizedKind::RegexGroup {
                return false;
            }
            member = owner;
        }
    }

    fn classify_redos(&mut self) {
        if self.incomplete.is_some() {
            return;
        }
        let groups = (0..self.facts.len())
            .filter(|&id| self.facts[id].kind == NormalizedKind::RegexGroup)
            .collect::<Vec<_>>();
        let mut repeated_groups = Vec::new();
        for group in groups {
            let Some(sequence) = self.facts.iter().position(|fact| {
                fact.kind == NormalizedKind::RegexSequence && fact.parent == Some(group)
            }) else {
                continue;
            };
            let Some(outer_quantifier) = self.facts.iter().position(|fact| {
                fact.kind == NormalizedKind::RegexQuantifier && fact.parent == Some(group)
            }) else {
                continue;
            };
            let Some(quantifier) = self.facts[outer_quantifier].quantifier else {
                continue;
            };
            if quantifier.maximum.is_some() {
                continue;
            }
            if quantifier.possessive {
                continue;
            }
            repeated_groups.push((group, sequence, outer_quantifier));
        }
        if repeated_groups.len() > MAX_REDOSE_GROUPS {
            self.mark_incomplete(0, self.chars.len(), "redos-group-budget");
            return;
        }
        let mut relation_budget = MAX_NFA_PRODUCT_PAIRS;
        for (group, sequence, outer_quantifier) in repeated_groups {
            let mut risk_found = false;
            let branch_count = self
                .facts
                .iter()
                .filter(|fact| {
                    fact.kind == NormalizedKind::RegexAlternation && fact.parent == Some(sequence)
                })
                .count()
                + 1;
            if branch_count > 1 {
                if branch_count > MAX_REDOSE_ALTERNATIVES {
                    self.mark_incomplete(
                        self.facts[group].start,
                        self.facts[group].end,
                        "redos-alternative-budget",
                    );
                    continue;
                }
                if self.flags.ignorecase && !self.flags.ascii {
                    self.mark_incomplete(
                        self.facts[group].start,
                        self.facts[group].end,
                        "redos-unicode-casefold-bound",
                    );
                }
                let branches = (0..branch_count)
                    .map(|branch| RegexNfa::compile(&self.facts, sequence, Some(branch)))
                    .collect::<Result<Vec<_>, _>>();
                let repeated = RegexNfa::compile(&self.facts, sequence, None)
                    .and_then(RegexNfa::positive_closure);
                match (branches, repeated) {
                    (Ok(branches), Ok(repeated)) => {
                        let mut overlap = false;
                        let mut budget_exceeded = false;
                        'pairs: for left in 0..branches.len() {
                            for right in left + 1..branches.len() {
                                match branches[left].intersects_on_nonempty_string(
                                    &branches[right],
                                    &mut relation_budget,
                                ) {
                                    Ok(true) => {
                                        overlap = true;
                                        break 'pairs;
                                    }
                                    Ok(false) => {}
                                    Err(NfaError::Budget) => {
                                        budget_exceeded = true;
                                        break 'pairs;
                                    }
                                    Err(NfaError::Unsupported) => unreachable!(
                                        "product comparison only rejects bounded automata"
                                    ),
                                }
                                match branches[left].has_repartitioned_prefix(
                                    &branches[right],
                                    &repeated,
                                    &mut relation_budget,
                                ) {
                                    Ok(true) => {
                                        overlap = true;
                                        break 'pairs;
                                    }
                                    Ok(false) => {}
                                    Err(NfaError::Budget) => {
                                        budget_exceeded = true;
                                        break 'pairs;
                                    }
                                    Err(NfaError::Unsupported) => unreachable!(
                                        "prefix comparison only rejects bounded automata"
                                    ),
                                }
                                match branches[right].has_repartitioned_prefix(
                                    &branches[left],
                                    &repeated,
                                    &mut relation_budget,
                                ) {
                                    Ok(true) => {
                                        overlap = true;
                                        break 'pairs;
                                    }
                                    Ok(false) => {}
                                    Err(NfaError::Budget) => {
                                        budget_exceeded = true;
                                        break 'pairs;
                                    }
                                    Err(NfaError::Unsupported) => unreachable!(
                                        "prefix comparison only rejects bounded automata"
                                    ),
                                }
                            }
                        }
                        if overlap && self.has_rejecting_suffix(group) {
                            risk_found = true;
                            self.pending_risks.push((
                                NormalizedKind::RegexRiskExponential,
                                outer_quantifier,
                                self.facts[outer_quantifier].start,
                                self.facts[outer_quantifier].end,
                                "overlapping-repeated-alternatives".to_owned(),
                            ));
                        }
                        if budget_exceeded {
                            self.mark_incomplete(
                                self.facts[group].start,
                                self.facts[group].end,
                                "redos-nfa-product-budget",
                            );
                        }
                    }
                    (Err(error), _) | (_, Err(error)) => self.mark_incomplete(
                        self.facts[group].start,
                        self.facts[group].end,
                        match error {
                            NfaError::Unsupported => "redos-nfa-unsupported",
                            NfaError::Budget => "redos-nfa-state-budget",
                        },
                    ),
                }
            }
            let has_backtracking_child = (0..self.facts.len()).any(|candidate| {
                candidate != outer_quantifier
                    && self.is_descendant(candidate, group)
                    && matches!(
                        self.facts[candidate].kind,
                        NormalizedKind::RegexAlternation | NormalizedKind::RegexQuantifier
                    )
            });
            if has_backtracking_child && !risk_found {
                if self.flags.ignorecase && !self.flags.ascii {
                    self.mark_incomplete(
                        self.facts[group].start,
                        self.facts[group].end,
                        "redos-unicode-casefold-bound",
                    );
                }
                match RegexNfa::compile(&self.facts, group, None)
                    .and_then(|nfa| nfa.has_pumpable_fork(&mut relation_budget))
                {
                    Ok(true)
                        if self.has_rejecting_suffix(group)
                            && !self.suffix_is_covered_by_repeated_body(group) =>
                    {
                        self.pending_risks.push((
                            NormalizedKind::RegexRiskExponential,
                            outer_quantifier,
                            self.facts[outer_quantifier].start,
                            self.facts[outer_quantifier].end,
                            "overlapping-nfa-cycles".to_owned(),
                        ));
                    }
                    Ok(_) => {}
                    Err(error) => self.mark_incomplete(
                        self.facts[group].start,
                        self.facts[group].end,
                        match error {
                            NfaError::Unsupported => "redos-nfa-unsupported",
                            NfaError::Budget => "redos-nfa-product-budget",
                        },
                    ),
                }
            }
        }
    }

    fn is_descendant(&self, mut fact: usize, ancestor: usize) -> bool {
        while let Some(parent) = self.facts[fact].parent {
            if parent == ancestor {
                return true;
            }
            fact = parent;
        }
        false
    }

    fn append_pending_facts(&mut self) {
        for (kind, parent, start, end, reason) in std::mem::take(&mut self.pending_risks) {
            if self.facts.len() >= MAX_PATTERN_FACTS - 1 {
                self.exceeded = true;
                break;
            }
            self.add_fact(kind, start, end, Some(parent), Some(reason), None);
        }
        if let Some((start, end, reason)) = self.incomplete.take() {
            self.add_fact(
                NormalizedKind::RegexIncomplete,
                start,
                end,
                Some(0),
                Some(reason),
                None,
            );
        }
    }
}

fn is_overly_broad_range(start: char, end: char) -> bool {
    let low = start as u32;
    let high = end as u32;
    let width = high.saturating_sub(low).saturating_add(1);
    if width < 10 {
        return false;
    }
    let alphanumeric = |character: char| character.is_ascii_alphanumeric();
    let wide_ascii = low < 128 && high < 128;
    let spans_letters = low <= 'Z' as u32 && high >= 'a' as u32;
    let spans_digits_to_letters = low <= '9' as u32 && high >= 'A' as u32;
    let has_non_alphanumeric_boundary = !alphanumeric(start) || !alphanumeric(end);
    let allowed = end == '~'
        || matches!(start, ' ' | '!')
        || start == '\0'
        || (start == '0' && end == '?')
        || (start == '@' && end == '_')
        || (start == '@' && end == 'Z');
    !allowed
        && (spans_letters
            || spans_digits_to_letters
            || (wide_ascii && has_non_alphanumeric_boundary))
}

fn codeql_range_character_set(start: char, end: char) -> CharacterSet {
    let codepoint = |character: char| {
        let value = character as u32;
        if value > 0xffff { 0xfffd } else { value }
    };
    let start = codepoint(start);
    let end = codepoint(end);
    CharacterSet {
        ranges: (start <= end).then_some((start, end)).into_iter().collect(),
    }
}

fn category_character_set(escaped: char, ascii: bool) -> Option<CharacterSet> {
    let (category, negated) = match escaped {
        'd' => ('d', false),
        'D' => ('d', true),
        's' => ('s', false),
        'S' => ('s', true),
        'w' => ('w', false),
        'W' => ('w', true),
        _ => return None,
    };
    let mut set = match category {
        'd' => CharacterSet {
            ranges: vec![(b'0' as u32, b'9' as u32)],
        },
        's' => CharacterSet {
            ranges: vec![(9, 13), (32, 32)],
        },
        'w' => CharacterSet {
            ranges: vec![
                (b'0' as u32, b'9' as u32),
                (b'A' as u32, b'Z' as u32),
                (b'_' as u32, b'_' as u32),
                (b'a' as u32, b'z' as u32),
            ],
        },
        _ => unreachable!("category is selected from d, s, w"),
    };
    if !ascii && negated {
        // A Unicode negated category is not the complement of its ASCII
        // subset. Leave it unknown rather than claim a false overlap.
    }
    if !ascii && negated {
        return None;
    }
    if negated {
        set = set.complement();
    }
    Some(set)
}

fn parse_regex_escape(
    chars: &[char],
    start: usize,
    in_class: bool,
    ascii: bool,
) -> Option<EscapeValue> {
    if chars.get(start) != Some(&'\\') {
        return None;
    }
    let escaped = *chars.get(start + 1)?;
    let mut end = start + 2;
    let mut value = None;
    let mut anchor = false;
    let mut incomplete = None;
    let mut backspace = false;
    let construct = match escaped {
        'A' | 'Z' | 'z' | 'b' | 'B' if !in_class => {
            anchor = true;
            Some(format!("boundary:{escaped}"))
        }
        'd' | 'D' | 's' | 'S' | 'w' | 'W' => Some(format!("category:{escaped}")),
        'a' => {
            value = Some('\u{7}');
            Some("U+0007".to_owned())
        }
        'f' => {
            value = Some('\u{c}');
            Some("U+000C".to_owned())
        }
        'n' => {
            value = Some('\n');
            Some("U+000A".to_owned())
        }
        'r' => {
            value = Some('\r');
            Some("U+000D".to_owned())
        }
        't' => {
            value = Some('\t');
            Some("U+0009".to_owned())
        }
        'v' => {
            value = Some('\u{b}');
            Some("U+000B".to_owned())
        }
        'b' if in_class => {
            value = Some('\u{8}');
            backspace = true;
            Some("backspace".to_owned())
        }
        'x' | 'u' | 'U' => {
            let digits = match escaped {
                'x' => 2,
                'u' => 4,
                _ => 8,
            };
            let scalar = hex_value(chars, start + 2, digits);
            end = start + 2 + digits;
            match scalar.and_then(char::from_u32) {
                Some(character) => {
                    value = Some(character);
                    Some(format!("U+{:04X}", character as u32))
                }
                None => {
                    incomplete = Some("invalid-hex-escape");
                    Some(format!("invalid:{escaped}"))
                }
            }
        }
        'N' => {
            incomplete = Some("named-unicode-escape");
            if chars.get(start + 2) == Some(&'{') {
                let mut close = start + 3;
                while close < chars.len() && chars[close] != '}' {
                    close += 1;
                }
                end = (close + 1).min(chars.len());
            }
            Some("unicode-name".to_owned())
        }
        '0'..='7' => {
            let mut codepoint = escaped as u32 - '0' as u32;
            let mut digits = 1usize;
            while digits < 3 {
                let Some(digit @ '0'..='7') = chars.get(start + 1 + digits).copied() else {
                    break;
                };
                codepoint = codepoint * 8 + (digit as u32 - '0' as u32);
                digits += 1;
            }
            end = start + 1 + digits;
            match char::from_u32(codepoint) {
                Some(character) => {
                    value = Some(character);
                    Some(format!("U+{codepoint:04X}"))
                }
                None => {
                    incomplete = Some("invalid-octal-escape");
                    Some("invalid-octal".to_owned())
                }
            }
        }
        '1'..='9' if !in_class => {
            incomplete = Some("backreference-not-supported");
            Some(format!("backreference:{escaped}"))
        }
        'g' | 'k' if !in_class => {
            incomplete = Some("named-backreference-not-supported");
            Some(format!("backreference:{escaped}"))
        }
        other if other.is_ascii_alphabetic() => {
            incomplete = Some("unknown-regex-escape");
            Some(format!("unknown:{other}"))
        }
        other => {
            value = Some(other);
            Some(other.to_string())
        }
    };
    if end > chars.len() {
        return None;
    }
    let first_set = value
        .map(CharacterSet::one)
        .or_else(|| category_character_set(escaped, ascii));
    Some(EscapeValue {
        end,
        anchor,
        construct,
        first_set,
        incomplete,
        backspace,
    })
}

fn parse_class_atom(chars: &[char], start: usize, ascii: bool) -> Option<ClassAtom> {
    let value = *chars.get(start)?;
    if value != '\\' {
        return Some(ClassAtom {
            start,
            end: start + 1,
            value: Some(value),
            set: Some(CharacterSet::one(value)),
            kind: NormalizedKind::RegexLiteral,
            construct: Some(value.to_string()),
            backspace: false,
            incomplete: None,
        });
    }
    let escape = parse_regex_escape(chars, start, true, ascii)?;
    Some(ClassAtom {
        start,
        end: escape.end,
        value: escape.first_set.as_ref().and_then(single_character),
        set: escape.first_set,
        kind: NormalizedKind::RegexEscape,
        construct: escape.construct,
        backspace: escape.backspace,
        incomplete: escape.incomplete,
    })
}

fn single_character(set: &CharacterSet) -> Option<char> {
    let [(start, end)] = set.ranges.as_slice() else {
        return None;
    };
    (start == end).then(|| char::from_u32(*start)).flatten()
}

fn facts_to_embedded(
    facts: Vec<Fact>,
    decoded: &DecodedValue,
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
            let range = mapped_source_range(fact.start, fact.end, decoded, &line_starts);
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
    decoded: &DecodedValue,
    line_starts: &[usize],
) -> Range {
    assert!(
        start <= end && end <= decoded.chars.len(),
        "regex parser ranges stay within the decoded pattern"
    );
    let (start_byte, end_byte) = if start < end {
        (
            decoded.chars[start].source_start,
            decoded.chars[end - 1].source_end,
        )
    } else {
        // An empty regex sequence (for example the body of `()`) still has a
        // precise source boundary. Mapping it to the whole Python literal
        // makes that child extend outside its enclosing group.
        let boundary = decoded.chars.get(start).map_or_else(
            || {
                decoded
                    .chars
                    .last()
                    .map_or(decoded.source_range.start_byte, |last| last.source_end)
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

#[cfg(test)]
mod tests {
    use super::*;
    use brokk_bifrost_test_macros::hardwon;

    #[test]
    fn public_string_value_decoder_decodes_escaped_format_braces() {
        let source = r#"value = "\x7b0\x7d""#;
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .expect("Python grammar is valid");
        let tree = parser.parse(source, None).expect("parser returns a tree");
        let mut pending = vec![tree.root_node()];
        let mut string = None;
        while let Some(node) = pending.pop() {
            if node.kind() == "string" {
                string = Some(node);
                break;
            }
            let mut cursor = node.walk();
            pending.extend(node.named_children(&mut cursor));
        }
        let string = string.expect("fixture contains a string expression");
        let mut cursor = string.walk();
        let parts = string
            .named_children(&mut cursor)
            .map(|child| (child.kind().to_owned(), node_text(child, source).to_owned()))
            .collect::<Vec<_>>();
        assert_eq!(
            decode_python_string_value(string, source).expect("string literal decodes"),
            "{0}",
            "parts={parts:?}; string={}",
            string.to_sexp()
        );
    }

    fn embedded_for_source(source: &str) -> Vec<EmbeddedLeafFact> {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .expect("Python grammar is valid");
        let tree = parser.parse(source, None).expect("parser returns a tree");
        let root = tree.root_node();
        let mut pending = vec![root];
        let mut facts = module_assigned_facts(root, source);
        while let Some(node) = pending.pop() {
            if matches!(node.kind(), "call" | "string" | "concatenated_string") {
                facts.extend(embedded_facts(node, source));
            }
            let mut children = Vec::new();
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                children.push(child);
            }
            pending.extend(children.into_iter().rev());
        }
        facts
    }

    #[hardwon(
        "#4874: bounded repetition cloned a fragment after concatenation linked its end outside"
    )]
    #[test]
    fn meshroom_assigned_regex_and_reduced_form_compile_without_incomplete_facts() {
        let patterns = [
            r"(?P<FILESTEM_PREFIX>.*?)(?P<FRAMEID_STR>[-._]\d+)?(?P<EXTENSION>\.\w{3,4})",
            r"(?P<run>a{3})",
        ];

        for pattern in patterns {
            let source = format!("import re\npattern = r\"{pattern}\"\nre.compile(pattern)\n");
            let facts = embedded_for_source(&source);
            assert!(
                facts
                    .iter()
                    .any(|fact| fact.kind == NormalizedKind::RegexPattern),
                "pattern={pattern:?}; facts={facts:#?}"
            );
            assert!(
                facts
                    .iter()
                    .all(|fact| fact.kind != NormalizedKind::RegexIncomplete),
                "pattern={pattern:?}; facts={facts:#?}"
            );
        }

        let unsupported = embedded_for_source(
            "import re\npattern = r\"(?P<anchored>^a)\"\nre.compile(pattern)\n",
        );
        assert!(
            unsupported.iter().any(|fact| {
                fact.kind == NormalizedKind::RegexIncomplete
                    && fact.construct.as_deref() == Some("bad-tag-nfa-unsupported")
            }),
            "unsupported NFA construct must be explicit; facts={unsupported:#?}"
        );
    }

    #[hardwon(
        "#4650: Python regex facts missed byte patterns, nested assigned values, Unicode ranges, and ReDoS"
    )]
    #[test]
    fn codeql_regex_facts_cover_byte_values_assignments_and_safe_redos_controls() {
        let source = r####"import re
re.compile(br"[\b\t ]")
re.compile(b"[AA]")
re.compile(br"(P<name>[\w]+)")
re.compile(b" ^abc")
re.compile(b"(?s) ^abc")
re.compile(b"abc$ ")
re.compile(r"[A-z]")
re.compile(r"^[z-a]$")
re.compile(r"[0-93-5]")
re.compile(r"[0-9\d]")
re.compile('[\U0001D173-\U0001D17A\U000E0020-\U000E007F\U000e0001]')
re.compile(r"<script.*?>.*?</script>", re.I)
re.compile(r"<script.*?>.*?</script>", re.re.DOTALL)
re.compile(r"""(<[a-z\/!$]("[^"]*"|'[^']*'|[^'">])*>|<!(--.*?--\s*)+>)""", re.I)
VERBOSE_REGEX = r"""
        \[
        (?P<header>[^]]+)                  # very permissive!
        \]
        """
re.compile(VERBOSE_REGEX, re.VERBOSE)
re.compile(r"(a|.)*")
re.compile(r"(a|aa?)*b")
re.compile(r"^([a-z]+)+$")
MY_REG = r'X(\u0061|a)*Y'
def matcher(name):
    re.match(MY_REG, name)
def shadowed(name, MY_REG):
    re.match(MY_REG, name)
re.compile(r"((.|[^a])*)\"")
re.compile(r"((a|[^a])*)\"")
re.compile(r"(a+)+aaaaa*a+")
"####;
        let facts = embedded_for_source(source);
        let has = |kind| facts.iter().any(|fact| fact.kind == kind);
        assert!(has(NormalizedKind::RegexRiskBackspaceEscape), "{facts:#?}");
        assert!(
            has(NormalizedKind::RegexRiskDuplicateClassCharacter),
            "{facts:#?}"
        );
        assert!(
            has(NormalizedKind::RegexRiskIncompleteSpecialGroup),
            "{facts:#?}"
        );
        assert!(has(NormalizedKind::RegexRiskUnmatchableCaret), "{facts:#?}");
        assert!(
            has(NormalizedKind::RegexRiskUnmatchableDollar),
            "{facts:#?}"
        );
        assert!(has(NormalizedKind::RegexRiskRange), "{facts:#?}");
        assert!(has(NormalizedKind::RegexRiskBadTag), "{facts:#?}");
        assert!(has(NormalizedKind::RegexRiskExponential), "{facts:#?}");
        let overlapping_range_start = source
            .find("[0-93-5]")
            .expect("overlapping range sample is present")
            + 1;
        assert!(
            facts.iter().any(|fact| {
                fact.kind == NormalizedKind::RegexRiskRange
                    && fact.range.start_byte == overlapping_range_start
                    && fact.range.end_byte == overlapping_range_start + 3
            }),
            "{facts:#?}"
        );
        let line_with = |needle: &str| {
            source
                .lines()
                .position(|line| line.contains(needle))
                .expect("regex fixture line is present")
                + 1
        };
        let risk_lines = facts
            .iter()
            .filter(|fact| fact.kind == NormalizedKind::RegexRiskExponential)
            .map(|fact| fact.range.start_line)
            .collect::<HashSet<_>>();
        assert!(risk_lines.contains(&line_with("^([a-z]+)+$")), "{facts:#?}");
        assert!(risk_lines.contains(&line_with("MY_REG =")), "{facts:#?}");
        assert!(risk_lines.contains(&line_with("((.|[^a])*)")), "{facts:#?}");
        assert!(
            !risk_lines.contains(&line_with("((a|[^a])*)")),
            "{facts:#?}"
        );
        assert!(!risk_lines.contains(&line_with("aaaaa*a+")), "{facts:#?}");
        let shadowed_line = source
            .lines()
            .enumerate()
            .filter_map(|(index, line)| {
                line.contains("re.match(MY_REG, name)").then_some(index + 1)
            })
            .last()
            .expect("shadowed pattern reference is present");
        assert!(
            facts.iter().any(|fact| {
                fact.kind == NormalizedKind::RegexIncomplete
                    && fact.range.start_line == shadowed_line
                    && fact
                        .construct
                        .as_deref()
                        .is_some_and(|reason| reason.starts_with("dynamic-pattern:"))
            }),
            "{facts:#?}"
        );
        assert!(
            facts.iter().any(|fact| {
                fact.kind == NormalizedKind::RegexRiskRange
                    && fact.range.start_line == line_with("U0001D173")
            }),
            "{facts:#?}"
        );
        assert!(
            facts.iter().any(|fact| {
                fact.kind == NormalizedKind::RegexRiskDuplicateClassCharacter
                    && fact.range.start_line == line_with("VERBOSE_REGEX =")
            }),
            "{facts:#?}"
        );
        assert!(
            facts.iter().any(|fact| {
                fact.kind == NormalizedKind::RegexRiskBadTag
                    && fact.range.start_line == line_with("<[a-z")
            }),
            "{facts:#?}"
        );
        let nested_flag_line = source
            .lines()
            .position(|line| line.contains("re.re.DOTALL"))
            .expect("upstream nested DOTALL flag case is present")
            + 1;
        assert!(facts.iter().any(|fact| {
            fact.kind == NormalizedKind::RegexRiskBadTag
                && fact.range.start_line == nested_flag_line
        }));
        let safe_line = source
            .lines()
            .position(|line| line.contains("(a|.)*"))
            .expect("safe redos control is present")
            + 1;
        assert!(!facts.iter().any(|fact| {
            fact.kind == NormalizedKind::RegexRiskExponential && fact.range.start_line == safe_line
        }));
        assert!(facts.iter().any(|fact| {
            fact.kind == NormalizedKind::RegexPattern
                && fact
                    .construct
                    .as_deref()
                    .is_some_and(|pattern| pattern.contains("very permissive"))
        }));
    }

    #[test]
    fn decodes_python_unknown_escapes_and_adjacent_literals_before_regex_parse() {
        let source = r#"import re
re.compile("\d" "\." r"\.")
"#;
        let facts = embedded_for_source(source);
        let pattern = facts
            .iter()
            .find(|fact| fact.kind == NormalizedKind::RegexPattern)
            .expect("selected compile call has a regex pattern fact");
        assert_eq!(pattern.construct.as_deref(), Some(r"\d\.\."));
        assert!(
            facts
                .iter()
                .any(|fact| fact.kind == NormalizedKind::RegexEscape)
        );
        assert!(
            !facts
                .iter()
                .any(|fact| fact.kind == NormalizedKind::RegexIncomplete)
        );
    }

    #[test]
    fn selects_only_recognized_pattern_arguments_and_marks_dynamic_values_incomplete() {
        let source = r#"import re
re.compile("selected")
re.sub("replacement", "pattern", "subject")
other.compile("unrecognized")
re.compile(pattern)
"#;
        let facts = embedded_for_source(source);
        let patterns = facts
            .iter()
            .filter(|fact| fact.kind == NormalizedKind::RegexPattern)
            .map(|fact| fact.construct.as_deref().expect("pattern stores value"))
            .collect::<Vec<_>>();
        assert_eq!(patterns, ["selected", "replacement"]);
        assert!(facts.iter().any(|fact| {
            fact.kind == NormalizedKind::RegexIncomplete
                && fact
                    .construct
                    .as_deref()
                    .is_some_and(|construct| construct.starts_with("dynamic-pattern:"))
        }));
        assert!(!patterns.contains(&"pattern"));
        assert!(!patterns.contains(&"subject"));
        assert!(!patterns.contains(&"unrecognized"));
    }

    #[test]
    fn supported_lookaround_groups_and_orphan_quantifiers_have_typed_facts() {
        let facts = embedded_for_source(
            "import re\nre.compile(r\"(?=lookahead)\")\nre.compile(r\"a$*\")\n",
        );
        assert!(facts.iter().any(|fact| {
            fact.kind == NormalizedKind::RegexGroup
                && fact.construct.as_deref() == Some("lookahead-positive")
        }));
        assert!(facts.iter().any(|fact| {
            fact.kind == NormalizedKind::RegexIncomplete
                && fact.construct.as_deref() == Some("quantifier-without-atom")
        }));
    }

    #[hardwon(
        "#4454: zero-width regex facts escaped their embedded parent and aborted workspace indexing"
    )]
    #[test]
    fn zero_width_regex_facts_stay_within_their_embedded_parents() {
        for (source, malformed) in [
            ("import re\nre.compile(r'^(v)(.*)()$')\n", false),
            ("import re\nre.subn(\"()\"r' am I'\"??\")\n", false),
            (
                "import re\nre.compile(r\"invalid literal for int().*: '?'?\")\n",
                false,
            ),
            ("import re\nre.compile(\"ab()+cd\")\n", false),
            ("import re\nre.sub('()x', r'\\g<0>\\g<0>', 'xx')\n", false),
            ("import re\nre.search('(', 'test')\n", true),
        ] {
            let facts = embedded_for_source(source);
            assert!(
                facts
                    .iter()
                    .any(|fact| fact.kind == NormalizedKind::RegexPattern),
                "source={source:?}; facts={facts:#?}"
            );
            for (fact_id, fact) in facts.iter().enumerate() {
                if let Some(parent) = fact.parent {
                    assert!(parent < fact_id, "source={source:?}; facts={facts:#?}");
                    let parent_fact = &facts[parent];
                    assert!(
                        parent_fact.range.start_byte <= fact.range.start_byte
                            && fact.range.end_byte <= parent_fact.range.end_byte,
                        "source={source:?}; fact={fact:#?}; parent={parent_fact:#?}"
                    );
                }
            }
            if !malformed {
                assert!(
                    facts.iter().any(|fact| {
                        fact.kind == NormalizedKind::RegexSequence
                            && fact.range.start_byte == fact.range.end_byte
                    }),
                    "source={source:?} retains its zero-width empty-group sequence; facts={facts:#?}"
                );
            }
            if malformed {
                assert!(
                    facts
                        .iter()
                        .any(|fact| fact.kind == NormalizedKind::RegexIncomplete),
                    "malformed pattern remains structurally unavailable; facts={facts:#?}"
                );
            }
        }
    }

    #[test]
    fn polynomial_redos_facts_cover_search_restarts_and_overlapping_repetitions() {
        for (source, expected) in [
            ("import re\nre.search(r'\\s+$', value)\n", true),
            ("import re\nre.search(r'^\\s+$', value)\n", false),
            ("import re\nre.search(r'^\\d+E?\\d+$', value)\n", true),
            ("import re\nre.search(r'^\\d+E\\d+$', value)\n", false),
            ("import re\nre.match(r'\\s+$', value)\n", false),
            ("import re\nre.compile(r'\\s+$')\n", false),
        ] {
            let facts = embedded_for_source(source);
            assert_eq!(
                facts
                    .iter()
                    .any(|fact| fact.kind == NormalizedKind::RegexRiskPolynomial),
                expected,
                "source={source:?}; facts={facts:#?}"
            );
        }
    }

    #[test]
    #[hardwon("#4443: an empty embedded regex sequence escaped its parent source range")]
    fn unquantified_empty_group_keeps_embedded_regex_facts_inside_parents() {
        let source = "import re\nre.search(r'function (no)?watchplus()', webpage)\n";
        let facts = embedded_for_source(source);
        assert!(
            facts
                .iter()
                .any(|fact| fact.kind == NormalizedKind::RegexPattern)
        );
        for (index, fact) in facts.iter().enumerate() {
            if let Some(parent) = fact.parent {
                assert!(parent < index, "{fact:?}");
                let parent_fact = &facts[parent];
                assert!(
                    parent_fact.range.start_byte <= fact.range.start_byte
                        && fact.range.end_byte <= parent_fact.range.end_byte,
                    "child {fact:?} is outside parent {parent_fact:?}"
                );
            }
        }
        let closing_paren = source.find("()'").expect("trailing empty group") + 1;
        assert!(facts.iter().any(|fact| {
            fact.kind == NormalizedKind::RegexSequence
                && fact.range.start_byte == closing_paren
                && fact.range.end_byte == closing_paren
        }));
    }
}
