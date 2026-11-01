use super::*;

#[derive(Debug, Clone, Default)]
pub(super) struct NfaState {
    pub(super) epsilon: Vec<usize>,
    pub(super) transitions: Vec<(CharacterSet, usize)>,
    pub(super) capture_ends: Vec<usize>,
    /// Possessive exit: the first character consumed after leaving this state
    /// through epsilon edges is outside this set. Only the builder sets it, on
    /// states without transitions; `compile` lowers it before returning.
    pub(super) guard: Option<CharacterSet>,
}

#[derive(Debug, Clone)]
struct NfaFragment {
    pub(super) start: usize,
    pub(super) end: usize,
    pub(super) states: Vec<usize>,
}

#[derive(Debug)]
pub struct RegexNfa {
    pub(super) states: Vec<NfaState>,
    pub(super) start: usize,
    pub(super) end: usize,
}

#[derive(Debug, Clone, Copy)]
pub enum NfaError {
    Unsupported,
    Budget,
}

impl RegexNfa {
    pub fn compile(
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
        builder.lower_possessive_guards(fragment.end)?;
        Ok(Self {
            states: builder.states,
            start: fragment.start,
            end: fragment.end,
        })
    }

    pub fn match_prefix_capture_groups(&self, sample: &str) -> (bool, HashSet<usize>) {
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

    pub(super) fn intersects_on_nonempty_string(
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

    pub(super) fn has_repartitioned_prefix(
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

    pub(super) fn has_pumpable_fork(&self, remaining_budget: &mut usize) -> Result<bool, NfaError> {
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

    pub(super) fn epsilon_closures(&self) -> Vec<Vec<usize>> {
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

    pub(super) fn product_reaches_fork(
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

    /// Repeats the automaton one or more times. Possessive guards were lowered
    /// against the old end, so a guard does not constrain the next repetition:
    /// the closure may accept more ambiguous paths than the dialect does.
    pub(super) fn positive_closure(mut self) -> Result<Self, NfaError> {
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

pub(super) struct NfaBuilder<'a> {
    pub(super) facts: &'a [Fact],
    pub(super) children: Vec<Vec<usize>>,
    pub(super) selected_branch: Option<(usize, usize)>,
    pub(super) capture_ids: &'a [Option<usize>],
    pub(super) states: Vec<NfaState>,
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
        let branches = regex_sequence_branches(self.facts, self.children[sequence].iter().copied())
            .into_iter()
            .map(|terms| {
                let terms = terms
                    .into_iter()
                    .filter(|&child| self.facts[child].kind != NormalizedKind::RegexQuantifier)
                    .map(|child| fragments[child].clone().ok_or(NfaError::Unsupported))
                    .collect::<Result<Vec<_>, _>>()?;
                self.concatenate(terms)
            })
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
        // A possessive repetition never gives back what it consumed, so it
        // stops early only where the next character cannot repeat it. That is
        // a character-set guard when one repetition consumes one character
        // from a known set; other possessive bodies are not modeled.
        let guard = if quantifier.possessive {
            let body = &self.facts[id];
            if !matches!(
                body.kind,
                NormalizedKind::RegexLiteral
                    | NormalizedKind::RegexWildcard
                    | NormalizedKind::RegexCharacterClass
                    | NormalizedKind::RegexCharacterRange
                    | NormalizedKind::RegexEscape
            ) {
                return Err(NfaError::Unsupported);
            }
            Some(body.first_set.clone().ok_or(NfaError::Unsupported)?)
        } else {
            None
        };
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
                    copies.push(self.optional(clone, guard.clone())?);
                }
                None
            }
            None => {
                let clone = self.clone_fragment(&base)?;
                Some(self.star(clone, guard)?)
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

    /// Replaces each guarded state's epsilon edges with copies of the states
    /// they reach, whose transitions exclude the guard. A copy accumulates
    /// the guards of guarded states it passes, and `end` stands for whatever
    /// follows the compiled root, which a guard here cannot see.
    fn lower_possessive_guards(&mut self, end: usize) -> Result<(), NfaError> {
        debug_assert!(
            self.states[end].epsilon.is_empty() && self.states[end].transitions.is_empty(),
            "the root end has no successors while compiling"
        );
        let guarded = (0..self.states.len())
            .filter(|&state| self.states[state].guard.is_some())
            .collect::<Vec<_>>();
        let mut copies = HashMap::new();
        let mut pending = Vec::new();
        for state in guarded {
            let guard = self.states[state].guard.take().expect("state is guarded");
            debug_assert!(self.states[state].transitions.is_empty());
            let successors = std::mem::take(&mut self.states[state].epsilon);
            for successor in successors {
                let copy = self.guarded_copy(successor, &guard, end, &mut copies, &mut pending)?;
                self.states[state].epsilon.push(copy);
            }
            while let Some((original, copy, exclusion)) = pending.pop() {
                let original = self.states[original].clone();
                let mut after = exclusion.clone();
                if let Some(guard) = &original.guard {
                    after.union_with(guard);
                }
                for (set, target) in original.transitions {
                    let allowed = set.difference(&exclusion);
                    if !allowed.ranges.is_empty() {
                        self.states[copy].transitions.push((allowed, target));
                    }
                }
                self.states[copy].capture_ends = original.capture_ends;
                for successor in original.epsilon {
                    let successor =
                        self.guarded_copy(successor, &after, end, &mut copies, &mut pending)?;
                    self.states[copy].epsilon.push(successor);
                }
            }
        }
        Ok(())
    }

    fn guarded_copy(
        &mut self,
        original: usize,
        exclusion: &CharacterSet,
        end: usize,
        copies: &mut HashMap<(usize, CharacterSet), usize>,
        pending: &mut Vec<(usize, usize, CharacterSet)>,
    ) -> Result<usize, NfaError> {
        if original == end {
            return Ok(end);
        }
        if let Some(&copy) = copies.get(&(original, exclusion.clone())) {
            return Ok(copy);
        }
        let copy = self.new_state()?;
        copies.insert((original, exclusion.clone()), copy);
        pending.push((original, copy, exclusion.clone()));
        Ok(copy)
    }

    pub(super) fn new_state(&mut self) -> Result<usize, NfaError> {
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

    /// `guard` constrains the skip edge of a possessive optional copy.
    fn optional(
        &mut self,
        inner: NfaFragment,
        guard: Option<CharacterSet>,
    ) -> Result<NfaFragment, NfaError> {
        let start = self.new_state()?;
        let end = self.new_state()?;
        let mut states = vec![start, end];
        let skip = self.exit(end, guard, &mut states)?;
        self.states[start].epsilon.extend([skip, inner.start]);
        self.states[inner.end].epsilon.push(end);
        states.extend(inner.states);
        Ok(NfaFragment { start, end, states })
    }

    /// `guard` constrains the exit edges of a possessive loop.
    fn star(
        &mut self,
        inner: NfaFragment,
        guard: Option<CharacterSet>,
    ) -> Result<NfaFragment, NfaError> {
        let start = self.new_state()?;
        let end = self.new_state()?;
        let mut states = vec![start, end];
        let exit = self.exit(end, guard, &mut states)?;
        self.states[start].epsilon.extend([exit, inner.start]);
        self.states[inner.end].epsilon.extend([exit, inner.start]);
        states.extend(inner.states);
        Ok(NfaFragment { start, end, states })
    }

    /// The state an exit edge targets: `end` itself, or a guarded state
    /// leading to it.
    fn exit(
        &mut self,
        end: usize,
        guard: Option<CharacterSet>,
        states: &mut Vec<usize>,
    ) -> Result<usize, NfaError> {
        let Some(guard) = guard else {
            return Ok(end);
        };
        let exit = self.new_state()?;
        self.states[exit].guard = Some(guard);
        self.states[exit].epsilon.push(end);
        states.push(exit);
        Ok(exit)
    }

    fn clone_fragment(&mut self, fragment: &NfaFragment) -> Result<NfaFragment, NfaError> {
        let mut remap = vec![usize::MAX; self.states.len()];
        for &old in &fragment.states {
            remap[old] = self.new_state()?;
        }
        for &old in &fragment.states {
            let new = remap[old];
            let old_state = self.states[old].clone();
            self.states[new].capture_ends = old_state.capture_ends;
            self.states[new].guard = old_state.guard;
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
