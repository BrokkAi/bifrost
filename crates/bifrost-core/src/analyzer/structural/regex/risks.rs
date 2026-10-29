use super::*;

impl RegexParser<'_> {
    pub(super) fn sequence_first_set(&self, sequence: usize) -> Option<CharacterSet> {
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

    pub(super) fn branch_first_sets(&self, sequence: usize) -> Vec<Option<CharacterSet>> {
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

    pub(super) fn compute_minimum_widths(&mut self) {
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
                        .is_some_and(|construct| {
                            construct.starts_with("look") || construct == "comment"
                        }) {
                        Some(0)
                    } else {
                        sequence.and_then(|sequence| self.facts[sequence].minimum_width)
                    };
                    let minimum = self
                        .facts
                        .iter()
                        .find(|fact| {
                            fact.parent == Some(id) && fact.kind == NormalizedKind::RegexQuantifier
                        })
                        .and_then(|fact| fact.quantifier)
                        .map_or(1, |quantifier| quantifier.minimum);
                    self.facts[id].minimum_width = self.facts[id]
                        .minimum_width
                        .and_then(|width| width.checked_mul(minimum));
                }
                _ => {}
            }
        }
    }

    pub(super) fn sequence_minimum_width(&self, sequence: usize) -> Option<u32> {
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

    pub(super) fn classify_unmatchable_anchors(&mut self) {
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
            let branches = regex_sequence_branches(
                &self.facts,
                self.facts
                    .iter()
                    .enumerate()
                    .filter(|(_, fact)| fact.parent == Some(sequence))
                    .map(|(id, _)| id),
            );
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

    pub(super) fn classify_hostname(&mut self) {
        if self.incomplete.is_some() {
            return;
        }

        // Recognize hostname-LIKE values, not the intent of the regex's caller.
        // A wildcard is projected to a separator only while recognizing this
        // shape. Escaped dots and singleton dot classes consume the same shape
        // character but are not risks. The accepted path must contain the dot;
        // a suffix in another alternative cannot supply its hostname context.
        #[derive(Clone, Copy)]
        enum Token {
            Character(char),
            WildcardDot(usize),
            StartAnchor,
            EndAnchor,
        }
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        enum LabelEnd {
            AlphaOne,
            AlphaMany,
            Alphanumeric,
            Hyphen,
        }
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        enum Shape {
            Start,
            Prefix(&'static str),
            FirstLabel,
            NextLabel,
            Label(bool, LabelEnd),
            Slash,
            End,
        }
        impl Shape {
            fn accepts(self) -> bool {
                matches!(
                    self,
                    Self::Label(true, LabelEnd::AlphaMany) | Self::Slash | Self::End
                )
            }

            fn advance(self, token: Token) -> Vec<Self> {
                let character = match token {
                    Token::StartAnchor => {
                        return if self == Self::Start {
                            vec![self]
                        } else {
                            Vec::new()
                        };
                    }
                    Token::EndAnchor => {
                        return if self.accepts() {
                            vec![Self::End]
                        } else {
                            Vec::new()
                        };
                    }
                    Token::Character(character) => character,
                    Token::WildcardDot(_) => '.',
                };
                let first = if character.is_ascii_alphabetic() {
                    Some(LabelEnd::AlphaOne)
                } else if character.is_ascii_digit() {
                    Some(LabelEnd::Alphanumeric)
                } else {
                    None
                };
                match self {
                    Self::Start => {
                        let mut next = first
                            .map(|end| Self::Label(false, end))
                            .into_iter()
                            .collect::<Vec<_>>();
                        if character == 'h' {
                            next.extend([Self::Prefix("ttp://"), Self::Prefix("ttps://")]);
                        }
                        next
                    }
                    Self::Prefix(rest) => {
                        if rest.starts_with(character) {
                            let rest = &rest[character.len_utf8()..];
                            vec![if rest.is_empty() {
                                Self::FirstLabel
                            } else {
                                Self::Prefix(rest)
                            }]
                        } else {
                            Vec::new()
                        }
                    }
                    Self::FirstLabel | Self::NextLabel => first
                        .map(|end| Self::Label(self == Self::NextLabel, end))
                        .into_iter()
                        .collect(),
                    Self::Label(separated, end) => {
                        let next = if character.is_ascii_alphabetic() {
                            Some(Self::Label(
                                separated,
                                match end {
                                    LabelEnd::AlphaOne | LabelEnd::AlphaMany => LabelEnd::AlphaMany,
                                    LabelEnd::Alphanumeric | LabelEnd::Hyphen => {
                                        LabelEnd::Alphanumeric
                                    }
                                },
                            ))
                        } else if character.is_ascii_digit() {
                            Some(Self::Label(separated, LabelEnd::Alphanumeric))
                        } else if character == '-' {
                            Some(Self::Label(separated, LabelEnd::Hyphen))
                        } else if character == '.' && end != LabelEnd::Hyphen {
                            Some(Self::NextLabel)
                        } else if character == '/' && self.accepts() {
                            Some(Self::Slash)
                        } else {
                            None
                        };
                        next.into_iter().collect()
                    }
                    Self::Slash | Self::End => Vec::new(),
                }
            }
        }

        // Two boundaries per existing fact form an acyclic graph. Groups and
        // alternatives reuse their fact boundaries rather than expanding the
        // Cartesian product of label choices. Both the graph and its product
        // with the fixed-size Shape state set are bounded by MAX_PATTERN_FACTS.
        let mut children = vec![Vec::new(); self.facts.len()];
        for (id, fact) in self.facts.iter().enumerate() {
            if let Some(parent) = fact.parent {
                children[parent].push(id);
            }
        }
        let mut edges = vec![Vec::<(usize, Option<Token>)>::new(); self.facts.len() * 2];
        for (id, fact) in self.facts.iter().enumerate() {
            if children[id]
                .iter()
                .any(|&child| self.facts[child].kind == NormalizedKind::RegexQuantifier)
            {
                continue;
            }
            let start = id * 2;
            let end = start + 1;
            match fact.kind {
                NormalizedKind::RegexPattern | NormalizedKind::RegexGroup
                    if fact.kind == NormalizedKind::RegexPattern
                        || matches!(
                            fact.construct.as_deref(),
                            Some("capturing" | "named-capturing" | "noncapturing" | "scoped-flags")
                        ) =>
                {
                    for &sequence in &children[id] {
                        if self.facts[sequence].kind == NormalizedKind::RegexSequence {
                            edges[start].push((sequence * 2, None));
                            edges[sequence * 2 + 1].push((end, None));
                        }
                    }
                }
                NormalizedKind::RegexSequence => {
                    for branch in regex_sequence_branches(&self.facts, children[id].iter().copied())
                    {
                        let mut previous = start;
                        for child in branch {
                            edges[previous].push((child * 2, None));
                            previous = child * 2 + 1;
                        }
                        edges[previous].push((end, None));
                    }
                }
                _ => {
                    let token = match fact.kind {
                        NormalizedKind::RegexWildcard
                            if fact.construct.as_deref() == Some("dot") =>
                        {
                            Some(Token::WildcardDot(id))
                        }
                        NormalizedKind::RegexAnchor => match fact.construct.as_deref() {
                            Some("^" | "boundary:A") => Some(Token::StartAnchor),
                            Some("$" | "boundary:Z" | "boundary:z") => Some(Token::EndAnchor),
                            _ => None,
                        },
                        NormalizedKind::RegexLiteral => {
                            fact.construct.as_deref().and_then(|value| {
                                let mut chars = value.chars();
                                let first = chars.next()?;
                                chars.next().is_none().then_some(Token::Character(first))
                            })
                        }
                        NormalizedKind::RegexEscape => fact.escaped_literal.map(Token::Character),
                        NormalizedKind::RegexCharacterClass => fact
                            .first_set
                            .as_ref()
                            .and_then(single_character)
                            .map(Token::Character),
                        _ => None,
                    };
                    if let Some(token) = token {
                        edges[start].push((end, Some(token)));
                    }
                }
            }
        }
        let start = (0, Shape::Start);
        let mut reverse = HashMap::<_, Vec<(_, Option<usize>)>>::from([(start, Vec::new())]);
        let mut pending = VecDeque::from([start]);
        while let Some((boundary, shape)) = pending.pop_front() {
            for &(target, token) in &edges[boundary] {
                let next_shapes = token.map_or_else(|| vec![shape], |token| shape.advance(token));
                let risk = match token {
                    Some(Token::WildcardDot(id)) => Some(id),
                    _ => None,
                };
                for next_shape in next_shapes {
                    let next = (target, next_shape);
                    let newly_seen = !reverse.contains_key(&next);
                    reverse
                        .entry(next)
                        .or_default()
                        .push(((boundary, shape), risk));
                    if newly_seen {
                        pending.push_back(next);
                    }
                }
            }
        }
        let mut pending = reverse
            .keys()
            .copied()
            .filter(|&(boundary, shape)| boundary == 1 && shape.accepts())
            .collect::<Vec<_>>();
        let mut visited = HashSet::new();
        let mut risks = HashSet::new();
        while let Some(node) = pending.pop() {
            if !visited.insert(node) {
                continue;
            }
            for &(previous, risk) in &reverse[&node] {
                risks.extend(risk);
                pending.push(previous);
            }
        }
        let mut risks = risks.into_iter().collect::<Vec<_>>();
        risks.sort_unstable();
        for dot in risks {
            let fact = &self.facts[dot];
            self.pending_risks.push((
                NormalizedKind::RegexRiskHostname,
                dot,
                fact.start,
                fact.end,
                "unescaped-dot-in-hostname-like-pattern".to_owned(),
            ));
        }
    }

    pub(super) fn classify_polynomial_redos(&mut self) {
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
                if !self.syntax.case_folding_is_complete(self.flags) && !repeated.is_empty() {
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

                if risky_quantifier.is_none() && self.scans_from_each_offset {
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

    pub(super) fn has_rejecting_suffix(&self, repeated_group: usize) -> bool {
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

    pub(super) fn suffix_is_covered_by_repeated_body(&self, repeated_group: usize) -> bool {
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

    pub(super) fn classify_redos(&mut self) {
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
                if !self.syntax.case_folding_is_complete(self.flags) {
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
                if !self.syntax.case_folding_is_complete(self.flags) {
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

    pub(super) fn is_descendant(&self, mut fact: usize, ancestor: usize) -> bool {
        while let Some(parent) = self.facts[fact].parent {
            if parent == ancestor {
                return true;
            }
            fact = parent;
        }
        false
    }

    pub(super) fn append_pending_facts(&mut self) {
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
