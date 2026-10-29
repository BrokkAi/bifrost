use super::*;

pub struct RegexParser<'a> {
    pub(super) value: &'a str,
    pub(super) syntax: &'a dyn RegexSyntax,
    pub(super) flags: RegexFlags,
    pub(super) scans_from_each_offset: bool,
    pub(super) chars: Vec<char>,
    pub(super) index: usize,
    pub(super) facts: Vec<Fact>,
    pub(super) frames: Vec<BranchFrame>,
    pub(super) pending_risks: Vec<(NormalizedKind, usize, usize, usize, String)>,
    pub(super) incomplete: Option<(usize, usize, String)>,
    pub(super) exceeded: bool,
}

impl<'a> RegexParser<'a> {
    pub fn new(
        value: &'a str,
        flags: RegexFlags,
        scans_from_each_offset: bool,
        syntax: &'a dyn RegexSyntax,
    ) -> Self {
        Self {
            value,
            syntax,
            flags,
            scans_from_each_offset,
            chars: value.chars().collect(),
            index: 0,
            facts: Vec::new(),
            frames: Vec::new(),
            pending_risks: Vec::new(),
            incomplete: None,
            exceeded: false,
        }
    }

    pub fn parse(mut self) -> Vec<Fact> {
        let length = self.chars.len();
        if !self.flags.complete {
            self.mark_incomplete(0, length, "unsupported-regex-flags");
        }
        let pattern = self.add_fact(
            NormalizedKind::RegexPattern,
            0,
            length,
            None,
            Some(self.value.to_owned()),
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
                if self.syntax.verbose_whitespace(self.chars[self.index]) {
                    self.index += 1;
                    continue;
                }
                if self.chars[self.index] == '#' {
                    while self.index < length
                        && !self
                            .syntax
                            .verbose_comment_terminator(self.chars[self.index])
                    {
                        self.index += 1;
                    }
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
        self.classify_unmatchable_anchors();
        self.classify_hostname();
        self.syntax.analyze(&mut RegexAnalysis {
            value: self.value,
            flags: self.flags,
            chars: &self.chars,
            facts: &self.facts,
            pending_risks: &mut self.pending_risks,
            incomplete: &mut self.incomplete,
        });
        self.classify_polynomial_redos();
        self.classify_redos();
        self.append_pending_facts();
        if self.exceeded {
            return self.budget_result();
        }
        self.facts
    }

    pub(super) fn budget_result(&self) -> Vec<Fact> {
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
                escaped_literal: None,
                quantifier: None,
                minimum_width: None,
            },
        ]
    }

    pub(super) fn add_fact(
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
            escaped_literal: None,
            quantifier: None,
            minimum_width,
        });
        id
    }

    pub(super) fn mark_incomplete(&mut self, start: usize, end: usize, reason: &str) {
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
            match self.syntax.group_prefix(&self.chars, content_start) {
                GroupPrefix::Noncapturing => {
                    group_type = "noncapturing";
                    content_start += 2;
                }
                GroupPrefix::Named { name_offset } => {
                    group_type = "named-capturing";
                    let mut close = content_start + name_offset;
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
                GroupPrefix::Comment => {
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
                GroupPrefix::LookaheadPositive => {
                    group_type = "lookahead-positive";
                    content_start += 2;
                }
                GroupPrefix::LookaheadNegative => {
                    group_type = "lookahead-negative";
                    content_start += 2;
                }
                GroupPrefix::LookbehindPositive => {
                    group_type = "lookbehind-positive";
                    content_start += 3;
                }
                GroupPrefix::LookbehindNegative => {
                    group_type = "lookbehind-negative";
                    content_start += 3;
                }
                GroupPrefix::Flags => {
                    let flags_start = content_start + 1;
                    let Some((delimiter, flags)) =
                        self.syntax
                            .inline_flags(&self.chars, flags_start, self.flags)
                    else {
                        self.mark_incomplete(
                            start,
                            (start + 3).min(self.chars.len()),
                            "invalid-inline-flags",
                        );
                        self.index = (start + 3).min(self.chars.len());
                        return;
                    };
                    debug_assert!(flags.complete == self.flags.complete);
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
        } else {
            missing_special_group_end =
                self.syntax.incomplete_group_end(&self.chars, content_start);
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
        let set = self.syntax.fold_case(set, self.flags);
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
        let set = self.syntax.wildcard(self.flags);
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
        if self
            .facts
            .iter()
            .any(|fact| fact.parent == Some(atom) && fact.kind == NormalizedKind::RegexQuantifier)
        {
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
            if quantifier.possessive && !self.syntax.supports_possessive_quantifiers() {
                self.mark_incomplete(start, self.index + 1, "unsupported-possessive-quantifier");
            }
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
        let Some(escape) = self.syntax.escape(&self.chars, start, in_class, self.flags) else {
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
        let escaped_literal = escape.first_set.as_ref().and_then(single_character);
        let first_set = escape
            .first_set
            .map(|set| self.syntax.fold_case(set, self.flags));
        let fact = self.add_fact(
            kind,
            start,
            self.index,
            Some(self.current_sequence()),
            escape.construct,
            first_set,
        );
        self.facts[fact].escaped_literal = escaped_literal;
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
            let Some(left) = self.syntax.class_atom(&self.chars, self.index, self.flags) else {
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
                let Some(right) = self.syntax.class_atom(&self.chars, self.index, self.flags)
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
                let range_set = self.syntax.fold_case(range_set, self.flags);
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
                let semantic_set = left
                    .set
                    .as_ref()
                    .map(|set| self.syntax.fold_case(set.clone(), self.flags));
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
}
