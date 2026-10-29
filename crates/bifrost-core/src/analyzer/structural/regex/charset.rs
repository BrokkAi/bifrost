#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CharacterSet {
    pub ranges: Vec<(u32, u32)>,
}

impl CharacterSet {
    pub fn one(value: char) -> Self {
        let value = value as u32;
        Self {
            ranges: vec![(value, value)],
        }
    }

    pub fn any_except_newline() -> Self {
        Self {
            ranges: vec![(0, 9), (11, 0x10ffff)],
        }
    }

    pub fn complement(mut self) -> Self {
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

    pub fn union_with(&mut self, other: &Self) {
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

    pub fn intersects(&self, other: &Self) -> bool {
        self.ranges.iter().any(|(left_start, left_end)| {
            other
                .ranges
                .iter()
                .any(|(right_start, right_end)| left_start <= right_end && right_start <= left_end)
        })
    }

    pub fn contains(&self, character: char) -> bool {
        let value = character as u32;
        self.ranges
            .iter()
            .any(|(start, end)| *start <= value && value <= *end)
    }

    pub fn with_ascii_case_variants(mut self) -> Self {
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

pub(super) fn is_overly_broad_range(start: char, end: char) -> bool {
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

pub(super) fn codeql_range_character_set(start: char, end: char) -> CharacterSet {
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

pub fn single_character(set: &CharacterSet) -> Option<char> {
    let [(start, end)] = set.ranges.as_slice() else {
        return None;
    };
    (start == end).then(|| char::from_u32(*start)).flatten()
}
