//! C# preprocessor-directive-aware parsing.
//!
//! The tree-sitter C# grammar accepts preprocessor directives only at statement
//! and declaration boundaries. A directive inside a declaration -- a modifier
//! list split across `#if NET` / `#else`, or a `#if` inside a ternary
//! expression -- breaks the parse and Bifrost loses every declaration after the
//! break (issue #1803).
//!
//! This module computes, per file, the tree-sitter "included ranges" that hide
//! every directive line and every inactive conditional branch from the parser.
//! Node offsets still refer to the original file, so no transformed source ever
//! exists and cache identity stays the raw checkout bytes.
//!
//! Branch selection follows compilation environments and file-local symbol
//! assignments. Undecided chains retain their earliest possibly active branch
//! and carry structured uncertainty through every consumer.
//!
//! The line scanner here is a lexical pre-pass, not a fallback for missing
//! structure: before it runs there is no tree, and a real C# lexer likewise
//! handles directives before the syntactic grammar.

use brokk_bifrost_core::analyzer::common::{advance_ts_point, parse_source_with_cancellation};
use brokk_bifrost_core::analyzer::usages::parsed_tree::ParseSpec;
use brokk_bifrost_core::cancellation::CancellationToken;

/// What a consumer is told when a file's index is partial because a
/// conditional branch was excluded from the parse.
///
/// The exact wording is part of the contract: hosts match on it.
pub const CSHARP_INACTIVE_BRANCHES_DETAIL: &str =
    "conditional compilation: inactive branches excluded from the index";

/// The result of scanning one C# file for preprocessor directives.
#[derive(Debug)]
pub struct PreprocessorScan {
    pub decisions: PreprocessorDecisions,
    /// Byte ranges the parser may read, or `None` when the file has no
    /// directives at all and must simply be parsed whole.
    pub included_ranges: Option<Vec<tree_sitter::Range>>,
    /// True when at least one conditional branch was excluded, which means the
    /// extraction for this file is partial by construction.
    pub has_inactive_regions: bool,
    /// Conditional directives and their branch spans, including skipped text.
    pub branches: Vec<ConditionalBranch>,
    /// File-local symbol assignments, in source order.
    pub symbol_directives: Vec<SymbolDirective>,
}

impl brokk_bifrost_core::analyzer::prepared_syntax::SourcePreprocessor for PreprocessorScan {
    fn included_ranges(&self) -> Option<&[tree_sitter::Range]> {
        self.included_ranges.as_deref()
    }
    fn conditional_regions(
        &self,
        source: &str,
    ) -> brokk_bifrost_core::analyzer::structural::conditional_regions::ConditionalRegions {
        self.conditional_regions(source)
    }
    fn estimated_retained_bytes(&self) -> usize {
        let strings = |set: &std::collections::BTreeSet<String>| {
            set.iter().map(|s| 64 + s.capacity()).sum::<usize>()
        };
        std::mem::size_of::<Self>()
            + self.included_ranges.as_ref().map_or(0, |r| {
                r.capacity() * std::mem::size_of::<tree_sitter::Range>()
            })
            + self.branches.capacity() * std::mem::size_of::<ConditionalBranch>()
            + self
                .branches
                .iter()
                .map(|b| b.condition.capacity() + b.directive.capacity())
                .sum::<usize>()
            + self.symbol_directives.capacity() * std::mem::size_of::<SymbolDirective>()
            + self
                .symbol_directives
                .iter()
                .map(|d| d.symbol.capacity())
                .sum::<usize>()
            + self.decisions.chains.capacity() * std::mem::size_of::<ChainDecision>()
            + strings(&self.decisions.referenced_symbols)
            + self
                .decisions
                .chains
                .iter()
                .map(|d| match d {
                    ChainDecision::Decided(_) => 0,
                    ChainDecision::Undecided(r) => {
                        strings(&r.unknown_symbols)
                            + strings(&r.open_reasons)
                            + r.disagreeing_owners.capacity() * std::mem::size_of::<String>()
                            + r.disagreeing_owners
                                .iter()
                                .map(String::capacity)
                                .sum::<usize>()
                    }
                })
                .sum::<usize>()
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// One branch of a conditional chain. Offsets refer to the original source.
#[derive(Debug, Clone)]
pub struct ConditionalBranch {
    pub chain: usize,
    pub directive_start: usize,
    pub directive_end: usize,
    pub end_byte: usize,
    pub condition: String,
    /// The directive keyword is retained even for an unconditional else branch.
    pub directive: String,
    /// The closing endif range on the chain's final branch, when present.
    pub closing_directive: Option<(usize, usize)>,
    pub kept: bool,
    /// Whether all owners prove this branch unreachable.
    pub definitely_inactive: bool,
}

impl PreprocessorScan {
    /// Activation comes from the same decisions that selected the parser ranges.
    pub fn chain_activations(
        &self,
    ) -> Vec<brokk_bifrost_core::analyzer::structural::conditional_regions::ChainActivation> {
        use brokk_bifrost_core::analyzer::structural::conditional_regions::{
            ConditionValue, chain_activation,
        };
        self.decisions
            .chains
            .iter()
            .map(|decision| match decision {
                ChainDecision::Decided(index) => chain_activation(
                    (0..=index.unwrap_or(0)).map(|i| ConditionValue::Decided(Some(i) == *index)),
                ),
                ChainDecision::Undecided(_) => chain_activation([ConditionValue::Unknown]),
            })
            .collect()
    }

    pub fn conditional_regions(
        &self,
        source: &str,
    ) -> brokk_bifrost_core::analyzer::structural::conditional_regions::ConditionalRegions {
        use brokk_bifrost_core::analyzer::structural::conditional_regions::{
            Activation, ConditionalRegion, ConditionalRegions,
        };
        let chains = self.chain_activations();
        let mut indices = vec![0; chains.len()];
        let mut regions = Vec::new();
        for branch in &self.branches {
            let index = &mut indices[branch.chain];
            let activation = chains[branch.chain].branch(*index, brokk_bifrost_core::analyzer::structural::conditional_regions::ConditionValue::Decided(!branch.definitely_inactive));
            *index += 1;
            regions.push(ConditionalRegion {
                range: branch.directive_end..branch.end_byte,
                activation,
                omitted: !branch.kept,
            });
            regions.push(ConditionalRegion {
                range: branch.directive_start..branch.directive_end,
                activation: Activation::DecidedInactive,
                omitted: false,
            });
            if let Some((start, end)) = branch.closing_directive {
                regions.push(ConditionalRegion {
                    range: start..end,
                    activation: Activation::DecidedInactive,
                    omitted: false,
                });
            }
        }
        ConditionalRegions::new(regions, source)
    }
}

/// The symbols supplied by one owning compilation. An open environment's
/// producer must list in `defined` only symbols defined under every evaluation
/// of its unknown parts (for example, proven implicit framework symbols).
/// Missing symbols in an open environment are unknown. In a closed environment
/// every missing symbol is false. Explicit file-local undefinitions remain false.
/// The empty compilation key and `no_owning_compilation` reason are reserved for
/// the evaluator's synthetic no-owner environment. Real owners use non-empty
/// compilation keys and discovery's fixed set of open reason labels.
#[derive(Debug, Clone)]
pub struct SymbolEnvironment {
    pub compilation_key: String,
    pub defined: std::collections::BTreeSet<String>,
    pub closed: bool,
    pub open_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainDecision {
    /// Branch indices are local to the chain. None means no branch executes
    /// (including chains nested inside a definitely inactive branch).
    Decided(Option<usize>),
    Undecided(DecisionReason),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DecisionReason {
    pub unknown_symbols: std::collections::BTreeSet<String>,
    pub open_reasons: std::collections::BTreeSet<String>,
    pub disagreeing_owners: Vec<String>,
    pub invalid_condition: bool,
}

#[derive(Debug, Clone)]
pub struct PreprocessorDecisions {
    pub chains: Vec<ChainDecision>,
    pub referenced_symbols: std::collections::BTreeSet<String>,
    pub decision_digest: [u8; 32],
    pub assignment_digest: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct SymbolDirective {
    pub offset: usize,
    pub symbol: String,
    pub defined: bool,
}

// A flat shunting-yard program avoids recursion both in parsing and evaluation.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ExpressionOp {
    Open,
    Not,
    Equal,
    Unequal,
    And,
    Or,
}
impl ExpressionOp {
    fn precedence(self) -> u8 {
        match self {
            Self::Open => 0,
            Self::Or => 1,
            Self::And => 2,
            Self::Equal | Self::Unequal => 3,
            Self::Not => 4,
        }
    }
    fn apply(self, values: &mut Vec<Option<bool>>) -> Option<()> {
        let right = values.pop()?;
        let value = if self == Self::Not {
            right.map(|v| !v)
        } else {
            let left = values.pop()?;
            match self {
                Self::And if left == Some(false) || right == Some(false) => Some(false),
                Self::Or if left == Some(true) || right == Some(true) => Some(true),
                Self::And => left.zip(right).map(|(a, b)| a && b),
                Self::Or => left.zip(right).map(|(a, b)| a || b),
                Self::Equal => left.zip(right).map(|(a, b)| a == b),
                Self::Unequal => left.zip(right).map(|(a, b)| a != b),
                _ => return None,
            }
        };
        values.push(value);
        Some(())
    }
}

/// Consume one identifier from the directive expression's lexical subset.
fn condition_identifier(text: &str) -> Option<(&str, &str)> {
    let end = text
        .char_indices()
        .take_while(|&(i, c)| c == '_' || c.is_alphabetic() || (i > 0 && c.is_ascii_digit()))
        .map(|(i, c)| i + c.len_utf8())
        .last()?;
    Some(text.split_at(end))
}

fn evaluate_condition(
    text: &str,
    lookup: impl Fn(&str) -> Option<bool>,
    symbols: &mut std::collections::BTreeSet<String>,
) -> (Option<bool>, bool) {
    let mut values = Vec::new();
    let mut operators = Vec::new();
    let mut rest = text;
    let mut operand = true;
    let parsed = (|| {
        loop {
            rest = rest.trim_start();
            if rest.is_empty() || rest.starts_with("//") {
                break;
            }
            if operand {
                if let Some(next) = rest.strip_prefix('!') {
                    operators.push(ExpressionOp::Not);
                    rest = next;
                    continue;
                }
                if let Some(next) = rest.strip_prefix('(') {
                    operators.push(ExpressionOp::Open);
                    rest = next;
                    continue;
                }
                let (name, next) = condition_identifier(rest)?;
                values.push(match name {
                    "true" => Some(true),
                    "false" => Some(false),
                    _ => {
                        symbols.insert(name.to_owned());
                        lookup(name)
                    }
                });
                rest = next;
                operand = false;
            } else if let Some(next) = rest.strip_prefix(')') {
                while operators.last().is_some_and(|op| *op != ExpressionOp::Open) {
                    operators.pop()?.apply(&mut values)?;
                }
                if operators.pop()? != ExpressionOp::Open {
                    return None;
                }
                rest = next;
            } else {
                let (token, op) = [
                    ("==", ExpressionOp::Equal),
                    ("!=", ExpressionOp::Unequal),
                    ("&&", ExpressionOp::And),
                    ("||", ExpressionOp::Or),
                ]
                .into_iter()
                .find(|(token, _)| rest.starts_with(token))?;
                while operators
                    .last()
                    .is_some_and(|top| top.precedence() >= op.precedence())
                {
                    operators.pop()?.apply(&mut values)?;
                }
                operators.push(op);
                rest = &rest[token.len()..];
                operand = true;
            }
        }
        if operand {
            return None;
        }
        while let Some(op) = operators.pop() {
            op.apply(&mut values)?;
        }
        if values.len() != 1 {
            return None;
        }
        values.pop()
    })();
    match parsed {
        Some(value) => (value, false),
        None => (None, true),
    }
}

struct OwnerState<'a> {
    owner: &'a SymbolEnvironment,
    local: std::collections::HashMap<String, Option<bool>>,
    decisions: Vec<ChainDecision>,
    remaining: Vec<Option<bool>>,
    active: Vec<Option<bool>>,
}
impl OwnerState<'_> {
    fn lookup(&self, name: &str) -> Option<bool> {
        self.local.get(name).copied().unwrap_or_else(|| {
            if self.owner.defined.contains(name) {
                Some(true)
            } else if self.owner.closed {
                Some(false)
            } else {
                None
            }
        })
    }
    fn branch(
        &mut self,
        chain: usize,
        index: usize,
        parent: Option<usize>,
        condition: Option<&str>,
    ) {
        let parent_active = parent.map_or(Some(true), |p| self.active[p]);
        while self.decisions.len() <= chain {
            self.decisions.push(ChainDecision::Decided(None));
            self.remaining.push(Some(true));
            self.active.push(Some(false));
        }
        if self.remaining[chain] == Some(false) || parent_active == Some(false) {
            self.active[chain] = Some(false);
            return;
        }
        let mut used = std::collections::BTreeSet::new();
        let (value, invalid) = match condition {
            None => (Some(true), false),
            Some(condition) => evaluate_condition(condition, |name| self.lookup(name), &mut used),
        };
        self.active[chain] = if value == Some(false) {
            Some(false)
        } else if parent_active.is_none() || self.remaining[chain].is_none() {
            None
        } else {
            value
        };
        if parent_active.is_none() || self.remaining[chain].is_none() || value.is_none() {
            let mut reason = match &self.decisions[chain] {
                ChainDecision::Undecided(r) => r.clone(),
                _ => DecisionReason::default(),
            };
            if let Some(p) = parent
                && let ChainDecision::Undecided(r) = &self.decisions[p]
            {
                reason.unknown_symbols.extend(r.unknown_symbols.clone());
                reason.open_reasons.extend(r.open_reasons.clone());
                reason.invalid_condition |= r.invalid_condition;
            }
            reason
                .unknown_symbols
                .extend(used.into_iter().filter(|name| self.lookup(name).is_none()));
            reason.invalid_condition |= invalid;
            if let Some(label) = &self.owner.open_reason {
                reason.open_reasons.insert(label.clone());
            }
            self.decisions[chain] = ChainDecision::Undecided(reason);
            self.remaining[chain] = None;
        } else if value == Some(true) {
            self.decisions[chain] = ChainDecision::Decided(Some(index));
            self.remaining[chain] = Some(false);
        }
    }
}

fn merge_decision(owners: &[OwnerState<'_>], chain: usize) -> ChainDecision {
    let first = &owners[0].decisions[chain];
    if matches!(first, ChainDecision::Decided(_))
        && owners.iter().all(|o| &o.decisions[chain] == first)
    {
        return first.clone();
    }
    let mut reason = DecisionReason::default();
    let mut decided = Vec::new();
    for owner in owners {
        match &owner.decisions[chain] {
            ChainDecision::Undecided(r) => {
                reason.unknown_symbols.extend(r.unknown_symbols.clone());
                reason.open_reasons.extend(r.open_reasons.clone());
                reason.invalid_condition |= r.invalid_condition;
            }
            ChainDecision::Decided(outcome) => decided.push((owner.owner, outcome)),
        }
    }
    if decided
        .first()
        .is_some_and(|(_, first)| decided.iter().any(|(_, outcome)| outcome != first))
    {
        reason.disagreeing_owners = decided
            .iter()
            .map(|(owner, _)| owner.compilation_key.clone())
            .collect();
    }
    ChainDecision::Undecided(reason)
}

fn finish_decisions(
    owners: &[OwnerState<'_>],
    count: usize,
    referenced_symbols: std::collections::BTreeSet<String>,
) -> PreprocessorDecisions {
    use brokk_bifrost_core::analyzer::canonical_hash::CanonicalHasher;
    let mut assignment = CanonicalHasher::new(b"csharp-preprocessor-assignment-v1");
    for state in owners.iter().filter(|_| count != 0) {
        let owner = state.owner;
        assignment.value(owner.compilation_key.as_bytes());
        assignment.value(&[u8::from(owner.closed)]);
        assignment.value(&[u8::from(owner.open_reason.is_some())]);
        if let Some(reason) = &owner.open_reason {
            assignment.value(reason.as_bytes());
        }
        for symbol in &referenced_symbols {
            assignment.value(symbol.as_bytes());
            assignment.value(&[if owner.defined.contains(symbol) {
                1
            } else if owner.closed {
                0
            } else {
                2
            }]);
        }
    }
    let chains: Vec<_> = (0..count)
        .map(|chain| {
            if owners[0].decisions.len() <= chain {
                ChainDecision::Decided(None)
            } else {
                merge_decision(owners, chain)
            }
        })
        .collect();
    let mut digest = CanonicalHasher::new(b"csharp-preprocessor-decisions-v1");
    for decision in &chains {
        match decision {
            ChainDecision::Decided(index) => {
                digest.value(b"decided");
                digest.value(&index.map(|i| i as u64).unwrap_or(u64::MAX).to_be_bytes());
            }
            ChainDecision::Undecided(r) => {
                digest.value(b"undecided");
                let symbols: Vec<_> = r.unknown_symbols.iter().collect();
                digest.sequence("symbols", &symbols, |h, s| h.value(s.as_bytes()));
                let reasons: Vec<_> = r.open_reasons.iter().collect();
                digest.sequence("reasons", &reasons, |h, s| h.value(s.as_bytes()));
                digest.sequence("owners", &r.disagreeing_owners, |h, s| {
                    h.value(s.as_bytes())
                });
                digest.value(&[u8::from(r.invalid_condition)]);
            }
        }
    }
    PreprocessorDecisions {
        chains,
        referenced_symbols,
        decision_digest: digest.finish(),
        assignment_digest: assignment.finish(),
    }
}
/// Lexical mode carried across lines while scanning for directive lines.
///
/// C# directives are recognized only when the lexer is outside comments and
/// strings, so the scanner must know which construct spans a line boundary.
#[derive(Clone, Copy, PartialEq, Eq)]
enum LexMode {
    Normal,
    BlockComment,
    /// `@"..."`, closed by a `"` that is not doubled.
    VerbatimString,
    /// `"""..."""`, closed by a run of at least this many quotes.
    RawString(usize),
}

/// One entry of the `#if` / `#elif` / `#else` / `#endif` stack.
#[derive(Clone, Copy)]
struct ChainState {
    chain: usize,
    index: usize,
    /// True when the branch currently open emits source.
    branch_active: bool,
    /// True once some branch of this chain has been chosen as the active one.
    chosen: bool,
    /// True when the region enclosing this whole chain is active.
    parent_active: bool,
}

/// Scan and decide in one source-order pass over the original bytes.
///
/// The default reading keeps the earliest branch whose merged reachability is
/// not definitely false. Later branches never revise that choice.
/// In a compiling configuration no multi-line input element spans a directive
/// recognized in that owner's reading: a directive inside a comment or string
/// would not be recognized and the chain would not terminate. Thus recognized
/// directives start in a clean lexical state, and one lexical mode following
/// the merged reading is consistent for all owners. Differing readings are
/// confined to branches of undecided chains. Noncompiling configurations are
/// outside this contract; the default reading retains the undecided obligation.
pub fn scan_and_decide_preprocessor(
    source: &str,
    owners: &[SymbolEnvironment],
) -> PreprocessorScan {
    let unowned = SymbolEnvironment {
        compilation_key: String::new(),
        defined: Default::default(),
        closed: false,
        open_reason: Some("no_owning_compilation".to_owned()),
    };
    let mut owners: Vec<_> = owners.iter().collect();
    owners.sort_by(|a, b| a.compilation_key.cmp(&b.compilation_key));
    assert!(owners.iter().all(|o| !o.compilation_key.is_empty()));
    assert!(
        owners
            .windows(2)
            .all(|w| w[0].compilation_key != w[1].compilation_key)
    );
    if owners.is_empty() {
        owners.push(&unowned);
    }
    let mut owners: Vec<_> = owners
        .into_iter()
        .map(|owner| OwnerState {
            owner,
            local: Default::default(),
            decisions: Vec::new(),
            remaining: Vec::new(),
            active: Vec::new(),
        })
        .collect();
    let mut referenced_symbols = std::collections::BTreeSet::new();
    let bytes = source.as_bytes();
    let mut mode = LexMode::Normal;
    let mut stack: Vec<ChainState> = Vec::new();
    let mut branches: Vec<ConditionalBranch> = Vec::new();
    let mut branch_stack: Vec<usize> = Vec::new();
    let mut symbol_directives = Vec::new();
    let mut next_chain = 0;
    let mut any_directive = false;
    let mut has_inactive_regions = false;
    // Byte spans that stay in the parse, accumulated as [start, end) pairs.
    let mut kept: Vec<(usize, usize)> = Vec::new();
    // A byte-order mark is not source text: the compiler reads past it before
    // it recognizes a directive, so `\u{feff}#if` opens a conditional. The
    // grammar skips the mark too, so leaving it out of the ranges loses nothing.
    let mut line_start = if source.starts_with('\u{feff}') {
        '\u{feff}'.len_utf8()
    } else {
        0
    };

    while line_start <= source.len() {
        let line_end = match bytes[line_start..].iter().position(|&b| b == b'\n') {
            Some(offset) => line_start + offset + 1,
            None => source.len(),
        };
        let line = &source[line_start..line_end];
        let region_active = stack.last().is_none_or(|state| state.branch_active);

        let is_directive = mode == LexMode::Normal && line.trim_start().starts_with('#');
        if is_directive {
            any_directive = true;
            let body = line.trim().trim_start_matches('#').trim_start();
            let (keyword, condition) = body.split_once(char::is_whitespace).unwrap_or((body, ""));
            if matches!(keyword, "elif" | "else" | "endif")
                && let Some(previous) = branch_stack.pop()
            {
                branches[previous].end_byte = line_start;
                if keyword == "endif" {
                    branches[previous].closing_directive = Some((line_start, line_end));
                }
                if keyword != "endif" {
                    branch_stack.push(previous);
                }
            }
            if matches!(keyword, "define" | "undef") {
                let symbol = condition.split("//").next().unwrap_or("").trim();
                let directive = SymbolDirective {
                    offset: line_start,
                    symbol: symbol.to_owned(),
                    defined: keyword == "define",
                };
                for owner in &mut owners {
                    let active = stack
                        .last()
                        .map_or(Some(true), |state| owner.active[state.chain]);
                    if active != Some(false) {
                        owner
                            .local
                            .insert(directive.symbol.clone(), active.map(|_| directive.defined));
                    }
                }
                symbol_directives.push(directive);
            }
            match keyword {
                "if" => {
                    let chain = next_chain;
                    let parent = stack.last().map(|s| s.chain);
                    for owner in &mut owners {
                        owner.branch(chain, 0, parent, Some(condition));
                    }
                    let active =
                        region_active && owners.iter().any(|o| o.active[chain] != Some(false));
                    stack.push(ChainState {
                        chain,
                        index: 0,
                        branch_active: active,
                        chosen: active,
                        parent_active: region_active,
                    });
                }
                "elif" | "else" => {
                    let parent = stack.iter().rev().nth(1).map(|s| s.chain);
                    if let Some(state) = stack.last_mut() {
                        state.index += 1;
                        for owner in &mut owners {
                            owner.branch(
                                state.chain,
                                state.index,
                                parent,
                                (keyword != "else").then_some(condition),
                            );
                        }
                        let active = state.parent_active
                            && !state.chosen
                            && owners.iter().any(|o| o.active[state.chain] != Some(false));
                        state.branch_active = active;
                        state.chosen |= active;
                    }
                }
                "endif" => {
                    stack.pop();
                }
                _ => {}
            }
            if matches!(keyword, "if" | "elif") {
                // Record every symbol in recognized conditions, including syntax
                // after a parse error and conditions after a taken branch.
                let mut rest = condition;
                while !rest.is_empty() && !rest.starts_with("//") {
                    if let Some((name, next)) = condition_identifier(rest) {
                        if !matches!(name, "true" | "false") {
                            referenced_symbols.insert(name.to_owned());
                        }
                        rest = next;
                    } else {
                        rest = &rest[rest.chars().next().unwrap().len_utf8()..];
                    }
                }
            }
            if matches!(keyword, "if" | "elif" | "else") {
                let chain = if keyword == "if" {
                    let chain = next_chain;
                    next_chain += 1;
                    chain
                } else if let Some(previous) = branch_stack.pop() {
                    branches[previous].chain
                } else {
                    next_chain += 1;
                    next_chain - 1
                };
                branch_stack.push(branches.len());
                branches.push(ConditionalBranch {
                    chain,
                    directive_start: line_start,
                    directive_end: line_end,
                    end_byte: source.len(),
                    condition: condition.trim().to_owned(),
                    directive: keyword.to_owned(),
                    closing_directive: None,
                    definitely_inactive: owners.iter().all(|o| {
                        o.active
                            .get(chain)
                            .is_none_or(|active| *active == Some(false))
                    }),
                    kept: stack.last().is_some_and(|state| state.branch_active),
                });
            }
        } else if region_active {
            kept.push((line_start, line_end));
            // Only active text is lexed, exactly as a C# compiler skips the
            // text of a disabled region without tokenizing it.
            mode = advance_lex_mode(line, mode);
        } else if !line.trim().is_empty() {
            has_inactive_regions = true;
        }

        if line_end == source.len() {
            break;
        }
        line_start = line_end;
    }

    let decisions = finish_decisions(&owners, next_chain, referenced_symbols);
    if !any_directive {
        return PreprocessorScan {
            decisions,
            included_ranges: None,
            has_inactive_regions: false,
            branches,
            symbol_directives,
        };
    }

    PreprocessorScan {
        decisions,
        included_ranges: Some(build_ranges(bytes, &kept)),
        has_inactive_regions,
        branches,
        symbol_directives,
    }
}

/// Merge adjacent kept spans and turn them into tree-sitter ranges.
///
/// An empty range slice tells tree-sitter to parse the whole file, so a file
/// whose every line is excluded emits one zero-width range instead.
fn build_ranges(bytes: &[u8], kept: &[(usize, usize)]) -> Vec<tree_sitter::Range> {
    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(kept.len());
    for &(start, end) in kept {
        match merged.last_mut() {
            Some(last) if last.1 == start => last.1 = end,
            _ => merged.push((start, end)),
        }
    }

    if merged.is_empty() {
        return vec![tree_sitter::Range {
            start_byte: 0,
            end_byte: 0,
            start_point: tree_sitter::Point { row: 0, column: 0 },
            end_point: tree_sitter::Point { row: 0, column: 0 },
        }];
    }

    let mut ranges = Vec::with_capacity(merged.len());
    let mut cursor = 0usize;
    let mut point = tree_sitter::Point { row: 0, column: 0 };
    for (start, end) in merged {
        let start_point = advance_ts_point(bytes, point, cursor, start);
        let end_point = advance_ts_point(bytes, start_point, start, end);
        ranges.push(tree_sitter::Range {
            start_byte: start,
            end_byte: end,
            start_point,
            end_point,
        });
        cursor = end;
        point = end_point;
    }
    ranges
}

/// The unowned case uses the reserved open compilation, including file-local
/// assignments and literal expression proofs.
pub fn scan_preprocessor(source: &str) -> PreprocessorScan {
    scan_and_decide_preprocessor(source, &[])
}

/// Advance the cross-line lexical mode across one source line.
fn advance_lex_mode(line: &str, mut mode: LexMode) -> LexMode {
    let bytes = line.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        match mode {
            LexMode::BlockComment => {
                if bytes[index] == b'*' && bytes.get(index + 1) == Some(&b'/') {
                    mode = LexMode::Normal;
                    index += 2;
                } else {
                    index += 1;
                }
            }
            LexMode::VerbatimString => {
                if bytes[index] == b'"' {
                    if bytes.get(index + 1) == Some(&b'"') {
                        index += 2;
                    } else {
                        mode = LexMode::Normal;
                        index += 1;
                    }
                } else {
                    index += 1;
                }
            }
            LexMode::RawString(opener) => {
                if bytes[index] == b'"' {
                    let run = quote_run(bytes, index);
                    if run >= opener {
                        mode = LexMode::Normal;
                    }
                    index += run;
                } else {
                    index += 1;
                }
            }
            LexMode::Normal => {
                match bytes[index] {
                    b'/' if bytes.get(index + 1) == Some(&b'/') => return LexMode::Normal,
                    b'/' if bytes.get(index + 1) == Some(&b'*') => {
                        mode = LexMode::BlockComment;
                        index += 2;
                    }
                    b'@' | b'$' => {
                        // `@"`, `$"`, `$@"`, `@$"`, `$"""` all start here.
                        let mut sigil_end = index;
                        let mut verbatim = false;
                        while let Some(&byte) = bytes.get(sigil_end) {
                            match byte {
                                b'@' => {
                                    verbatim = true;
                                    sigil_end += 1;
                                }
                                b'$' => sigil_end += 1,
                                _ => break,
                            }
                        }
                        if bytes.get(sigil_end) == Some(&b'"') {
                            let run = quote_run(bytes, sigil_end);
                            if run >= 3 {
                                mode = LexMode::RawString(run);
                                index = sigil_end + run;
                            } else if verbatim {
                                mode = LexMode::VerbatimString;
                                index = sigil_end + 1;
                            } else {
                                index = sigil_end + 1 + plain_string_len(bytes, sigil_end + 1);
                            }
                        } else {
                            index = sigil_end.max(index + 1);
                        }
                    }
                    b'"' => {
                        let run = quote_run(bytes, index);
                        if run >= 3 {
                            mode = LexMode::RawString(run);
                            index += run;
                        } else {
                            index += 1 + plain_string_len(bytes, index + 1);
                        }
                    }
                    b'\'' => index += 1 + plain_char_len(bytes, index + 1),
                    _ => index += 1,
                }
            }
        }
    }
    mode
}

/// Length of the run of `"` starting at `index`.
fn quote_run(bytes: &[u8], index: usize) -> usize {
    bytes[index..].iter().take_while(|&&b| b == b'"').count()
}

/// Length of a plain `"..."` string body, including its closing quote.
///
/// A plain string cannot span a line, so an unterminated one ends at the line
/// end and the mode returns to normal.
fn plain_string_len(bytes: &[u8], start: usize) -> usize {
    plain_quoted_len(bytes, start, b'"')
}

/// Length of a plain quoted literal body, including its closing delimiter.
fn plain_quoted_len(bytes: &[u8], start: usize, quote: u8) -> usize {
    let mut index = start;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => index += 2,
            byte if byte == quote => return index + 1 - start,
            _ => index += 1,
        }
    }
    bytes.len() - start
}

/// Length of a `'x'` character literal body, including its closing quote.
fn plain_char_len(bytes: &[u8], start: usize) -> usize {
    plain_quoted_len(bytes, start, b'\'')
}

/// The included ranges for one C# source, or `None` when it has no directives.
///
/// This is the function pointer form the language-blind parse helpers take.
pub fn csharp_included_ranges(source: &str) -> Option<Vec<tree_sitter::Range>> {
    scan_preprocessor(source).included_ranges
}

/// The C# parse spec: the grammar plus the directive-aware pre-parse.
///
/// Language-blind machinery -- the usage-graph on-demand parse, for one --
/// takes a spec instead of a bare grammar so that no C# parse can forget the
/// pre-parse and produce node ranges the declaration walk disagrees with.
pub fn csharp_parse_spec(language: &tree_sitter::Language) -> ParseSpec<'_> {
    ParseSpec::restricted(language, csharp_included_ranges)
}

/// Parse C# source with preprocessor directives and inactive branches hidden.
///
/// Every C# parse in Bifrost goes through here or through
/// [`csharp_parse_spec`]. If the declaration walk and the usage-graph scan
/// parsed the same file differently, their node ranges would disagree and
/// navigation would break in ways that are hard to see.
pub fn parse_csharp(source: &str) -> Option<tree_sitter::Tree> {
    parse_csharp_with_cancellation(source, None)
}

/// Parse C# source and also report what the scan found.
///
/// A caller that must tell its consumer the index is partial -- the semantic
/// diagnostics pass does -- needs `has_inactive_regions` from the same scan
/// that produced the tree, not a second scan of the same bytes.
pub fn parse_csharp_scanned(source: &str) -> Option<(tree_sitter::Tree, PreprocessorScan)> {
    scan_and_parse_csharp(source, None)
}

/// Cancellation-aware form of [`parse_csharp`].
pub fn parse_csharp_with_cancellation(
    source: &str,
    cancellation: Option<&CancellationToken>,
) -> Option<tree_sitter::Tree> {
    scan_and_parse_csharp(source, cancellation).map(|(tree, _)| tree)
}

fn scan_and_parse_csharp(
    source: &str,
    cancellation: Option<&CancellationToken>,
) -> Option<(tree_sitter::Tree, PreprocessorScan)> {
    let scan = scan_preprocessor(source);
    let tree = parse_csharp_scan_with_cancellation(source, &scan, cancellation)?;
    Some((tree, scan))
}

pub fn parse_csharp_scan_with_cancellation(
    source: &str,
    scan: &PreprocessorScan,
    cancellation: Option<&CancellationToken>,
) -> Option<tree_sitter::Tree> {
    let language = tree_sitter_c_sharp::LANGUAGE.into();
    parse_source_with_cancellation(
        &language,
        source,
        scan.included_ranges.as_deref(),
        cancellation,
    )
}

#[cfg(test)]
mod tests {
    use brokk_bifrost_test_macros::hardwon;

    use super::*;

    /// The `StringSlice` shape: a member signature split across `#if NET`.
    const STRING_SLICE: &str = r#"namespace Markdig.Helpers
{
    public struct StringSlice
    {
        public string Text;
        public int Start;

#if NET
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public readonly void TrimStart()
#else
        public void TrimStart()
#endif
        {
            Start++;
        }

        public char NextChar()
        {
            return Text[Start];
        }

        public char PeekChar()
        {
            return Text[Start];
        }
    }
}
"#;

    /// The `TypeConverter` shape: `#if` inside a ternary expression.
    const TYPE_CONVERTER: &str = r#"namespace CommandLine.Core
{
    static class TypeConverter
    {
        public static object ChangeType(string value, Type type)
        {
            return type == typeof(int)
                ? ParseInt(value)
#if !SKIP_FSHARP
                : IsFsharpOption(type)
                    ? ParseOption(value)
                    : ParseOther(value);
#else
                : ParseOther(value);
#endif
        }

        public static object ParseInt(string value) { return 0; }
    }
}
"#;

    fn parse_raw(source: &str) -> tree_sitter::Tree {
        crate::test_support::parse_raw_csharp(source)
    }

    /// Collect every method name the tree exposes, in document order.
    fn method_names(tree: &tree_sitter::Tree, source: &str) -> Vec<String> {
        let mut names = Vec::new();
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            if node.kind() == "method_declaration"
                && let Some(name) = node.child_by_field_name("name")
            {
                names.push(source[name.byte_range()].to_string());
            }
            for index in (0..node.child_count()).rev() {
                stack.push(node.child(index).unwrap());
            }
        }
        names.sort();
        names
    }

    /// Count ERROR and MISSING nodes anywhere in the tree.
    fn error_count(tree: &tree_sitter::Tree) -> usize {
        let mut count = 0;
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            if node.is_error() || node.is_missing() {
                count += 1;
            }
            for index in (0..node.child_count()).rev() {
                stack.push(node.child(index).unwrap());
            }
        }
        count
    }

    #[test]
    #[hardwon("#1803: directives split a signature and cause duplicate declarations")]
    fn probe_raw_parse_distorts_a_split_signature() {
        // The raw parse recovers, but it recovers wrongly: `TrimStart` appears
        // twice, once from each branch, and the later members hang inside the
        // `#else` branch of an unterminated `preproc_if`.
        let raw = parse_raw(STRING_SLICE);
        assert!(raw.root_node().has_error(), "expected a broken raw parse");
        assert_eq!(
            method_names(&raw, STRING_SLICE),
            vec![
                "NextChar".to_string(),
                "PeekChar".to_string(),
                "TrimStart".to_string(),
                "TrimStart".to_string()
            ],
            "the raw parse duplicates the split member"
        );

        let repaired = parse_csharp(STRING_SLICE).unwrap();
        assert_eq!(
            method_names(&repaired, STRING_SLICE),
            vec![
                "NextChar".to_string(),
                "PeekChar".to_string(),
                "TrimStart".to_string()
            ],
            "the repaired parse names each member exactly once"
        );
        assert_eq!(error_count(&repaired), 0, "repaired parse must be clean");
        // Every member is a direct child of the struct body again.
        let sexp = repaired.root_node().to_sexp();
        assert!(
            !sexp.contains("preproc"),
            "no directive nodes remain: {sexp}"
        );
    }

    #[test]
    #[hardwon("#1803: a conditional modifier fragment breaks the following method declaration")]
    fn a_modifier_only_split_parses_cleanly() {
        let source = concat!(
            "public struct S {\n",
            "    public\n",
            "#if NET\n",
            "    readonly\n",
            "#endif\n",
            "    void TrimStart() { }\n",
            "    public char NextChar() { return 'a'; }\n",
            "}\n",
        );
        assert!(parse_raw(source).root_node().has_error());
        let repaired = parse_csharp(source).unwrap();
        assert_eq!(error_count(&repaired), 0);
        assert_eq!(
            method_names(&repaired, source),
            vec!["NextChar".to_string(), "TrimStart".to_string()]
        );
    }

    #[test]
    #[hardwon("#1803: conditional expression branches corrupt following method declarations")]
    fn probe_raw_parse_of_ternary_split_is_broken() {
        let raw = parse_raw(TYPE_CONVERTER);
        assert!(raw.root_node().has_error(), "expected a broken raw parse");
        assert!(error_count(&raw) > 0);

        let repaired = parse_csharp(TYPE_CONVERTER).unwrap();
        assert_eq!(error_count(&repaired), 0, "repaired parse must be clean");
        assert_eq!(
            method_names(&repaired, TYPE_CONVERTER),
            vec!["ChangeType".to_string(), "ParseInt".to_string()]
        );
    }

    /// The kept text, reconstructed from the ranges, for readable assertions.
    fn kept_text(source: &str) -> String {
        match scan_preprocessor(source).included_ranges {
            None => source.to_string(),
            Some(ranges) => ranges
                .iter()
                .map(|range| &source[range.start_byte..range.end_byte])
                .collect(),
        }
    }

    #[test]
    #[hardwon("#1803: false conditional branches must select the later active branch")]
    fn literal_false_condition_activates_the_next_branch() {
        let source = "#if false\nint a;\n#elif false\nint b;\n#else\nint c;\n#endif\n";
        assert_eq!(kept_text(source), "int c;\n");
    }

    #[test]
    #[hardwon("#1803: a nested chain cannot activate inside an inactive parent branch")]
    fn nested_chain_inside_an_inactive_branch_stays_inactive() {
        let source = "#if false\n#if A\nint a;\n#else\nint b;\n#endif\n#else\nint c;\n#endif\n";
        assert_eq!(kept_text(source), "int c;\n");
    }

    #[test]
    #[hardwon("#1803: nested directives preserve branch selection inside active parent text")]
    fn nested_chain_inside_an_active_branch_selects_its_first_branch() {
        let source = "#if A\n#if B\nint a;\n#else\nint b;\n#endif\n#endif\n";
        assert_eq!(kept_text(source), "int a;\n");
    }

    #[test]
    #[hardwon("#1803: directive markers inside comments and strings are source text")]
    fn hash_inside_comments_and_strings_is_not_a_directive() {
        let source = concat!(
            "// #if A\n",
            "/*\n",
            "#if B\n",
            "*/\n",
            "var v = @\"\n",
            "#if C\n",
            "\";\n",
            "var r = \"\"\"\n",
            "#if D\n",
            "\"\"\";\n",
        );
        let scan = scan_preprocessor(source);
        assert!(
            scan.included_ranges.is_none(),
            "no line here is a directive line"
        );
        let controlled =
            format!("{source}#if false\nclass Hidden {{}}\n#else\nclass Kept {{}}\n#endif\n");
        assert_eq!(kept_text(&controlled), format!("{source}class Kept {{}}\n"));
    }

    #[test]
    fn lexical_boundaries_preserve_active_declarations() {
        let source = r####"class C {
/* comment */
#if false
int HiddenBlock;
#else
int KeptBlock;
#endif
string Escaped = "\"/*";
#if false
int HiddenEscape;
#else
int KeptEscape;
#endif
string Ordinary = "text"; /* real comment
#if false
*/
int KeptComment;
#if false
int HiddenOrdinary;
#else
int KeptOrdinary;
#endif
}"####;
        let tree = parse_csharp(source).expect("active C# tree");
        assert!(
            !tree.root_node().has_error(),
            "{}",
            tree.root_node().to_sexp()
        );
        let file =
            brokk_bifrost_core::analyzer::ProjectFile::new(std::env::temp_dir(), "Active.cs");
        let parsed = crate::declarations::parse_csharp_file(&file, source, &tree);
        let mut names: Vec<_> = parsed
            .declarations()
            .iter()
            .map(|unit| unit.identifier())
            .collect();
        names.sort_unstable();
        assert_eq!(
            names,
            [
                "C",
                "Escaped",
                "KeptBlock",
                "KeptComment",
                "KeptEscape",
                "KeptOrdinary",
                "Ordinary"
            ]
        );
    }

    #[test]
    #[hardwon("#1803: doubled quotes keep a verbatim string open across directive-like lines")]
    fn doubled_quotes_do_not_close_a_verbatim_string() {
        let source = "var v = @\"a\"\"b\n#if A\n\";\nint x;\n";
        assert!(
            scan_preprocessor(source).included_ranges.is_none(),
            "the `#if` sits inside the verbatim string"
        );
    }

    #[test]
    #[hardwon("#1803: an interpolated verbatim string can contain directive-like lines")]
    fn interpolated_verbatim_string_spans_lines() {
        let source = "var v = $@\"{x}\n#if A\n\";\n";
        assert!(scan_preprocessor(source).included_ranges.is_none());
    }

    #[test]
    #[hardwon("#1803: raw strings close only when the quote run reaches the opener length")]
    fn raw_string_closes_only_on_an_equal_or_longer_quote_run() {
        let source = "var v = \"\"\"\"\n\"\"\"\n#if A\nint a;\n\"\"\"\"\n";
        assert!(
            scan_preprocessor(source).included_ranges.is_none(),
            "a three-quote run cannot close a four-quote raw string"
        );
    }

    #[test]
    #[hardwon("#1803: unmatched conditional directives must not discard source or panic")]
    fn unbalanced_directives_do_not_panic() {
        assert_eq!(kept_text("#endif\nint a;\n"), "int a;\n");
        assert_eq!(kept_text("#else\nint a;\n"), "int a;\n");
        assert_eq!(kept_text("#if A\nint a;\n"), "int a;\n");
        assert_eq!(kept_text("#elif A\nint a;\n"), "int a;\n");
    }

    #[test]
    #[hardwon("#1803: CRLF boundaries must preserve complete conditional branches")]
    fn crlf_line_endings_scan_as_lines() {
        let source = "#if false\r\nint a;\r\n#else\r\nint b;\r\n#endif\r\n";
        assert_eq!(kept_text(source), "int b;\r\n");
    }

    #[test]
    #[hardwon("#1803: a final directive without a newline must still be recognized")]
    fn directive_on_the_last_line_without_a_newline() {
        let source = "int a;\n#endif";
        assert_eq!(kept_text(source), "int a;\n");
    }

    #[test]
    #[hardwon(
        "#6139: a byte-order mark hid the opening #if, so Dapper's SnowflakeTests.cs parsed with a MISSING #endif"
    )]
    fn a_directive_after_a_byte_order_mark_is_recognized() {
        let source =
            "\u{feff}#if !NETFRAMEWORK\r\nnamespace A\r\n{\r\n    class B { }\r\n}\r\n#endif";
        assert_eq!(
            kept_text(source),
            "namespace A\r\n{\r\n    class B { }\r\n}\r\n"
        );
        assert_eq!(error_count(&parse_csharp(source).unwrap()), 0);
    }

    #[test]
    #[hardwon("#1803: a fully inactive file publishes an empty parser range")]
    fn a_wholly_inactive_file_emits_one_zero_width_range() {
        let source = "#if false\nint a;\n#endif\n";
        let ranges = scan_preprocessor(source).included_ranges.unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].start_byte, 0);
        assert_eq!(ranges[0].end_byte, 0);
        let tree = parse_csharp(source).unwrap();
        assert_eq!(tree.root_node().named_child_count(), 0);
    }

    #[test]
    #[hardwon("#1803: included-range points must match their original byte offsets")]
    fn range_points_match_their_byte_offsets() {
        let ranges = scan_preprocessor(STRING_SLICE).included_ranges.unwrap();
        for range in &ranges {
            let prefix = &STRING_SLICE[..range.start_byte];
            assert_eq!(range.start_point.row, prefix.matches('\n').count());
            let column = prefix.len() - prefix.rfind('\n').map_or(0, |index| index + 1);
            assert_eq!(range.start_point.column, column);
        }
    }

    #[test]
    #[hardwon("#1803: repaired syntax nodes must keep original source byte offsets")]
    fn recovered_nodes_keep_raw_file_offsets() {
        let tree = parse_csharp(STRING_SLICE).unwrap();
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            if node.kind() == "method_declaration"
                && let Some(name) = node.child_by_field_name("name")
                && &STRING_SLICE[name.byte_range()] == "TrimStart"
            {
                let expected = STRING_SLICE.find("void TrimStart").unwrap() + "void ".len();
                assert_eq!(name.start_byte(), expected);
                return;
            }
            for index in (0..node.child_count()).rev() {
                stack.push(node.child(index).unwrap());
            }
        }
        panic!("TrimStart was not found in the repaired tree");
    }
}
