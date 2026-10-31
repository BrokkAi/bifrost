//! Shared structured classification of branch and loop bodies.
//!
//! A body is classified from its direct syntax children.  Comments and
//! grammar extras do not make a body non-empty, but a comment-only body is
//! kept distinct from a genuinely empty body because several policy rules
//! make that distinction.  The grammar-specific names and fields live in the
//! small [`BodySyntax`] hooks below; the ownership and state algorithms are
//! shared by all adapters that opt in.

use super::conditional_regions::{Activation, ConditionalRegions};
use crate::analyzer::Language;
use crate::analyzer::tree_walk::{is_comment_kind, named_children_iter};
use tree_sitter::Node;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BodyState {
    Empty,
    CommentOnly,
    Code,
}

impl BodyState {
    pub const ALL: [Self; 3] = [Self::Empty, Self::CommentOnly, Self::Code];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::CommentOnly => "comment-only",
            Self::Code => "code",
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|state| state.label() == label)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BodyOwner {
    IfConsequence,
    IfAlternative,
    LoopBody,
}

impl BodyOwner {
    pub const ALL: [Self; 3] = [Self::IfConsequence, Self::IfAlternative, Self::LoopBody];

    pub const fn label(self) -> &'static str {
        match self {
            Self::IfConsequence => "if-consequence",
            Self::IfAlternative => "if-alternative",
            Self::LoopBody => "loop-body",
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|owner| owner.label() == label)
    }
}

/// The grammar names and field layout needed by the shared body algorithm.
/// Keep this hook declarative: ownership, comment handling, and emptiness do
/// not belong in a language adapter.
#[derive(Debug, Clone, Copy)]
pub struct BodySyntax {
    pub block_kinds: &'static [&'static str],
    pub if_kinds: &'static [&'static str],
    pub loop_kinds: &'static [&'static str],
    pub for_kinds: &'static [&'static str],
    pub empty_statement_kinds: &'static [&'static str],
    pub consequence_field: &'static str,
    pub alternative_field: &'static str,
    pub loop_body_field: &'static str,
    pub update_field: &'static str,
}

const CPP_SYNTAX: BodySyntax = BodySyntax {
    block_kinds: &["compound_statement"],
    if_kinds: &["if_statement"],
    loop_kinds: &[
        "for_statement",
        "for_range_loop",
        "while_statement",
        "do_statement",
    ],
    for_kinds: &["for_statement"],
    empty_statement_kinds: &["empty_statement"],
    consequence_field: "consequence",
    alternative_field: "alternative",
    loop_body_field: "body",
    update_field: "update",
};

const CSHARP_SYNTAX: BodySyntax = BodySyntax {
    block_kinds: &["block"],
    if_kinds: &["if_statement"],
    loop_kinds: &[
        "for_statement",
        "foreach_statement",
        "while_statement",
        "do_statement",
    ],
    for_kinds: &["for_statement"],
    empty_statement_kinds: &["empty_statement"],
    consequence_field: "consequence",
    alternative_field: "alternative",
    loop_body_field: "body",
    update_field: "update",
};

pub fn syntax_for(language: Language) -> Option<&'static BodySyntax> {
    match language {
        Language::Cpp => Some(&CPP_SYNTAX),
        Language::CSharp => Some(&CSHARP_SYNTAX),
        _ => None,
    }
}

/// Uncertainty is an answer, not a fourth queryable body-state label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyStateAnswer {
    Decided(BodyState),
    Undecided,
}

/// Classify direct children, allowing handlers to supply their own no-op rules.
/// A certain executable child proves code despite other uncertain children.
pub fn classify_body(
    block: Node<'_>,
    regions: &ConditionalRegions,
    is_no_op: impl Fn(Node<'_>) -> bool,
) -> BodyStateAnswer {
    let mut saw_comment = false;
    let mut saw_uncertain_comment = false;
    let mut uncertain = false;
    for child in named_children_iter(block) {
        let activation = regions.activation_at(child.start_byte());
        if activation == Activation::DecidedInactive {
            continue;
        }
        if is_no_op(child) {
            continue;
        }
        if is_comment_kind(child.kind()) {
            saw_comment |= activation == Activation::CertainActive;
            saw_uncertain_comment |= activation == Activation::Uncertain;
            continue;
        }
        if child.is_extra() {
            continue;
        }
        if activation == Activation::CertainActive {
            return BodyStateAnswer::Decided(BodyState::Code);
        }
        uncertain = true;
    }
    if uncertain || regions.has_uncertain_omission(block.byte_range()) {
        BodyStateAnswer::Undecided
    } else if saw_comment {
        BodyStateAnswer::Decided(BodyState::CommentOnly)
    } else if saw_uncertain_comment {
        BodyStateAnswer::Undecided
    } else {
        BodyStateAnswer::Decided(BodyState::Empty)
    }
}

/// Preserve preprocessor wrapper handling until C/C++ supplies regions (#7510).
pub fn body_state(block: Node<'_>, regions: &ConditionalRegions) -> BodyStateAnswer {
    classify_body(block, regions, |child| child.kind().starts_with("preproc_"))
}

#[derive(Debug, Clone, Copy)]
pub struct BodyRelation<'tree> {
    pub block: Node<'tree>,
    pub owner: Node<'tree>,
    pub owner_kind: BodyOwner,
    pub state: BodyStateAnswer,
    /// CodeQL's empty-block rule excludes a `for` body when the header has an
    /// update expression.  The fact is retained here so every consumer uses
    /// the same structured exception.
    pub for_has_update: bool,
}

/// Return the body relation for a block that is directly owned by an if or a
/// loop.  The returned relation is absent for ordinary nested blocks.
pub fn body_relation_for_block<'tree>(
    block: Node<'tree>,
    language: Language,
    regions: &ConditionalRegions,
) -> Option<BodyRelation<'tree>> {
    let syntax = syntax_for(language)?;
    if !syntax.block_kinds.contains(&block.kind()) {
        return None;
    }
    let parent = block.parent()?;
    let (owner, owner_kind) = if syntax.if_kinds.contains(&parent.kind()) {
        if same_node(parent.child_by_field_name(syntax.consequence_field), block) {
            (parent, BodyOwner::IfConsequence)
        } else if if_alternative_body(parent, syntax)
            .is_some_and(|body| same_node(Some(body), block))
        {
            (parent, BodyOwner::IfAlternative)
        } else {
            return None;
        }
    } else if syntax.loop_kinds.contains(&parent.kind())
        && same_node(parent.child_by_field_name(syntax.loop_body_field), block)
    {
        (parent, BodyOwner::LoopBody)
    } else if parent.kind() == "else_clause" {
        let owner = parent.parent()?;
        if !syntax.if_kinds.contains(&owner.kind())
            || !if_alternative_body(owner, syntax).is_some_and(|body| same_node(Some(body), block))
        {
            return None;
        }
        (owner, BodyOwner::IfAlternative)
    } else {
        return None;
    };
    Some(BodyRelation {
        block,
        owner,
        owner_kind,
        state: body_state(block, regions),
        for_has_update: syntax.for_kinds.contains(&owner.kind())
            && owner.child_by_field_name(syntax.update_field).is_some(),
    })
}

/// The structured state of one if arm.  A non-block statement is code unless
/// the grammar explicitly represents it as an empty statement.
pub fn if_arm_state(
    node: Node<'_>,
    language: Language,
    regions: &ConditionalRegions,
) -> Option<BodyStateAnswer> {
    let syntax = syntax_for(language)?;
    let mut uncertain = false;
    let mut arm = node;
    let state = loop {
        if syntax.empty_statement_kinds.contains(&arm.kind()) {
            break BodyStateAnswer::Decided(BodyState::Empty);
        }
        if !syntax.block_kinds.contains(&arm.kind()) {
            break match regions.activation_at(arm.start_byte()) {
                Activation::CertainActive => BodyStateAnswer::Decided(BodyState::Code),
                Activation::DecidedInactive => BodyStateAnswer::Decided(BodyState::Empty),
                Activation::Uncertain => BodyStateAnswer::Undecided,
            };
        }
        match body_state(arm, regions) {
            BodyStateAnswer::Decided(BodyState::Code) => {}
            state => break state,
        }
        let statements: Vec<_> = named_children_iter(arm)
            .filter(|child| {
                !child.is_extra()
                    && !is_comment_kind(child.kind())
                    && !child.kind().starts_with("preproc_")
            })
            .collect();
        let mut certain = statements
            .iter()
            .copied()
            .filter(|child| regions.activation_at(child.start_byte()) == Activation::CertainActive);
        let statement = certain
            .next()
            .expect("body_state Code has a certainly active statement");
        if certain.next().is_some() {
            break BodyStateAnswer::Decided(BodyState::Code);
        }
        uncertain |= statements
            .iter()
            .any(|child| regions.activation_at(child.start_byte()) == Activation::Uncertain)
            || regions.has_uncertain_omission(arm.byte_range());
        arm = statement;
    };
    Some(match state {
        BodyStateAnswer::Decided(BodyState::Empty) if uncertain => BodyStateAnswer::Undecided,
        state => state,
    })
}

#[derive(Debug, Clone, Copy)]
pub struct EmptyIfArmRelation<'tree> {
    pub state: BodyStateAnswer,
    pub owner: Node<'tree>,
    pub consequence: Node<'tree>,
    pub alternative: Option<Node<'tree>>,
}

/// Return an if whose arms are empty or undecided. A certainly nonempty arm
/// excludes the relation. Comment-only blocks are deliberately not empty.
pub fn empty_if_arm_relation<'tree>(
    node: Node<'tree>,
    language: Language,
    regions: &ConditionalRegions,
) -> Option<EmptyIfArmRelation<'tree>> {
    let syntax = syntax_for(language)?;
    if !syntax.if_kinds.contains(&node.kind()) {
        return None;
    }
    let consequence = node.child_by_field_name(syntax.consequence_field)?;
    let alternative = if_alternative_body(node, syntax);
    let mut state = BodyStateAnswer::Decided(BodyState::Empty);
    for arm in [Some(consequence), alternative].into_iter().flatten() {
        match if_arm_state(arm, language, regions)? {
            BodyStateAnswer::Decided(BodyState::Empty) => {}
            BodyStateAnswer::Decided(BodyState::Code | BodyState::CommentOnly) => return None,
            BodyStateAnswer::Undecided => state = BodyStateAnswer::Undecided,
        }
    }
    Some(EmptyIfArmRelation {
        state,
        owner: node,
        consequence,
        alternative,
    })
}

/// Select the alternative body, unwrapping the grammar's else clause.
pub fn if_alternative_body<'tree>(owner: Node<'tree>, syntax: &BodySyntax) -> Option<Node<'tree>> {
    let alternative = owner.child_by_field_name(syntax.alternative_field)?;
    if alternative.kind() == "else_clause" {
        let mut children = named_children_iter(alternative).filter(|child| {
            !child.is_extra()
                && !is_comment_kind(child.kind())
                && !child.kind().starts_with("preproc_")
        });
        let body = children.next()?;
        children.next().is_none().then_some(body)
    } else {
        Some(alternative)
    }
}

fn same_node(left: Option<Node<'_>>, right: Node<'_>) -> bool {
    left.is_some_and(|left| left.id() == right.id())
}
