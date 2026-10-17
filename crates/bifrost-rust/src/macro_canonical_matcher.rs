//! Match live invocation tokens against source-owned definition patterns.

use super::*;
use brokk_bifrost_core::analyzer::rust_facts::{
    RustMacroArmSourceFact, RustMacroDefinitionSourceFact, RustMacroPatternSourceKind,
};
use brokk_bifrost_core::hash::HashMap;

pub fn match_macro_rules(
    definition: &RustMacroDefinitionSourceFact,
    invocation_arguments: Node<'_>,
    invocation_source: &str,
    keep_going: &dyn Fn() -> bool,
) -> Result<MacroArmMatch, MacroMatchError> {
    let input = capture_macro_input(invocation_arguments, invocation_source, keep_going)?;
    match_captured_macro_rules(definition, &input, keep_going)
}

pub fn match_captured_macro_rules(
    definition: &RustMacroDefinitionSourceFact,
    input: &brokk_bifrost_core::analyzer::rust_facts::RustMacroTokenTree,
    keep_going: &dyn Fn() -> bool,
) -> Result<MacroArmMatch, MacroMatchError> {
    let input_tree = MacroInputTree::new(input, keep_going)?;
    if !keep_going() {
        return Err(MacroMatchError::Interrupted);
    }
    if !definition.is_macro_rules {
        return Err(MacroMatchError::NotMacroRules);
    }
    if definition.arms.is_empty() {
        return Err(MacroMatchError::EmptyRules);
    }
    for (arm_index, arm) in definition.arms.iter().enumerate() {
        if !keep_going() {
            return Err(MacroMatchError::Interrupted);
        }
        if arm.pattern.is_none() {
            continue;
        }
        if let Some(bindings) =
            MatchMachine::new(arm, input_tree.root(), keep_going)?.run(&input.source, keep_going)?
        {
            return Ok(MacroArmMatch {
                arm_index,
                bindings,
            });
        }
    }
    Err(MacroMatchError::NoArmMatched)
}

pub(super) fn macro_invocation_prefix_len(
    root: Node<'_>,
    expected_start: usize,
    prefix_len: usize,
    source_start: usize,
    input: &TokenCursor<'_>,
) -> Option<usize> {
    let mut pending = vec![root];
    while let Some(node) = pending.pop() {
        if node.kind() == "macro_invocation" && node.start_byte() == expected_start {
            let macro_path = node.child_by_field_name("macro")?;
            if macro_path.start_byte() == expected_start && !macro_path.has_error() {
                let mut cursor = node.walk();
                let parsed_group = node
                    .children(&mut cursor)
                    .find(|child| child.kind() == "token_tree")?;
                let group_start =
                    source_start.checked_add(parsed_group.start_byte().checked_sub(prefix_len)?)?;
                if let Some(group) = input.tokens.iter().skip(input.index).find(|token| {
                    token.kind() == "token_tree"
                        && token.start_byte() == group_start
                        && token.has_balanced_delimiters()
                }) {
                    let group_len = group.end_byte().checked_sub(source_start)?;
                    let mut expression = node;
                    let mut parent = node.parent();
                    while let Some(ancestor) = parent {
                        if ancestor.start_byte() != expected_start || ancestor.kind() == "block" {
                            break;
                        }
                        expression = ancestor;
                        parent = ancestor.parent();
                    }
                    if expression.kind() == "expression_statement" {
                        expression = expression.named_child(0)?;
                    }
                    if expression.start_byte() == expected_start
                        && expression.kind() != "macro_invocation"
                        && !has_errors_outside_macro_invocation(expression, expected_start)
                    {
                        return Some(
                            (expression.end_byte().checked_sub(prefix_len)?).max(group_len),
                        );
                    }
                    return Some(group_len);
                }
            }
        }
        let mut cursor = node.walk();
        pending.extend(node.children(&mut cursor));
    }
    None
}

fn has_errors_outside_macro_invocation(expression: Node<'_>, macro_start: usize) -> bool {
    let mut pending = vec![expression];
    while let Some(node) = pending.pop() {
        if node.kind() == "macro_invocation" && node.start_byte() == macro_start {
            continue;
        }
        if node.is_error() || node.is_missing() {
            return true;
        }
        let mut cursor = node.walk();
        pending.extend(node.children(&mut cursor));
    }
    false
}

struct MatchMachine<'facts, 'tree> {
    arm: &'facts RustMacroArmSourceFact,
    children: Vec<Vec<usize>>,
    parents: Vec<Option<usize>>,
    ident_roles: HashMap<&'facts str, MacroIdentRole>,
    input: TokenCursor<'tree>,
    bindings: Vec<MacroBinding>,
    frames: Vec<MatchFrame<'tree>>,
    repetition_path: Vec<usize>,
}

enum MatchFrame<'tree> {
    Sequence {
        parent: usize,
        next: usize,
    },
    Group {
        parent_input: TokenCursor<'tree>,
        binding_len: usize,
    },
    Repetition {
        pattern: usize,
        count: usize,
        after_last_group: Option<usize>,
        saved_input: usize,
        binding_len: usize,
    },
}

enum MatchFlow {
    Continue,
    Done(bool),
}

impl<'facts, 'tree> MatchMachine<'facts, 'tree> {
    fn new(
        arm: &'facts RustMacroArmSourceFact,
        arguments: MacroInputNode<'tree>,
        keep_going: &dyn Fn() -> bool,
    ) -> Result<Self, MacroMatchError> {
        let mut positions: HashMap<_, usize> = HashMap::default();
        let mut parents = vec![None; arm.patterns.len()];
        let children = macro_children_from_parents(arm.patterns.len(), |position| {
            if !keep_going() {
                return Err(MacroMatchError::Interrupted);
            }
            let pattern = &arm.patterns[position];
            let parent_position = if let Some(parent) = pattern.parent {
                Some(
                    *positions
                        .get(&parent)
                        .expect("published pattern parent precedes its child"),
                )
            } else {
                assert_eq!(position, 0, "a published matcher has one first root");
                assert_eq!(Some(pattern.occurrence), arm.pattern);
                None
            };
            parents[position] = parent_position;
            assert!(positions.insert(pattern.occurrence, position).is_none());
            Ok(parent_position)
        })?;
        let mut ident_roles = HashMap::default();
        for role in &arm.ident_roles {
            if !keep_going() {
                return Err(MacroMatchError::Interrupted);
            }
            assert!(ident_roles.insert(role.name.as_str(), role.role).is_none());
        }
        let (tokens, end_byte) = arguments.interior(keep_going)?;
        Ok(Self {
            arm,
            children,
            parents,
            ident_roles,
            input: TokenCursor {
                tokens,
                index: 0,
                end_byte,
                source_start: arguments.tree.source.start_byte,
            },
            bindings: Vec::new(),
            frames: vec![MatchFrame::Sequence { parent: 0, next: 0 }],
            repetition_path: Vec::new(),
        })
    }

    fn run(
        mut self,
        source: &str,
        keep_going: &dyn Fn() -> bool,
    ) -> Result<Option<Vec<MacroBinding>>, MacroMatchError> {
        loop {
            if !keep_going() {
                return Err(MacroMatchError::Interrupted);
            }
            let Some(MatchFrame::Sequence { parent, next }) = self.frames.last_mut() else {
                unreachable!("active matcher frame is a sequence");
            };
            let pattern = self.children[*parent].get(*next).copied();
            *next += usize::from(pattern.is_some());
            let flow = match pattern {
                Some(pattern) => self.step_element(pattern, source, keep_going)?,
                None => {
                    self.frames.pop();
                    self.finish_child(true, keep_going)?
                }
            };
            if let MatchFlow::Done(success) = flow {
                return Ok((success && self.input.index == self.input.tokens.len())
                    .then_some(self.bindings));
            }
        }
    }

    fn step_element(
        &mut self,
        pattern: usize,
        source: &str,
        keep_going: &dyn Fn() -> bool,
    ) -> Result<MatchFlow, MacroMatchError> {
        let matched = match &self.arm.patterns[pattern].kind {
            RustMacroPatternSourceKind::Binding { name, fragment } => {
                if let Some((start_byte, end_byte)) =
                    consume_fragment(*fragment, &mut self.input, source)
                {
                    self.bindings.push(MacroBinding {
                        name: name.clone(),
                        fragment: *fragment,
                        start_byte,
                        end_byte,
                        repetition_path: self.repetition_path.clone(),
                        ident_role: (*fragment == MacroFragmentKind::Ident).then(|| {
                            crate::macro_matcher::captured_ident_role(
                                *self
                                    .ident_roles
                                    .get(name.as_str())
                                    .expect("published ident binding has a transcriber role"),
                                &source[start_byte - self.input.source_start
                                    ..end_byte - self.input.source_start],
                            )
                        }),
                    });
                    true
                } else {
                    false
                }
            }
            RustMacroPatternSourceKind::Group { delimiter } => {
                if *delimiter
                    == Some(brokk_bifrost_core::analyzer::rust_facts::RustMacroDelimiter::Bracket)
                    && self.input.current().is_some_and(|comment| {
                        comment.is_doc_comment()
                            && self.is_doc_meta_attribute_group(pattern, comment)
                    })
                {
                    let comment = self.input.current().expect("doc comment is current");
                    let group = self.children[pattern][0];
                    let RustMacroPatternSourceKind::Binding { name, fragment } =
                        &self.arm.patterns[group].kind
                    else {
                        unreachable!("doc attribute group captures one meta fragment");
                    };
                    assert_eq!(*fragment, MacroFragmentKind::Meta);
                    self.bindings.push(MacroBinding {
                        name: name.clone(),
                        fragment: *fragment,
                        start_byte: comment.start_byte(),
                        end_byte: comment.end_byte(),
                        repetition_path: self.repetition_path.clone(),
                        ident_role: None,
                    });
                    self.input.advance();
                    return self.finish_child(true, keep_going);
                }
                let Some(current) = self
                    .input
                    .current()
                    .filter(|node| node.kind() == "token_tree")
                else {
                    return self.finish_child(false, keep_going);
                };
                if delimiter.is_none() || *delimiter != current.delimiter() {
                    return self.finish_child(false, keep_going);
                }
                let (tokens, end_byte) = current.interior(keep_going)?;
                let parent_input = std::mem::replace(
                    &mut self.input,
                    TokenCursor {
                        tokens,
                        index: 0,
                        end_byte,
                        source_start: current.tree.source.start_byte,
                    },
                );
                self.frames.push(MatchFrame::Group {
                    parent_input,
                    binding_len: self.bindings.len(),
                });
                self.frames.push(MatchFrame::Sequence {
                    parent: pattern,
                    next: 0,
                });
                return Ok(MatchFlow::Continue);
            }
            RustMacroPatternSourceKind::Repetition { .. } => {
                self.frames.push(MatchFrame::Repetition {
                    pattern,
                    count: 0,
                    after_last_group: None,
                    saved_input: self.input.index,
                    binding_len: self.bindings.len(),
                });
                self.begin_repetition_attempt();
                return Ok(MatchFlow::Continue);
            }
            RustMacroPatternSourceKind::Literal { syntax_kind, text } => {
                let doc_attribute_prefix = self
                    .input
                    .current()
                    .is_some_and(|comment| self.is_doc_meta_attribute_token(pattern, comment));
                let matched = doc_attribute_prefix
                    || self.input.current().is_some_and(|token| {
                        (token.kind() == syntax_kind
                            || (identifier_kind_like(syntax_kind) && identifier_like(token)))
                            && token.text().trim() == text
                    });
                if matched && !doc_attribute_prefix {
                    self.input.advance();
                }
                matched
            }
            RustMacroPatternSourceKind::Invalid => false,
        };
        self.finish_child(matched, keep_going)
    }

    fn is_doc_meta_attribute_token(&self, pattern: usize, comment: MacroInputNode<'_>) -> bool {
        let Some(parent) = self.parents[pattern] else {
            return false;
        };
        let siblings = &self.children[parent];
        let Some(position) = siblings.iter().position(|&sibling| sibling == pattern) else {
            return false;
        };
        let RustMacroPatternSourceKind::Literal { text, .. } = &self.arm.patterns[pattern].kind
        else {
            return false;
        };
        match text.as_str() {
            "#" => {
                if siblings
                    .get(position + 1)
                    .is_some_and(|&group| self.is_doc_meta_group(group))
                {
                    return comment.is_outer_doc_comment();
                }
                comment.is_inner_doc_comment()
                    && siblings.get(position + 1).is_some_and(|&bang| {
                        matches!(
                            &self.arm.patterns[bang].kind,
                            RustMacroPatternSourceKind::Literal { text, .. } if text == "!"
                        ) && siblings
                            .get(position + 2)
                            .is_some_and(|&group| self.is_doc_meta_group(group))
                    })
            }
            "!" => {
                comment.is_inner_doc_comment()
                    && position > 0
                    && matches!(
                        &self.arm.patterns[siblings[position - 1]].kind,
                        RustMacroPatternSourceKind::Literal { text, .. } if text == "#"
                    )
                    && siblings
                        .get(position + 1)
                        .is_some_and(|&group| self.is_doc_meta_group(group))
            }
            _ => false,
        }
    }

    fn is_doc_meta_group(&self, pattern: usize) -> bool {
        matches!(
            self.arm.patterns[pattern].kind,
            RustMacroPatternSourceKind::Group {
                delimiter: Some(
                    brokk_bifrost_core::analyzer::rust_facts::RustMacroDelimiter::Bracket
                )
            }
        ) && self.children[pattern]
            .as_slice()
            .first()
            .is_some_and(|&child| {
                self.children[pattern].len() == 1
                    && matches!(
                        self.arm.patterns[child].kind,
                        RustMacroPatternSourceKind::Binding {
                            fragment: MacroFragmentKind::Meta,
                            ..
                        }
                    )
            })
    }

    fn is_doc_meta_attribute_group(&self, pattern: usize, comment: MacroInputNode<'_>) -> bool {
        if !self.is_doc_meta_group(pattern) {
            return false;
        }
        let Some(parent) = self.parents[pattern] else {
            return false;
        };
        let siblings = &self.children[parent];
        let Some(position) = siblings.iter().position(|&sibling| sibling == pattern) else {
            return false;
        };
        let Some(&previous) = position
            .checked_sub(1)
            .and_then(|position| siblings.get(position))
        else {
            return false;
        };
        match &self.arm.patterns[previous].kind {
            RustMacroPatternSourceKind::Literal { text, .. } if text == "#" => {
                comment.is_outer_doc_comment()
            }
            RustMacroPatternSourceKind::Literal { text, .. } if text == "!" && position >= 2 => {
                matches!(
                    &self.arm.patterns[siblings[position - 2]].kind,
                    RustMacroPatternSourceKind::Literal { text, .. } if text == "#"
                ) && comment.is_inner_doc_comment()
            }
            _ => false,
        }
    }

    fn begin_repetition_attempt(&mut self) {
        let Some(MatchFrame::Repetition {
            pattern,
            count,
            saved_input,
            binding_len,
            ..
        }) = self.frames.last_mut()
        else {
            unreachable!("a repetition attempt has a repetition frame");
        };
        *saved_input = self.input.index;
        *binding_len = self.bindings.len();
        self.repetition_path.push(*count);
        let parent = *pattern;
        self.frames.push(MatchFrame::Sequence { parent, next: 0 });
    }

    fn finish_child(
        &mut self,
        mut success: bool,
        keep_going: &dyn Fn() -> bool,
    ) -> Result<MatchFlow, MacroMatchError> {
        loop {
            if !keep_going() {
                return Err(MacroMatchError::Interrupted);
            }
            let Some(frame) = self.frames.last_mut() else {
                return Ok(MatchFlow::Done(success));
            };
            match frame {
                MatchFrame::Sequence { .. } => {
                    if success {
                        return Ok(MatchFlow::Continue);
                    }
                    self.frames.pop();
                }
                MatchFrame::Group { .. } => {
                    let MatchFrame::Group {
                        parent_input,
                        binding_len,
                    } = self.frames.pop().expect("group frame")
                    else {
                        unreachable!()
                    };
                    success &= self.input.index == self.input.tokens.len();
                    self.input = parent_input;
                    if success {
                        self.input.advance();
                    } else {
                        self.bindings.truncate(binding_len);
                    }
                }
                MatchFrame::Repetition {
                    pattern,
                    count,
                    after_last_group,
                    saved_input,
                    binding_len,
                } => {
                    assert_eq!(self.repetition_path.pop(), Some(*count));
                    let RustMacroPatternSourceKind::Repetition {
                        operator,
                        separator,
                    } = &self.arm.patterns[*pattern].kind
                    else {
                        unreachable!()
                    };
                    if success && self.input.index == *saved_input {
                        self.bindings.truncate(*binding_len);
                        self.frames.pop();
                        success = false;
                        continue;
                    }
                    if success {
                        *after_last_group = Some(self.input.index);
                        *count += 1;
                        if *operator == RepetitionOp::Optional {
                            self.frames.pop();
                            continue;
                        }
                        let repeat = match separator.as_deref() {
                            Some(separator) => {
                                match_separator(separator, &mut self.input, keep_going)?
                            }
                            None => true,
                        };
                        if repeat {
                            self.begin_repetition_attempt();
                            return Ok(MatchFlow::Continue);
                        }
                    } else {
                        self.input.index = *saved_input;
                        self.bindings.truncate(*binding_len);
                        success = *count > 0 || *operator != RepetitionOp::Plus;
                        if *count > 0 {
                            self.input.index =
                                after_last_group.expect("successful repetition resume index");
                        }
                    }
                    self.frames.pop();
                }
            }
        }
    }
}
