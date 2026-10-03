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

struct MatchMachine<'facts, 'tree> {
    arm: &'facts RustMacroArmSourceFact,
    children: Vec<Vec<usize>>,
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
        let mut children = vec![Vec::new(); arm.patterns.len()];
        for (position, pattern) in arm.patterns.iter().enumerate() {
            if !keep_going() {
                return Err(MacroMatchError::Interrupted);
            }
            if let Some(parent) = pattern.parent {
                let parent = *positions
                    .get(&parent)
                    .expect("published pattern parent precedes its child");
                children[parent].push(position);
            } else {
                assert_eq!(position, 0, "a published matcher has one first root");
                assert_eq!(Some(pattern.occurrence), arm.pattern);
            }
            assert!(positions.insert(pattern.occurrence, position).is_none());
        }
        assert!(!arm.patterns.is_empty(), "present matcher has a root node");
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
                            *self
                                .ident_roles
                                .get(name.as_str())
                                .expect("published ident binding has a transcriber role")
                        }),
                    });
                    true
                } else {
                    false
                }
            }
            RustMacroPatternSourceKind::Group { delimiter } => {
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
                let matched = self.input.current().is_some_and(|token| {
                    (token.kind() == syntax_kind
                        || (identifier_kind_like(syntax_kind) && identifier_like(token)))
                        && token.text().trim() == text
                });
                if matched {
                    self.input.advance();
                }
                matched
            }
            RustMacroPatternSourceKind::Invalid => false,
        };
        self.finish_child(matched, keep_going)
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
