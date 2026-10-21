use crate::analyzer::semantic::lexical_definitions::FormalParameterLayout;

use crate::analyzer::semantic::lexical_definitions::FormalParameterSlot;

use crate::analyzer::semantic::ArgumentDomain;

use crate::analyzer::semantic::CallArgumentExpansion;

use crate::analyzer::semantic::SemanticCallArgument;

/// The ordinary (non-receiver) formal slots of one callable, in declaration
/// order, together with the rule that maps one actual onto one of them.
///
/// This is the single computation the production call-relation binder and the
/// `call_binding` rows both read. Changing the rule here changes both, which is
/// what keeps a row from ever claiming a binding `call_input` does not make.
#[doc(hidden)]
pub struct OrdinaryFormalSlots<'a> {
    #[doc(hidden)]
    pub slots: Vec<(usize, &'a FormalParameterSlot)>,
}

impl<'a> OrdinaryFormalSlots<'a> {
    /// `bind_first` drops the first ordinary slot, which is how a Python
    /// instance method's `self` is already consumed by the receiver.
    #[doc(hidden)]
    pub fn of(layout: &'a FormalParameterLayout, bind_first: bool) -> Self {
        let mut slots = layout
            .slots
            .iter()
            .filter(|slot| !slot.receiver)
            .collect::<Vec<_>>();
        if bind_first && !slots.is_empty() {
            slots.remove(0);
        }
        Self {
            slots: slots.into_iter().enumerate().collect(),
        }
    }

    /// Every ordinary slot with the ordinal an actual binding it reports.
    #[doc(hidden)]
    pub fn slots(&self) -> &[(usize, &'a FormalParameterSlot)] {
        &self.slots
    }

    /// The formal slot one actual binds, or `None` when it binds none.
    ///
    /// A spread actual binds nothing: its members are not statically known, so
    /// naming one slot for the whole pack would be a claim nobody checked. A
    /// named actual takes the slot whose declared names match, otherwise the
    /// last keyword-accepting variadic slot. A positional actual takes the slot
    /// at its ordinal, otherwise the last positional-accepting variadic slot.
    #[doc(hidden)]
    pub fn slot_for(
        &self,
        name: Option<&str>,
        position: Option<usize>,
        spread: bool,
    ) -> Option<(usize, &'a FormalParameterSlot)> {
        if spread {
            return None;
        }
        if let Some(name) = name {
            return self
                .slots
                .iter()
                .copied()
                .find(|(_, slot)| {
                    slot.passing_mode.accepts_named()
                        && slot
                            .names
                            .iter()
                            .any(|candidate| names_match(candidate, name))
                })
                .or_else(|| {
                    self.slots.iter().copied().rev().find(|(_, slot)| {
                        slot.passing_mode.accepts_named()
                            && slot.variadic.is_some_and(|kind| kind.accepts_keyword())
                    })
                });
        }
        position.and_then(|position| {
            self.slots
                .iter()
                .copied()
                .filter(|(_, slot)| slot.passing_mode.accepts_positional())
                .nth(position)
                .or_else(|| {
                    self.slots.iter().copied().rev().find(|(_, slot)| {
                        slot.passing_mode.accepts_positional()
                            && slot.variadic.is_some_and(|kind| kind.accepts_positional())
                    })
                })
        })
    }
}

/// Bind one structured semantic call's direct actuals with the same slot
/// matcher used by call-binding rows and call-input relations. Spreads,
/// unknown argument shapes, duplicate bindings, and unbound required formals
/// remain incomplete.
#[doc(hidden)]
pub fn bind_semantic_call_arguments(
    arguments: &[SemanticCallArgument],
    layout: &FormalParameterLayout,
) -> Option<Box<[u32]>> {
    if layout.slots.iter().any(|slot| slot.receiver) {
        return None;
    }
    let formals = OrdinaryFormalSlots::of(layout, false);
    let mut supplied = vec![false; formals.slots().len()];
    let mut actual_to_formal = Vec::with_capacity(arguments.len());
    let mut positional_index = 0usize;
    let mut saw_keyword = false;

    for argument in arguments {
        let (name, position) = match (&argument.expansion, argument.keyword.as_deref()) {
            (CallArgumentExpansion::Direct(ArgumentDomain::Positional), None) => {
                if saw_keyword {
                    return None;
                }
                let position = positional_index;
                positional_index += 1;
                (None, Some(position))
            }
            (CallArgumentExpansion::Direct(ArgumentDomain::Positional), Some(_)) => return None,
            (CallArgumentExpansion::Direct(ArgumentDomain::Keyword), Some(name)) => {
                saw_keyword = true;
                (Some(name), None)
            }
            (CallArgumentExpansion::Direct(ArgumentDomain::PositionalOrKeyword), name) => {
                if let Some(name) = name {
                    saw_keyword = true;
                    (Some(name), None)
                } else {
                    if saw_keyword {
                        return None;
                    }
                    let position = positional_index;
                    positional_index += 1;
                    (None, Some(position))
                }
            }
            (CallArgumentExpansion::Direct(ArgumentDomain::Keyword), None)
            | (CallArgumentExpansion::Direct(ArgumentDomain::LanguageDefined(_)), _)
            | (CallArgumentExpansion::Spread(_), _)
            | (CallArgumentExpansion::Unclassified, _) => return None,
        };
        let (formal, slot) = formals.slot_for(name, position, false)?;
        let bound = supplied.get_mut(formal)?;
        if *bound && slot.variadic.is_none() {
            return None;
        }
        *bound = true;
        actual_to_formal.push(u32::try_from(formal).expect("formal slot count fits u32"));
    }

    formals
        .slots()
        .iter()
        .zip(supplied)
        .all(|((_, slot), supplied)| {
            supplied || slot.default_range.is_some() || slot.variadic.is_some()
        })
        .then(|| actual_to_formal.into_boxed_slice())
}

#[doc(hidden)]
pub fn names_match(formal: &str, argument: &str) -> bool {
    formal == argument
        || formal.strip_prefix('$') == Some(argument)
        || argument.strip_prefix('$') == Some(formal)
}
