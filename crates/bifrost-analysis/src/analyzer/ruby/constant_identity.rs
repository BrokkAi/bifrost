//! The one place that turns a Ruby constant path into a declaration identity in
//! the activated semantic-model overlay, and a constant under it into the
//! overlay symbol that proves it.
//!
//! Semantic diagnostics (`ruby::diagnostics`) and boundary refinement for
//! `get_definition` (`usages::get_definition::trace`) must answer "which gem
//! declaration is this" identically. Two parallel implementations would agree
//! only by accident, so both consume this resolver: the `rubygems` ecosystem
//! string, the `::`-joined name shape the Ruby pack producer mints under, the
//! identity-not-name lookup rule, and the ancestor walk Ruby constant lookup
//! follows all live here once.
//!
//! Every method reads retained overlay state. None of them runs Bundler, reads
//! a gem archive, walks a gem directory, or starts dependency discovery.

use crate::analyzer::SemanticDiagnosticDomain;
use crate::analyzer::semantic_model::{
    SemanticModelCompleteness, SemanticModelOverlay, SemanticModelOverlayDisposition,
    SemanticModelSymbol, SemanticModelSymbolKind, TypeIdentity, type_declaration_id,
};

/// The ecosystem every Ruby declaration identity is minted under, in the gem
/// pack producer (`ruby::rbs_artifact`, `ruby::source_artifact`) and here.
pub(crate) const RUBY_GEM_ECOSYSTEM: &str = "rubygems";

/// The hierarchy edges Ruby's `Owner::CONST` lookup walks. `mixin_extend` is
/// absent on purpose: `extend` adds singleton methods to an object, it does not
/// put the extended module's constants in the extender's lookup path.
const CONSTANT_LOOKUP_EDGES: [&str; 5] = [
    "extends",
    "implements",
    "uses_trait",
    "mixin_include",
    "mixin_prepend",
];

/// The ancestor walk stops here. A gem hierarchy deeper than this is not a
/// surface a diagnostic should spend a request budget proving complete.
const MAX_RUBY_ANCESTOR_WALK: usize = 64;

/// The activated overlay, read as a Ruby constant index.
#[derive(Clone, Copy)]
pub(crate) struct RubyOverlayConstants<'a> {
    overlay: Option<&'a SemanticModelOverlay>,
}

/// The published surface a constant lookup under one gem owner may search.
pub(crate) struct RubyConstantSurface<'a> {
    /// The owner and every ancestor the walk could reach. Best effort: a name
    /// published anywhere in it suppresses a diagnostic even when `open` is set.
    pub(crate) searched: Vec<&'a SemanticModelSymbol>,
    /// Why a name missing from `searched` is still not proven absent, if it is
    /// not. `None` means every hop on Ruby's constant lookup path is published,
    /// unambiguous, and described completely.
    pub(crate) open: Option<String>,
}

impl<'a> RubyOverlayConstants<'a> {
    pub(crate) fn new(overlay: Option<&'a SemanticModelOverlay>) -> Self {
        Self { overlay }
    }

    /// The declaration identity a Ruby gem pack mints for a `::`-joined constant
    /// path. Both the producer and every consumer must spell this one way.
    pub(crate) fn declaration_id(constant_path: &str) -> String {
        type_declaration_id(TypeIdentity {
            ecosystem: RUBY_GEM_ECOSYSTEM,
            name: constant_path,
        })
    }

    /// Whether any activated pack publishes `constant_path` as a type.
    ///
    /// The question a suppression asks: one published record is enough to keep a
    /// reference from being called absent, even when two packs publish it.
    pub(crate) fn publishes_type(&self, constant_path: &str) -> bool {
        self.overlay.is_some_and(|overlay| {
            !overlay
                .symbols_with_id(&Self::declaration_id(constant_path))
                .records
                .is_empty()
        })
    }

    /// The single type an activated pack publishes for `constant_path`.
    ///
    /// The lookup is by declaration identity rather than by name, so it cannot
    /// be satisfied by a same-named symbol from another ecosystem. A path that
    /// more than one activated pack claims is deliberately not unique: the
    /// overlay marks it `Conflict` and this returns `None`, so neither
    /// navigation nor a diagnostic picks an arbitrary winner.
    pub(crate) fn unique_type(&self, constant_path: &str) -> Option<&'a SemanticModelSymbol> {
        let matched = self
            .overlay?
            .symbols_with_id(&Self::declaration_id(constant_path));
        (matched.disposition == SemanticModelOverlayDisposition::Unique)
            .then(|| matched.records.first().copied())
            .flatten()
    }

    /// Whether more than one activated pack claims `constant_path`.
    pub(crate) fn conflicts(&self, constant_path: &str) -> bool {
        self.overlay.is_some_and(|overlay| {
            overlay
                .symbols_with_id(&Self::declaration_id(constant_path))
                .disposition
                == SemanticModelOverlayDisposition::Conflict
        })
    }

    /// Whether the packs publish `terminal` under `owner`: a nested type, or a
    /// constant, method, property or alias the owner declares.
    ///
    /// Any published member with the name counts. This answer only ever
    /// suppresses a diagnostic, so admitting a member whose kind a projection
    /// recorded imprecisely is the safe direction.
    pub(crate) fn publishes_under(&self, owner: &SemanticModelSymbol, terminal: &str) -> bool {
        if self.publishes_type(&format!("{}::{terminal}", owner.qualified_name)) {
            return true;
        }
        let Some(overlay) = self.overlay else {
            return false;
        };
        overlay.members_of(&owner.id).records.iter().any(|member| {
            member.name == terminal || member.aliases.iter().any(|alias| alias == terminal)
        })
    }

    /// The surface `Owner::CONST` searches: the owner plus every ancestor on
    /// Ruby's constant lookup path, or the reason the chain stays open.
    ///
    /// Closing the chain needs three things at every hop: the pack that
    /// published it claims a complete surface, the hop is not claimed by two
    /// packs at once, and every hierarchy edge it declares resolves to a
    /// published type. An edge whose target no pack publishes is the #1789 case:
    /// the surface is not complete, whatever the pack's own manifest says,
    /// because the members it inherits were never described.
    pub(crate) fn constant_surface(
        &self,
        owner: &'a SemanticModelSymbol,
    ) -> RubyConstantSurface<'a> {
        let Some(overlay) = self.overlay else {
            return RubyConstantSurface {
                searched: Vec::new(),
                open: Some("no activated gem pack is published".to_string()),
            };
        };
        let mut searched: Vec<&'a SemanticModelSymbol> = Vec::new();
        let mut open = None;
        let mut queue = vec![owner];
        // The walk keeps going after it records a reason: what it still finds
        // can suppress a diagnostic even once absence is off the table.
        while let Some(symbol) = queue.pop() {
            if searched.iter().any(|seen| seen.id == symbol.id) {
                continue;
            }
            if searched.len() >= MAX_RUBY_ANCESTOR_WALK {
                open.get_or_insert_with(|| {
                    format!(
                        "`{}` has a constant lookup chain deeper than {MAX_RUBY_ANCESTOR_WALK} types",
                        owner.qualified_name
                    )
                });
                break;
            }
            if symbol.provenance.completeness != SemanticModelCompleteness::Complete {
                open.get_or_insert_with(|| {
                    format!(
                        "the activated gem pack for `{}` describes a partial surface",
                        symbol.qualified_name
                    )
                });
            }
            if symbol.provenance.ambiguous {
                open.get_or_insert_with(|| {
                    format!(
                        "more than one activated gem pack declares `{}`",
                        symbol.qualified_name
                    )
                });
            }
            searched.push(symbol);
            for relation in overlay.relations_from(&symbol.id).records {
                if !CONSTANT_LOOKUP_EDGES.contains(&relation.kind.as_str()) {
                    continue;
                }
                let mut matched = overlay.symbols_with_id(&relation.to);
                if matched.records.is_empty() {
                    matched = overlay.symbols_named(&relation.to);
                }
                match matched.records.first().copied() {
                    Some(ancestor) => queue.push(ancestor),
                    // #1789: an unresolvable ancestor means the surface is not
                    // complete whatever the pack manifest claims, because the
                    // constants it inherits were never described.
                    None => {
                        open.get_or_insert_with(|| {
                            format!(
                                "`{}` reaches `{}`, which no activated gem pack publishes",
                                symbol.qualified_name, relation.to
                            )
                        });
                    }
                }
            }
        }
        RubyConstantSurface { searched, open }
    }

    /// The structured domain an absence proof under `owner` names: the checked
    /// surface is the owner's, so the proof identifies the owner, not the file.
    pub(crate) fn absence_domain(owner: &SemanticModelSymbol) -> SemanticDiagnosticDomain {
        let name = owner.qualified_name.clone();
        match owner.kind {
            SemanticModelSymbolKind::Module => SemanticDiagnosticDomain::Module { name },
            _ => SemanticDiagnosticDomain::Type { name },
        }
    }
}
