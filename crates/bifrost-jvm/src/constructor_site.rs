//! The rows that declare one constructor of a type, shared by the JVM
//! producers.
//!
//! A producer decides what source the constructor stands for and where its
//! site is anchored. A written constructor stands for its own declaration. A
//! constructor the language supplies when none is written (Java's default
//! constructor, Kotlin's zero-parameter primary constructor) stands for the
//! class declaration, anchored at the class name token, so a call that selects
//! it navigates to the class. Either way the rows below are the same: the
//! constructor is named after its type, bound scope-wide in the type's body,
//! and owned by the type as a member that is reached through the type.

use brokk_bifrost_core::analyzer::resolution_facts::{
    FileResolutionFacts, PositionedIdentifierFact, ResolutionBinderFact, ResolutionBinderKind,
    ResolutionIdentifierRole, ResolutionMemberAccess, ResolutionMemberKind,
    ResolutionMemberOwnerFact, ResolutionMemberQualifierCompatibility, ResolutionNameId,
    ResolutionNamespace, ResolutionScopeId, ResolutionSiteId,
};
use brokk_bifrost_core::analyzer::structural::resolution::HoistingClass;

/// One constructor of a type that has a body scope.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ConstructorSite {
    /// The constructor's declaration site.
    pub(crate) site: ResolutionSiteId,
    /// The type declaration that owns the constructor.
    pub(crate) owner: ResolutionSiteId,
    /// The owner's simple name, which names its constructors too.
    pub(crate) owner_name: ResolutionNameId,
    /// The owner's type-body scope, in which the constructor is declared.
    pub(crate) scope: ResolutionScopeId,
}

impl ConstructorSite {
    /// Publish the constructor's declaration identifier, its scope-wide binder
    /// and its member-owner row. The member-owner row is what gives a call that
    /// selects the constructor its result type, the owner.
    pub(crate) fn publish(self, facts: &mut FileResolutionFacts) {
        let scope = *facts.scope(self.scope);
        facts.identifiers.push(PositionedIdentifierFact {
            site: self.site,
            name: self.owner_name,
            role: ResolutionIdentifierRole::Declaration,
            namespace: ResolutionNamespace::Constructor,
            qualifier: None,
        });
        facts.binders.push(ResolutionBinderFact {
            declaration: self.site,
            scope: self.scope,
            kind: ResolutionBinderKind::Constructor,
            hoisting: HoistingClass::ScopeWide,
            activation_start: scope.start_byte,
            activation_end: scope.end_byte,
        });
        facts.member_owners.push(ResolutionMemberOwnerFact {
            member: self.site,
            owner: self.owner,
            kind: ResolutionMemberKind::Constructor,
            access: ResolutionMemberAccess::Type,
            qualifier_compatibility: ResolutionMemberQualifierCompatibility::TypeOnly,
        });
    }
}
