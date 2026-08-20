//! Compile-time proof that a request scope is open (issue #2414 step 3).
//!
//! The syntax information tier is the bottom rung of the ladder described in
//! `.agents/plans/issue-2414-tier-ladder-enforcement.md`: reaching it parses a
//! file. Parsing is only cheap when a request scope is open, because the
//! scope owns the memoization that keeps one file's tree alive across the
//! hundreds of accessor calls a single usage scan makes. Every ticket in the
//! #1175/#1181 re-parse defect family was the same mistake: a chain that
//! reached a syntax accessor with no scope anywhere above it, so each call
//! re-parsed.
//!
//! [`QueryToken`] turns that mistake into a compile error. The syntax
//! accessors take one, and the only way to obtain one is from an open scope.

use std::marker::PhantomData;

/// Proof that an analyzer request scope is open somewhere up the stack.
///
/// Holding a token means request-scoped memoization is active for the
/// analyzer the scope was opened on, so a syntax accessor call is a cache
/// probe rather than a parse. The token carries no data: accessors that take
/// one may ignore the value entirely. Its lifetime is the scope's borrow, so
/// a token cannot outlive the scope that minted it.
///
/// There is deliberately no `Default`, no public field, and no constructor.
/// The single mint is [`QueryScope::token`], implemented by
/// `AnalyzerQueryScope` in `brokk-bifrost-analysis`. Do not add another one:
/// a second way to make a token is a second way to forget the scope.
#[derive(Clone, Copy, Debug)]
pub struct QueryToken<'a> {
    scope: PhantomData<&'a ()>,
}

/// The minting side of [`QueryToken`].
///
/// Implemented by `AnalyzerQueryScope` in `brokk-bifrost-analysis` and by
/// nothing else. The trait lives here, below the analysis crate, because the
/// language crates' analyzer-support traits carry the token in their own
/// signatures and cannot depend on `brokk-bifrost-analysis`.
pub trait QueryScope {
    /// Mint proof that this scope is open.
    fn token(&self) -> QueryToken<'_> {
        QueryToken { scope: PhantomData }
    }
}
