//! Resolution-time identity reconciliation for C++ out-of-line member
//! definitions (#1134).
//!
//! A method nested inside a class that is itself inside a namespace --
//! `log4cxx::Outer::Inner::method` -- is declared in a header (indexed
//! `log4cxx.Outer$Inner.method`: `$` joins the class-nesting chain, the
//! enclosing namespace is the package) and defined out-of-line in a `.cpp`
//! (`int Outer::Inner::method() const {...}`). Per-file extraction cannot see
//! the header's class layout, so it must guess whether each qualifier segment
//! (`Outer`, `Inner`) is a namespace or a class. Two shapes guess wrong (#1121
//! left them documented, not masked): a file-scope definition under a
//! `using namespace` directive, and the template-specialization twin. Both are
//! irreducibly class-table-dependent -- the only signal that `Outer` is a class
//! and not a namespace is the set of classes visible to the `.cpp` through its
//! `#include` graph.
//!
//! This module holds the pure decision: given the ordered owner segments of a
//! definition's qualifier, the candidate enclosing namespaces (the lexical
//! package plus any in-scope `using namespace` targets), and a view of the
//! include-visible class table, decide the one canonical `(package, owner-chain,
//! member)` a visible class actually confirms -- or refuse when nothing
//! confirms or the confirmation is ambiguous. The function is analyzer-free and
//! I/O-free so it can be unit-tested in isolation; the analyzer wiring that
//! feeds it the real class table lives in the surrounding modules.

/// A minimal, testable view of one class visible to a file through its
/// `#include` graph: its enclosing namespace (`::`-joined, empty at global
/// scope) and its class-nesting chain as Bifrost's `$`-joined short name
/// (`Outer$Inner` for `Outer::Inner`, `Klass` for a non-nested class).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VisibleClass<'a> {
    pub package: &'a str,
    pub nested_short_name: &'a str,
}

/// The canonical identity a definition should unify under: the enclosing
/// namespace (`::`-joined), the class-nesting chain (`$`-joined short name), and
/// the member name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReconciledIdentity {
    pub package: String,
    pub owner_chain: String,
    pub member: String,
}

impl ReconciledIdentity {
    /// Render this identity as a `CodeUnit`-style `fq_name`
    /// (`package.owner_chain.member`, package omitted at global scope), so it can
    /// be compared against and keyed alongside stored identities.
    pub(crate) fn fq_name(&self) -> String {
        let short = format!("{}.{}", self.owner_chain, self.member);
        if self.package.is_empty() {
            short
        } else {
            format!("{}.{}", self.package, short)
        }
    }
}

/// Decide the canonical identity of an out-of-line member definition from its
/// qualifier segments and the include-visible class table.
///
/// `owner_segments` are the qualifier segments in source order, excluding the
/// terminal member -- `["Outer", "Inner"]` for `Outer::Inner::method`.
/// `namespace_candidates` are the enclosing namespaces to try, most-authoritative
/// first: the lexical package (the `namespace {}` block the definition sits in,
/// or empty at file scope) followed by every `using namespace` target in scope
/// at that point. `class_table` is the include-visible class table.
///
/// The function partitions the segments into a namespace prefix and a
/// class-nesting suffix at every split point, prepending the leading segments
/// onto each candidate namespace, and keeps a partition only when some visible
/// class confirms it exactly (same package, same `$`-joined chain). It prefers
/// the reading with the *longest* confirmed class chain (the deepest real
/// nesting is the most specific true identity). It returns `None` when nothing
/// in the table confirms any reading (caller leaves the provisional identity
/// untouched) and when two distinct identities tie at the deepest confirmed
/// nesting (genuinely ambiguous -- never guess).
pub(crate) fn reconcile_out_of_line_member_identity(
    owner_segments: &[&str],
    member: &str,
    namespace_candidates: &[&str],
    class_table: &[VisibleClass<'_>],
) -> Option<ReconciledIdentity> {
    if owner_segments.is_empty() || member.is_empty() {
        return None;
    }

    // Split points ordered by longest class chain first (smallest `i` reads the
    // fewest leading segments as namespace, so the most as class nesting). The
    // class suffix must be non-empty, so `i` never reaches `owner_segments.len()`.
    for split in 0..owner_segments.len() {
        let chain = owner_segments[split..].join("$");
        let namespace_prefix = &owner_segments[..split];

        let mut confirmed: Option<ReconciledIdentity> = None;
        for namespace in namespace_candidates {
            let package = join_namespace(namespace, namespace_prefix);
            let matches = class_table.iter().any(|visible| {
                visible.package == package && visible.nested_short_name == chain
            });
            if !matches {
                continue;
            }
            let candidate = ReconciledIdentity {
                package,
                owner_chain: chain.clone(),
                member: member.to_string(),
            };
            match &confirmed {
                // A second, *distinct* reading at the same (deepest) nesting is
                // genuinely ambiguous -- two visible classes with the same chain
                // in different namespaces both match. Refuse rather than guess.
                Some(existing) if existing != &candidate => return None,
                Some(_) => {}
                None => confirmed = Some(candidate),
            }
        }

        if let Some(identity) = confirmed {
            return Some(identity);
        }
    }

    None
}

/// Join an enclosing namespace with the leading owner segments that are being
/// read as further namespace nesting, in Bifrost's `::`-joined package form.
fn join_namespace(namespace: &str, extra_segments: &[&str]) -> String {
    let extra = extra_segments.join("::");
    match (namespace.is_empty(), extra.is_empty()) {
        (true, true) => String::new(),
        (true, false) => extra,
        (false, true) => namespace.to_string(),
        (false, false) => format!("{namespace}::{extra}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(package: &str, owner_chain: &str, member: &str) -> ReconciledIdentity {
        ReconciledIdentity {
            package: package.to_string(),
            owner_chain: owner_chain.to_string(),
            member: member.to_string(),
        }
    }

    /// File-scope definition under `using namespace log4cxx;`:
    /// `int Outer::Inner::method()` at file scope. The lexical package is empty;
    /// the using-directive contributes `log4cxx`. The include-visible class
    /// table confirms `log4cxx::Outer::Inner`, so the whole qualifier is a class
    /// chain under `log4cxx`, not a namespace path.
    #[test]
    fn file_scope_using_directive_shape_recovers_namespace_and_chain() {
        let table = [
            VisibleClass { package: "log4cxx", nested_short_name: "Outer" },
            VisibleClass { package: "log4cxx", nested_short_name: "Outer$Inner" },
        ];
        let reconciled = reconcile_out_of_line_member_identity(
            &["Outer", "Inner"],
            "method",
            &["", "log4cxx"],
            &table,
        );
        assert_eq!(reconciled, Some(identity("log4cxx", "Outer$Inner", "method")));
    }

    /// Template-specialization twin inside `namespace ns {}`:
    /// `Outer::Inner<int>::method`. The lexical package is `ns`; the templated
    /// splitter mis-reads `Outer` as a namespace. The class table confirms
    /// `ns::Outer::Inner`, folding `Outer` back into the class chain.
    #[test]
    fn template_shape_inside_namespace_block_folds_outer_into_chain() {
        let table = [VisibleClass { package: "ns", nested_short_name: "Outer$Inner" }];
        let reconciled = reconcile_out_of_line_member_identity(
            &["Outer", "Inner"],
            "method",
            &["ns"],
            &table,
        );
        assert_eq!(reconciled, Some(identity("ns", "Outer$Inner", "method")));
    }

    /// Genuine namespace chain `ns1::ns2::Klass::method` written out-of-line at
    /// file scope: the class table contains the real class
    /// (`package ns1::ns2`, `Klass`) but no nested-class reading of the leading
    /// segments. Reconciliation confirms the namespace reading unchanged -- it
    /// must never corrupt the owner into `ns1$ns2$Klass`.
    #[test]
    fn genuine_namespace_chain_keeps_namespace_reading() {
        let table = [VisibleClass { package: "ns1::ns2", nested_short_name: "Klass" }];
        let reconciled = reconcile_out_of_line_member_identity(
            &["ns1", "ns2", "Klass"],
            "method",
            &[""],
            &table,
        );
        assert_eq!(reconciled, Some(identity("ns1::ns2", "Klass", "method")));
    }

    /// Deepest confirmed nesting wins: when both a shallow and a deep reading are
    /// visible, the deeper class chain is the more specific true identity.
    #[test]
    fn prefers_longest_confirmed_class_chain() {
        let table = [
            VisibleClass { package: "a::Outer", nested_short_name: "Inner" },
            VisibleClass { package: "a", nested_short_name: "Outer$Inner" },
        ];
        let reconciled = reconcile_out_of_line_member_identity(
            &["Outer", "Inner"],
            "method",
            &["a"],
            &table,
        );
        assert_eq!(reconciled, Some(identity("a", "Outer$Inner", "method")));
    }

    /// Nothing visible confirms any reading: leave the provisional identity
    /// untouched (caller keeps today's behavior).
    #[test]
    fn no_visible_class_returns_none() {
        let reconciled = reconcile_out_of_line_member_identity(
            &["Outer", "Inner"],
            "method",
            &["", "log4cxx"],
            &[],
        );
        assert_eq!(reconciled, None);
    }

    /// Two visible classes confirm distinct readings at the same (deepest)
    /// nesting depth -- genuinely ambiguous, so refuse rather than guess.
    #[test]
    fn ambiguous_equal_depth_readings_return_none() {
        let table = [
            VisibleClass { package: "one", nested_short_name: "Outer$Inner" },
            VisibleClass { package: "two", nested_short_name: "Outer$Inner" },
        ];
        let reconciled = reconcile_out_of_line_member_identity(
            &["Outer", "Inner"],
            "method",
            &["one", "two"],
            &table,
        );
        assert_eq!(reconciled, None);
    }

    /// Empty owner segments or empty member name cannot name a member.
    #[test]
    fn degenerate_inputs_return_none() {
        assert_eq!(
            reconcile_out_of_line_member_identity(&[], "method", &["ns"], &[]),
            None
        );
        assert_eq!(
            reconcile_out_of_line_member_identity(&["Outer"], "", &["ns"], &[]),
            None
        );
    }
}
