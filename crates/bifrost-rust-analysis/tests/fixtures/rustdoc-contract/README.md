These small rustdoc format-61 documents were written for #6542 as test-only input.
They are synthetic and contain no copied standard-library or premium pack content.
Use.source deliberately disagrees with the structured external paths: only paths
and external_crates may determine the cross-document join.

Milestone 2 adds a deliberately missing impl item on Broken (item 999) to
exercise owner-scoped decoding diagnostics, plus an outside-source-set trait
sharing the primitive walk family. The alloc document implements a core trait
so certification must wait for the cross-document source-set join.
The alloc document also contains a skipped impl member for core.Widget, whose
owner is defined only in core; that decoding diagnostic blocks its families.

Milestone 1b adds a trait-owned bare-parameter blanket impl and its per-type
presentation copy on alloc.boxed.Box<I, A>. The copy has only binder I, matching
the real pinned rustdoc failure: it must not become a Box implementation fact or
a forwarding rule with unbound A. Schema 19 retains the real bare-parameter
rule, its explicit and implicit bounds, and its implicit Self scope. It also
retains the explicit negative Forbidden implementation and the conditional
Traverse implementation on Widget, while skipping the synthesized Send impl.
The alloc concrete implementation joins Widget in core before certification.
The roundtrip exercises both inventory claims and both absence-predicate paths;
an auto-trait rival remains unknown.

The primitive-owner regression adds an alloc inherent slice impl without a
local primitive declaration; only core emits its owner. The i128 extension
has no owner in either document and must still be diagnosed and dropped.
Box's new constructor returns Self and as_self returns a nested reference to
Self, retaining the structured impl application and its owner parameters.
