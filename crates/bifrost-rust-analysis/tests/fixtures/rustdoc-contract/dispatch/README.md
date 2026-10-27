Synthetic format-61 rustdoc documents authored for #6542 product dispatch acceptance.
These test-only declarations contain no copied std or premium pack content. The real
RustdocJsonPackProducer joins them before activation; they are not a product pack.
Vec<T> supplies len and Deref::Target = [T]; Option<T> supplies take; primitive
str supplies split and slice supplies iter_mut. In-scope trait declarations cover
negative applicability and downstream local-trait-argument competition.

The private core.iter.Internal<T> constructor implements Iterator but has no
exported TypeFact. Its rule must not prevent proving that Vec and Option do not
implement Iterator: a different structured constructor head is sufficient.

Vec also implements private alloc.vec.InternalSpec, whose hierarchy edge has no
published trait declaration. Unrelated private hierarchy gaps must not reject a
certified direct family after scope and competition have been checked.

The engine receiver regression adds a synthetic Box<T> inherent len family,
a parameterized Extend rival, and a constructor returning Self, projected by the real producer onto its
structured Vec<T> owner application. These are test-only
contracts, not copied standard-library APIs. The opaque workspace macro pins
coherence exclusions and the fundamental/parameterized exceptions.

Synthetic Vec<T, A = T> deliberately uses a dependent trailing default.
Its constructor Self target omits A, while Deref requires both T and A.
The constructor/autoderef golden therefore pins substitution and default
completion for both written receiver types and produced Self results.

Box also supplies a synthetic Self-returning constructor. Its result proves
the Box head before len competition, so the fundamental-boundary case cannot
pass merely because native typing of an annotated Box<Local> is incomplete.

Milestone 4 adds synthetic trait declaration surfaces, an Iter receiver with an
unoverridden map method, a Printable Display implementation and the trait-owned
ToString blanket rule. IntoIterator::IntoIter has an Iterator bound; OtherNext
provides a second in-scope next declaration. These minimal declarations test
exact declaration navigation and open implementation dispatch, not std API
content or a second product catalog. The blanket rule's ordinary concrete-member
projection produces one expected nonconcrete-owner diagnostic.
