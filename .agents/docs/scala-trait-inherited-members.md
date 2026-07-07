# Scala trait inherited members

Scala trait default members are modeled through hierarchy-driven receiver-owner lookup in the usage graph. Bifrost does not materialize synthetic inherited members on descendant classes.

For a trait-owned method or field target, the Scala usage graph treats a descendant type as a receiver owner when the descendant inherits that target through the type hierarchy and the nearest ancestor/member state resolves unambiguously to the target family. Declaring family owners remain limited to the target declaration and real method overrides; inherited receiver-only types are used for receiver typing, not owner-qualified imports or synthetic declarations. Trait method overrides remain part of the declaring family, so existing override-family find-usages behavior is preserved.

Concrete receiver `get_definition` keeps its existing lookup order: the concrete owner is checked first, then ancestors. That means an overriding class member is preferred for concrete receiver lookup, while a class that inherits a trait default member resolves to the trait declaration.
