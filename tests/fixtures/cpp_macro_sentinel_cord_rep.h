#pragma once

#include "cord_internal.h"

namespace absl {
// Deliberately undefined: in the generated parser this object-like namespace
// sentinel swallows the first using declaration.  The declarations below are
// still in the recovered absl namespace and must retain the cord_internal
// owner for their nullability-annotated return and parameter types.
ABSL_NAMESPACE_BEGIN
using ::absl::cord_internal::CordRep;

static inline CordRep* absl_nullable VerifyTree(CordRep* absl_nullable node) {
  return node;
}

static inline CordRep* absl_nonnull TakeRep(CordRep* absl_nonnull node) {
  return CordRep::Ref(node);
}
}  // namespace absl

namespace unrelated {
class CordRep {};

static CordRep* absl_nullable VerifyTree(CordRep* absl_nullable node) {
  return node;
}
}  // namespace unrelated
