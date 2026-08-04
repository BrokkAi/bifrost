#pragma once

#include "cpp_macro_sentinel_cord_rep_btree_forward.h"

namespace absl {
ABSL_NAMESPACE_BEGIN
namespace cord_internal {
class CordRepBtree {
 public:
  static const CordRepBtree* AssertValid(const CordRepBtree* tree);
};

#ifdef NDEBUG
inline const CordRepBtree* CordRepBtree::AssertValid(
    const CordRepBtree* tree) {
  return tree;
}
#endif
}  // namespace cord_internal
ABSL_NAMESPACE_END
}  // namespace absl
