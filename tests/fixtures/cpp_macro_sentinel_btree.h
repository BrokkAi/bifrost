#pragma once

namespace std {
template <typename First, typename Second>
struct pair {
  First first;
  Second second;
};
}  // namespace std

namespace absl {
// Deliberately undefined: Abseil's object-like namespace sentinel is parsed
// as a malformed function wrapper until the analyzer recovers the indexed
// namespace and class owner.
ABSL_NAMESPACE_BEGIN
namespace container_internal {

template <typename Node, typename Reference, typename Pointer>
struct btree_iterator {
  using iterator = Node*;
};

template <typename Params>
struct btree_node {};

template <typename Params>
struct btree {
  using node_type = btree_node<Params>;
  using reference = Params*;
  using pointer = Params*;
  using iterator =
      typename btree_iterator<node_type, reference, pointer>::iterator;

  template <typename K>
  std::pair<iterator, bool> lower_bound_equal(const K&) const;

  template <typename K>
  auto equal_range(const K&) -> std::pair<iterator, iterator>;
};

template <typename P>
template <typename K>
auto btree<P>::equal_range(const K& key) -> std::pair<iterator, iterator> {
  const std::pair<iterator, bool> lower_and_equal = lower_bound_equal(key);
  const iterator lower = lower_and_equal.first;
  node_type* node = nullptr;
  (void)lower;
  (void)node;
  {
    using iterator = int;
    std::pair<iterator, bool> shadowed;
    (void)shadowed;
  }
  return {lower, lower};
}

template <typename P>
template <typename K>
auto btree<P>::lower_bound_equal(const K& key)
    const -> std::pair<iterator, bool> {
  (void)key;
  return {iterator{}, false};
}

struct ReturnType {};

template <typename P>
struct Outer {
  struct ReturnType {};
  struct Inner {
    static ReturnType method();
  };
};

template <typename P>
ReturnType Outer<P>::Inner::method() {
  return {};
}

struct ScopedType {};

namespace helper {
struct ScopedType {};
ScopedType use_scoped(ScopedType value) {
  return value;
}
}  // namespace helper

}  // namespace container_internal

namespace sibling_after_sentinel {
struct ScopedType {};
ScopedType use_sibling(ScopedType value) {
  return value;
}
}  // namespace sibling_after_sentinel

}  // namespace absl

namespace unrelated {
template <typename Params>
struct btree {
  using node_type = Params*;
  using iterator = Params*;
};

template <typename P>
void use_unrelated(typename btree<P>::iterator value,
                   typename btree<P>::node_type node) {
  (void)value;
  (void)node;
}
}  // namespace unrelated
