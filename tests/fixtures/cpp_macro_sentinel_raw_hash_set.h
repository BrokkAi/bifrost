// Parser-recovery fixture extracted from Abseil's malformed raw_hash_set.h class prefix.
// The realistic member prefix is intentional: tree-sitter only exposes the class tail
// as declaration-list siblings (and the standalone semicolon boundary) after this
// prefix. The later InsertSlot/tail members are synthetic acceptance witnesses;
// keep the prefix when minimizing this regression fixture.
namespace absl {
ABSL_NAMESPACE_BEGIN
namespace container_internal {
template <class Policy, class... Params>
class raw_hash_set {
  using PolicyTraits = hash_policy_traits<Policy>;
  using Hash = GetFromListOr<typename Policy::DefaultHash, 0, Params...>;
  using Eq = GetFromListOr<typename Policy::DefaultEq, 1, Params...>;
  using Alloc = GetFromListOr<typename Policy::DefaultAlloc, 2, Params...>;
  using KeyArgImpl =
      KeyArg<IsTransparent<Eq>::value && IsTransparent<Hash>::value>;

  static_assert(
      std::is_same_v<
          typename InstantiateRawHashSet<Policy, Hash, Eq, Alloc>::type,
          raw_hash_set>,
      "Redundant template parameters were passed. Use InstantiateRawHashSet<> "
      "instead");

 public:
  using init_type = typename PolicyTraits::init_type;
  using key_type = typename PolicyTraits::key_type;
  using allocator_type = Alloc;
  using size_type = size_t;
  using difference_type = ptrdiff_t;
  using hasher = Hash;
  using key_equal = Eq;
  using policy_type = Policy;
  using value_type = typename PolicyTraits::value_type;
  using reference = value_type&;
  using const_reference = const value_type&;
  using pointer = typename std::allocator_traits<
      allocator_type>::template rebind_traits<value_type>::pointer;
  using const_pointer = typename std::allocator_traits<
      allocator_type>::template rebind_traits<value_type>::const_pointer;

 private:
  // Alias used for heterogeneous lookup functions.
  // `key_arg<K>` evaluates to `K` when the functors are transparent and to
  // `key_type` otherwise. It permits template argument deduction on `K` for the
  // transparent case.
  template <class K>
  using key_arg = typename KeyArgImpl::template type<K, key_type>;

  using slot_type = typename PolicyTraits::slot_type;

  constexpr static bool kIsDefaultHash =
      std::is_same_v<hasher, absl::Hash<key_type>> ||
      std::is_same_v<hasher, absl::container_internal::StringHash>;

  // TODO(b/289225379): we could add extra SOO space inside raw_hash_set
  // after CommonFields to allow inlining larger slot_types (e.g. std::string),
  // but it's a bit complicated if we want to support incomplete mapped_type in
  // flat_hash_map. We could potentially do this for flat_hash_set and for an
  // allowlist of `mapped_type`s of flat_hash_map that includes e.g. arithmetic
  // types, strings, cords, and pairs/tuples of allowlisted types.
  constexpr static bool SooEnabled() {
    return PolicyTraits::soo_enabled() &&
           sizeof(slot_type) <= sizeof(HeapOrSoo) &&
           alignof(slot_type) <= alignof(HeapOrSoo);
  }

  constexpr static size_t DefaultCapacity() {
    return SooEnabled() ? SooCapacity() : 0;
  }
  constexpr static size_t MaxValidSize() {
    return container_internal::MaxValidSize(sizeof(key_type),
                                            sizeof(slot_type));
  }
  constexpr static size_t MaxValidCapacity() {
    return SizeToCapacity(MaxValidSize());
  }

  // Whether `size` fits in the SOO capacity of this table.
  bool fits_in_soo(size_t size) const {
    return SooEnabled() && size <= SooCapacity();
  }
  // Whether this table is in SOO mode or non-SOO mode.
  bool is_soo() const {
    HashtableCapacity cap = maybe_invalid_capacity();
    return cap.IsValid() && fits_in_soo(cap.capacity());
  }
  bool is_full_soo() const { return is_soo() && !empty(); }

  bool is_small() const { return common().is_small(); }

  // Give an early error when key_type is not hashable/eq.
  auto KeyTypeCanBeHashed(const Hash& h, const key_type& k) -> decltype(h(k));
  auto KeyTypeCanBeEq(const Eq& eq, const key_type& k) -> decltype(eq(k, k));

  // Try to be helpful when the hasher returns an unreasonable type.
  using key_hash_result =
      absl::remove_cvref_t<decltype(std::declval<const Hash&>()(
          std::declval<const key_type&>()))>;
  static_assert(sizeof(key_hash_result) >= sizeof(size_t),
                "`Hash::operator()` should return a `size_t`");

  using AllocTraits = std::allocator_traits<allocator_type>;
  using SlotAlloc = typename std::allocator_traits<
      allocator_type>::template rebind_alloc<slot_type>;
  // People are often sloppy with the exact type of their allocator (sometimes
  // it has an extra const or is missing the pair, but rebinds made it work
  // anyway).
  using CharAlloc =
      typename std::allocator_traits<Alloc>::template rebind_alloc<char>;
  using SlotAllocTraits = typename std::allocator_traits<
      allocator_type>::template rebind_traits<slot_type>;

  static_assert(std::is_lvalue_reference_v<reference>,
                "Policy::element() must return a reference");

  // An enabler for insert(T&&): T must be convertible to init_type or be the
  // same as [cv] value_type [ref].
  template <class T>
  using Insertable = std::disjunction<
      std::is_same<absl::remove_cvref_t<reference>, absl::remove_cvref_t<T>>,
      std::is_convertible<T, init_type>>;
  template <class T>
  using IsNotBitField = std::is_pointer<T*>;

  // RequiresNotInit is a workaround for gcc prior to 7.1.
  // See https://godbolt.org/g/Y4xsUh.
  template <class T>
  using RequiresNotInit = std::enable_if_t<!std::is_same_v<T, init_type>, int>;

  template <class... Ts>
  using IsDecomposable = IsDecomposable<void, PolicyTraits, Hash, Eq, Ts...>;

  template <class T>
  using IsDecomposableAndInsertable =
      IsDecomposable<std::enable_if_t<Insertable<T>::value, T>>;

  // Evaluates to true if an assignment from the given type would require the
  // source object to remain alive for the life of the element.
  template <class U>
  using IsLifetimeBoundAssignmentFrom = std::conditional_t<
      policy_trait_element_is_owner<Policy>::value, std::false_type,
      type_traits_internal::IsLifetimeBoundAssignment<init_type, U>>;

 public:
  static_assert(std::is_same_v<pointer, value_type*>,
                "Allocators with custom pointer types are not supported");
  static_assert(std::is_same_v<const_pointer, const value_type*>,
                "Allocators with custom pointer types are not supported");

  class iterator : private HashSetIteratorGenerationInfo {
    friend class raw_hash_set;
    friend struct HashtableFreeFunctionsAccess;

   public:
    using iterator_category = std::forward_iterator_tag;
    using value_type = typename raw_hash_set::value_type;
    using reference =
        std::conditional_t<PolicyTraits::constant_iterators::value,
                            const value_type&, value_type&>;
    using pointer = std::remove_reference_t<reference>*;
    using difference_type = typename raw_hash_set::difference_type;

    // We use DefaultIterSlot() for default-constructed iterators so that
    // they can be distinguished from end iterators, which have nullptr slot_.
    iterator() : slot_(static_cast<slot_type*>(DefaultIterSlot())) {}

    // PRECONDITION: not an end() iterator.
    reference operator*() const {
      assert_is_full("operator*()");
      return unchecked_deref();
    }

    // PRECONDITION: not an end() iterator.
    pointer operator->() const {
      assert_is_full("operator->");
      return &operator*();
    }

    // PRECONDITION: not an end() iterator.
    iterator& operator++() {
      assert_is_full("operator++");
      ++ctrl_;
      ++slot_;
      skip_empty_or_deleted();
      if (ABSL_PREDICT_FALSE(*ctrl_ == ctrl_t::kSentinel)) slot_ = nullptr;
      return *this;
    }
    // PRECONDITION: not an end() iterator.
    iterator operator++(int) {
      auto tmp = *this;
      ++*this;
      return tmp;
    }

    friend bool operator==(const iterator& a, const iterator& b) {
      AssertIsValidForComparison(a.ctrl_, a.slot_, a.generation(),
                                 a.generation_ptr());
      AssertIsValidForComparison(b.ctrl_, b.slot_, b.generation(),
                                 b.generation_ptr());
      AssertSameContainer(a.ctrl_, b.ctrl_, a.slot_, b.slot_,
                          a.generation_ptr(), b.generation_ptr());
      return a.unchecked_equals(b);
    }
    friend bool operator!=(const iterator& a, const iterator& b) {
      return !(a == b);
    }

   private:
    iterator(ctrl_t* ctrl, slot_type* slot,
             const GenerationType* generation_ptr)
        : HashSetIteratorGenerationInfo(generation_ptr),
          ctrl_(ctrl),
          slot_(slot) {
      // This assumption helps the compiler know that any non-end iterator is
      // not equal to any end iterator.
      ABSL_ASSUME(slot != nullptr);
    }
    // For end() iterators.
    explicit iterator(const GenerationType* generation_ptr)
        : HashSetIteratorGenerationInfo(generation_ptr), slot_(nullptr) {}

    void assert_is_full(const char* operation) const {
      AssertIsFull(ctrl_, slot_, generation(), generation_ptr(), operation);
    }

    // Fixes up `ctrl_` to point to a full or sentinel by advancing `ctrl_` and
    // `slot_` until they reach one.
    void skip_empty_or_deleted() {
      while (IsEmptyOrDeleted(*ctrl_)) {
        ++ctrl_;
        ++slot_;
      }
    }

    // An equality check which skips ABSL Hardening iterator invalidation
    // checks.
    // Should be used when the lifetimes of the iterators are well-enough
    // understood to prove that they cannot be invalid.
    bool unchecked_equals(const iterator& b) const { return slot_ == b.slot(); }

    // Dereferences the iterator without ABSL Hardening iterator invalidation
    // checks.
    reference unchecked_deref() const { return PolicyTraits::element(slot_); }

    ctrl_t* control() const { return ctrl_; }
    slot_type* slot() const { return slot_; }

    // To avoid uninitialized member warnings, put ctrl_ in an anonymous union.
    // The member is not initialized on singleton and end iterators.
    union {
      ctrl_t* ctrl_;
    };
    slot_type* slot_;
  };

  class const_iterator {
    friend class raw_hash_set;
    template <class Container, typename Enabler>
    friend struct absl::container_internal::hashtable_debug_internal::
        HashtableDebugAccess;

   public:
    using iterator_category = typename iterator::iterator_category;
    using value_type = typename raw_hash_set::value_type;
    using reference = typename raw_hash_set::const_reference;
    using pointer = typename raw_hash_set::const_pointer;
    using difference_type = typename raw_hash_set::difference_type;

    const_iterator() = default;
    // Implicit construction from iterator.
    const_iterator(iterator i) : inner_(std::move(i)) {}  // NOLINT

    reference operator*() const { return *inner_; }
    pointer operator->() const { return inner_.operator->(); }

    const_iterator& operator++() {
      ++inner_;
      return *this;
    }
    const_iterator operator++(int) { return inner_++; }

    friend bool operator==(const const_iterator& a, const const_iterator& b) {
      return a.inner_ == b.inner_;
    }
    friend bool operator!=(const const_iterator& a, const const_iterator& b) {
      return !(a == b);
    }

   private:
    const_iterator(const ctrl_t* ctrl, const slot_type* slot,
                   const GenerationType* gen)
        : inner_(const_cast<ctrl_t*>(ctrl), const_cast<slot_type*>(slot), gen) {
    }
    bool unchecked_equals(const const_iterator& b) const {
      return inner_.unchecked_equals(b.inner_);
    }
    ctrl_t* control() const { return inner_.control(); }
    slot_type* slot() const { return inner_.slot(); }

    iterator inner_;
  };

  using node_type = node_handle<Policy, hash_policy_traits<Policy>, Alloc>;
  using insert_return_type = InsertReturnType<iterator, node_type>;

  // Note: can't use `= default` due to non-default noexcept (causes
  // problems for some compilers). NOLINTNEXTLINE
  raw_hash_set() noexcept(
      std::is_nothrow_default_constructible_v<hasher> &&
      std::is_nothrow_default_constructible_v<key_equal> &&
      std::is_nothrow_default_constructible_v<allocator_type>) {}

  explicit raw_hash_set(size_t reservation_size, const hasher& hash = hasher(),
                        const key_equal& eq = key_equal(),
                        const allocator_type& alloc = allocator_type())
      : settings_(CommonFields::CreateDefault<SooEnabled()>(), hash, eq,
                  alloc) {
    if (reservation_size > DefaultCapacity()) {
      ReserveTableToFitNewSize(common(), GetPolicyFunctions(),
                               reservation_size);
    }
  }

  raw_hash_set(size_t reservation_size, const hasher& hash,
               const allocator_type& alloc)
      : raw_hash_set(reservation_size, hash, key_equal(), alloc) {}

  raw_hash_set(size_t reservation_size, const allocator_type& alloc)
      : raw_hash_set(reservation_size, hasher(), key_equal(), alloc) {}

  explicit raw_hash_set(const allocator_type& alloc)
      : raw_hash_set(0, hasher(), key_equal(), alloc) {}

  template <class InputIter>
  raw_hash_set(InputIter first, InputIter last, size_t reservation_size = 0,
               const hasher& hash = hasher(), const key_equal& eq = key_equal(),
               const allocator_type& alloc = allocator_type())
      : raw_hash_set(
            SelectReservationSizeForIterRange(first, last, reservation_size),
            hash, eq, alloc) {
    insert(first, last);
  }

  template <class InputIter>
  raw_hash_set(InputIter first, InputIter last, size_t reservation_size,
               const hasher& hash, const allocator_type& alloc)
      : raw_hash_set(first, last, reservation_size, hash, key_equal(), alloc) {}

  template <class InputIter>
  raw_hash_set(InputIter first, InputIter last, size_t reservation_size,
               const allocator_type& alloc)
      : raw_hash_set(first, last, reservation_size, hasher(), key_equal(),
                     alloc) {}

  template <class InputIter>
  raw_hash_set(InputIter first, InputIter last, const allocator_type& alloc)
      : raw_hash_set(first, last, 0, hasher(), key_equal(), alloc) {}

  // Instead of accepting std::initializer_list<value_type> as the first
  // argument like std::unordered_set<value_type> does, we have two overloads
  // that accept std::initializer_list<T> and std::initializer_list<init_type>.
  // This is advantageous for performance.
  //
  //   // Turns {"abc", "def"} into std::initializer_list<std::string>, then
  //   // copies the strings into the set.
  //   std::unordered_set<std::string> s = {"abc", "def"};
  //
  //   // Turns {"abc", "def"} into std::initializer_list<const char*>, then
  //   // copies the strings into the set.
  //   absl::flat_hash_set<std::string> s = {"abc", "def"};
  //
  // The same trick is used in insert().
  //
  // The enabler is necessary to prevent this constructor from triggering where
  // the copy constructor is meant to be called.
  //
  //   absl::flat_hash_set<int> a, b{a};
  //
  // RequiresNotInit<T> is a workaround for gcc prior to 7.1.
  template <class T, RequiresNotInit<T> = 0,
            std::enable_if_t<Insertable<T>::value, int> = 0>
  raw_hash_set(std::initializer_list<T> init, size_t reservation_size = 0,
               const hasher& hash = hasher(), const key_equal& eq = key_equal(),
               const allocator_type& alloc = allocator_type())
      : raw_hash_set(init.begin(), init.end(), reservation_size, hash, eq,
                     alloc) {}

  raw_hash_set(std::initializer_list<init_type> init,
               size_t reservation_size = 0, const hasher& hash = hasher(),
               const key_equal& eq = key_equal(),
               const allocator_type& alloc = allocator_type())
      : raw_hash_set(init.begin(), init.end(), reservation_size, hash, eq,
                     alloc) {}

  template <class T, RequiresNotInit<T> = 0,
            std::enable_if_t<Insertable<T>::value, int> = 0>
  raw_hash_set(std::initializer_list<T> init, size_t reservation_size,
               const hasher& hash, const allocator_type& alloc)
      : raw_hash_set(init, reservation_size, hash, key_equal(), alloc) {}

  raw_hash_set(std::initializer_list<init_type> init, size_t reservation_size,
               const hasher& hash, const allocator_type& alloc)
      : raw_hash_set(init, reservation_size, hash, key_equal(), alloc) {}

  template <class T, RequiresNotInit<T> = 0,
            std::enable_if_t<Insertable<T>::value, int> = 0>
  raw_hash_set(std::initializer_list<T> init, size_t reservation_size,
               const allocator_type& alloc)
      : raw_hash_set(init, reservation_size, hasher(), key_equal(), alloc) {}

  raw_hash_set(std::initializer_list<init_type> init, size_t reservation_size,
               const allocator_type& alloc)
      : raw_hash_set(init, reservation_size, hasher(), key_equal(), alloc) {}

  template <class T, RequiresNotInit<T> = 0,
            std::enable_if_t<Insertable<T>::value, int> = 0>
  raw_hash_set(std::initializer_list<T> init, const allocator_type& alloc)
      : raw_hash_set(init, 0, hasher(), key_equal(), alloc) {}

  raw_hash_set(std::initializer_list<init_type> init,
               const allocator_type& alloc)
      : raw_hash_set(init, 0, hasher(), key_equal(), alloc) {}

  raw_hash_set(const raw_hash_set& that)
      : raw_hash_set(that, AllocTraits::select_on_container_copy_construction(
                               allocator_type(that.char_alloc_ref()))) {}

  raw_hash_set(const raw_hash_set& that, const allocator_type& a)
      : raw_hash_set(0, that.hash_ref(), that.eq_ref(), a) {
    that.AssertNotDebugCapacity();
    if (that.empty()) return;
    Copy(common(), GetPolicyFunctions(), that.common(),
         [this](void* dst, const void* src) {
           // TODO(b/413598253): type erase for trivially copyable types via
           // PolicyTraits.
           construct(to_slot(dst),
                     PolicyTraits::element(
                         static_cast<slot_type*>(const_cast<void*>(src))));
         });
  }

  ABSL_ATTRIBUTE_NOINLINE raw_hash_set(raw_hash_set&& that) noexcept(
      std::is_nothrow_copy_constructible_v<hasher> &&
      std::is_nothrow_copy_constructible_v<key_equal> &&
      std::is_nothrow_copy_constructible_v<allocator_type>)
      :  // Hash, equality and allocator are copied instead of moved because
         // `that` must be left valid. If Hash is std::function<Key>, moving it
         // would create a nullptr functor that cannot be called.
         // Note: we avoid using exchange for better generated code.
        settings_(PolicyTraits::transfer_uses_memcpy() || !that.is_full_soo()
                      ? std::move(that.common())
                      : CommonFields{full_soo_tag_t{},
                                     that.common().soo_has_tried_sampling()},
                  that.hash_ref(), that.eq_ref(), that.char_alloc_ref()) {
    if (!PolicyTraits::transfer_uses_memcpy() && that.is_full_soo()) {
      transfer(soo_slot(), that.soo_slot());
    }
    that.common() = CommonFields::CreateDefault<SooEnabled()>();
    annotate_for_bug_detection_on_move(that);
  }

  raw_hash_set(raw_hash_set&& that, const allocator_type& a)
      : settings_(CommonFields::CreateDefault<SooEnabled()>(), that.hash_ref(),
                  that.eq_ref(), a) {
    if (CharAlloc(a) == that.char_alloc_ref()) {
      swap_common(that);
      annotate_for_bug_detection_on_move(that);
    } else {
      move_elements_allocs_unequal(std::move(that));
    }
  }

  template <bool do_destroy>
  struct InsertSlot {
    raw_hash_set& s;
    int invoke();
  };
  int tail;
};
}
ABSL_NAMESPACE_END
}
