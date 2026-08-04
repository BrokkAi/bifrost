// Production-shaped regression for a macro-qualified C++ return type.
//
// The undefined namespace sentinel intentionally drives tree-sitter through
// the same malformed envelope as Abseil's random headers.  In particular,
// the object-like return macro leaves a phantom field immediately before each
// helper definition in the nested param_type class.
namespace absl {
ABSL_NAMESPACE_BEGIN

template <typename RealType = double>
class beta_distribution {
 public:
  using result_type = RealType;

  class param_type {
   private:
#define ABSL_RANDOM_INTERNAL_LOG_EXP_CONSTEXPR
    static ABSL_RANDOM_INTERNAL_LOG_EXP_CONSTEXPR result_type
    ThresholdForSmallA() {
      return result_type(1);  // positive-small-a-return-type
    }
    static ABSL_RANDOM_INTERNAL_LOG_EXP_CONSTEXPR result_type
    ThresholdForLargeA() {
      return result_type(2);  // positive-large-a-return-type
    }
#undef ABSL_RANDOM_INTERNAL_LOG_EXP_CONSTEXPR

    // A malformed real field followed by a normally typed function is a
    // near miss for the macro-return recovery and must remain indexed.
    DWORD preserved_field
    void PreserveFollowingFunction() {}
  };
};

ABSL_NAMESPACE_END
}  // namespace absl

namespace other {
template <typename T>
class beta_distribution {
 public:
  using result_type = T;
};

template <typename T>
void use_same_spelled_alias() {
  typename other::beta_distribution<T>::result_type value = {};
  (void)value;
}
}  // namespace other
