// Small production-shaped C++ fixture for Abseil random-distribution aliases.
//
// The object-like namespace sentinel is intentionally left undefined.  The
// tree-sitter C++ grammar treats it as a declaration-like node and recovers the
// declarations below through an ERROR envelope, matching the real Abseil
// headers.  Keep the out-of-line templates and dependent aliases: they are the
// useful part of this regression, not compiler-valid standalone code.
namespace absl {
ABSL_NAMESPACE_BEGIN

namespace random_internal {
template <typename T>
struct wide_multiply {
  static T multiply(T, T);
};
template <typename T>
struct make_unsigned_bits {
  using type = T;
};
}  // namespace random_internal

template <typename RealType = double>
class beta_distribution {
 public:
  using result_type = RealType;

  class param_type {
   private:
#ifdef _MSC_VER
#define ABSL_RANDOM_INTERNAL_LOG_EXP_CONSTEXPR
#else
#define ABSL_RANDOM_INTERNAL_LOG_EXP_CONSTEXPR constexpr
#endif
    // The macro-fragmented return type is the malformed helper envelope.
    static ABSL_RANDOM_INTERNAL_LOG_EXP_CONSTEXPR result_type
    ThresholdForSmallA() {
      return result_type(1);  // positive-beta-param-result-type
    }
    static ABSL_RANDOM_INTERNAL_LOG_EXP_CONSTEXPR result_type  // positive-beta-param-result-type
    ThresholdForLargeA() {
      return result_type(2);  // positive-beta-param-result-type-2
    }
#undef ABSL_RANDOM_INTERNAL_LOG_EXP_CONSTEXPR
  };

  template <typename URBG>
  result_type Algorithm(URBG&, const param_type&);
};

template <typename RealType>
template <typename URBG>
typename beta_distribution<RealType>::result_type
beta_distribution<RealType>::Algorithm(URBG&, const param_type&) {
  static constexpr result_type kLogFour =
      result_type(1.3862943611198906);  // positive-beta-result-type
  return kLogFour;
}

template <typename IntType = int>
class uniform_int_distribution {
 private:
  using unsigned_type =
      typename random_internal::make_unsigned_bits<IntType>::type;

 public:
  using result_type = IntType;
  class param_type {
   public:
    using distribution_type = uniform_int_distribution;
  };

 private:
  template <typename URBG>
  unsigned_type Generate(URBG&, unsigned_type);
};

template <typename IntType>
template <typename URBG>
typename uniform_int_distribution<IntType>::unsigned_type
uniform_int_distribution<IntType>::Generate(URBG&, unsigned_type) {
  using helper =
      random_internal::wide_multiply<unsigned_type>;  // positive-uniform-unsigned-type
  return static_cast<unsigned_type>(helper::multiply(1, 1));
}

template <typename IntType = int>
class discrete_distribution {
 public:
  using result_type = IntType;
  class param_type {
   public:
    using distribution_type = discrete_distribution;
  };

  template <typename URBG>
  result_type operator()(URBG&, const param_type&);

  void param(const param_type& p) { (void)p; }  // positive-discrete-inline-param-type
};

template <typename IntType>
template <typename URBG>
typename discrete_distribution<IntType>::result_type
discrete_distribution<IntType>::operator()(URBG&, const param_type&) {
  auto idx =
      uniform_int_distribution<result_type>(0, 0);  // positive-discrete-result-type
  return static_cast<result_type>(idx);  // positive-discrete-result-type
}

template <typename CharT, typename Traits, typename IntType>
void operator>>(discrete_distribution<IntType>& x) {
  using param_type =
      typename discrete_distribution<IntType>::param_type;  // positive-discrete-param-type
  (void)sizeof(param_type);
  (void)x;
}

template <typename IntType = int>
class log_uniform_int_distribution {
 private:
  using unsigned_type =
      typename random_internal::make_unsigned_bits<IntType>::type;

 public:
  using result_type = IntType;
  class param_type {};

 private:
  template <typename URNG>
  unsigned_type Generate(URNG&, const param_type&);
};

template <typename IntType>
template <typename URBG>
typename log_uniform_int_distribution<IntType>::unsigned_type
log_uniform_int_distribution<IntType>::Generate(URBG&, const param_type&) {
  return static_cast<unsigned_type>(1);  // positive-log-uniform-unsigned-type
}

ABSL_NAMESPACE_END
}  // namespace absl

namespace other {
template <typename T>
class beta_distribution {
 public:
  using result_type = T;
  class param_type {};
};
template <typename T>
class uniform_int_distribution {
 public:
  using unsigned_type = T;
};
template <typename T>
class discrete_distribution {
 public:
  using result_type = T;
  class param_type {};
};

template <typename T>
void use_same_spelled_siblings() {
  typename other::beta_distribution<T>::result_type beta = {};
  typename other::uniform_int_distribution<T>::unsigned_type uniform = {};
  typename other::discrete_distribution<T>::result_type discrete = {};
  using param_type = typename other::discrete_distribution<T>::param_type;
  (void)beta;
  (void)uniform;
  (void)discrete;
  (void)sizeof(param_type);
}
}  // namespace other
