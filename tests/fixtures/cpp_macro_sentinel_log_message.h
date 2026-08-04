// Production-shaped namespace-sentinel fixture distilled from Abseil's
// absl/log/internal/log_message.h.
namespace absl {
ABSL_NAMESPACE_BEGIN
namespace log_internal {
class LogMessage {
 public:
  LogMessage& NoPrefix();
  LogMessage& operator<<(std::ios_base& (*m)(std::ios_base& os));
};
}
ABSL_NAMESPACE_END
}
