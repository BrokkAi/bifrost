// Production-shaped receiver chains distilled from Abseil's cord headers.
// The object-like namespace sentinel is intentionally undefined: this is the
// parser shape used by the installed headers when their config macros are not
// expanded by the analyzer.
namespace absl {
ABSL_NAMESPACE_BEGIN

namespace cord_internal {

struct CordRep {};

class CordRepBtree {
 public:
  struct CopyResult {
    CordRep* edge;
    int height;
  };

  static CordRep* New(CordRep*);
  CordRepBtree* SubTree();
};

namespace {
using CopyResult = CordRepBtree::CopyResult;

CordRepBtree* copy_prefix() {
  CopyResult prefix;
  prefix.edge = CordRepBtree::New(prefix.edge);
  return nullptr;
}
}  // namespace

class InlineData {
 public:
  char* as_chars();
  const char* as_chars() const;
};

}  // namespace cord_internal

class Cord {
 private:
  class InlineRep {
   public:
    void reduce_size();

   private:
    cord_internal::InlineData data_;
  };
};

inline void Cord::InlineRep::reduce_size() {
  data_.as_chars();
}

ABSL_NAMESPACE_END
}  // namespace absl

namespace unrelated {
struct CopyResult {
  int edge;
};

void copy_prefix() {
  CopyResult prefix;
  prefix.edge = 1;
}

class InlineData {
 public:
  const char* as_chars() const;
};

class InlineRep {
 public:
  void reduce_size() {
    InlineData data;
    data.as_chars();
  }
};
}  // namespace unrelated
