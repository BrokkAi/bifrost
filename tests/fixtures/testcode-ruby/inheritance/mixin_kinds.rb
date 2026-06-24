module Auditable
  def audit
    "audited"
  end
end

module Findable
  def find(id)
    id
  end
end

# `include` adds instance methods; `extend` adds class/singleton methods.
class User
  include Auditable
  extend Findable
end
