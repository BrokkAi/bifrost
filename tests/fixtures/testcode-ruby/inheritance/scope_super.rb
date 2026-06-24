module Outer
  class Base
    def base_method
      :base
    end
  end
end

class Derived < Outer::Base
  def derived_method
    :derived
  end
end
