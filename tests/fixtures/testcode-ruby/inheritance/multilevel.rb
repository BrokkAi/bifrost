class Base
  def root
    :base
  end
end

class Middle < Base
  def mid
    :middle
  end
end

class Child < Middle
  def leaf
    :child
  end
end
