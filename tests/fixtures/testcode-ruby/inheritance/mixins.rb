module Walkable
  def walk
    "walking"
  end
end

module Swimmable
  def swim
    "swimming"
  end
end

class Duck
  include Walkable
  include Swimmable
  prepend Comparable

  def quack
    "Quack"
  end
end
