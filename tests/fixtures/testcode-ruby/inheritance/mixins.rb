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

module Comparable
end

module Findable
end

class Duck
  include Walkable
  include Swimmable
  prepend Comparable
  extend Findable

  def quack
    "Quack"
  end
end
