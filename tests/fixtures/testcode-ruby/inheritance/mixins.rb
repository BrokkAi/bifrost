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

module Quackable
  def quack_loudly
    "QUACK"
  end
end

class Duck
  include Walkable
  include Swimmable
  prepend Quackable

  def quack
    "Quack"
  end
end
