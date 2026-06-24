require "test/unit"

class CalculatorTestUnit < Test::Unit::TestCase
  def test_subtract
    assert_equal(1, 3 - 2)
  end
end
