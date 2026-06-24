require "minitest/autorun"

class CalculatorMinitest < Minitest::Test
  def test_add
    assert_equal 3, 1 + 2
  end
end
