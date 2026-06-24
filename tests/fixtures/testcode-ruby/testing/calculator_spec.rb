require "spec_helper"

RSpec.describe Calculator do
  describe "#add" do
    it "adds two numbers" do
      expect(Calculator.new.add(1, 2)).to eq(3)
    end
  end
end
