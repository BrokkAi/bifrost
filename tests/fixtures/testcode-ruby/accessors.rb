class Account
  MAX_BALANCE = 1_000_000

  attr_accessor :balance
  attr_reader :owner
  attr_writer :pin

  def initialize(owner)
    @owner = owner
    @balance = 0
  end
end
