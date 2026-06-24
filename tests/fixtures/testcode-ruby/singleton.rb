class Logger
  def self.default
    new
  end

  class << self
    def configure
      :configured
    end
  end

  def log(message)
    message
  end
end
