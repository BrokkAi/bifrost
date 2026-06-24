module Loggable
  def log(message)
    message
  end
end

class Service
  include Loggable

  def work
    log("working")
  end

  def retry_work
    log("retrying")
  end
end
