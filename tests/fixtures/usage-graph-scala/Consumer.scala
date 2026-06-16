package example

class Consumer {
  def viaInstance(): Int = {
    val s = new Service()
    s.run()
  }

  def viaParam(svc: Service): Int = {
    svc.run()
  }

  def viaObject(): Int = {
    Helpers.help()
  }

  def callsLocal(): Int = {
    local()
  }

  def local(): Int = 7

  def makeService(): Service = {
    new Service()
  }

  def wrongReceiver(other: Consumer): Int = {
    other.run()
  }

  def recurse(): Int = {
    recurse()
  }
}
