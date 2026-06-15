package example

class Indented:
  def callsThis(): Int =
    this.help()

  def help(): Int = 3

  def shadowInBranch(svc: Service): Int =
    if cond() then
      val svc = new Consumer()
      svc.hashCode()
    svc.run()

  def cond(): Boolean = true
