class SelectionService { def value: Int = 1; def zero(): Int = 0 }
object Calls {
  def selection(service: SelectionService): Int = service.value
  def explicit(service: SelectionService): Int = service.zero()
}
object MissingSelection { def caller(service: Service) = service.value }
