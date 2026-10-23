package p
var PackageValue int
func use(outer int, values []int) {
    for _, item := range values {
        callback := func(input int) (result int, extra int) {
            _ = input
            _ = result
            _ = extra
            _ = outer
            _ = PackageValue
            _ = item
            return outer, item
        }
        _ = callback
    }
}
