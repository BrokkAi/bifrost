package p

func len(values []int) int { return 1 }
func new(value int) *int { return &value }
func use(values []int) { _ = len(values); _ = new(1) }
