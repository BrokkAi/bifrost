package app

import "example.com/app/sub"

// callsCrossPackage calls an exported function in another package through a
// plain package selector (`sub.Helper`); the edge must resolve to sub.Helper.
func callsCrossPackage() int {
	return sub.Helper()
}

// describeAlpha calls a method on a receiver typed `*Alpha`, so the edge must
// resolve to Alpha.Channel specifically (not Beta.Channel, which shares the name).
func describeAlpha(a *Alpha) string {
	return a.Channel()
}

func runService() string {
	service := NewService()
	return service.Execute()
}

func shadowedGroupedService() string {
	var (
		NewService = func() Other { return Other{} }
		service    = NewService()
	)
	return service.Execute()
}

// total calls helper twice on two distinct lines: the edge weight aggregates to 2.
func total() int {
	first := helper()
	second := helper()
	return first + second
}

func helper() int { return 1 }

// recurse references itself; a self-reference must not produce an edge.
func recurse(n int) int {
	if n <= 0 {
		return 0
	}
	return recurse(n - 1)
}
