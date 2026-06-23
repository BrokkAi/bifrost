package app

// Alpha and Beta both declare a method named `Channel`, but neither calls the
// other's. The previous per-symbol resolver cross-linked every same-named
// method (an O(n^2) false-positive cluster on generated code); the inverted
// builder must produce no edge between them.

type Alpha struct{}

func (a *Alpha) Channel() string { return "alpha" }

type Beta struct{}

func (b *Beta) Channel() string { return "beta" }

type Service struct{}

func NewService() Service { return Service{} }

func (s Service) Execute() string { return "service" }

type Other struct{}

func (o Other) Execute() string { return "other" }
