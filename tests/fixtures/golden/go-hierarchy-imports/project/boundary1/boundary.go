package p

type Widget struct{}
func (Widget) Method() {}
type Speaker interface { Speak() }
func Target() {}
func MissingResult() Missing
func use(w Widget, speaker Speaker) {
    Target()
    w.Method()
    Widget.Method(w)
    speaker.Speak()
    MissingResult()
}
