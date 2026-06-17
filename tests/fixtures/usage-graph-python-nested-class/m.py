class Foo:
    def method(self):
        return 1


def outer():
    recv = Foo()

    class Inner:
        # Class-body-level access of a function-scoped receiver. Receiver typing
        # is function-scoped, so this must NOT create an edge — matching the
        # per-symbol scan, whose enclosing lookup resolves this to `Inner` (a
        # class, which has no scope facts).
        y = recv.method()

    # Function-level access: this SHOULD create an edge outer -> Foo.method.
    return recv.method()
