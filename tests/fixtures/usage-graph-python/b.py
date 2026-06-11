from a import helper


# Module-level call site: its enclosing scope is not a class or function, so
# this reference must not produce an edge from a non-node.
TOP = helper()


def run():
    return helper()


def run_twice():
    first = helper()
    second = helper()
    return first + second
